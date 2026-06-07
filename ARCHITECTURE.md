# Architecture

## Design Philosophy

**One file. No dependencies. No build step.**

Servette is built around a single constraint: the entire server must live in one Python file with no dependencies beyond the standard library. A server you can audit in one sitting, copy with `scp`, and run with `python3` is a fundamentally different kind of tool than one that requires a package manager, a build step, or a configuration directory.

Three priorities follow from this:

**Scope discipline.** Servette serves one HTML file over HTTPS. It does not route requests, render templates, handle form submissions, or manage sessions. Sharp boundaries keep the codebase small and the remaining features trustworthy.

**Handled, not delegated.** TLS configuration, security headers, certificate renewal, rate limiting, service management — these are real concerns that every public-facing server has to get right. Servette handles them automatically so the operator can focus on the HTML file, not the infrastructure around it.

**Transparent by design.** Everything Servette does is visible in one readable file. There are no layers of abstraction hiding how requests are handled or how security decisions are made.

---

## Architecture Diagram

Servette is a single file, but it is not a monolith. It is organized into discrete modules with well-defined responsibilities. Config and Logging are cross-cutting — nearly every module reads config and writes to the log. The functional flow runs between them.

Solid arrows are control flow. Dashed arrows are dependencies.

```mermaid
graph LR
    CFG[Config]

    EP[Entry Point]
    SH[Shell]
    SV[Server]
    SD[systemd]
    HTTPS[HTTPS Handler]
    HTTP[HTTP Redirect]
    RL[Rate Limiter]
    FC[File Cache]

    LOG[Logging]

    CFG -.-> SH
    CFG -.-> SV
    CFG -.-> HTTPS
    CFG -.-> HTTP

    EP -->|--serve| SV
    EP -->|interactive| SH
    SH --> SV
    SH --> SD

    SV --> HTTPS
    SV --> HTTP

    HTTPS --> RL
    HTTPS --> FC

    HTTPS -.-> LOG
    HTTP -.-> LOG
    SV -.-> LOG
    SH -.-> LOG
```

---

## Modules

### Config

Config holds all settings in a single object and reads from and writes to `servette.json`. Accessing any setting is `config.html_file`, `config.port`, and so on. The config file is kept separate from `servette.py` deliberately — updating the server never overwrites your configuration.

On each incoming request, `reload_if_changed()` checks the file's modification time and reloads if it has changed. This means you can edit `servette.json` directly and have changes take effect without restarting the server.

**Password storage.** Passwords are hashed with PBKDF2-HMAC-SHA256 at 260,000 iterations — the OWASP recommendation at the time of writing. Passwords are never stored in plaintext. A migration path handles older config files that contain a plaintext `password` field: on first load the password is hashed and the plaintext key is removed.

**File permissions.** `servette.json` is written with mode `0o600` (owner read/write only) because it contains the password hash and salt.

---

### Logging

Python's standard `logging` module writes timestamped entries to both a log file and the terminal. The behavior differs between the two runtime modes:

- **Interactive shell:** only warnings and errors appear in the terminal. Informational entries go to the log file only, so they don't clutter the shell output.
- **Systemd service (`--serve`):** there is no file handler. Systemd captures stdout and appends it to the configured log file via `StandardOutput=append:`. This avoids two processes writing to the same file simultaneously.

If the log file cannot be opened, the error is silently ignored — logging is not worth crashing the server over.

---

### Rate Limiter

Two independent sliding-window rate limits, both over a 60-second window:

- **Request limit** (`rate_limit`, default 30/min): caps total requests per IP. Stops bots from hammering the server.
- **Auth limit** (`auth_rate_limit`, default 6/min): caps failed authentication attempts per IP. Makes brute-force password guessing impractical.

Both trackers are in-memory dicts of `{ip: [timestamp, ...]}`. A threading lock protects concurrent access. Stale entries — IPs not seen in over 60 seconds — are pruned on each check to keep memory bounded.

The auth limit only triggers when credentials are actually submitted, not on unauthenticated requests. This prevents locking out a visitor who simply hasn't logged in yet.

---

### File Cache

The HTML file is read once, gzip-compressed, and held in memory. On each request the file's modification time is checked; if it has changed the cache is refreshed. Edits take effect immediately without restarting the server.

An ETag is computed as the first 16 hex characters of the SHA-256 hash of the raw file contents. If a browser sends back the same ETag in `If-None-Match`, the server returns 304 Not Modified with no body — the browser uses its cached copy.

Both compressed and raw bytes are stored. If the client sends `Accept-Encoding: gzip` (all modern browsers do), the compressed version is sent. A `Vary: Accept-Encoding` header tells caching proxies to store separate copies for clients that do and don't support gzip.

The cache is protected by a threading lock since multiple request handler threads may read and update it simultaneously.

---

### HTTPS Handler

`HTTPSHandler` subclasses Python's `BaseHTTPRequestHandler` and implements `do_GET` and `do_HEAD` — the only HTTP methods Servette accepts. All other methods return 405 Method Not Allowed.

On each request, in order:

1. Reload config if `servette.json` has changed on disk
2. Check the request rate limit for this IP
3. If auth is configured, check credentials — then check the auth rate limit if credentials were submitted and wrong
4. Read the HTML file from cache (refreshing from disk if the file has changed)
5. Return 304 if the client's ETag matches
6. Send the response with security headers

**Security headers sent on every response:**

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Tells browsers to use HTTPS for this domain from now on |
| `X-Frame-Options: DENY` | Prevents the page from being embedded in iframes on other sites |
| `X-Content-Type-Options: nosniff` | Stops browsers from misinterpreting the content type |
| `Referrer-Policy: no-referrer` | Prevents your URL from leaking to sites your page links to |

`Content-Security-Policy` and `Permissions-Policy` are supported but not sent by default. The correct values depend on what your HTML file loads — inline scripts, CDN sources, required browser APIs — so they are left to the operator via `config` → `csp` / `perms`.

**Connection timeout.** Connections that don't send a complete request within 10 seconds are closed. This defends against slow loris attacks, where a client opens a connection and trickles headers slowly to tie up server threads.

**Threading model.** `HTTPSHandler` runs inside a `ThreadingMixIn` server, which spawns a new OS thread per connection. Since the file is served from memory and most repeat requests return a 304 with no body, individual thread lifetimes are extremely short. The rate limiter bounds the realistic request volume per IP. A thread pool executor would cap total simultaneous threads, but adds queue management complexity for no practical benefit at Servette's expected scale.

---

### HTTP Redirect Handler

`HTTPRedirectHandler` listens on port 80 and handles two cases:

**ACME challenge requests.** Let's Encrypt verifies domain ownership by fetching a token file over plain HTTP at `/.well-known/acme-challenge/<token>`. The handler serves these files from `ACME_WEBROOT` on disk. This allows certificate renewal without stopping the server — certbot drops the token file, the running handler serves it, and renewal completes without any downtime.

Token paths are validated: empty tokens and paths containing `/` or `..` are rejected with 404 to prevent directory traversal.

**Everything else.** Plain HTTP requests are redirected to the HTTPS equivalent with 301 Moved Permanently. The port is omitted from the redirect URL when the HTTPS port is 443, keeping the URL clean. Browsers cache 301 redirects, so subsequent visits go straight to HTTPS without touching port 80.

---

### Server

`start_server()` creates two `ThreadedHTTPServer` instances — one for HTTPS on the configured port, one for the HTTP redirect on port 80 — and starts each in a daemon thread. Daemon threads shut down automatically when the main process exits.

Binding to port 80 requires root. If it fails, the HTTPS server still starts — visitors just need to type `https://` manually. The failure is reported but is not fatal.

On startup, the SSL certificate's expiry date is checked. If it expires within 30 days, a warning is printed with instructions to renew.

`stop_server()` calls `shutdown()` on both servers, which blocks until `serve_forever()` returns. Because `stop_server()` runs in the shell thread (separate from the `serve_forever()` threads), there is no deadlock risk.

---

### Shell

The shell is the interactive terminal interface — a command loop that reads input and dispatches to the appropriate function. When Servette is started by systemd (`--serve`), the shell is skipped entirely.

**Config sub-shell.** `config` opens a nested prompt where each setting can be viewed and edited individually. Settings are written to `servette.json` immediately on change. The Shell module is the only place that writes to Config.

**Setup wizard.** `setup` walks through each configuration step in order, checks whether it is already complete, and offers to run it if not. It detects the server's public IP, checks certificate expiry, and offers to install the systemd service. This is the recommended starting point for new users.

**Service management.** `enable` and `disable` write and remove the systemd service file, call `daemon-reload`, and enable/disable the unit. The service file is generated programmatically from the current environment — Python path, `servette.py` path, and log file path are all resolved at enable time, so the service file is always consistent with where Servette actually lives.

---

### Entry Point

`__main__` checks for the `--serve` flag:

- **`--serve`**: calls `start_server()` directly and enters a sleep loop. Used exclusively by the systemd service.
- **Interactive**: calls `shell()`. The server starts only when the user runs `start`.

---

## Testing

The test suite (`test.py`) starts a temporary HTTPS server on port 8443, runs checks against it, and tears everything down. `openssl` must be available on the system. No configuration required.

Three areas are intentionally not covered by the automated suite:

**Shell and config commands.** The interactive shell can't be driven programmatically without significant scaffolding. Test manually by running `sudo python3 servette.py` and working through `setup`, `config`, `status`, and `log`.

**systemd integration.** Requires a real Linux system with systemd. Test by running `enable`, closing your terminal, and verifying the server is still reachable. Reboot and verify it comes back automatically.

**SSL certificate issuance and renewal.** Requires a domain pointed at a real server. Let's Encrypt verifies domain ownership over the public internet — it cannot be faked in a test environment. Test by running `config` → `cert` with a real domain and checking the expiry date with `status`.

---

## Design Decisions

Things an experienced server operator might question — with the reasoning behind each.

**Running as root.** Servette requires `sudo` because binding to ports 80 and 443 is reserved for root on Linux. The standard alternative — a dedicated system user with `CAP_NET_BIND_SERVICE` — requires creating a system account, configuring file permissions, and managing certificate access across multiple paths. That is several steps that work against Servette's core purpose. For a server with no database, no exec paths, and a single cached file to serve, running as root is a deliberate and reasonable tradeoff.

**`ThreadingMixIn` over a thread pool executor.** A bounded thread pool would cap total simultaneous connections and prevent thread exhaustion under extreme load. For Servette's workload — one cached file, extremely short thread lifetimes, per-IP rate limiting already bounding realistic request volume — the benefit is theoretical. `ThreadingMixIn` is simpler, more readable, and sufficient.

**IPv6 not supported.** Servette currently binds to IPv4 only. For the typical deployment — a domain pointed at a VPS — IPv4 is the common case. IPv6 dual-stack support is a future improvement.

**Multiple files or static directories.** Serving a directory requires path routing, MIME type detection, and path traversal protection across every file. That is a different tool. If you need more, use nginx or caddy.

**POST handling and form processing.** POST implies data going somewhere — a database, an email, a file on disk. Servette has no destination for POST data, so it returns 405. If your HTML file submits a form, the backend it posts to is outside Servette's scope.

**WebSockets.** WebSockets require protocol upgrade handling and persistent connection management — out of scope for a static file server.

**Windows and macOS service management.** The `enable` and `disable` commands use systemd, which is Linux-only. Supporting launchd (macOS) and the Windows Service Control Manager would add significant branching complexity for a tool that is, by definition, deployed to a Linux server.

**CSP and Permissions-Policy defaults.** These headers are supported but not sent by default. The correct values depend entirely on what your HTML file loads — inline scripts, external resources, required browser APIs. Hardcoding defaults that would break most pages is worse than sending nothing.
