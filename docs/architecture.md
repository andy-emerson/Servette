# Architecture

How `servette.py` is built — the current state of the system, for anyone who wants to understand or modify it. For *why* (scope, non-goals, methodology) see [`principles.md`](principles.md); to deploy and operate it see [`tutorial.md`](tutorial.md); the new-user introduction is [`README.md`](../README.md). This is the design philosophy made into a system: every piece below exists to serve a principle.

## How it works

Servette is a single file (`servette.py`, ~2,200 lines) with three sections, each readable on its own. Settings persist to `servette.toml` beside it.

| Section | Lines | Responsibility |
| - | - | - |
| **Server** | ~660 | every incoming request: config, rate limiting, file cache, the two ASGI apps |
| **System** | ~760 | the environment: bootstrap, server lifecycle, certificates, systemd |
| **Shell** | ~720 | the interactive terminal interface |

```mermaid
graph LR
    EP[Entry Point]

    subgraph SERVER
        CFG[Config]
        LOG[Logging]
        RL[Rate Limiter]
        FC[File Cache]
        HTTPS[HTTPS App]
        HTTP[Redirect App]
    end

    subgraph SYSTEM
        BS[Bootstrap]
        SRV[Server Lifecycle]
        ASG[ASGI Runner]
        CW[Cert Watchdog]
        ACME[ACME]
        SD[systemd]
    end

    SH[Shell]

    CFG -.-> HTTPS
    CFG -.-> HTTP
    CFG -.-> SRV
    CFG -.-> SH

    EP --> BS
    BS -->|--serve| SRV
    BS -->|interactive| SH

    SH --> SRV
    SH --> SD

    SRV --> ASG
    SRV --> CW
    ASG --> HTTPS
    ASG --> HTTP

    CW --> ACME

    HTTPS --> RL
    HTTPS --> FC

    HTTPS -.-> LOG
    HTTP -.-> LOG
    SRV -.-> LOG
    SH -.-> LOG
```

### Server

**Config.** A `Config` object reads and writes `servette.toml`; every field has a default. `reload_if_changed()` runs on every incoming request, so edits take effect without a restart. Passwords are hashed with scrypt (memory-hard; N=2¹⁴, r=8, p=1) and never stored in plaintext; plaintext `password` fields in old configs are migrated on first load. The file is written `0o600`.

**Logging.** Interactive mode sends warnings and errors to the terminal; service mode sends output to the systemd journal (`journalctl -u servette`), which handles rotation and retention.

**Rate limiter.** Two independent in-memory sliding-window dicts per IP — total requests (default 120/min) and failed auth attempts (default 6/min) — under a `threading.Lock`. The auth limiter activates only when credentials are actually submitted, not on unauthenticated requests. IPv6-mapped IPv4 addresses are normalized. `X-Forwarded-For` is trusted only when a `trusted_proxy` IP is configured, and only its rightmost value (one hop). Stale-IP eviction runs in a background `_rate_sweep` thread every 30 seconds, off the request hot path; it starts and stops with the server, not at import.

**File cache.** Files are read once and cached in `_file_cache` keyed by path; compressible (text-like) types are also gzip-stored and the right encoding is sent per `Accept-Encoding`, while already-compressed types (images, fonts, video) are served raw. A file too large to fit the cache is served raw (uncompressed) without being stored, so it can't purge everything else and isn't re-compressed on every request. `mtime` is checked on each request, so the cache refreshes when a file changes — this is the live reload. ETags (SHA-256 of contents) drive 304 responses. Reading and compressing happen in a worker thread (via `asyncio.to_thread`), so a large file never blocks the event loop and starves other connections.

**HTTPS app.** The ASGI coroutine for every HTTPS request: rate limiting → auth → path resolution → file serving. `_resolve_request_path()` resolves URLs within `serve_dir`, enforces path-traversal protection (403), and falls directories back to `index.html`. Serves a custom `404.html` if present, infers MIME types from extensions, honors single byte ranges (`206` / `416`) for media seeking, and sends security headers on every response: X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, Permissions-Policy, and HSTS when a domain cert is active.

**Redirect app.** The ASGI coroutine on port 80: serves ACME HTTP-01 challenge tokens from `ACME_WEBROOT` during issuance, preserves the query string, and 301-redirects everything else to HTTPS.

Both apps run under Hypercorn in a background daemon thread with its own asyncio event loop, started by `start_server()`. `start_server()` fails closed: if the listener does not come up, it stops the thread and (under `--serve`) exits nonzero rather than leaving a process that looks healthy but serves nothing. Shutdown is coordinated via a `threading.Event` passed to Hypercorn's `shutdown_trigger`.

### System

**Bootstrap (`_bootstrap`).** Runs before any other code. If `sys.prefix` isn't the managed venv, it creates `.servette-env/`, installs the four dependencies, and `os.execv`s back into itself inside the venv. As a systemd service the venv Python is invoked directly and bootstrap is a no-op.

**Server lifecycle.** `start_server()` / `stop_server()` own the daemon thread, the event loop, and the background threads (rate sweep, cert watchdog). `_production_issues()` returns the conditions blocking production readiness — serve directory missing, cert not configured, self-signed cert, no password — and is printed on startup and on every `status`. This function *is* the claim ladder in code: it refuses to imply production-ready while anything is wrong.

**Certificates.** Self-signed certs come from the `cryptography` library (`_generate_self_signed_cert`). Let's Encrypt certs use `acme`+`josepy` (`_run_acme`) over HTTP-01, temporarily starting `redirect_app` on port 80 if the main server isn't running. `_run_acme` first attempts a cert covering both `domain` and `www.domain`; if `www.` fails DNS validation only, it falls back to the bare domain and says so. Retries up to 3 times with backoff; skips the spinner when stdout isn't a TTY (auto-renewal).

**Cert watchdog (`_cert_watchdog`).** A daemon thread polling every 60s: for a configured domain, renews when the cert expires in < 30 days (at most once per hour on failure); for self-signed certs, detects external file changes by mtime and reloads. `_wait_for_port_free()` gates restarts on the TCP port actually being free.

**systemd.** `enable`/`disable` write and manage `/etc/systemd/system/servette.service`. `cmd_install` creates the `servette` system user (no login shell, no home), chowns cert/key/config to it, and the unit runs as that user, sandboxed: `AmbientCapabilities=CAP_NET_BIND_SERVICE` lets it bind 80/443 without root, while `NoNewPrivileges`, `ProtectSystem=strict` (with `ReadWritePaths` limited to the server's own directory and the ACME webroot), `PrivateTmp`, and the kernel/cgroup protections confine it. `sudo` is needed only for the interactive shell, which writes the unit and calls `useradd`.

**Self-update (`cmd_update`).** Updates come from signed GitHub Releases, not raw `main`. `cmd_update` fetches the latest release's `servette.py` and `servette.py.sig`, verifies the signature against the pinned `_SIGNING_PUBLIC_KEY`, validates syntax, and swaps the file in atomically; if the systemd service is active it then offers to restart it. The signature is the trust anchor, and it is why distribution goes through releases at all: a release is verifiable, whereas `main` is whatever is currently there, signed by no one. Settings in `servette.toml` are never touched by an update. The release-publishing procedure (a maintainer task, since it needs the private key) is in [`AGENTS.md`](../AGENTS.md#releasing-maintainer-task).

### Shell

The interactive REPL shown when running without `--serve`. Dispatches to `cmd_setup`, `cmd_config`, `cmd_install`/`cmd_uninstall`, `cmd_start`/`cmd_stop`, `cmd_status`, `cmd_log`, `cmd_update`. The `config` sub-shell writes each setting to `servette.toml` immediately. It contains only UI logic and is the only layer that writes to Config interactively.

### Key constants

| Name | Value | Purpose |
| - | - | - |
| `_VENV_DIR` | `<BASE_DIR>/.servette-env` | managed virtualenv |
| `SERVICE_PATH` | `/etc/systemd/system/servette.service` | systemd unit |
| `ACME_WEBROOT` | `/var/lib/letsencrypt/webroot` | ACME challenge file root |
| `RATE_WINDOW` | `60` seconds | sliding window for both rate limits |

### Notable design decisions

- **Hypercorn over a hand-rolled server** — HTTP/2, modern TLS defaults, and async concurrency that would take significant code to get right. The cost is a dependency, which bootstrap manages invisibly.
- **Managed virtualenv over system packages** — `.servette-env/` is isolated, reproducible, and invisible to the rest of the system.
- **CSP default blocks what static sites never need** — plugins (`object-src 'none'`), `eval()`, plain-HTTP external resources — while allowing own-origin, HTTPS externals, inline styles/scripts, and data URIs. Tune via `config > csp`; blank disables it.
- **Permissions-Policy default denies hardware APIs** — camera, microphone, USB, MIDI, serial — that need a backend or specialized hardware. APIs a static site might use (geolocation, fullscreen, payment) are left at browser defaults. Tune via `config > perms`; blank disables it.
