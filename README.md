<p>
  <img alt="" src="https://raw.githubusercontent.com/andy-emerson/Servette/main/assets/servette-mark.svg" width="64">&nbsp;&nbsp;<picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/andy-emerson/Servette/main/assets/servette-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/andy-emerson/Servette/main/assets/servette-light.svg">
    <img alt="Servette" src="https://raw.githubusercontent.com/andy-emerson/Servette/main/assets/servette-light.svg" width="277">
  </picture>
</p>

### The Simple, Secure, Static-Site Server

[![Tests](https://github.com/andy-emerson/servette/actions/workflows/test.yml/badge.svg)](https://github.com/andy-emerson/servette/actions/workflows/test.yml)
[![CodeQL](https://img.shields.io/badge/CodeQL-enabled-2f81f7?logo=github&logoColor=white)](https://github.com/andy-emerson/servette/security/code-scanning)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)

---

The `http.server` module in Python's standard library is the canonical nanoserver: it serves a folder in one command and, by its own documentation, is not built for production. Servette builds on that same `http.server` and adds everything the public internet demands: a trusted certificate that renews itself, HTTP redirected up to HTTPS, security headers on every response, rate limiting, password protection (optional), and a hardened service that survives reboots. No configuration language to learn, one dependency the install brings with it. Install the package, run `servette`

```
pipx install servette
servette
```

then, at the prompt type `setup`, and you are done.

You need Python 3.11+, a Linux machine you can SSH into (macOS runs in session mode), ports 80 and 443 reachable from the internet, and a domain pointed at it for a trusted certificate — skip the domain to serve your LAN over a self-signed one. You never prefix `sudo`: Servette asks for your password when it reaches the work that needs root. Setup ends with a certificate, an optional password, and a service that keeps running after you close the terminal, restarts on reboot, and renews its certificate on its own.

Then put your site on it from your own computer: run `servette admin` over SSH and open the printed link. The admin page is served over your own SSH tunnel and exists nowhere on the public internet, with a one-time passcode per run as the login. Drop your site's folder on its card and press Publish. The content is staged, checked, and swapped in atomically; the tree it replaced is kept, and `restore-site` rolls back to it.

## What Servette provides

| Feature | What it does |
|---|---|
| HTTPS by default | Your site is encrypted, browsers show the padlock, and plain-HTTP requests are redirected up to HTTPS |
| Public or private sites | A site is public by default; make it private with a username and password, and visitors sign in to view it |
| Rate limiting | Stops bots from hammering the server; makes password guessing impractical |
| Instant content updates | New content is served the moment it lands — every request re-checks the file on disk, so publishing needs no restart and drops no connections |
| Auto cert renewal | Let's Encrypt certificates renew automatically before they expire |
| Security headers | HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, and Permissions-Policy sent by default on every response |
| Automatic startup | Keeps running after you close your terminal; restarts automatically if the server reboots |
| Automatic recovery | A dead server process is restarted by systemd within seconds; a watchdog timer recovers a dropped network route |
| A browser admin page | `servette admin` serves an admin page to your browser over your own SSH tunnel — one card per site (publish, preview, domain, certificate, access, redirects, history), the server's own status and settings, and traffic statistics read from its log. It never exists on the public internet: the tunnel is the road in, and a one-time code per session is the login |
| Several sites per server | One machine serves many sites, each with its own certificate and optional password — the admin page's cards are the site list, and every card publishes independently |
| Publishing keeps a history | Every publish keeps the content it replaced. The five most recent are held, and any of them goes live again in one click, or one `restore-site`, as instantly as a publish |
| Preview before you publish | Look at the folder you chose, served over your own tunnel and not published: links and stylesheets resolve, so you see what landed before anyone else does |
| Redirects | Point an old path at a new one, per site, from either surface — permanently, or temporarily while the old path stays the real address. Stored as a setting, not as a file in your site |
| A connection test built in | Every site serves a live check page at `/.well-known/servette-check`: the encryption, the security headers, and whether your site root is published at all, reported from a real browser's vantage. The default 404 page links it — and your own `404.html` can take the error page over without ever losing the check |

**Will it serve your site?** Servette serves static files as they are. It returns `405` to `POST` requests (it has nowhere to put submitted data) and it does not rewrite deep links for single-page-app routers (React Router, Vue Router, and the like). If your site needs either, you are looking for a different project (a general-purpose server, not Servette). That is by design, not a limitation to work around. 

## Who is Servette for?

**People who want to understand what their server is running.** General-purpose servers do the job, but they are large systems you configure and take on trust. Servette is one readable module (~6,800 lines of Python, no hidden machinery), sized and structured so that one person can fully understand all of it. Reading the entire source, which was written to be read, is a weekend's honest work.

**People with a site to share that needs a simple secure server.** Development servers are perfect while you build, but they are not meant to face the internet. Servette is built to stay up: a trusted certificate that renews itself, and a hardened service that survives reboots.

**People who want to own what they serve.** Managed platforms host it for you, on their infrastructure and their terms. Servette runs on your own server, with your own certificate and authentication, without giving up the intuitive GUI.

**Raspberry Pi users.** Servette was designed with constrained hardware in mind. If you can SSH in and install a Python package, you can have a real HTTPS site live in under ten minutes.

## How it compares

The common ways to serve a folder sit at two extremes: the general-purpose servers can be made secure, but are not simple; nanoservers are simple, but not secure.

| | Servette | nginx | Apache | miniserve | Static Web Server |
|---|:--:|:--:|:--:|:--:|:--:|
| Serves a folder in a single command | ✓ | ✗ | ✗ | ✓ | ✓ |
| No config language to learn | ✓ | ✗ | ✗ | ✓ | ✓ |
| Trusted HTTPS with auto-renew | ✓ | Configurable | Configurable | ✗ | ✗ |
| Security headers and rate limiting | Automatic | Configurable | Configurable | ✗ | ✗ |
| Survives a reboot as a service | ✓ | ✓ | ✓ | ✗ | Configurable |
| Readable source | literate Markdown | large C binary | large C binary | Rust crate | Rust crate |

Both extremes are right for their jobs: nanoservers are appropriate for building and testing, while production servers such as nginx and Apache are appropriate for more complex deployments, including large server-side applications. Servette is for the gap between: production security with nanoserver simplicity, from a single module you can read. (Peer columns hand-checked 2026-08.)

## Operating it

Re-run `servette` any time for the interactive shell — or run any command as `servette <command>` and it executes once and exits, which is how scripts and external tools drive Servette (there is deliberately no network admin API):

| Command | What it does |
|---|---|
| `setup` | Guided first-time walkthrough |
| `config` | View and edit settings |
| `start` / `stop` | Start or stop the server |
| `enable` / `disable` | Add or remove the background service |
| `status [--json]` | Show whether the server is running |
| `log [n]` | Show recent activity |
| `traffic` | Requests, statuses, and top paths from the last 7 days |
| `sites [--json]` | List configured sites |
| `set [n] k=v ...` | Change settings non-interactively (`servette set 0 active=no`) |
| `admin` | Open the browser admin page (publish, settings) over your SSH tunnel |
| `publish [n] <folder>` | Publish a folder on the server as a site's content |
| `restore-site [n]` | Roll back a site's content to a kept version |
| `help` · `quit` | Command list · exit |

**Update your site** with `admin`: pick the folder in the browser, publish, done. Or, from the terminal: copy the folder to the server and run `publish 0 <folder>`, done.

**Update Servette** with `pipx upgrade servette`; the next `servette` notices the service unit is stale and refreshes it when it has the permission (otherwise, it says so, and `enable` refreshes the service onto the new version).

**Roll back Servette** by installing the version you want (`pipx install --force servette==x.y.z`). Your `servette.toml` is never touched by an update.

> If you set a password, `servette.toml` holds its hash — sharing the file gives a recipient material for an offline cracking attempt.

## Links

- **[servette.org](https://servette.org)** — the project site, with a browsable view of the sources.
- **[Source on GitHub](https://github.com/andy-emerson/Servette)** — the code, the tests, and the issue tracker.
- **[DESIGN](https://github.com/andy-emerson/Servette/blob/main/DESIGN.md)** — why Servette is built this way, and what is deliberately out of scope.
- **[Security policy](https://github.com/andy-emerson/Servette/blob/main/SECURITY.md)** — how to report a vulnerability.
- MIT licensed.
