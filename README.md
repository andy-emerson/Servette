<p>
  <img alt="" src="assets/servette-mark.svg" width="64">&nbsp;&nbsp;<picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/servette-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/servette-light.svg">
    <img alt="Servette" src="assets/servette-light.svg" width="277">
  </picture>
</p>

### The Simple, Secure, Static-Site Server

[![Tests](https://github.com/andy-emerson/servette/actions/workflows/test.yml/badge.svg)](https://github.com/andy-emerson/servette/actions/workflows/test.yml)
[![CodeQL](https://img.shields.io/badge/CodeQL-enabled-2f81f7?logo=github&logoColor=white)](https://github.com/andy-emerson/servette/security/code-scanning)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)

---

Servette is a production nanoserver. The `http.server` module in Python's standard library is the canonical nanoserver: it serves a folder in one command and, by its own documentation, is not built for production. Servette builds on that same `http.server` and adds everything the public internet demands: a trusted certificate that renews itself, HTTP redirected up to HTTPS, security headers on every response, rate limiting, password protection (optional), and a hardened service that survives reboots. No configuration language to learn, one dependency the install brings with it. Install the package, run `servette`, follow the wizard, done.

Most ways to serve a website sit at an extreme. **General-purpose servers** (nginx, Apache, Caddy) do *everything*: any site at any scale, once you have configured them. **Development servers** (`http.server`) do *one thing*: serve a folder right now, and stop there. **Managed platforms** (GitHub Pages, Netlify, Vercel) do it *for* you, on infrastructure and terms that are theirs, not yours.

Servette aims at the space between: **do everything _necessary_ to do one thing _well_.** The one thing is hosting a static site you own (anything that runs in a browser, from a simple portfolio to a serious client-side app). *Everything necessary* is what you cannot honestly skip on the public internet (trusted HTTPS that renews itself, optional passwords, rate limiting, a hardened service that survives reboots), and nothing past that line. Within that domain, nothing is missing.

The tools closest in spirit are small and focused, like Servette. Here is how a few peers compare on that one job:

| | Servette | bottle.py | srv | Static Web Server |
|---|:--:|:--:|:--:|:--:|
| **Built for** | static sites | dynamic web apps | static sites | static sites |
| Automatic trusted HTTPS | ✓ | ✗ | ✓ | ✗ |
| Hardened for production | ✓ | ✗ | ✗ | ~ |
| Readable source | ~6,800 lines | ~4,600 lines | binary | binary |
| Actively maintained | ✓ | ✓ | ✗ | ✓ |
| Runs on a Raspberry Pi out of the box | ✓ | ✓ | ✗ | ✗ |

All of these are excellent at what they are built for. None of them do what Servette does: serve a static site you own, securely, on the public internet, from a single module you can read. (Peer columns as checked 2026-08; only Servette's own figures are gated by CI.)

---

## Who is Servette for?

**People who want to understand what their server is running.** General-purpose servers do the job, but they are large systems you configure and take on trust. Servette is one readable module (~6,800 lines of Python, no hidden machinery), sized and structured so that one person can fully understand all of it — a weekend's honest work, not an afternoon's skim, and not a career.

**People with a real site that needs a real server.** Development servers (like `http.server`) are perfect while you build, but they are not meant to face the internet (no trusted HTTPS, no auth, gone when you close the terminal). Servette is built to stay up: a trusted certificate that renews itself, and a hardened service that survives reboots.

**People who want to own what they serve.** Managed platforms host it for you, on their infrastructure and their terms. Servette runs on your own server, with your own certificate, behind a password if you want one. Install it, answer a few questions, walk away.

**Raspberry Pi users.** Servette was designed with the Pi in mind. If you can SSH in and install a Python package, you can have a real HTTPS site live in under ten minutes (trusted certificate, automatic renewal, and a server that survives reboots).

---

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
| Publishing keeps a history | Every publish keeps the content it replaced. The five most recent are held, and any of them goes live again in one click, or one `restore-site`, as instantly as a publish |
| Preview before you publish | Look at the folder you chose, served over your own tunnel and not published: links and stylesheets resolve, so you see what landed before anyone else does |
| Redirects | Point an old path at a new one, per site, from either surface — permanently, or temporarily while the old path stays the real address. Stored as a setting, not as a file in your site |
| A connection test built in | Every site serves a live check page at `/.well-known/servette-check`: the encryption, the security headers, and whether your site root is published at all, reported from a real browser's vantage. The default 404 page links it — and your own `404.html` can take the error page over without ever losing the check |

**Will it serve your site?** Servette serves static files as they are. It returns `405` to `POST` requests (it has nowhere to put submitted data) and it does not rewrite deep links for single-page-app routers (React Router, Vue Router, and the like). If your site needs either, you are looking for a different project (a general-purpose server, not Servette), and that is by design, not a limitation to work around; see [Scope & non-goals](DESIGN.md#scope--non-goals) for what is out of scope and why.

---

## Get started

You need a Linux machine on the internet (Ubuntu 22.04+, Debian 12+, or Raspberry Pi OS; Python 3.11+; SSH access) and your site files. (macOS works in session mode — serving, certificates, and the shell, with no boot-persistent service; production deployment targets Linux.) Getting the machine is the same as for any site and isn't Servette-specific; two common shapes follow, then setup — which is identical everywhere.

### Deploy on a cloud VPS (e.g. AWS Lightsail)

The example is Lightsail; DigitalOcean, Linode, and Vultr are the same idea.

1. **Create a small Linux instance** — Ubuntu is a safe default. Note the login user (on Lightsail Ubuntu it's `ubuntu`).
2. **Open ports 80 and 443** in the provider's firewall panel (on Lightsail: the instance's **Networking** tab). This is separate from the OS firewall and is the step people miss — 80 carries the HTTP→HTTPS redirect and Let's Encrypt validation, 443 serves the site.
3. **Attach a static IP** so the address survives restarts.
4. **Point your domain at it** — an `A` record to the static IP, before requesting a certificate.
5. **SSH in and install Servette:**
   ```
   pipx install servette
   ```
   `pipx` puts Servette and its one dependency in their own environment and the
   `servette` command on your path. If it isn't installed yet, `sudo apt install
   pipx` first — Debian and Ubuntu recommend pipx for Python applications, and
   refuse `pip install` into the system Python.

   You never prefix Servette with `sudo`. It needs root for a few things — the
   systemd unit, the service user, its own config, the folders it serves — and
   asks for it when it gets there, one password prompt at a time.

   <details><summary><b>If that doesn't work</b></summary>

   | What you see | What it means |
   |---|---|
   | `pipx: command not found` | `sudo apt install pipx`, then re-run. On macOS, `brew install pipx`. |
   | `E: Unable to locate package pipx` | The package index is stale or the repository holding pipx is off. `sudo apt update` first; on Ubuntu, pipx lives in `universe` (`sudo add-apt-repository universe`), and on Debian 12 it is in `main` once the index is current. |
   | `No matching distribution found for servette` | Your Python is older than 3.11 — check `python3 --version`. |
   | `error: externally-managed-environment` | Something used `pip` against the system Python. Use `pipx`, which makes its own environment. |
   | `servette: command not found` after installing | pipx put it in `~/.local/bin`, which isn't on your `PATH` yet. Run `pipx ensurepath`, then open a new shell. |
   | `sudo: a password is required` and you have no sudo rights | Servette cannot install a service without root. Run it as root, or on a machine where you can. |
   | Building `cryptography` from source, or a Rust compiler error | No prebuilt wheel matched your platform — usually a 32-bit or very old OS. A current 64-bit release has wheels. |

   Re-running the install is always safe.
   </details>

### Deploy on your own machine (e.g. a Raspberry Pi)

1. **Install a Linux OS and enable SSH** (the Raspberry Pi Imager can set this up before first boot).
2. **Forward ports 80 and 443** on your router to the machine, and point a domain's `A` record at your public IP (a dynamic-DNS service keeps the record current if your home IP changes). Skip this to run on your LAN only, with a self-signed certificate.
3. **SSH in and install Servette** — the same one line as the VPS shape above, troubleshooting table included.

### Run setup

Servette keeps everything it serves and everything it saves in its data directory, `/var/lib/servette`. Setup creates the `site/` folder there, owned by you (the service only reads it), and leaves it empty — an empty site still answers: visitors get Servette's error page, which reports that the server is up. From the server:

```
servette   # then, at the prompt: setup
```

Setup asks for your password when it reaches the work that needs root: writing the systemd unit and creating the restricted `servette` user — the server runs as that user, never as root. If Servette is installed under your home directory, setup also says it is copying itself into `/var/lib/servette/runtime`; that is deliberate, and it is what lets the service keep running when your home directory is unreadable to it. The wizard sets up a certificate (trusted Let's Encrypt if you gave a domain, else self-signed), sets an optional password, then enables and starts the service. Close your terminal — Servette keeps running, restarts on reboot, and renews its certificate automatically.

To put your site on it, use the admin page: on your own computer, add the one-time line setup printed to `~/.ssh/config`, inside the host entry you already use to reach the server. Then run `servette admin` and open the printed link. The page runs in your browser but is served by your server over that SSH connection — it exists nowhere on the public internet. Drop your site's folder on its card (or pick it), press Publish, and the content is staged, checked, and swapped in atomically; `restore-site` undoes it.

### Operate it

Re-run `servette` any time for the interactive shell — or run any command below as `servette <command>` and it executes once and exits, which is how scripts and external tools drive Servette (there is deliberately no network admin API):

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

**Update your site** with `admin` — pick the folder in the browser, publish, done — or from the terminal: copy the folder to the server and run `publish 0 ~/sites/blog`. A tidy convention (a convention only — Servette attaches no meaning to the path): keep site folders under `~/sites/`, one complete site per folder, and publish when the copy has finished — `publish` reads the folder as it stands, so a half-copied tree publishes half a site. Either way the content swaps in atomically, and the tree it replaced is kept: `restore-site` rolls back to it.

**Update Servette** with `pipx upgrade servette`; the next `servette` notices the service unit is stale and refreshes it when it has the permission — otherwise it says so, and `enable` refreshes the service onto the new version.

**Roll back Servette** by installing the version you want (`pipx install --force servette==x.y.z`). Your `servette.toml` is never touched by an update.

> If you set a password, `servette.toml` holds its hash — sharing the file gives a recipient material for an offline cracking attempt.

### Host several sites

One machine can serve several sites, each with its own certificate and optional password — and the admin page's Publish tab is the site list: one card per site to publish, plus add, reorder (drag a card's header, or its arrows), and remove. From the shell, `config` → `add-site` adds one, `sites` lists what you have, `remove-site <n>` deletes one (its copies on the server — your originals are untouched), `set <n> active=no` deactivates one without deleting anything, and `move-site <n> <to>` reorders — order matters only for sites without a domain: the first of those answers requests that match no site.

Every site has an index, shown by `sites` and starting at `0` — the one `setup` created. Commands that act on a single site take that index and default to `0`: `cert [n]` and `username [n]` / `password [n]` under `config`, plus `restore-site [n]` from the main shell. So `cert 1` requests a certificate for the second site, and `restore-site 2` rolls the third site's content back.

**Update each site's content by publishing to it** — the card's Publish button, or `publish <n> <folder>` — never by editing the served folder in place: where content lives is Servette's business, and publishing is what keeps the version history that makes `restore-site` possible.

### Publishing over SSH, and checking a site

Content reaches a site only by your own publish: the admin page over your SSH tunnel, or `publish` on the server itself. Servette never accepts content pushed from the network, and there is nothing to configure — no account, no signing key, no hosted shelf. With a password set, your site also answers `GET /.well-known/servette` with `{"running": "<version>"}` to logged-in clients. **Check any Servette site from a browser** by asking it for a path that isn't there: the error page that answers reports the certificate, the redirect, and the headers from a real browser's vantage, on the site that served it.

### If something's wrong

- **Site unreachable** → confirm ports 80 and 443 are open in the provider firewall / router (not just the OS firewall).
- **Let's Encrypt won't issue** → your domain must already resolve to this server's IP (`dig +short yourdomain.com`); Let's Encrypt validates over port 80. If `www.` has no DNS record, Servette falls back to a bare-domain certificate and tells you.
- **Browser warns about the certificate** → expected with a self-signed cert; add a domain, then `config` → `cert`.
- **A page 404s that shouldn't** → open the URL and read the error page: it reports whether your site root is published at all, which separates a wrong path from content that never landed. `GET /` showing `200` means the site is fine and the path is wrong.
- **Anything else** → `log` in the shell (or `journalctl -u servette`), and open any missing path on your own site — the default error page runs the connection tests and reports what it found.

## Repository map

| Path | What it is |
|---|---|
| `servette.py` | The entire product — server, system, and shell in one module, generated from `src/` and committed to be read. The package build regenerates it from `src/` at every install, and CI holds the committed copy equal to the sources. The error page, the connection test, and the admin page are inlined into it from `src/404.html`, `src/connection.html`, and `src/admin.html`, so an install is Python only |
| `src/` | The source of truth: five literate Markdown files (`INIT`/`SERVER`/`SYSTEM`/`SHELL`/`MAIN`), the three embedded pages (`404.html`, `connection.html`, `admin.html`), and the build — `build.py`, plus the backend that runs it inside every package build |
| `tests/test.py` | The whole test suite, run by CI against the pip-installed package on Ubuntu (Python 3.11 through 3.14) and Debian 12 |
| `README.md` | This file — the user-facing introduction and deploy guide |
| `DESIGN.md` | Developer's document: scope, invariants, architecture, and how to operate on the code |
| `AGENTS.md` · `CLAUDE.md` | The human–agent working agreement, and the pointer to it |
| `CONTRIBUTING.md` · `SECURITY.md` | How to contribute, and how to report a vulnerability |
| `LICENSE` | MIT |

The deploy guide above is the complete walkthrough; [servette.org](https://servette.org) carries a browsable view of the sources and the publish tool.
