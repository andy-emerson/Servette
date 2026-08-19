<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/servette-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/servette-light.svg">
  <img alt="Servette" src="assets/servette-light.svg" width="300">
</picture>

### The Simple, Secure, Static-Site Server

[![Tests](https://github.com/andy-emerson/servette/actions/workflows/test.yml/badge.svg)](https://github.com/andy-emerson/servette/actions/workflows/test.yml)
[![CodeQL](https://github.com/andy-emerson/servette/actions/workflows/codeql.yml/badge.svg)](https://github.com/andy-emerson/servette/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)

---

Servette is a production nanoserver. The `http.server` module in Python's standard library is the canonical nanoserver: it serves a folder in one command and, by its own documentation, is not built for production. Servette builds on that same `http.server` and adds everything the public internet demands: a trusted certificate that renews itself, HTTP redirected up to HTTPS, security headers on every response, rate limiting, password protection (optional), and a hardened service that survives reboots. No configuration language to learn, automatic certificate management, and a single dependency the install brings with it. Install the package, run `servette`, follow the wizard, done.

Most ways to serve a website sit at an extreme. **General-purpose servers** (nginx, Apache, Caddy) do *everything*: any site at any scale, once you have configured them. **Development servers** (`http.server`) do *one thing*: serve a folder right now, and stop there. **Managed platforms** (GitHub Pages, Netlify, Vercel) do it *for* you, on infrastructure and terms that are theirs, not yours.

Servette aims at the space between: **do everything _necessary_ to do one thing _well_.** The one thing is hosting a static site you own (anything that runs in a browser, from a simple portfolio to a serious client-side app). *Everything necessary* is what you cannot honestly skip on the public internet (trusted HTTPS that renews itself, optional passwords, rate limiting, a hardened service that survives reboots), and nothing past that line. Within that domain, nothing is missing.

The tools closest in spirit are small and focused, like Servette. Here is how a few peers compare on that one job:

| | Servette | bottle.py | srv | Static Web Server |
|---|:--:|:--:|:--:|:--:|
| **Built for** | static sites | dynamic web apps | static sites | static sites |
| Automatic trusted HTTPS | ✓ | ✗ | ✓ | ✗ |
| Hardened for production | ✓ | ✗ | ✗ | ~ |
| Readable source | ~4,500 lines | ~4,600 lines | binary | binary |
| Actively maintained | ✓ | ✓ | ✗ | ✓ |
| Runs on a Raspberry Pi out of the box | ✓ | ✓ | ✗ | ✗ |

All of these are excellent at what they are built for. None of them do what Servette does: serve a static site you own, securely, on the public internet, from a single module you can read.

---

## Who is Servette for?

**People who want to understand what their server is running.** General-purpose servers do the job, but they are large systems you configure and take on trust. Servette is one readable module (~4,500 lines of Python, no hidden machinery) that you can follow top to bottom in an afternoon.

**People with a real site that needs a real server.** Development servers (like `http.server`) are perfect while you build, but they are not meant to face the internet (no trusted HTTPS, no auth, gone when you close the terminal). Servette is built to stay up: a trusted certificate that renews itself, and a hardened service that survives reboots.

**People who want to own what they serve.** Managed platforms host it for you, on their infrastructure and their terms. Servette runs on your own server, with your own certificate, behind a password if you want one. Install it, answer a few questions, walk away.

**Raspberry Pi users.** Servette was designed with the Pi in mind. If you can SSH in and install a Python package, you can have a real HTTPS site live in under ten minutes (trusted certificate, automatic renewal, and a server that survives reboots).

---

## What Servette provides

| Feature | What it does |
|---|---|
| HTTPS by default | Your site is encrypted, browsers show the padlock, and plain-HTTP requests are redirected up to HTTPS |
| Basic Auth | Optional username and password to restrict access |
| Rate limiting | Stops bots from hammering the server; makes password guessing impractical |
| Instant content updates | New content is served the moment it lands — files are read fresh from disk on every request, so a `pull` needs no restart and drops no connections |
| Auto cert renewal | Let's Encrypt certificates renew automatically before they expire |
| Security headers | HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, and Permissions-Policy sent on every response |
| Automatic startup | Keeps running after you close your terminal; restarts automatically if the server reboots |
| Automatic recovery | A dead server process is restarted by systemd within seconds; a watchdog timer recovers a dropped network route |
| An error page that diagnoses | A missing path returns `404` with a page that reports the live connection — the certificate, the headers, and whether your site root is published at all — instead of a bare `Not found.` Drop in your own `404.html` and it takes over |

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

Servette keeps everything it serves and everything it saves in its data directory, `/var/lib/servette` — setup creates the `site/` folder there and owns it to *you* (the service only reads it), leaving it empty — an empty folder still answers, because a site with nothing published answers with Servette's error page, which reports that the server is up and what the connection is actually sending. From the server:

```
servette   # then, at the prompt: setup
```

Setup asks for your password when it reaches the work that needs root: writing the systemd unit and creating the restricted `servette` user — the server runs as that user, never as root. If Servette is installed under your home directory, setup also says it is copying itself into `/var/lib/servette/runtime`; that is deliberate, and it is what lets the service keep running when your home directory is unreadable to it. The wizard sets up a certificate (trusted Let's Encrypt if you gave a domain, else self-signed), sets an optional password, then enables and starts the service. Close your terminal — Servette keeps running, restarts on reboot, and renews its certificate automatically.

To put your site on it, build a signed bundle in the browser at [servette.org/pub/](https://servette.org/pub/) — it never uploads anything; the signing happens on your machine — host the `.tar.gz` and `.sig` pair anywhere reachable over HTTPS, set the URL and key once with `config` → `publish`, and run `pull`. Servette verifies the signature against that site's key before it swaps anything in, and `restore-site` undoes the last pull.

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
| `sites [--json]` | List configured sites |
| `set [n] k=v ...` | Change settings non-interactively (`servette set 0 publish_url=…`) |
| `pull [n]` | Pull new site content from a site's publish channel |
| `restore-site [n]` | Roll back a site's content to before its last pull |
| `help` · `quit` | Command list · exit |

**Update your site** with `pull` — the publish tool signs a new bundle, Servette verifies it and swaps it in atomically, and `restore-site` rolls back the last one. **Update Servette** with `pipx upgrade servette`; the next `servette` notices the service unit is stale and says so — run `enable` to refresh the service onto the new version. **Roll back** by installing the version you want (`pipx install --force servette==x.y.z`). Your `servette.toml` is never touched by an update.

> If you set a password, `servette.toml` holds its hash — sharing the file gives a recipient material for an offline cracking attempt.

### Host several sites

One machine can serve several sites, each with its own folder, certificate, and optional password. From the shell, `config` → `add-site` adds one (it asks for the folder, domain, password, and publish channel); `sites` lists what you have, and `remove-site <n>` drops one.

Every site has an index, shown by `sites` and starting at `0` — the one `setup` created. Commands that act on a single site take that index and default to `0`: `dir [n]`, `cert [n]`, `publish [n]`, and `username [n]` / `password [n]` under `config`, plus `pull [n]` and `restore-site [n]` from the main shell. So `cert 1` requests a certificate for the second site, and `pull 2` updates the third site's content from its channel.

**Update each site's content** in its own folder — the path you named when you added it. The single `/var/lib/servette/site` in the quickstart above is just site `0`'s folder.

### Publish without copying files (optional)

Each site can have a **publish channel**: build a signed bundle of your site in the browser at [servette.org/pub/](https://servette.org/pub/), host the `.tar.gz` + `.sig` pair at any HTTPS URL, and run `pull` — Servette fetches the bundle, verifies its signature against that site's `publish_key`, and swaps the content in atomically; `restore-site` undoes the last pull. Configure it with `config` → `publish [n]`. `servette pull [n]` runs one-shot, so a cron line gives you hands-off deploys — and the trigger always stays on your box: Servette never accepts content pushed from the network. With a password set, your site also answers `GET /.well-known/servette` with `{"running": "<version>"}` to logged-in clients — the version readout the error page shows. **Check any Servette site from a browser** by asking it for a path that isn't there: the error page that answers reports the certificate, the redirect, and the headers from a real browser's vantage, on the site that served it.

### If something's wrong

- **Site unreachable** → confirm ports 80 and 443 are open in the provider firewall / router (not just the OS firewall).
- **Let's Encrypt won't issue** → your domain must already resolve to this server's IP (`dig +short yourdomain.com`); Let's Encrypt validates over port 80. If `www.` has no DNS record, Servette falls back to a bare-domain certificate and tells you.
- **Browser warns about the certificate** → expected with a self-signed cert; add a domain, then `config` → `cert`.
- **A page 404s that shouldn't** → open the URL and read the error page: it reports whether your site root is published at all, which separates a wrong path from content that never landed. `GET /` showing `200` means the site is fine and the path is wrong.
- **Anything else** → `log` in the shell (or `journalctl -u servette`), and open any missing path on your own site — the default error page runs the connection checks and reports what it found.

## Repository map

| Path | What it is |
|---|---|
| `servette.py` | The entire product — server, system, and shell in one module, generated from `src/` and committed to be read. The package build regenerates it from `src/` at every install, and CI holds the committed copy equal to the sources. The error page is inlined into it from `src/404.html`, so an install is Python only |
| `src/` | The source of truth: five literate Markdown files (`INIT`/`SERVER`/`SYSTEM`/`SHELL`/`MAIN`), the error page (`404.html`), and the build — `build.py`, plus the backend that runs it inside every package build |
| `tests/test.py` | The whole test suite, run by CI against the pip-installed package on Ubuntu (Python 3.11 and 3.14) and Debian 12 |
| `README.md` | This file — the user-facing introduction and deploy guide |
| `DESIGN.md` | Developer's document: scope, invariants, architecture, and how to operate on the code |
| `AGENTS.md` · `CLAUDE.md` | The human–agent working agreement, and the pointer to it |
| `CONTRIBUTING.md` · `SECURITY.md` | How to contribute, and how to report a vulnerability |
| `LICENSE` | MIT |

The deploy guide above is the complete walkthrough; [servette.org](https://servette.org) carries a browsable view of the sources and the publish tool.
