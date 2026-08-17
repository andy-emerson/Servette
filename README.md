<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/servette-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/servette-light.svg">
  <img alt="Servette" src="assets/servette-light.svg" width="300">
</picture>

### The Simple, Secure Static-Site Server

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
| Readable source | ~3,900 lines | ~4,600 lines | binary | binary |
| Actively maintained | ✓ | ✓ | ✗ | ✓ |
| Runs on a Raspberry Pi out of the box | ✓ | ✓ | ✗ | ✗ |

All of these are excellent at what they are built for. None of them do what Servette does: serve a static site you own, securely, on the public internet, from a single module you can read.

---

## Who is Servette for?

**People who want to understand what their server is running.** General-purpose servers do the job, but they are large systems you configure and take on trust. Servette is one readable module (~3,900 lines of Python, no hidden machinery) that you can follow top to bottom in an afternoon.

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
5. **SSH in and install Servette** — one line:
   ```
   sudo python3 -m venv /opt/servette && sudo /opt/servette/bin/pip install servette && sudo ln -s /opt/servette/bin/servette /usr/local/bin/servette
   ```
   Three things happen: a private environment for Servette and its one
   dependency, the install into it, and `servette` placed on the system path so
   `sudo servette` finds it. The environment is needed because Debian, Ubuntu,
   and Raspberry Pi OS refuse `pip install` into the system Python; the symlink
   is needed because `sudo` ignores your own `PATH`.

   <details><summary><b>If that doesn't work</b></summary>

   | What you see | What it means |
   |---|---|
   | `No module named venv` / `ensurepip is not available` | `sudo apt install python3-venv` (Debian, Ubuntu, Raspberry Pi OS), then re-run. |
   | `No matching distribution found for servette` | Your Python is older than 3.11 — check with `python3 --version`. |
   | `error: externally-managed-environment` | The `venv` step was skipped, so pip is being pointed at the system Python. Run the line as written. |
   | `servette: command not found` | The symlink didn't land. `ls -l /usr/local/bin/servette` — if it's missing, re-run the third command alone. |
   | `sudo servette` not found but plain `servette` works | The command is on your `PATH` but not on `sudo`'s. Servette needs root to write its systemd unit, so it has to be in `/usr/local/bin` — re-run the third command. |
   | `File exists` on the symlink | An older install is already there. Remove it (`sudo rm /usr/local/bin/servette`) and re-run that command. |
   | Building `cryptography` from source, or a Rust compiler error | No prebuilt wheel matched your platform — usually a 32-bit or very old OS. Upgrade to a current 64-bit release, where wheels are published. |
   | `Permission denied` writing `/opt/servette` | The `sudo` was dropped from one of the commands. |

   Nothing here needs undoing before a retry: the line is safe to run again.
   </details>

### Deploy on your own machine (e.g. a Raspberry Pi)

1. **Install a Linux OS and enable SSH** (the Raspberry Pi Imager can set this up before first boot).
2. **Forward ports 80 and 443** on your router to the machine, and point a domain's `A` record at your public IP (a dynamic-DNS service keeps the record current if your home IP changes). Skip this to run on your LAN only, with a self-signed certificate.
3. **SSH in and install Servette** — the same one-line install as the VPS shape above, troubleshooting table included.

### Run setup

Servette keeps everything it serves and everything it saves in its data directory, `/var/lib/servette` — setup creates the `site/` folder there and owns it to *you* (the service only reads it), leaving it empty — an empty folder still answers, because a site with nothing published serves Servette's diagnostic page, which reports that the server is up and what the connection is actually sending. From the server:

```
sudo servette   # then, at the prompt: setup
```

`sudo` is needed because setup writes a systemd unit and creates a restricted `servette` user — the server runs as that user, not root. The wizard sets up a certificate (trusted Let's Encrypt if you gave a domain, else self-signed), sets an optional password, then enables and starts the service. Close your terminal — Servette keeps running, restarts on reboot, and renews its certificate automatically.

To put your site on it, build a signed bundle in the browser at [servette.org/pub/](https://servette.org/pub/) — it never uploads anything; the signing happens on your machine — host the `.tar.gz` and `.sig` pair anywhere reachable over HTTPS, set the URL and key once with `config` → `publish`, and run `pull`. Servette verifies the signature against that site's key before it swaps anything in, and `restore-site` undoes the last pull.

### Operate it

Re-run `sudo servette` any time for the interactive shell — or run any command below as `sudo servette <command>` and it executes once and exits, which is how scripts and external tools drive Servette (there is deliberately no network admin API):

| Command | What it does |
|---|---|
| `setup` | Guided first-time walkthrough |
| `config` | View and edit settings |
| `start` / `stop` | Start or stop the server |
| `enable` / `disable` | Add or remove the background service |
| `status [--json]` | Show whether the server is running |
| `log [n]` | Show recent activity |
| `sites [--json]` | List configured sites |
| `set [n] k=v ...` | Change settings non-interactively (`sudo servette set 0 publish_url=…`) |
| `pull [n]` | Pull new site content from a site's publish channel |
| `restore-site [n]` | Roll back a site's content to before its last pull |
| `help` · `quit` | Command list · exit |

**Update your site** with `pull` — the publish tool signs a new bundle, Servette verifies it and swaps it in atomically, and `restore-site` rolls back the last one. **Update Servette** the way you update any pip-installed tool (`sudo /opt/servette/bin/pip install -U servette`); the next `sudo servette` notices a stale service unit and refreshes it. **Roll back** by installing the version you want (`sudo /opt/servette/bin/pip install servette==x.y.z`). Your `servette.toml` is never touched by an update.

> If you set a password, `servette.toml` holds its hash — sharing the file gives a recipient material for an offline cracking attempt.

### Host several sites

One machine can serve several sites, each with its own folder, certificate, and optional password. From the shell, `config` → `add-site` adds one (it asks for the folder, domain, password, and publish channel); `sites` lists what you have, and `remove-site <n>` drops one.

Every site has an index, shown by `sites` and starting at `0` — the one `setup` created. Commands that act on a single site take that index and default to `0`: `dir [n]`, `cert [n]`, `publish [n]`, and `username [n]` / `password [n]` under `config`, plus `pull [n]` and `restore-site [n]` from the main shell. So `cert 1` requests a certificate for the second site, and `pull 2` updates the third site's content from its channel.

**Update each site's content** in its own folder — the path you named when you added it. The single `/var/lib/servette/site` in the quickstart above is just site `0`'s folder.

### Publish without copying files (optional)

Each site can have a **publish channel**: build a signed bundle of your site in the browser at [servette.org/pub/](https://servette.org/pub/), host the `.tar.gz` + `.sig` pair at any HTTPS URL, and run `pull` — Servette fetches the bundle, verifies its signature against that site's `publish_key`, and swaps the content in atomically; `restore-site` undoes the last pull. Configure it with `config` → `publish [n]`. `sudo servette pull [n]` runs one-shot, so a cron line gives you hands-off deploys — and the trigger always stays on your box: Servette never accepts content pushed from the network. With a password set, your site also answers `GET /.well-known/servette` with `{"running": "<version>"}` to logged-in clients — the version readout the self-test shows. **Verify any Servette site at `/selftest/`** — every install serves the connection self-test there (your own `selftest/` content takes precedence), checking the certificate, redirect, and headers from a real browser's vantage.

### If something's wrong

- **Site unreachable** → confirm ports 80 and 443 are open in the provider firewall / router (not just the OS firewall).
- **Let's Encrypt won't issue** → your domain must already resolve to this server's IP (`dig +short yourdomain.com`); Let's Encrypt validates over port 80. If `www.` has no DNS record, Servette falls back to a bare-domain certificate and tells you.
- **Browser warns about the certificate** → expected with a self-signed cert; add a domain, then `config` → `cert`.
- **A page 404s that shouldn't** → open the URL and read the error page: it reports whether your site root is published at all, which separates a wrong path from content that never landed. `GET /` showing `200` means the site is fine and the path is wrong.
- **Anything else** → `log` in the shell (or `journalctl -u servette`), and open any missing path on your own site — the default error page runs the connection checks and reports what it found.

## Repository map

| Path | What it is |
|---|---|
| `servette/` | The installable package: `__init__.py` is the entire product — server, system, and shell in one module, generated from `src/` and not edited by hand — beside a stub `__main__.py`. The diagnostic page is inlined into the module at build time from `src/diagnostics.html`, so an install is Python only |
| `src/` | The source of truth: five literate Markdown files (`INIT`/`SERVER`/`SYSTEM`/`SHELL`/`MAIN`) plus `build.py`, which assembles them into the module |
| `tests/test.py` | The whole test suite, run by CI against the pip-installed package on Ubuntu (Python 3.11 and 3.14) and Debian 12 |
| `README.md` | This file — the user-facing introduction and deploy guide |
| `DESIGN.md` | Developer's document: scope, invariants, architecture, and how to operate on the code |
| `AGENTS.md` · `CLAUDE.md` | The human–agent working agreement, and the pointer to it |
| `CONTRIBUTING.md` · `SECURITY.md` | How to contribute, and how to report a vulnerability |
| `LICENSE` | MIT |

The deploy guide above is the complete walkthrough; [servette.org](https://servette.org) carries the live self-test, a browsable view of the sources, and the publish tool.
