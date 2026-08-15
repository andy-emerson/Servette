<picture>
  <source media="(prefers-color-scheme: dark)" srcset="site/assets/servette-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="site/assets/servette-light.svg">
  <img alt="Servette" src="site/assets/servette-light.svg" width="300">
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
| Readable source | ~3,000 lines | ~4,600 lines | binary | binary |
| Actively maintained | ✓ | ✓ | ✗ | ✓ |
| Runs on a Raspberry Pi out of the box | ✓ | ✓ | ✗ | ✗ |

All of these are excellent at what they are built for. None of them do what Servette does: serve a static site you own, securely, on the public internet, from a single module you can read.

---

## Who is Servette for?

**People who want to understand what their server is running.** General-purpose servers do the job, but they are large systems you configure and take on trust. Servette is one readable file (~3,000 lines of Python, no hidden machinery) that you can follow top to bottom in an afternoon.

**People with a real site that needs a real server.** Development servers (like `http.server`) are perfect while you build, but they are not meant to face the internet (no trusted HTTPS, no auth, gone when you close the terminal). Servette is built to stay up: a trusted certificate that renews itself, and a hardened service that survives reboots.

**People who want to own what they serve.** Managed platforms host it for you, on their infrastructure and their terms. Servette runs on your own server, with your own certificate, behind a password if you want one. Install it, answer a few questions, walk away.

**Raspberry Pi users.** Servette was designed with the Pi in mind. If you can SSH in and run a Python script, you can have a real HTTPS site live in under ten minutes (trusted certificate, automatic renewal, and a server that survives reboots).

---

## What Servette provides

| Feature | What it does |
|---|---|
| HTTPS by default | Your site is encrypted, browsers show the padlock, and plain-HTTP requests are redirected up to HTTPS |
| Basic Auth | Optional username and password to restrict access |
| Rate limiting | Stops bots from hammering the server; makes password guessing impractical |
| Live reload | Edit any file and changes appear immediately, no restart required |
| Auto cert renewal | Let's Encrypt certificates renew automatically before they expire |
| Security headers | HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, and Permissions-Policy sent on every response |
| Automatic startup | Keeps running after you close your terminal; restarts automatically if the server reboots |
| Automatic recovery | A dead server process is restarted by systemd within seconds; a watchdog timer recovers a dropped network route |

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
   ssh -i your-key.pem user@YOUR.IP
   sudo python3 -m venv /opt/servette
   sudo /opt/servette/bin/pip install "servette @ git+https://github.com/andy-emerson/Servette"
   sudo ln -s /opt/servette/bin/servette /usr/local/bin/servette
   ```
   (Once Servette has its first PyPI release this becomes `pip install servette`; the venv keeps the install isolated either way, and `pipx install --global servette` does the same job where pipx ≥ 1.5 is available.)

### Deploy on your own machine (e.g. a Raspberry Pi)

1. **Install a Linux OS and enable SSH** (the Raspberry Pi Imager can set this up before first boot).
2. **Forward ports 80 and 443** on your router to the machine, and point a domain's `A` record at your public IP (a dynamic-DNS service keeps the record current if your home IP changes). Skip this to run on your LAN only, with a self-signed certificate.
3. **SSH in and install Servette** — the same three lines as the VPS shape above.

### Run setup

Servette keeps everything it serves and everything it saves in its data directory, `/var/lib/servette` — setup creates the `site/` folder there, owns it to *you* (the service only reads it), and offers to write Servette's placeholder page when it's empty, so a fresh install serves a real page immediately. From the server:

```
sudo servette   # then, at the prompt: setup
```

`sudo` is needed because setup writes a systemd unit and creates a restricted `servette` user — the server runs as that user, not root. The wizard sets up a certificate (trusted Let's Encrypt if you gave a domain, else self-signed), sets an optional password, then enables and starts the service. Close your terminal — Servette keeps running, restarts on reboot, and renews its certificate automatically. Copy your site in whenever you like:

```
scp -r mysite/* user@YOUR.IP:/var/lib/servette/site/
```

### Operate it

Re-run `sudo servette` any time for the interactive shell — or run any command below as `sudo servette <command>` and it executes once and exits, which is how scripts and external tools drive Servette (there is deliberately no network admin API):

| Command | What it does |
|---|---|
| `setup` | Guided first-time walkthrough |
| `config` | View and edit settings |
| `start` / `stop` | Start or stop the server |
| `enable` / `disable` | Add or remove the background service |
| `status` | Show whether the server is running |
| `log [n]` | Show recent activity |
| `sites [--json]` | List configured sites |
| `set [n] k=v ...` | Change settings non-interactively (`sudo servette set 0 publish_url=…`) |
| `pull [n]` | Pull new site content from a site's publish channel |
| `restore-site [n]` | Roll back a site's content to before its last pull |
| `help` · `quit` | Command list · exit |

**Update your site** by copying new files over (`scp -r mysite/* user@your.server.ip:/var/lib/servette/site/`) — changes appear immediately, no restart. **Update Servette** the way you update any pip-installed tool (`sudo /opt/servette/bin/pip install -U …`); the next `sudo servette` notices a stale service unit and refreshes it. **Roll back** by installing the version you want (`pip install servette==x.y.z`). Your `servette.toml` is never touched by an update.

> If you set a password, `servette.toml` holds its hash — sharing the file gives a recipient material for an offline cracking attempt.

### Host several sites

One machine can serve several sites, each with its own folder, certificate, and optional password. From the shell, `config` → `add-site` adds one (it asks for the folder, domain, password, and publish channel); `sites` lists what you have, and `remove-site <n>` drops one.

Every site has an index, shown by `sites` and starting at `0` — the one `setup` created. Commands that act on a single site take that index and default to `0`: `dir [n]`, `cert [n]`, `publish [n]`, and `username [n]` / `password [n]` under `config`, plus `pull [n]` and `restore-site [n]` from the main shell. So `cert 1` requests a certificate for the second site, and `pull 2` updates the third site's content from its channel.

**Update each site's content** in its own folder — the path you named when you added it. The single `/var/lib/servette/site` in the quickstart above is just site `0`'s folder.

### If something's wrong

- **Site unreachable** → confirm ports 80 and 443 are open in the provider firewall / router (not just the OS firewall).
- **Let's Encrypt won't issue** → your domain must already resolve to this server's IP (`dig +short yourdomain.com`); Let's Encrypt validates over port 80. If `www.` has no DNS record, Servette falls back to a bare-domain certificate and tells you.
- **Browser warns about the certificate** → expected with a self-signed cert; add a domain, then `config` → `cert`.
- **Anything else** → `log` in the shell (or `journalctl -u servette`).

## Repository map

| Path | What it is |
|---|---|
| `servette/` | The installable package: `__init__.py` is the entire product — server, system, and shell in one module, generated from `src/` and not edited by hand — beside a two-line `__main__.py` |
| `src/` | The source of truth: five literate Markdown files (`INIT`/`SERVER`/`SYSTEM`/`SHELL`/`MAIN`) plus `build.py`, which assembles them into the module |
| `tests/test.py` | The whole test suite, run by CI on Python 3.11 and 3.14 |
| `site/` | The Servette website's source, and the folder a checkout serves by default; `site/demo/` is the live demo page servette.org links, `site/src/` is a browsable view of the literate sources, `site/pub/` is the client-side publish tool, and `site/assets/` holds the logos this README displays |
| `README.md` | This file — the user-facing introduction and deploy guide |
| `DESIGN.md` | Developer's document: scope, invariants, architecture, and how to operate on the code |
| `AGENTS.md` · `CLAUDE.md` | The human–agent working agreement, and the pointer to it |
| `CONTRIBUTING.md` · `SECURITY.md` | How to contribute, and how to report a vulnerability |
| `LICENSE` | MIT |

A comprehensive tutorial will live at the project site once it exists; until then, the deploy guide above is the complete walkthrough.
