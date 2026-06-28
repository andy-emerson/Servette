<picture>
  <source media="(prefers-color-scheme: dark)" srcset="servette-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="servette-light.svg">
  <img alt="Servette" src="servette-light.svg" width="300">
</picture>

### The Simple, Secure Static-Site Server

[![Tests](https://github.com/andy-emerson/servette/actions/workflows/test.yml/badge.svg)](https://github.com/andy-emerson/servette/actions/workflows/test.yml)
[![CodeQL](https://github.com/andy-emerson/servette/actions/workflows/codeql.yml/badge.svg)](https://github.com/andy-emerson/servette/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

---

Servette is a production nanoserver. A nanoserver focuses on doing one thing well, minimizing complexity and file size, which makes them very popular as dev tools. Servette, however, is not a dev tool. It serves a real site on the public internet and, therefore, inherits features that a dev tool may not have: a trusted certificate, automatic renewal, HTTPS enforced at the redirect level, a password if you want one. No configuration language to learn. No certificates to manage. No dependencies to install. Simply copy Servette to a server, run it, follow the wizard, done.

Most ways to host a static site ask you to choose between simplicity and control:

- **Platforms** (GitHub Pages, Netlify, Vercel) are easy but live on someone else's infrastructure, don't support password protection, and disappear if the free tier changes.
- **General-purpose servers** (nginx, Caddy, Apache) give you full control but require learning configuration languages, managing certificates manually, and wiring everything together yourself.

Servette is the middle option: your own server, with the simplicity of a platform. It serves anything that runs in a browser, from a simple portfolio to a serious client-side application. The decrease in complexity is not a decrease in capability — within its domain, nothing is missing.

The closest alternative is Caddy, which handles HTTPS and Let's Encrypt with a famously simple config syntax. But Caddy's core is ~73,000 lines of Go; Servette is around 2,000 lines of Python. For serving a static site, they cover the same ground. Caddy's additional bulk comes from features like reverse proxying, load balancing, and a live config API that a Pi-hosted static site doesn't need. That size difference matters: if something goes wrong, Servette is readily debuggable where Caddy is effectively a black box, and on more constrained hardware like a Raspberry Pi, a smaller footprint has real advantages.

---

## Who is Servette for?

**People who want to own what they ship.** You built something, and you want it on the internet. Not on someone else's platform. Not dependent on a free tier that might disappear. On your own server, with a real certificate, behind a password if you want one. You want to copy a file to a server, answer a few questions, and walk away.

**Raspberry Pi users.** Servette was designed with the Pi in mind. If you can SSH in and run a Python script, you can have a real HTTPS site running on your Pi in under ten minutes, with a trusted certificate, automatic renewal, and a server that survives reboots.

**Developers who want to understand what they're running.** Servette is around 2,000 lines of Python with no hidden magic. It is a working server, not a toy example, and it is readable in an afternoon.

---

## What Servette provides

| Feature | What it does |
|---|---|
| HTTPS with HTTP/2 | Your site is encrypted; browsers show the padlock; pages load faster with multiplexed requests |
| Basic Auth | Optional username and password to restrict access |
| Rate limiting | Stops bots from hammering the server; makes password guessing impractical |
| Live reload | Edit any file and changes appear immediately, no restart required |
| Auto cert renewal | Let's Encrypt certificates renew automatically before they expire |
| Security headers | HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, and Permissions-Policy sent on every response |
| Automatic startup | Keeps running after you close your terminal; restarts automatically if the server reboots |

---

## What you'll need

**A Linux server.** A Raspberry Pi works. So does any VPS. Common choices include [DigitalOcean](https://digitalocean.com), [Linode](https://linode.com), [Vultr](https://vultr.com), and [AWS Lightsail](https://aws.amazon.com/lightsail/). Ubuntu 22.04 is a reliable starting point. You'll need the server's IP address and SSH access.

**Python 3.11 or higher.** Pre-installed on most current Linux servers. Raspberry Pi OS Bookworm (the current release) satisfies both the OS and Python requirements on a Raspberry Pi 4.

**A folder with your site files.** Servette serves the `site/` folder, which ships with a placeholder demo page so a fresh copy runs immediately — useful for confirming everything works before you have a site of your own. Replace it with your own files when you're ready; Servette looks for `index.html` at the root and in any subdirectory.

**A domain name.** Required for a trusted certificate and recommended for any public-facing site. Without one, Servette can use a self-signed certificate, but visitors' browsers will warn them before they can access your site. Self-signed is fine for a private home network or local testing.

Servette depends on a handful of Python packages — Hypercorn, cryptography, and two ACME libraries — but manages them itself. On first run it creates a private virtualenv and installs everything. You will not need to run pip.

---

## Getting started

### 1. Copy your files to the server

From your local machine:

```
scp servette.py user@your.server.ip:~
scp -r mysite/ user@your.server.ip:~/site
```

Replace `user` with your server's login name (`ubuntu` on Ubuntu, `pi` on Raspberry Pi) and `your.server.ip` with its IP address. If your server uses a key file, add `-i your-key.pem` before the filenames.

Servette serves the `site/` folder next to `servette.py`. It ships with a placeholder demo page — replace its contents with your own files and Servette will find them.

### 2. SSH into your server

```
ssh user@your.server.ip
```

### 3. Run Servette

```
sudo python3 servette.py
```

`sudo` is required because setup writes a service file to `/etc/systemd/system/` and creates a system user. The server itself runs as a restricted system user afterward, not as root.

On first run, Servette installs its dependencies before dropping you into the shell. This takes about a minute.

### 4. Run setup

```
setup
```

The wizard walks you through everything:

1. Set a password (optional)
2. Set up an SSL certificate
3. Confirm you're ready. Servette enables itself as a service and starts.

That's it. Your site is live. Close your terminal. Servette keeps running and restarts automatically if the server reboots. If you used a domain name, SSL certificates renew automatically.

---

## The Servette shell

Any time you want to check on Servette or change a setting, SSH into your server and run `sudo python3 servette.py` again.

| Command | What it does |
|---|---|
| `setup` | Guided walkthrough for getting started |
| `config` | View and edit your settings |
| `enable` | Enable Servette as a permanent background service |
| `disable` | Remove the background service |
| `start` | Start the server |
| `stop` | Stop the server |
| `status` | Show whether the server is running |
| `log` | Show recent activity |
| `update` | Download the latest version of Servette |
| `help` | Show the command list |
| `quit` | Exit the shell |

---

## Updating your site

To update your site files, copy the new version to your server:

```
scp -r mysite/ user@your.server.ip:~
```

Changes appear immediately, no restart required.

To update Servette itself, run `update` from the Servette shell. Your settings are stored in `servette.toml` and are never affected by updates.

If you have a password set, `servette.toml` contains its hash. Sharing the file — for troubleshooting, for example — gives anyone who receives it material they can use to attempt an offline cracking attack against your password.

---

## How it's built

Servette is a single file — `servette.py`, around 2,000 lines in three clear sections (Server, System, and Shell) — readable in an afternoon. There is no hidden machinery and no framework to learn: if something ever goes wrong, you can open the file and follow it top to bottom. The full architecture, the design rationale, and the things Servette deliberately *doesn't* do are documented in [design.md](design.md).

**Will it serve your site?** Servette serves static files as they are. It returns `405` to `POST` requests — it has nowhere to put submitted data — and it does not rewrite deep links for single-page-app routers (React Router, Vue Router, and the like). If your site needs either, see [Scope & non-goals](design.md#scope--non-goals).
