<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/servette-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/servette-light.svg">
  <img alt="Servette" src="assets/servette-light.svg" width="300">
</picture>

### The Simple, Secure Static-Site Server

[![Tests](https://github.com/andy-emerson/servette/actions/workflows/test.yml/badge.svg)](https://github.com/andy-emerson/servette/actions/workflows/test.yml)
[![CodeQL](https://github.com/andy-emerson/servette/actions/workflows/codeql.yml/badge.svg)](https://github.com/andy-emerson/servette/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)

---

Servette is a production nanoserver. A nanoserver focuses on doing one thing well, minimizing complexity and file size, which makes them very popular as dev tools. Servette, however, is not a dev tool. It serves a real site on the public internet and, therefore, inherits features that a dev tool may not have: a trusted certificate, automatic renewal, HTTPS enforced at the redirect level, a password if you want one. No configuration language to learn. No certificates to manage. No dependencies to install. Simply copy Servette to a server, run it, follow the wizard, done.

Most ways to serve a website sit at an extreme. **General-purpose servers** — nginx, Apache, Caddy — do *everything*: any site at any scale, once you've configured them. **Development tools** — `python -m http.server` — do *one thing*: serve a folder right now, nothing else. And **managed platforms** — GitHub Pages, Netlify, Vercel — do it for you, on infrastructure and terms that are theirs, not yours.

Servette aims at the space between: **do everything _necessary_ to do one thing _well_.** The one thing is hosting a static site you own — anything that runs in a browser, from a simple portfolio to a serious client-side app. *Everything necessary* is what you can't honestly skip on the public internet — trusted HTTPS that renews itself, optional passwords, rate limiting, a hardened service that survives reboots — and nothing past that line. Within that domain, nothing is missing.

The tools closest in spirit are small and focused, like Servette. Here is how they line up against that one job:

| | Servette | `http.server` | bottle.py | srv | Static Web Server |
|---|:--:|:--:|:--:|:--:|:--:|
| **Built for** | static sites | development | dynamic web apps | static sites | static sites |
| Automatic trusted HTTPS | ✓ | ✗ | ✗ | ✓ | ✗ |
| Hardened for production | ✓ | ✗ | ✗ | ✗ | ~ |
| Readable source | ~2,200 lines | ~1,300 lines | ~4,600 lines | binary | binary |
| Actively maintained | ✓ | ✓ | ✓ | ✗ | ✓ |
| Runs on a Raspberry Pi out of the box | ✓ | ✓ | ✓ | ✗ | ✗ |

All of these are excellent at what they're built for. None of them do what Servette does: serve a static site you own — safely, on the public internet, from a single file you can read.

---

## Who is Servette for?

**People who want to understand what their server is running.** General-purpose servers do the job, but they're large systems you configure and take on trust. Servette is one readable file — ~2,200 lines of Python, no hidden machinery — that you can follow top to bottom in an afternoon.

**People with a real site that needs a real server.** Development servers (like `python -m http.server`) are perfect while you build, but they aren't meant to face the internet — no trusted HTTPS, no auth, gone when you close the terminal. Servette is built to stay up: a trusted certificate that renews itself, and a hardened service that survives reboots.

**People who want to own what they serve.** Managed platforms host it for you, on their infrastructure and their terms. Servette runs on your own server, with your own certificate, behind a password if you want one — copy a file, answer a few questions, walk away.

**Raspberry Pi users.** Servette was designed with the Pi in mind. If you can SSH in and run a Python script, you can have a real HTTPS site live in under ten minutes — trusted certificate, automatic renewal, and a server that survives reboots.

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

**A folder with your site files.** Servette serves the `site/` folder, which ships with a demo page that runs a live self-test in your browser — so a fresh copy not only runs immediately but confirms the server is working before you have a site of your own. Replace it with your own files when you're ready; Servette looks for `index.html` at the root and in any subdirectory.

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

Servette serves the `site/` folder next to `servette.py`. It ships with a self-testing demo page — replace its contents with your own files and Servette will find them.

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

## Troubleshooting

**The site isn't reachable.** Make sure your server's firewall allows inbound traffic on **ports 80 and 443**. On a cloud VPS this is often a separate "security group" or firewall panel in the provider's dashboard, not just the OS firewall — port 80 carries the HTTP→HTTPS redirect and Let's Encrypt's validation, and 443 serves the site.

**Let's Encrypt won't issue a certificate.** Your **domain must already point at this server's IP** before you request a trusted certificate — Let's Encrypt validates by connecting back to your domain over port 80. Confirm DNS with `dig +short yourdomain.com`, make sure port 80 is reachable from the internet, and check that nothing else is bound to it. If `www.yourdomain.com` has no DNS record, Servette falls back to a certificate for the bare domain and tells you.

**The browser warns the certificate isn't trusted.** That's expected with a self-signed certificate (no domain). Add a domain and run `config` then `cert` to get a trusted Let's Encrypt certificate.

**Something else is wrong.** Run `log` in the Servette shell (or `journalctl -u servette`) to see recent activity and errors.

---

## How it's built

Servette is a single file — `servette.py`, in three clear sections (Server, System, and Shell) — readable in an afternoon. There is no hidden machinery and no framework to learn: if something ever goes wrong, you can open the file and follow it top to bottom. The full architecture, the design rationale, and the things Servette deliberately *doesn't* do are documented in [design.md](design.md).

**Will it serve your site?** Servette serves static files as they are. It returns `405` to `POST` requests — it has nowhere to put submitted data — and it does not rewrite deep links for single-page-app routers (React Router, Vue Router, and the like). If your site needs either, see [Scope & non-goals](design.md#scope--non-goals).
