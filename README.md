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

Servette is a production nanoserver. The `http.server` module in Python's standard library is the canonical nanoserver: it serves a folder in one command and, by its own documentation, is not built for production. Servette builds on that same `http.server` and adds everything the public internet demands: a trusted certificate that renews itself, HTTP redirected up to HTTPS, security headers on every response, rate limiting, password protection (optional), and a hardened service that survives reboots. No configuration language to learn, automatic certificate management, and a single dependency it installs for you. Copy one file to a server, run it, follow the wizard, done.

Most ways to serve a website sit at an extreme. **General-purpose servers** (nginx, Apache, Caddy) do *everything*: any site at any scale, once you have configured them. **Development servers** (`http.server`) do *one thing*: serve a folder right now, and stop there. **Managed platforms** (GitHub Pages, Netlify, Vercel) do it *for* you, on infrastructure and terms that are theirs, not yours.

Servette aims at the space between: **do everything _necessary_ to do one thing _well_.** The one thing is hosting a static site you own (anything that runs in a browser, from a simple portfolio to a serious client-side app). *Everything necessary* is what you cannot honestly skip on the public internet (trusted HTTPS that renews itself, optional passwords, rate limiting, a hardened service that survives reboots), and nothing past that line. Within that domain, nothing is missing.

The tools closest in spirit are small and focused, like Servette. Here is how a few peers compare on that one job:

| | Servette | bottle.py | srv | Static Web Server |
|---|:--:|:--:|:--:|:--:|
| **Built for** | static sites | dynamic web apps | static sites | static sites |
| Automatic trusted HTTPS | ✓ | ✗ | ✓ | ✗ |
| Hardened for production | ✓ | ✗ | ✗ | ~ |
| Readable source | ~2,400 lines | ~4,600 lines | binary | binary |
| Actively maintained | ✓ | ✓ | ✗ | ✓ |
| Runs on a Raspberry Pi out of the box | ✓ | ✓ | ✗ | ✗ |

All of these are excellent at what they are built for. None of them do what Servette does: serve a static site you own, securely, on the public internet, from a single file you can read.

---

## Who is Servette for?

**People who want to understand what their server is running.** General-purpose servers do the job, but they are large systems you configure and take on trust. Servette is one readable file (~2,400 lines of Python, no hidden machinery) that you can follow top to bottom in an afternoon.

**People with a real site that needs a real server.** Development servers (like `http.server`) are perfect while you build, but they are not meant to face the internet (no trusted HTTPS, no auth, gone when you close the terminal). Servette is built to stay up: a trusted certificate that renews itself, and a hardened service that survives reboots.

**People who want to own what they serve.** Managed platforms host it for you, on their infrastructure and their terms. Servette runs on your own server, with your own certificate, behind a password if you want one. Copy a file, answer a few questions, walk away.

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

**Will it serve your site?** Servette serves static files as they are. It returns `405` to `POST` requests (it has nowhere to put submitted data) and it does not rewrite deep links for single-page-app routers (React Router, Vue Router, and the like). If your site needs either, you are looking for a different project (a general-purpose server, not Servette), and that is by design, not a limitation to work around; see [Scope & non-goals](docs/principles.md#scope--non-goals) for what is out of scope and why.

---

## Get started

Copy one file to your server, run it, and follow the wizard:

```
scp servette.py user@your.server.ip:~
ssh user@your.server.ip
sudo python3 servette.py   # then: setup
```

Full step-by-step walkthroughs for **AWS Lightsail** and **Raspberry Pi**, plus day-to-day operation, are in the [tutorial](docs/tutorial.md).

## Documentation

- [**Tutorial**](docs/tutorial.md): deploy on Lightsail or a Raspberry Pi, then operate it.
- [**Architecture**](docs/architecture.md): how `servette.py` is built, section by section.
- [**Design principles**](docs/principles.md): scope, non-goals, and how we work.
- [**Contributing**](docs/CONTRIBUTING.md) · [**Security policy**](docs/SECURITY.md)
