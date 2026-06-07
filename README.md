# Ser*vette*
### The Simple Secure Single-File Server

---

Servette is a nanoserver — a single Python file that takes one HTML file and puts it on the internet, encrypted and protected, with no additional dependencies.

Most servers are built for large, complex applications. They come with databases, routing systems, templating engines, and dozens of configuration files. If all you have is a single HTML file and you just want people to be able to visit it, that is a lot of machinery you do not need.

Servette does one thing well: it takes your HTML file and puts it on the internet, encrypted and protected.

---

## Who is Servette for?

**Single-file app developers.** If your entire application lives in one HTML file — a notebook, a dashboard, a tool, a game — Servette is built for exactly that use case. Copy your file, run a few commands, and your app is live with HTTPS and optional password protection.

**Developers who need a quick private deployment.** Built something for your team or a client? Servette puts it on a domain with password protection in minutes, with no infrastructure to maintain.

**People putting their first website online.** You built something. Now you want it live. Existing options are either overwhelming, expensive, or designed for problems much bigger than yours. Servette gets you from a file on your computer to a real website with a padlock with as little friction as possible.

---

## What Servette provides

| Feature | What it does |
|---|---|
| HTTPS | Your site is encrypted end-to-end; browsers show the padlock |
| Basic Auth | Optional username and password to restrict access |
| Rate limiting | Stops bots from hammering the server and makes password guessing impractical |
| Live reload | Edit your HTML file and changes appear immediately — no restart required |
| HSTS | Tells browsers to always use HTTPS for your domain, even if someone types http:// |
| X-Frame-Options | Prevents your page from being embedded in iframes on other sites |
| X-Content-Type-Options | Stops browsers from misinterpreting your file as something executable |
| Referrer-Policy | Your URL is not leaked to third-party sites your page links to |
| Automatic startup | Keeps running after you close your terminal; restarts automatically if the server reboots |

---

## What you'll need

**A Linux server.** Any VPS will work. Common choices include [DigitalOcean](https://digitalocean.com), [Linode](https://linode.com), [Vultr](https://vultr.com), and [AWS Lightsail](https://aws.amazon.com/lightsail/). Ubuntu 22.04 is a reliable starting point. You'll need the server's IP address and SSH access.

**Python 3.8 or higher.** Pre-installed on most Linux servers.

**An HTML file.** The page you want to serve. If you don't have one yet, use `demo.html` from this repository to verify everything is working first.

**A domain name (optional).** Only required if you want a free SSL certificate from [Let's Encrypt](https://letsencrypt.org). If you don't have a domain, Servette works with a self-signed certificate or one from another provider — you'll just need to tell your browser to trust it.

No pip installs. No dependencies. Nothing else.

---

## Getting started

### 1. Copy your files to the server

From your local machine, copy `servette.py` and your HTML file to the server. If your server uses a password to log in:

```
scp servette.py yourfile.html ubuntu@your.server.ip:~
```

If your server uses a key file:

```
scp -i your-key.pem servette.py yourfile.html ubuntu@your.server.ip:~
```

Replace `ubuntu` with your server's username and `your.server.ip` with its IP address.

### 2. SSH into your server

```
ssh ubuntu@your.server.ip
```

Or with a key file:

```
ssh -i your-key.pem ubuntu@your.server.ip
```

### 3. Run Servette

```
sudo python3 servette.py
```

`sudo` is required because Servette listens on ports 80 and 443 — the standard ports for HTTP and HTTPS — and Linux reserves those ports for processes running as root. This is a one-time step; once Servette is installed as a service, it starts automatically on reboot without any manual intervention.

You will land in the Servette shell.

### 4. Run setup

```
setup
```

The wizard walks you through everything:

1. Choose your HTML file
2. Set a password (optional)
3. Set up an SSL certificate
4. Enable Servette as a system service
5. Start the server

That's it. Your site is live. Close your terminal and walk away — Servette keeps running and restarts automatically if the server reboots. SSL certificates renew automatically.

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
| `help` | Show the command list |
| `quit` | Exit the shell |

---

## Updating your site

To update your HTML file, copy the new version to your server:

```
scp yourfile.html ubuntu@your.server.ip:~
```

Changes appear immediately — no restart required.

To update Servette itself, copy the new `servette.py` and restart the service:

```
scp servette.py ubuntu@your.server.ip:~
sudo systemctl restart servette
```

Your settings are stored in `servette.json` and are never affected by updates to `servette.py`.

---

For implementation details and design decisions, see [ARCHITECTURE.md](ARCHITECTURE.md).

Built with assistance from [Claude](https://claude.ai) (Anthropic).
