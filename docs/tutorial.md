# Tutorial: Deploy & Use Servette

Getting a real HTTPS site online with Servette takes two things: a machine on the internet, and Servette's setup wizard. This tutorial covers both — the hosting part first (which isn't Servette-specific), then [Using Servette](#using-servette), where the actual setup happens and which is the same everywhere.

You host on hardware you control, and that comes in two broad shapes:

- **Managed hardware** — a server you rent from a cloud provider (DigitalOcean, Linode, Vultr, AWS Lightsail, …). They run the physical machine; you run the software on it.
- **DIY hardware** — a machine you own and operate: a Raspberry Pi, an old laptop, a home server.

Each section below works through one popular example — Lightsail for managed, a Raspberry Pi for DIY — but the steps apply to any host of that kind. Where a command has to be specific it's shown as such; everything else is general.

For *what Servette is and whether it fits your site*, see the [README](../README.md). For *how it's built*, see [architecture.md](architecture.md).

## Contents

- [What you'll need](#what-youll-need)
- [Managed hardware (a cloud VPS)](#managed-hardware-a-cloud-vps)
- [DIY hardware (your own machine)](#diy-hardware-your-own-machine)
- [Using Servette](#using-servette)
  - [Run setup](#run-setup)
  - [The Servette shell](#the-servette-shell)
  - [Updating your site](#updating-your-site)
  - [Troubleshooting](#troubleshooting)

## What you'll need

- **A Linux machine you control** — rented or your own (see below). Ubuntu 22.04+ is a reliable starting point; Raspberry Pi OS works too. You'll need its IP address and SSH access.
- **Python 3.11 or higher** — pre-installed on most current Linux servers and on Raspberry Pi OS Bookworm.
- **Your site files** — anything that runs in a browser. Servette serves a `site/` folder by default (you can point it elsewhere with `config`), and ships with a demo page that self-tests in the browser, so a fresh copy runs immediately; replace it when you're ready. It looks for `index.html` at the root and in any subdirectory.
- **A domain name (recommended).** Required for a trusted certificate. Without one, Servette uses a self-signed certificate and browsers warn visitors first — fine for a private network or local testing.

Servette installs its one dependency (`cryptography`) into a private virtualenv on first run. You never run `pip`.

## Managed hardware (a cloud VPS)

Renting a server from a cloud provider. The example here is **AWS Lightsail**, but the same steps apply to DigitalOcean, Linode, Vultr, and the rest — and none of it is specific to Servette. This is simply what putting any site on a rented server involves.

1. **Create a server.** Spin up a small Linux instance — Ubuntu is a safe default. Note the login username the provider assigns (on a Lightsail Ubuntu instance it's `ubuntu`).
2. **Open ports 80 and 443.** Cloud providers put a firewall *in front of* your server, separate from the OS firewall, and it often allows only SSH (22) at first. Open **80** and **443** in the provider's networking panel (on Lightsail: the instance's **Networking** tab → IPv4 Firewall). Port 80 carries the HTTP→HTTPS redirect and Let's Encrypt validation; 443 serves the site. This is the step people miss — the OS firewall isn't the one blocking traffic.
3. **Give it a stable address.** Attach a static/reserved IP so the address survives restarts (on Lightsail, Networking → attach a static IP).
4. **Get your SSH key.** The provider either gives you a key to download or lets you add your own. Keep it safe and `chmod 400 your-key.pem`.
5. **Point your domain at it.** Add an `A` record for your domain pointing to the static IP, before you request a trusted certificate.
6. **Copy your files over** and SSH in (substitute your username, IP, and key):
   ```
   scp -i your-key.pem servette.py user@YOUR.IP:~
   scp -i your-key.pem -r mysite/ user@YOUR.IP:~/site
   ssh -i your-key.pem user@YOUR.IP
   ```

Then continue with [Using Servette](#using-servette).

## DIY hardware (your own machine)

A machine you own and run — a Raspberry Pi, an old laptop, a home server. The example is a **Raspberry Pi**, but the steps apply to any self-hosted box. As with managed hosting, none of this is Servette-specific; it's what self-hosting any site requires.

1. **Set up the machine.** Install a Linux OS and enable SSH. (On a Pi, the Raspberry Pi Imager can set the username/password and enable SSH before first boot.)
2. **Reach it on your network.** Find the machine's local IP and SSH in:
   ```
   ssh user@YOUR.LOCAL.IP
   ```
3. **Open it to the internet** (for a public site). On your router, forward **ports 80 and 443** to the machine, and point a domain's `A` record at your home's public IP. Home IP addresses often change, so a dynamic-DNS service is worth setting up to keep the record current. (Skip this to run on your LAN only — Servette will use a self-signed certificate.)
4. **Copy your files over** from another machine:
   ```
   scp servette.py user@YOUR.LOCAL.IP:~
   scp -r mysite/ user@YOUR.LOCAL.IP:~/site
   ```

Then continue with [Using Servette](#using-servette).

## Using Servette

Servette serves the `site/` folder next to `servette.py` by default. Everything from here is the same whether your machine is rented or your own.

### Run setup

From your server:

```
sudo python3 servette.py
```

`sudo` is needed because setup writes a systemd unit to `/etc/systemd/system/` and creates a restricted `servette` system user — the server then runs as that user, not as root. On first run, Servette installs its dependencies before dropping you into the shell.

At the prompt, run:

```
setup
```

The wizard walks you through it:

1. Set a password (optional).
2. Set up an SSL certificate — a trusted Let's Encrypt one if you gave a domain, otherwise self-signed.
3. Confirm. Servette enables itself as a service and starts.

That's it — your site is live. Close your terminal; Servette keeps running, restarts on reboot, and (with a domain) renews its certificate automatically.

### The Servette shell

Servette does more than start and stop. Re-running `sudo python3 servette.py` any time drops you back into its shell, where you reconfigure settings, check status, read logs, and update to a new release. The full command set:

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
| `update` | Download the latest signed release of Servette |
| `restore` | Roll back to the previous version (undoes the last `update`) |
| `help` | Show the command list |
| `quit` | Exit the shell |

### Updating your site

Copy the new files over; changes appear immediately, no restart required:

```
scp -r mysite/ user@your.server.ip:~
```

To update Servette itself, run `update` from the shell — it pulls the latest signed release, verifies it, and (if running as a service) offers to restart. Your `servette.toml` settings are never touched by an update.

> If you set a password, `servette.toml` holds its hash. Sharing the file — for troubleshooting, say — gives the recipient material for an offline cracking attempt against that password.

### Troubleshooting

**The site isn't reachable.** Make sure inbound traffic is allowed on **ports 80 and 443**. On a cloud VPS this is often a separate firewall/security-group panel in the provider's dashboard (for Lightsail, the instance's Networking tab); when self-hosting, it's your router's port forwarding. The OS firewall is rarely the only thing in the way.

**Let's Encrypt won't issue a certificate.** Your **domain must already point at this server's IP** — Let's Encrypt validates by connecting back over port 80. Check DNS with `dig +short yourdomain.com`, make sure port 80 is reachable, and that nothing else is bound to it. If `www.yourdomain.com` has no DNS record, Servette falls back to a bare-domain certificate and tells you.

**The browser warns the certificate isn't trusted.** Expected with a self-signed certificate (no domain). Add a domain, then run `config` → `cert` for a trusted Let's Encrypt certificate.

**Something else.** Run `log` in the shell (or `journalctl -u servette`) to see recent activity and errors.
