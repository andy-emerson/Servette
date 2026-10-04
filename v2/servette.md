> Draft of `servette/servette`'s README for 2.0. The server it describes is the 1.x server minus the browser admin page, plus the extension seams; the changes are not built, and the line counts below are estimates until the counts gate sets them at release. It replaces this repository's `README.md` when 2.0 merges.

<p>
  <img alt="" src="https://raw.githubusercontent.com/servette/servette/main/assets/servette-mark.svg" width="64">&nbsp;&nbsp;<picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/servette/servette/main/assets/servette-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/servette/servette/main/assets/servette-light.svg">
    <img alt="Servette" src="https://raw.githubusercontent.com/servette/servette/main/assets/servette-light.svg" width="277">
  </picture>
</p>

### The Simple, Secure, Static-Site Server

The `http.server` module in Python's standard library is the canonical nanoserver: it serves a folder in one command and, by its own documentation, is not built for production. Servette builds on that same `http.server` and adds everything the public internet demands: a trusted certificate that renews itself, HTTP redirected up to HTTPS, security headers on every response, rate limiting, password protection (optional), and a hardened service that survives reboots. No configuration language to learn, one dependency the install brings with it. Install the package, run `servette`

```
pipx install servette
servette
```

then, at the prompt type `setup`, and you are done.

You need Python 3.11+, a Linux machine you can SSH into (macOS runs in session mode), ports 80 and 443 reachable from the internet, and a domain pointed at it for a trusted certificate — skip the domain to serve your LAN over a self-signed one. You never prefix `sudo`: Servette asks for your password when it reaches the work that needs root.

Then put your site on it. From the terminal: copy the folder to the server and run `servette publish 0 <folder>`. From your own computer: [Servette Admin](https://github.com/servette/servette-admin) connects over your SSH key, shows your boxes, and publishes with a drop. Either way the content is staged, checked, and swapped in atomically; the tree it replaced is kept, and `restore-site` rolls back to it.

## What Servette provides

| Feature | What it does |
|---|---|
| HTTPS by default | Your site is encrypted, browsers show the padlock, and plain-HTTP requests are redirected up to HTTPS |
| Public or private sites | A site is public by default; make it private with a username and password, and visitors sign in to view it |
| Rate limiting | Stops bots from hammering the server; makes password guessing impractical |
| Instant content updates | New content is served the moment it lands — every request re-checks the file on disk, so publishing needs no restart and drops no connections |
| Auto cert renewal | Let's Encrypt certificates renew automatically before they expire |
| Security headers | X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, and Permissions-Policy sent by default on every response — plus HSTS on every site with a domain |
| Automatic startup and recovery | Keeps running after you close your terminal; restarts on reboot and after a crash; a watchdog timer recovers a dropped network route |
| Several sites per server | One machine serves many sites, each with its own certificate and optional password |
| Publishing keeps a history | Every publish keeps the content it replaced. The five most recent are held, and any of them goes live again in one `restore-site` |
| Redirects | Point an old path at a new one, per site — permanently, or temporarily while the old path stays the real address. Stored as a setting, not as a file in your site |
| A connection test built in | Every site serves a live check page at `/.well-known/servette-check`: the encryption, the security headers, and whether your site root is published at all, from a real browser's vantage |
| A command line that is the API | Every command runs once as `servette <command>` and the read commands answer `--json`, which is how Servette Admin and your own scripts drive it over SSH |

**Will it serve your site?** Servette serves static files as they are. It returns `405` to `POST` requests (it has nowhere to put submitted data) and it does not rewrite deep links for single-page-app routers. If your site needs either, you are looking for a different project. That is by design, not a limitation to work around.

**Need to serve a database instead?** [Servette Database](https://github.com/servette/servette-database) is this same server with one more verb, `QUERY`, for read-only SQLite and DuckDB files. It is a separate install because it is a separate promise.

## Who is Servette for?

**People who want to understand what their server is running.** Servette is one readable module (~6,500 lines of Python — estimate; the counts gate sets the figure), sized and structured so that one person can fully understand all of it. Reading the entire source, which was written to be read, is a weekend's honest work.

**People with a site to share that needs a simple secure server.** Development servers are perfect while you build, but they are not meant to face the internet. Servette is built to stay up.

**People who want to own what they serve.** Servette runs on your own server, with your own certificate and authentication.

**Raspberry Pi users.** If you can SSH in and install a Python package, you can have a real HTTPS site live in under ten minutes.

## Operating it

Re-run `servette` any time for the interactive shell, or run any command as `servette <command>` and it executes once and exits:

| Command | What it does |
|---|---|
| `setup` | Guided first-time walkthrough |
| `config` | View and edit settings |
| `start` / `stop` | Start or stop the server |
| `enable` / `disable` | Add or remove the background service |
| `status [--json]` | Show whether the server is running |
| `log [n]` | Show recent activity |
| `traffic [--json]` | Requests, statuses, and top paths from the last 7 days |
| `sites [--json]` | List configured sites |
| `set [n] k=v ...` | Change settings non-interactively |
| `publish <folder>` | Publish a folder on the server as a site's content |
| `restore-site [n]` | Roll back a site's content to a kept version |
| `help` · `quit` | Command list · exit |

**Update Servette** with `pipx upgrade servette`. **Roll back** by installing the version you want. Your `servette.toml` is never touched by an update.

> If you set a password, `servette.toml` holds its hash — sharing the file gives a recipient material for an offline cracking attempt.

## Extending it

Servette has no plugins. An extension is a compiled edition: more literate source files built with the server's own into one module, with its own hardening and its own tests. The server offers a short list of seams for that and nothing else; `DESIGN.md` lists them. The first edition is [Servette Database](https://github.com/servette/servette-database). There are no third-party extensions.

## Links

- **[servette.org](https://servette.org)** — the project site, with a browsable view of the sources.
- **[DESIGN](DESIGN.md)** — why Servette is built this way, and what is deliberately out of scope. **[DECISIONS](DECISIONS.md)** — the rulings and what they rejected.
- **[Security policy](SECURITY.md)** — how to report a vulnerability.
- MIT licensed.
