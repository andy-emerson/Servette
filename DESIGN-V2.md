# DESIGN-V2.md

The plan for Servette 2.0 — what it ships, how it is administered, and why. [`DESIGN.md`](DESIGN.md) describes 1.x, which is what runs today; this document describes the version after it. Where the two disagree, `DESIGN.md` is the truth about the code and this is the truth about the destination. Rulings that 2.0 needs and that are not yet closed are listed under [Open decisions](#open-decisions). They are listed here, not in issues, because 2.0 is not yet scheduled work: this document is a destination under consideration, and its forks stay with it until the Human confirms the move toward 2.0 — expected after 1.x's release, not before. At that point each becomes an issue and this section points to them.

## Why a 2.0

Servette exists to answer Python's own warning that `http.server` is not for production. 1.x answers it, and then keeps going: the same module carries a setup wizard, content publishing with version history, swap and network-watchdog management, traffic statistics, a live CPU meter, preview staging, and a root-run loopback web server with a 2,500-line admin page. Each addition was defensible under the principles — "Production-grade" and "Zero-friction" license almost any operations feature — and together they made a second product, wrapped around the first.

Measured at 0.26.246 with `python3 src/build.py --counts`, plus the generated lines of the Shell section's *Loopback page server* alone:

| Part | Lines in the module | What it is |
| - | - | - |
| Server | 1,731 | config, rate limiting, file cache, request handler, TLS |
| System | 2,084 | certificates and ACME, lifecycle, systemd units and sandbox, network watchdog, swap |
| Shell | 3,134 | shell, setup, status, publishing — and the admin page's loopback server, 664 of them |
| Init and Main | 171 | version, imports, the entry point |
| Embedded pages | 3,306 | `src/admin.html` (2,504), `src/connection.html` (472), `src/404.html` (330) — HTML and JavaScript, not Python |

The secure server is about a third of the module. Two costs follow. **Auditability:** "understood by one person" now means reading a CPU meter's JavaScript to audit TLS. **Attack surface:** the admin server runs as root and accepts uploads; it is reachable only through the operator's SSH tunnel, but it ships with — and must be audited as part of — the security product.

2.0 separates the two products and gives each one its own audience: the server for the person who installs software with a package manager and operates it from a terminal, and an application for the person who wants a familiar install and a window.

## The shape of 2.0

Two products, in two repositories, beside the website that already has its own ([ruling](DECISIONS.md#the-website-lives-in-its-own-repository)):

| Product | Job | Delivered by | Runs on |
| - | - | - | - |
| **The server** — `servette.py` | serve static sites securely: TLS, ACME, headers, auth, rate limits, the service unit, and a command line that is the whole administrative interface | PyPI, through pipx — one file, as today | the box |
| **The app** | administer boxes from the operator's own computer: hold the list of boxes, open the SSH connection, drive the server's command line, and show a browser interface served on the computer's own loopback | an installer built in CI and published as a release, linked from servette.org | the operator's computer |
| **servette.org** | the project site, as now — a Servette box serving itself; it links to both and holds neither | its own repository | a Servette box |

From the operator's side: install the server once with pipx and run `setup`; install the app once; add the box to the app by address, user, and key; click it. The terminal remains a complete second way in — every operation the app performs is a command the operator could type — and a box that never meets the app loses nothing.

## The server

`servette.py` is 1.x without the loopback admin server and its page. Every 1.x principle in [`DESIGN.md`](DESIGN.md#scope--non-goals) holds unchanged, and one scope rule is added that 1.x lacked: **the server grows only for serving and for its command line; a graphical way to administer the box belongs to the app.**

- **The command line is the API**, as the [standing ruling](DECISIONS.md#the-cli-is-the-api) says and as nothing yet depends on. In 2.0 the app depends on it: `status --json`, `sites --json`, `set`, `publish`, `restore-site`, and the rest are a contract, stable within a major version, with their JSON shapes stated in `DESIGN.md` and pinned by the suite. Commands the app needs that answer only in prose today gain a `--json` form — `traffic` first.
- **Publishing from elsewhere.** `publish` takes a folder on the box. The app's content arrives over SSH, so the command gains a way to take a bundle from standard input, through the same `_land_bundle` every publish runs; the extraction guards, the ring, and the lock are unchanged.
- **`admin` leaves the command list.** Until the app exists, `servette admin` keeps working exactly as 1.x documents it; the day the app is proven, the loopback server and `src/admin.html` leave the module and `help` names the app instead. The connection test and the error page stay: they are served to visitors by every box.
- **The service is untouched.** Nothing the service user can reach changes; the sandbox, the runtime copy, and the request-time invariant are as 1.x states them.

What else leaves the server is not yet decided — see [what is core](#what-is-core).

## The app

A desktop application, designed and documented in its own repository. This document records only what the server owes it and the shape the two agreed on:

- **It holds the operator's boxes** — alias, address, user, key path — in its own configuration on the operator's computer. Nothing is stored on any box, and no key material is copied: the system's `ssh` and its agent open every connection, as they do for the terminal today.
- **It drives the server's command line over SSH.** Every read is a `--json` command; every write is the command the terminal would run. There is no admin protocol, no loopback server on the box, and no network-reachable door: the SSH connection is the authentication, as it always was.
- **Its interface is a browser page served on the computer's own loopback.** `src/admin.html` moves to the app largely as it is; its three functions that talk to a server talk to the app's local process instead of the box.
- **Publish and preview become local.** The folder being published is on the operator's computer, so the app builds the bundle there and sends it over SSH; a preview is that folder served locally, so nothing is staged on the box.
- **Login disappears.** There is no browser talking to a box, so there is no passcode, no guess ceiling, no login page, and no pairing. The app's own loopback page carries a per-launch token in the address the app opens, against other local processes and sites.
- **How it is delivered is where its trust lives.** The installer is built in CI from a release tag, published as a release asset with its checksum and provenance, and signed and notarized for the platforms that check. servette.org links to the release; it does not serve the binary, because a single box's content tree is not where a download's integrity should rest, however well the server guarding it is built.

## Trust, summarized

| Who could act on a box | 1.x | 2.0 |
| - | - | - |
| Someone with the operator's SSH key | yes | yes — unchanged; the key is the credential in both |
| Someone with a copied admin link or passcode | yes, for that run | no such thing: no browser logs in to a box |
| servette.org's host or its scripts | n/a | no — it links to the app's release and serves nothing that runs anywhere |
| Whoever can alter the app's release | n/a | yes, on the operator's computer and so on every box — the trade 2.0 accepts, and why the release is built in public CI, attested, and signed |
| A compromised service user | no | no — unchanged |

The new row is the honest cost of the second audience. It is bounded by the same means every installed application relies on, and it touches nobody who administers from the terminal.

## What 2.0 costs

For operators who use the app: one installer, and the platform warnings an unsigned or unfamiliar application draws until signing is in place. For operators who do not: nothing — the terminal is complete.

For maintainers: a second product in a second repository, with a build matrix, installers for each platform, signing certificates that expire, and a release cadence of its own; the command line's JSON becomes a compatibility promise the suite pins and the app's tests exercise against the server versions it supports; the admin page's browser checks move with the page; and a migration in which 1.x operators keep `servette admin` until the app is proven.

## Rejected on the way here

Each of these was considered for how the admin tool should be delivered; the reason each lost is the reason the shape above holds.

- **An extension fetched from GitHub by the server and verified against an embedded checksum.** Fetch-verify-run-as-root is the path the [distribution ruling](DECISIONS.md#distribution-is-pippypi--servette-is-not-its-own-package-manager) deleted, and its reopen conditions have not fired; every upgraded box would also need GitHub before `admin` worked again.
- **The admin page hosted on servette.org, talking to the box over the tunnel.** The browser trusts the origin that served the document; a page from servette.org makes servette.org's host a party who can act on every box while the tool is open, whatever data the box withholds.
- **A loader on the box that fetches the page from servette.org and verifies its hash before running it.** Sound, but it keeps the admin server in the module, ties the tool to servette.org's uptime against the [no-mirror ruling](DECISIONS.md#servetteorg-has-no-mirror-the-box-is-the-only-origin), and makes every release a two-repository event.
- **A second module shipped in the same wheel.** Breaks the expectation that `pipx install servette` delivers `servette.py` and nothing else.
- **A `servette-admin` package injected into the server's environment.** Keeps the box's single file and PyPI's trust root, but keeps a root-run loopback server on the box and the tunnel, the passcode or a pairing scheme, and an `ssh` configuration in front of every operator.
- **servette.org as a launcher** — framing the box's page from an https site, with browser pairing in place of the passcode. The most machinery of any option, with open browser questions, for a flow the app gives without a launcher.
- **A zero-click `ssh` configuration entry** that starts `admin` and opens the browser. Workable, but it asks the operator to maintain an unusual `Host` entry and still leaves the admin server on the box.

## Open decisions

Each is the Human's to close; what it gates follows it.

- <a id="what-is-core"></a>**What is core.** Removing the loopback server and its page takes the module from about 10,400 lines to about 7,300, of which about 6,500 are Python. Getting toward 3,000–4,000 means deciding whether these are serving or administering: publishing and version history, the config sub-shell, status and traffic reporting, the setup wizard, and swap and the network watchdog in `src/SYSTEM.md`. The app drives whatever stays through the command line, so moving a feature out means the app reimplements it on its side. *Gates:* the size of the server and the breadth of the command-line contract.
- **Privileged commands from the app.** `servette admin` elevates with `sudo` and asks for the password in the terminal. The app runs commands over SSH without a terminal of its own; it must either request one and relay the prompt, rely on the box's `sudo` asking no password, or something else. *Gates:* the app's connection design and what setup must say about the operator account.
- **The command-line contract.** Which commands gain `--json`, how a bundle reaches `publish` over SSH, and how the contract's version is stated. *Gates:* the first step of the build.
- **The app's technology and first packaging.** A Python application shipped through PyPI first, wrapped in an installer later, or a binary installer from the start. *Gates:* the app repository's own design document.
- **The repositories.** Two products in two repositories beside the website's; whether they move under one organization. *Gates:* where the app's repository is created.
- **Superseded rulings.** The app amends [multi-step features pair a shell flow with a loopback browser page](DECISIONS.md#multi-step-features-pair-a-shell-flow-with-a-loopback-browser-page) and [one admin page with tabs is the browser surface](DECISIONS.md#one-admin-page-with-tabs-is-the-browser-surface) — the browser surface leaves the box — and retires [the front door is a login](DECISIONS.md#the-front-door-is-a-login-link-and-passcode-printed-apart) with the door itself; [the build emits one `servette.py`](DECISIONS.md#the-build-emits-one-servettepy-the-package-build-runs-the-literate-transform) becomes true in the strict sense. *Gates:* the rewrite of `DESIGN.md` and `DECISIONS.md` at merge.
- **The transport stays out.** Replacing threaded `http.server` with asyncio is not part of 2.0; it is a core question to reopen only on evidence — the connection cap hit under real traffic, or per-connection memory measurably hurting a small box.

## Building it

Each step is its own branch and merges on its own; 1.x operators keep working after every one.

1. **The contract**, in this repository: `--json` where the app needs it, `publish` from a bundle, the shapes stated in `DESIGN.md` and pinned by the suite. Nothing is removed.
2. **The app**, in its own repository: the page and a local process that drives `ssh`, working against 1.x boxes, with its own design document and suite.
3. **The admin server leaves** once the app is proven: the loopback server and `src/admin.html` leave the module, `admin` leaves the command list, `help` names the app.
4. **`DESIGN.md` is rewritten** for the server alone, the superseded rulings are recorded, and this document retires into it.
