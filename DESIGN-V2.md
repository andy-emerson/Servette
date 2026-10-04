# DESIGN-V2.md

The plan for Servette 2.0: the principles it rests on, the organization and repositories it is built in, what this repository owes the others, and the rulings it still needs. [`DESIGN.md`](DESIGN.md) describes 1.x, which is what runs today; where the two disagree, `DESIGN.md` is the truth about the code and this is the truth about the destination. Each product's own story — what it is, who it is for, what it promises — is drafted as that repository's README under [`v2/`](v2/README.md); those drafts leave with the repositories when they are created, and this document retires into `DESIGN.md` when 2.0 merges.

The open decisions are listed here, not in issues, because 2.0 is not yet scheduled work: this document is a destination under consideration, and its forks stay with it until the Human confirms the move toward 2.0 — expected after 1.x's release, not before. At that point each becomes an issue and this section points to them.

## Why a 2.0

Servette exists to answer Python's own warning that `http.server` is not for production. 1.x answers it, and then keeps going: the same module carries a setup wizard, content publishing with version history, swap and network-watchdog management, traffic statistics, a live CPU meter, preview staging, and a root-run loopback web server with a 2,500-line admin page. Each addition was defensible under the principles, and together they made a second product wrapped around the first.

Measured at 0.26.246 with `python3 src/build.py --counts`, plus the generated lines of the Shell section's *Loopback page server* alone:

| Part | Lines in the module | What it is |
| - | - | - |
| Server | 1,731 | config, rate limiting, file cache, request handler, TLS |
| System | 2,084 | certificates and ACME, lifecycle, systemd units and sandbox, network watchdog, swap |
| Shell | 3,134 | shell, setup, status, publishing — and the admin page's loopback server, 664 of them |
| Init and Main | 171 | version, imports, the entry point |
| Embedded pages | 3,306 | `src/admin.html` (2,504), `src/connection.html` (472), `src/404.html` (330) — HTML and JavaScript, not Python |

The secure server is about a third of the module. **Auditability:** "understood by one person" now means reading a CPU meter's JavaScript to audit TLS. **Attack surface:** the admin server runs as root and accepts uploads; it is reachable only through the operator's SSH tunnel, but it ships with — and must be audited as part of — the security product. 2.0 separates the products and gives each its own audience and its own claim.

## The principles, as a hierarchy

One root principle, **simple and secure**, and under it a derived principle per product, each as strong as that product's purpose allows and no stronger. The derived principle is always weaker than the root's best case, and each product's documents say by how much.

| Product | Simple and secure … | Derived principle |
| - | - | - |
| `servette` | from the developer's point of view, for serving static files | at request time the server never writes and never evaluates input — read and send, nothing more ([`DESIGN.md`](DESIGN.md#the-request-time-invariant)) |
| `servette-database` | from the developer's point of view, for serving databases | the server still never writes; input is evaluated only inside an engine that cannot write, cannot reach outside its file, and cannot exceed a time and size budget |
| `servette-admin` | from the operator's point of view, for using Servette and its extensions | the only credential is the SSH key the operator's system already holds; the app keeps no secret of its own, adds nothing network-reachable anywhere, and its download is verifiable against its release |
| `servette-website` | as the product demonstrating itself | a Servette box serving a static site, with no mirror and nothing that runs anywhere else ([ruling](DECISIONS.md#servetteorg-has-no-mirror-the-box-is-the-only-origin)) |

The hierarchy's guard: a lower principle licenses only what the product's purpose needs. "Read-only" admits `QUERY` and does not admit a query cache, a result dashboard, or schema browsing, each of which is read-only and none of which serves the purpose. The decision rule stays the core's — complexity is earned only by a stated principle, and "it is also read-only" is not one.

## Extensions are compiled editions

An extension adds a verb, the hardening that verb requires, and the proof that the hardening holds, shipped as one unit. It is compiled, never loaded:

- **Build time, not run time.** `build.py` already concatenates `src/*.md` in order into one module. An extension is more literate source files in that concatenation, built against the core's sources from a pinned PyPI release — the sdist carries `src/` because the package build runs the literate transform. The output is one module per edition, read end to end by one person. The scope table's refusal of plugins becomes precise rather than reversed: **no runtime plugins; extensions are compiled editions.** There are no third-party extensions: the project cannot audit them and will not lend them its claims.
- **Every extension carries a ledger.** Its design states its own invariant, then lists what the new verb stopped getting for free — the properties the core's invariant hands out by never doing certain things — and what now earns each one by code and by test. What is not on the ledger is still free, and saying so is what keeps the hardening bounded. Its suite section pins the invariant and runs against every edition that includes it.
- **The core owes seams, not features.** A seam is ordinary structure the core uses itself, listed in `DESIGN.md` as the extension contract and stable within a major version, added only when a real extension needs it and the Human rules on it. The first edition needs three: a **verb table**, where `_handle_request` hardcodes `GET` and `HEAD` today and answers everything else `405`; a **site kind**, since a site is a folder today; and the **config vocabulary**, so an extension's settings pass the same validators and load door as the core's. The suite is the fourth, so an edition reuses the core's harness.
- **`OPTIONS` and CORS are seam machinery in the core.** Driven by the verb table, written once: the static edition answers `Allow: GET, HEAD, OPTIONS` and nothing more; an extension registers a verb with the headers `OPTIONS` should add for it. Preflights arrive without credentials, so the CORS half answers anonymously and per-verb metadata only past the site's auth — one place to get that right instead of one per extension. CORS allowances become an operator setting through the usual door; the core has none today.
- **An edition's version names the core it embeds.** An edition built from a pinned core lags that core until rebuilt; the lag is made visible by the number rather than hidden, and a workflow in each extension repository rebuilds and releases when a new core appears.

## The organization and its repositories

| Repository | Product | Delivered by | Runs on |
| - | - | - | - |
| [`servette/servette`](v2/servette.md) | the server — `servette.py`, serving and its command line | PyPI, through pipx — one file | the box |
| [`servette/servette-database`](v2/servette-database.md) | the first extension: `QUERY` for read-only embedded databases, SQLite first | PyPI, as its own edition built from the core's sources | the box |
| [`servette/servette-admin`](v2/servette-admin.md) | the desktop application that administers boxes over SSH through the server's command line | an installer built in CI, published as a release, linked from servette.org | the operator's computer |
| [`servette/servette-website`](v2/servette-website.md) | servette.org — the project site, a Servette box serving itself | its own repository, published like any operator's site | a Servette box |

The organization's profile README is drafted at [`v2/README.md`](v2/README.md). The website already lives apart ([ruling](DECISIONS.md#the-website-lives-in-its-own-repository)); the same reasoning gives each product its own repository: its own build, its own release, its own secrets, its own claims, and none of them in the core's audit boundary.

## What this repository owes

- **The command line is the API**, as the [standing ruling](DECISIONS.md#the-cli-is-the-api) says and as nothing yet depends on. The app depends on it: `status --json`, `sites --json`, `set`, `publish`, `restore-site`, and the rest are a contract, stable within a major version, with their JSON shapes stated in `DESIGN.md` and pinned by the suite. Commands that answer only in prose gain `--json` — `traffic` first. `publish` gains a way to take a bundle from standard input, through the same `_land_bundle` every publish runs.
- **The three seams and the `OPTIONS` machinery** above, each ruled before it is built.
- **`admin` leaves the command list.** Until the app exists, `servette admin` keeps working exactly as 1.x documents it; the day the app is proven, the loopback server and `src/admin.html` leave the module and `help` names the app. The connection test and the error page stay: every box serves them to visitors.
- **The service is untouched.** Nothing the service user can reach changes; the sandbox, the runtime copy, and the request-time invariant are as 1.x states them.

## Rejected on the way here

Each was considered for how the admin tool should be delivered; the reason each lost is the reason the shape above holds.

- **An extension fetched from GitHub by the server and verified against an embedded checksum** — fetch-verify-run-as-root is the path the [distribution ruling](DECISIONS.md#distribution-is-pippypi--servette-is-not-its-own-package-manager) deleted, and its reopen conditions have not fired.
- **The admin page hosted on servette.org, talking to the box over the tunnel** — the browser trusts the origin that served the document, so servette.org's host becomes a party who can act on every box while the tool is open.
- **A loader on the box that fetches the page from servette.org and verifies its hash** — sound, but keeps the admin server in the module and ties the tool to servette.org's uptime against the no-mirror ruling.
- **A second module in the same wheel, or a `servette-admin` package injected into the server's environment** — the first breaks the expectation that `pipx install servette` delivers `servette.py` alone; the second keeps a root-run loopback server, the tunnel, and a login on every box.
- **servette.org as a launcher, framing the box's page with browser pairing in place of the passcode** — the most machinery of any option, with open browser questions, for a flow the app gives without a launcher.
- **A zero-click `ssh` configuration entry** — workable, but an unusual `Host` entry for every operator to maintain, and the admin server stays on the box.
- **Runtime plugins and third-party extensions** — code the serving process discovers and imports dissolves the audit boundary; extensions the project cannot audit cannot carry its claims.
- **A SQL parser in the database edition** — a second opinion about what a query means, in front of the engine that holds the first; where they disagree the attacker wins, and the server stops being engine-agnostic.

## Open decisions

Each is the Human's to close; what it gates follows it.

- <a id="what-is-core"></a>**What is core.** Removing the loopback server and its page takes the module from about 10,400 lines to about 7,300, of which about 6,500 are Python. Getting toward 3,000–4,000 means deciding whether these are serving or administering: publishing and version history, the config sub-shell, status and traffic reporting, the setup wizard, and swap and the network watchdog in `src/SYSTEM.md`. The app drives whatever stays through the command line, so moving a feature out means the app reimplements it. *Gates:* the size of the server and the breadth of the command-line contract.
- **The three seams, exactly.** The verb table's shape, how a site declares its kind, and how an extension's config keys join the vocabulary. *Gates:* the first extension's build.
- **Privileged commands from the app.** `servette admin` elevates with `sudo` and asks in the terminal. The app runs commands over SSH without a terminal of its own; it must request one and relay the prompt, rely on the box's `sudo` asking no password, or something else. *Gates:* the app's connection design and what setup says about the operator account.
- **The command-line contract.** Which commands gain `--json`, how a bundle reaches `publish` over SSH, and how the contract's version is stated. *Gates:* the first step of the build.
- **The app's technology and first packaging.** A Python application shipped through PyPI first and wrapped in an installer later, or a binary installer from the start. *Gates:* the app repository's design document.
- **The database edition's ledger.** The four refusals per engine, the budget, what a refused query answers, the result format, and whether query text with bound values is the only accepted form. *Gates:* `DATABASE.md`, which is written after the ledger, not before.
- **Superseded rulings.** The app amends [multi-step features pair a shell flow with a loopback browser page](DECISIONS.md#multi-step-features-pair-a-shell-flow-with-a-loopback-browser-page) and [one admin page with tabs is the browser surface](DECISIONS.md#one-admin-page-with-tabs-is-the-browser-surface) — the browser surface leaves the box — and retires [the front door is a login](DECISIONS.md#the-front-door-is-a-login-link-and-passcode-printed-apart) with the door itself; the scope table's "plugins" row is rewritten as above. *Gates:* the rewrite of `DESIGN.md` and `DECISIONS.md` at merge.
- **The transport stays out.** Replacing threaded `http.server` with asyncio is not part of 2.0; it is a core question to reopen only on evidence — the connection cap hit under real traffic, or per-connection memory measurably hurting a small box.

## Building it

Each step is its own branch and merges on its own; 1.x operators keep working after every one.

1. **The organization and the four repositories**, each opened with its README from `v2/`; the website moves from its current repository.
2. **The contract**, in this repository: `--json` where the app needs it, `publish` from a bundle, the shapes stated in `DESIGN.md` and pinned by the suite. Nothing is removed.
3. **The seams and `OPTIONS`**, in this repository, each ruled first, with the static edition's behaviour unchanged except that `OPTIONS` answers truthfully.
4. **The app**, in its repository: the page and a local process that drives `ssh`, working against 1.x boxes, with its own design document and suite.
5. **The admin server leaves** once the app is proven: the loopback server and `src/admin.html` leave the module, `admin` leaves the command list, `help` names the app.
6. **The database edition**, in its repository: the ledger first, then `DATABASE.md`, the SQLite adapter, and the battery.
7. **`DESIGN.md` is rewritten** for the server alone, the superseded rulings are recorded, and this document retires into it.
