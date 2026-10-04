# DESIGN-V2.md

The plan for Servette 2.0 — what it ships, how it is administered, and why. [`DESIGN.md`](DESIGN.md) describes 1.x, which is what runs today; this document describes the version after it. Where the two disagree, `DESIGN.md` is the truth about the code and this is the truth about the destination. Rulings that 2.0 needs and that are not yet closed are listed under [Open decisions](#open-decisions); open work lives in the repository's GitHub issues.

## Why a 2.0

Servette exists to answer Python's own warning that `http.server` is not for production. 1.x answers it, and then keeps going: the same module carries a setup wizard, content publishing with version history, swap and network-watchdog management, traffic statistics, a live CPU meter, preview staging, and a root-run loopback web server with a 2,500-line admin page. Each addition was defensible under the principles — "Production-grade" and "Zero-friction" license almost any operations feature — and together they made a second product, wrapped around the first.

Measured at 0.26.246, of roughly 7,100 lines of Python plus 3,300 of embedded HTML and JavaScript:

| Part | Lines | What it is |
| - | - | - |
| `src/SERVER.md` | 1,709 | config, rate limiting, file cache, request handler, TLS |
| `src/SYSTEM.md` | 2,077 | certificates and ACME, lifecycle, systemd units and sandbox, network watchdog, swap |
| `src/SHELL.md` | 3,132 | shell, setup, status, publishing, and the admin page's server (674) |
| `src/admin.html`, `src/connection.html`, `src/404.html` | 3,328 | the browser pages |

The secure server is about a third of it. Two costs follow. **Auditability:** "understood by one person" now means reading a CPU meter's JavaScript to audit TLS. **Attack surface:** the admin server runs as root and accepts uploads; it is reachable only through the operator's SSH tunnel, but it ships with — and must be audited as part of — the security product.

2.0 separates the two products and keeps each one honest about what it is.

## The shape of 2.0

Three parts, each with one job:

| Part | Job | Delivered by | Runs on |
| - | - | - | - |
| **The core** — `servette.py` | serve static sites securely: TLS, ACME, headers, auth, rate limits, the service unit, and a command line | PyPI, through pipx | the server |
| **The admin extension** | the browser admin tool: its loopback server and its page | a GitHub release, fetched and verified by the core | the server, only where the operator installs it |
| **servette.org** | the front door: a launcher that opens the tunnel and frames the box's own admin page | static hosting | the operator's browser |

From the operator's side it is one website with an unusual login: open servette.org, pick a box, click Connect; a terminal window opens the tunnel, and the box's admin tool appears in the same tab.

## The core

The core is `servette.py` without the admin server and pages. It keeps every 1.x principle in [`DESIGN.md`](DESIGN.md#scope--non-goals) unchanged — and gains one scope rule that 1.x lacked: **a feature for administering the box belongs to the extension; the core grows only for serving.** The core's command line is the extension's interface: `status --json`, `sites --json`, `set`, `publish`, and the rest, stable within a major version.

What else leaves the core is not yet decided — see [what is core](#what-is-core).

## The admin extension

The admin server and its pages, shipped separately and installed on demand.

- **Installing.** `servette admin` on a box without the extension says so and offers to fetch it. On yes, the core downloads the extension's release archive from GitHub.
- **Trust comes from the core, not from GitHub.** Every core release embeds the SHA-256 of the one extension release it was built with — they are versioned in lockstep. The core refuses an archive that does not match. The checksum arrives inside the core, through PyPI, so the extension inherits the core's trust; GitHub only serves bytes, and a tampered release or download fails the check. No signing key, no new trust root, and the core never replaces its own code.
- **Where it lives.** A root-owned directory the sandboxed service can read but not write — the runtime-copy directory is already that. Never under `/var/lib/servette`: the service can write there, so code placed there could be altered by a compromised service and then run as root at the next `servette admin`.
- **Checked on every load,** not only at install: the checksum is recomputed before the extension is imported.
- **Unpacked by the core's existing hardened extraction** — the same path publishing uses for uploaded archives, which refuses escaping paths and links — not by a second extractor.
- **Lockstep versions remove compatibility negotiation.** A core only ever runs the extension release it names.
- **Uninstalling** is deleting the directory.
- **Offline boxes** install from a local archive under the same checksum check.

This is not the self-update machinery that [the distribution ruling](DECISIONS.md#distribution-is-pippypi--servette-is-not-its-own-package-manager) deleted: that ruling governs how Servette itself is delivered, and Servette is still delivered only by pipx. The extension is code the installed core fetches and verifies; its own ruling, scoped beside that one, is an [open decision](#open-decisions).

## servette.org: the launcher

servette.org stops being a brochure and becomes the way in — without becoming the infrastructure.

- **Connect.** Setup prints a complete `Host` entry for the operator's `~/.ssh/config`: the box's address, user, a `LocalForward` on a port unique to that box, `RequestTTY yes`, and `RemoteCommand servette admin`. servette.org's Connect button is an `ssh://<host-alias>` link; on macOS it opens Terminal, which opens the tunnel and starts the admin server in one step. Where the platform has no `ssh://` handler (Windows, most Linux desktops), Connect copies `ssh <host-alias>` to paste into a terminal.
- **A port per box.** Every box tunnelled to the same local port would share one browser origin and one key store; setup assigns each its own.
- **Detecting the tunnel.** The page polls an unauthenticated `/hello` on the box's local port until it answers. `/hello` reveals only that an admin server is listening and its version.
- **The admin tool appears in the tab.** servette.org embeds the box's page — served by the box, through the tunnel, from `http://localhost:<port>` — in a frame. The browser's same-origin policy forbids servette.org's own code from reading or scripting that frame: servette.org draws the frame around the tool but cannot see into it or act on the box. A compromised servette.org can break the launcher; it cannot administer anyone's server.
- **Framing is the box's to permit.** The box's admin page sends `Content-Security-Policy: frame-ancestors https://servette.org` and accepts no other framer.
- **The box list.** The launcher keeps the operator's boxes (alias, address, user, port) encrypted at rest in the browser — a non-extractable AES-GCM key in IndexedDB, the pattern Neodide's secrets manager uses. Nothing there is a credential; it is convenience.
- **What servette.org never holds:** SSH keys (the system's ssh and agent keep them), pairing keys (they live with the box's page, below), or any route to a box that does not run through the operator's own tunnel.

Unverified, to settle before building: Chrome and Firefox allow an https page to frame `http://localhost` (Chrome behind its one-time local-network-access prompt); Safari's behavior is untested.

## Pairing: logging in without a passcode

1.x logs in with a six-character passcode printed per run. 2.0 replaces it with a key that cannot leave the browser.

- **The first login on a browser** uses a one-time code the admin server prints in the terminal as a clickable link, `https://servette.org/#c=<code>`. The code rides in the URL fragment, which browsers never send to a server: servette.org's host never sees it, only the page in the operator's browser, which hands it to the framed admin page.
- **Pairing.** On that first login, the box's admin page — on the box's origin, not servette.org's — generates a non-extractable ECDSA key with WebCrypto, stores it in IndexedDB, and sends the box its public half. The box keeps a list of trusted browsers, in the manner of `authorized_keys`.
- **Every later login** is a challenge the browser signs: click Connect, the tunnel opens, the page signs the box's challenge, and the tool opens. Nothing to read or type.
- **Two locks:** the SSH key opens the tunnel; a browser key that cannot be exported passes the admin server. A copied link or leaked code is worthless after first use.
- **Revoking** a browser is deleting one line from the trusted list, from the terminal.
- **Per browser, per device:** a new laptop or cleared storage pairs once more from the terminal link — by design.

This removes the passcode, its guess ceiling, and the login page from the admin server. The box verifies signatures with `cryptography`, already the core's one dependency.

## Trust, summarized

| Who could act on a box | 1.x | 2.0 |
| - | - | - |
| Someone with the operator's SSH key | yes | yes, and only from a paired browser or the terminal link |
| servette.org's host or its scripts | n/a | no — same-origin forbids reading or scripting the framed tool |
| Someone with a copied admin link or code | yes, for that run | no — single use, then pairing |
| A compromised service user | no | no — the extension lives where the service cannot write, and is checksummed on load |

## What 2.0 costs

For operators: a one-time pairing per browser; one-click Connect on macOS and copy-a-command elsewhere; browser prompts for local-network access that vary by browser; and the launcher is unavailable while servette.org is down — the terminal and every command line keep working.

For maintainers: two artifacts released in lockstep, with CI enforcing that each core release names a published extension checksum; servette.org's publishing becomes part of the product (static files, built by CI from this repository, no third-party scripts, integrity hashes), even though it holds no keys; ~60–100 lines of fetch-verify-install code in the core that decide what runs as root, under the [verification bar](DESIGN.md#verification-bar)'s human read; and a migration in which 1.x operators keep `servette admin` working until the 2.0 path is proven.

## Open decisions

Each is the Human's to close; what it gates follows it.

- <a id="what-is-core"></a>**What is core.** Moving the admin server and pages takes the core from ~10,400 lines to ~6,700. Getting toward 3,000–4,000 means deciding whether these are serving or administering: publishing and version history (558), the config sub-shell (468), status and traffic reporting (592), the setup wizard, and swap and the network watchdog in `src/SYSTEM.md`. *Gates:* the size of the core and the extension's interface.
- **The extension ruling.** "The installed core may fetch one extension from GitHub, verified against a checksum the core carries" — scoped beside [the distribution ruling](DECISIONS.md#distribution-is-pippypi--servette-is-not-its-own-package-manager), which it leaves standing for Servette itself. *Gates:* the install path.
- **Superseded rulings.** Pairing replaces [the front door is a login: link and passcode, printed apart](DECISIONS.md#the-front-door-is-a-login-link-and-passcode-printed-apart); the extension amends [one admin page with tabs is the browser surface](DECISIONS.md#one-admin-page-with-tabs-is-the-browser-surface) and [the build emits one servette.py](DECISIONS.md#the-build-emits-one-servettepy-the-package-build-runs-the-literate-transform); "Understood by one person — one literate module" becomes one literate module per product. *Gates:* the rewrite of `DESIGN.md` at merge.
- **Safari.** Whether it frames `http://localhost` from an https page. *Gates:* whether the launcher frames or navigates the tab on Safari.
- **The transport stays out.** Replacing threaded `http.server` with asyncio is not part of 2.0; it is a core question to reopen only on evidence — the connection cap hit under real traffic, or per-connection memory measurably hurting a small box.

## Building it

Each step is its own branch and merges on its own; 1.x operators keep working after every one.

1. **Split the build** into the core and the extension, behaviour unchanged: two outputs from `src/`, the extension still bundled.
2. **Fetch and verify:** the extension leaves the core's package; `servette admin` installs it from a GitHub release against the embedded checksum.
3. **Pairing** replaces the passcode.
4. **`/hello` and framing:** the box answers the launcher and permits servette.org to frame it.
5. **The launcher** on servette.org: box list, Connect, frame.
6. **Setup** prints the `Host` entry with a port per box; `DESIGN.md` is rewritten for two products and this document retires into it.
