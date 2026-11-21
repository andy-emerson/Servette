# Handoff: Servette 2.0 (`v2` branch)

**Written:** 2026-11-21, from a planning conversation
**Status:** design only. No code has been written and no branch has been created yet.
**Placement:** a planning file on a working branch, not a durable document; open decisions still belong in issues before anything lands on `main`.

## Where things stand

- **Servette 1.x** is live and in a 90-day soak: real sites running on it, no
  changes. When it reaches 90 days without failure, it ships as **1.0 unchanged**.
- **Servette 2.0** is the next major version, for fundamental, breaking changes.
  This document records the design agreed so far.

## How the 2.0 work is organized

- Develop on a long-lived **`v2` branch** in the Servette repo (preferred over a
  separate fork, so 1.x fixes can flow into 2.0 easily and issues/CI stay in one
  place). A fork also works; that choice is still open.
- Publish **opt-in pre-releases** (`2.0.0a1`, `2.0.0b1`) so testers can use
  `pip install --pre servette` while everyone else stays on 1.x.
- Merge back and release 2.0 when ready.

## Two major changes

### 1. Simplicity: replace manual SSH-tunnel admin with a launcher

Goal: a beginner can install and manage a site without ever using a terminal.

- **Restructure the code into three layers** (two names: servette.py for the
  library, servette.org for the website):
  - **Server core:** serving plus production hardening (today's server module).
  - **Management library:** today's shell commands and system module as plain
    functions (certificates, service install, settings).
  - **Front ends:** the web admin UI and a thin CLI, both calling the
    management library, so they can never drift apart.
- **Launcher app** for Mac, Windows and Linux:
  - Downloaded from servette.org (OS auto-detected).
  - Launched from a **"Launch admin" button** on servette.org via a
    `servette://` link, with the standard fallback ("Nothing happened? Download
    the app.").
  - Stores the user's server connections, opens the SSH tunnel (using the SSH
    client built into all three OSes), picks a free local port, and opens the
    admin UI in the browser.
  - First-time setup: generate an SSH key and walk the user through installing
    it on their server.
- **The admin UI is served by the user's own Servette server**, bound to
  localhost, reached only through the tunnel. It always matches the server
  version and is never exposed to the internet.
- **servette.org serves only docs, the launch link and the download.** It never
  runs admin code and stores no user data.
- **Easier installation:** a Raspberry Pi image with Servette preinstalled
  (first-run setup at `servette.local`) and a copy-paste cloud setup script for
  VPS providers.

Rejected alternatives and why:

- *Admin UI hosted as a web app on servette.org:* the site would deliver the
  admin code to every user, so one compromise (registrar, DNS, hosting) would
  reach every user at once; browsers also can't speak SSH without a relay.
- *Internet-facing admin page on each server:* simplest, but a permanent public
  admin surface and it breaks the GET-only design. Possible later as an opt-in
  only, with passkeys and its own port.

Security requirements for the launcher:

- **Code-sign** the app (Apple notarization ~$99/yr; Windows code-signing
  certificate, typically hundreds/yr). This also avoids "unidentified
  developer" warnings that would scare beginners.
- **Sign updates with an offline key**; the app refuses unsigned updates.
- **Treat every `servette://` link as untrusted:** only accept servers the user
  already configured, never take hostnames or commands from the link, confirm
  before connecting.

### 2. Concurrency: replace `http.server` with an asyncio server

Goal: handle real web apps, including large client-side/WebAssembly bundles
downloading to slow clients, for self-hosters who won't put a CDN in front.

- Build it as a **separate importable library**: asyncio, **standard library
  only**, HTTP/1.1, production hardening built in (timeouts, connection limits,
  strict parsing). Servette is its first consumer.
- **Name: still open.** Avoid stdlib-looking names: `http.parser` can't work
  (stdlib `http` would shadow it or be shadowed), `async.server` can't be
  imported (`async` is a keyword), and `https.*` implies an official module.
  Check PyPI availability for candidates.
- **The HTTP parser is the main risk** (request smuggling, malformed headers,
  chunked encoding). Its verification is the core deliverable:
  differential testing against h11 and existing servers, fuzzing, and known
  request-smuggling test suites, in the same "witness" style as lua.wasm and
  love.wasm.
- Carry over the existing **range-request** handling (single range,
  206/416, already in 1.x) and review **caching headers**.

## Suggested order

1. **Restructure** into server core / management library / front ends while
   still on `http.server`. Low risk, invisible to users, and both changes
   depend on it.
2. **Ship the launcher** and route the admin UI through the tunnel.
3. **Swap in the async server** once it passes verification; thanks to step 1,
   this touches only the server core.

## Open decisions

- [ ] `v2` branch vs. separate fork.
- [ ] Does a fix during the 1.0 soak restart the 90-day clock?
- [ ] Migration path from 1.x to 2.0 (keep the thin CLI; read or convert 1.x
      settings).
- [ ] Name for the async server library.
- [ ] Whether the launcher is written with tkinter (stdlib-only spirit) and
      how it's bundled so beginners don't need Python installed.

## Checked against the code (main @ 37a31be, 2026-11-21)

- **Range requests already exist:** `_parse_range` serves a single byte range,
  returns 416 when unsatisfiable, and falls back to the full body for
  multi-range or malformed headers. Remove range requests from the 2.0 list.
- **Slowloris mitigations already exist:** a 30 s per-connection timeout plus
  `MAX_CONNECTIONS = 128` and `MAX_CONNECTIONS_PER_IP = 32`.
- **Size:** `servette.py` is 10,426 lines, built from literate sources in
  `src/` (`SERVER.md`, `SHELL.md`, `SYSTEM.md`, `INIT.md`, `MAIN.md`, plus
  `admin.html`). The proposed layer split should follow those source files.
- [ ] Still unchecked: whether the module is importable as a library today,
      and what its public API would be.

## Related, out of scope for this branch

- **TallyDB hybrid idea:** server-side TallyDB ingests continuously; a
  WebAssembly build in the browser computes over slices it fetches. If
  segments are immutable files, Servette could serve them via range requests;
  a live tail would need a separate async component.
- **lua.wasm recommendations:** drafted in a separate `handoff.md` (value
  passing, host functions, releases, published wasm-EH sysroot).
