# Dynamic Servette — Design Exploration

> **Status: exploration, not adopted.** This document records a design
> discussion for later reference. It does **not** describe planned work, and
> nothing here has been built or tested — every claim below is at the *Stated*
> rung of the claim ladder ([`principles.md`](principles.md#status--the-claim-ladder)).
>
> **It also collides head-on with the current scope.** Dynamic content
> (`POST` → 405) is a named **non-goal** in
> [`principles.md`](principles.md#scope--non-goals): *"A request to
> add any of these is not a feature request; it is a request for a different
> program."* Supporting server-side apps is that different program. This file
> exists so that, if the question is ever raised again, the reasoning is on
> record — not to pre-authorize the work.

## The question

Servette serves static files — sufficient for client-side apps. Could the same
hardened shell (TLS, ACME auto-renewal, rate limiting, auth, security headers,
the systemd sandbox) instead serve a **server-side** app, and if so, how much
of Servette would have to change, and at what cost to the "secure" promise?

## The architecture it starts from

`servette.py` divides into three labelled sections:

- **Server** — config, rate limiter, file cache, the request core, the request
  handlers, the threaded HTTP/HTTPS servers.
- **System** — venv bootstrap, server lifecycle, ACME / certificate management,
  the systemd unit.
- **Shell** — the interactive terminal UI (pure UI; delegates all real work to
  System).

The load-bearing seam is `_handle_request(method, url_path, headers, raw_ip)`:
it is **transport-agnostic**, taking parsed inputs and returning
`(status, headers, body)`. The handler class is a thin adapter over it. That
seam is effectively a micro-framework already, and it is where any dynamic
dispatch would hang.

## Two shapes of the change: Swap vs. Add

**Swap** (replace static serving with server-side Python) is *not* difficult.
System and Shell are untouched — they are the valuable, reusable parts and they
do not care whether responses are static or dynamic. Only the tail of the
request core changes. You replace one closed threat model ("read-only file
server") with another closed threat model ("app server") and re-audit once.

**Add** (keep static serving *and* offer dynamic alongside it) is where the
"secure" promise gets expensive — and the cost is **not** proportional to the
lines of dynamic code. It comes from two things:

1. **Emergent guarantees you lose.** Several of Servette's security properties
   are not features anyone wrote; they are guarantees you get *for free* by
   never doing certain things. Adding a dynamic path breaks them even for the
   static path, because they share one process:
   - **Read-only filesystem.** The systemd unit is `ProtectSystem=strict` with
     `ReadWritePaths` limited to Servette's own dir and the ACME webroot; "the
     server never writes the served directory." A dynamic app that stores
     anything (sessions, uploads, a DB) forces that open, widening the blast
     radius of any RCE.
   - **No request body is ever read.** The core 405s every non-GET/HEAD method
     and closes the connection so an unread body can't poison keep-alive. That
     invariant eliminates a whole class of bugs (body-size DoS, multipart
     parsing, content-type confusion) up front.
   - **Effectively stateless per request.** No sessions today means session
     fixation, CSRF, and cookie-security concerns simply do not exist.
   - **Auditability.** "A single file you can read" holds partly *because* the
     request core is small enough to reason about.

2. **Seam bugs unique to Add** — defects that live *between* the two paths even
   when each is individually correct: routing precedence (does a file shadow a
   route, or vice versa?), whether every dynamic route is provably behind the
   auth gate, whether a dynamic response can ever land in the file cache (ETag
   confusion → cross-user leak), and a CSP tuned for static content that a
   reflecting app would need to revisit.

## What actually changes in the request core

Three concrete things, all in the Server section:

1. **Method allowlist** — today `if method not in ("GET", "HEAD"): 405`.
2. **Body reading** — the core has no body parameter and deliberately never
   reads `rfile`. Dynamic needs to read `Content-Length` bytes **and impose a
   maximum body size** (there is no bound today; unbounded reads are a DoS
   vector).
3. **Dispatch** — a route table consulted before falling through to static
   serving (static-as-fallback is a clean pattern).

The auth gate and rate limiter already live in the core, so they carry over —
but note they would then guard app logic, and Basic-auth-only is thin for a
real app (no login form, no sessions).

## The static machinery: three buckets

Not all "static-specific" code is equal when swapping to dynamic.

**Bucket A — genuinely vestigial (drop, no equivalent needed):** the MIME table
(`MIME_TYPES`/`_mime_type`), the custom `404.html` path, and the Shell niceties
`_cache_warnings` / `_config_dir`. Dynamic handlers state these things directly.

**Bucket B — vestigial *as wired*, but dynamic wants its own version (feature
gaps, not security):**
- **File cache** → app-level response caching. Note the cache also gave an
  *implicit bound on work per request*; dynamic handlers recompute every time
  and can do unbounded work, so the DoS surface shifts from bytes to compute.
- **gzip** → keyed to file extension inside the cache, so dynamic text gets no
  compression unless re-added at the response layer.
- **ETag / 304** → file-bytes-bound today; conditional GET is re-implementable
  by hashing response bodies.
- **Byte ranges / 206** → near-pure vestige for an API, *unless* the app serves
  files (downloads, media, uploads), where seeking needs them back.

**Bucket C — looks static-specific, is actually load-bearing security (the ones
to worry about):**
- **`_resolve_request_path` + `_within`** read like "URL → file mapping" but are
  the **path-traversal and symlink-escape defense** (`realpath` + `commonpath`
  containment). The instant a dynamic app maps *any* user input to a filesystem
  path (a download, a template-by-name, an upload), this logic is needed again —
  and hand-rolled path-safety is a classic CVE source. It must live in shared
  core, never be duplicated per path.
- **`_cache_control_header`** discipline (`private`/`no-store` when auth is on)
  is what keeps authenticated content out of browser and intermediary caches.
  For a dynamic app it must become **per-response**, not one global default — a
  logged-in page cached as `public` is a real data-leak / cache-poisoning bug.

The one-line takeaway: most static machinery is safely vestigial or a
re-buildable feature, but path-safety and cache-control are **security controls
disguised as static plumbing** — swap them out and you have quietly deleted a
defense you must consciously rebuild.

## The systemd sandbox does not follow a runtime flag

This is the sharpest constraint and it is invisible until you look below the
Python. Servette's static security is partly the systemd unit
(`ProtectSystem=strict`, tight `ReadWritePaths`, `CAP_NET_BIND_SERVICE` only),
written at **install time** by `cmd_install`. If "dynamic vs static" is a
**runtime** choice, the two clocks disagree, and every reconciliation is bad:

- Unit always tight → dynamic mode can't write its state; it breaks.
- Unit always loose → every static deployment runs under a weakened sandbox it
  never uses (the union of privileges, not the intersection).
- Unit written to match mode at install → flipping the mode later in the shell
  desynchronizes config from kernel posture, silently.

You can gate the Python behind an `if`. You cannot gate `ProtectSystem=strict`
behind the same `if` — it is enforced one layer below the process reading the
flag. Any "choose at runtime" design must therefore treat the mode as
**start-time-only** (not hot-reloaded via `reload_if_changed`, which runs per
request) and **fail-safe default to static**, and must regenerate the systemd
unit to match, ideally requiring an explicit re-install to go dynamic.

## Three implementation options

### Option 1 — Build step, separate single-file artifacts

Author `core` + `static` + `dynamic`; a small build **concatenates** core with
one use case to emit `servette.py` (static) *or* `servette-dynamic.py`. Each
deployed artifact is one self-contained file.

- **Pros:** best *minimal surface* — the static build contains **zero lines of
  dynamic code**, preserving the exact attack surface the project is built
  around. Deployed artifact stays a single auditable file.
- **Cons:** introduces build tooling (itself on the trust path — it produces the
  audited file). Forks the **signed self-update flow**: two artifacts to build,
  sign, publish, and teach `cmd_update` to distinguish (two `.sig` files, "am I
  the static or dynamic build?"). Three source files to keep in sync. Bends the
  "single file" principle at the *source* level (one artifact, three sources).

### Option 2 — Runtime module import (rejected)

Ship `servette.py` (core) that imports a use-case module at run time; "the shell
pulls in the module."

- **Pros:** conceptually simple.
- **Cons:** breaks the philosophy twice — you now deploy *two* files (no longer
  "one file you can read"), **and** you add a dynamic-import surface, the exact
  "what actually got loaded?" question auditability exists to kill. All code is
  present *and* there is an import seam: worst of both. **Rejected.**

### Option 3 — Both built in, one active, chosen via the shell

No build, no separate modules. Both engines live in `servette.py`; a config
value selects which path is live.

- **Pros:** most faithful to the *literal* single-file philosophy — one file, no
  build, no plugin. **Single, simple update path** (one `servette.py`, one
  `.sig`, `cmd_update` unchanged) — a real advantage over Option 1. If the
  dynamic dispatch sits behind one early, unbypassable branch defaulting to
  static, the *network-reachable* surface of a static deployment is close to
  static-only (an attacker can't flip a config value without already holding
  local shell + file-write).
- **Cons:** the **systemd sandbox problem above** — OS posture can't follow the
  runtime flag, so you tend toward the union of privileges or install/mode skew.
  The mode becomes security-critical state that currently *hot-reloads* per
  request, which must be disabled. Static users still **ship and must audit** a
  dormant dynamic engine, so the *present* (if not *reachable*) surface grows —
  directly in tension with "minimal footprint" and "single file = one
  comprehensible thing."

### Comparison

| | Opt 1 (build) | Opt 2 (import) | Opt 3 (runtime flag) |
| - | - | - | - |
| Deployed artifact | one file | **two files** | one file |
| No build tooling | ✗ | ✓ | ✓ |
| Static ships zero dynamic code | ✓ | ✗ | ✗ |
| Simple signed-update path | ✗ (forked) | ~ | ✓ |
| OS sandbox tracks mode cleanly | ✓ (per artifact) | ✗ | ✗ (hard) |
| Adds a dynamic-import surface | ✗ | ✓ | ✗ |

## The fork underneath all of it

"Single file philosophy" is really **two** philosophies, and Option 3 forces
them apart:

- **Single file = literal artifact** (one `.py`, no build, no plugin) →
  **Option 3 wins.**
- **Single file = minimal auditable surface** ("you can read the whole thing and
  it does *one comprehensible thing*") → **Option 1 wins**, because Option 3's
  file is bigger and implements an app framework you may not run.

Servette's stated security brand — the README's "a single file you can read,"
the whole minimal-surface argument, `principles.md`'s "no module sprawl, no
hidden machinery" — is the **second** reading. The deciding question is not
"build step or not"; it is *which meaning of the philosophy the project is
protecting.*

## Where it stands

- Going dynamic is a **scope/identity decision** (static server vs. server
  platform), reserved to the human with design authority — not an engineering
  default, and currently on the wrong side of a stated non-goal.
- If the brand is *minimal auditable surface*, **Option 1** is the fit; the
  update-path fork is the price.
- If the brand is *literal one-file distribution*, **Option 3** is defensible —
  but only disciplined: default static, mode fixed at first-run / install (not a
  hot config toggle), and the systemd unit generated to match, with switching to
  dynamic requiring an explicit re-install.
- **Option 2 is rejected** regardless.

Open questions if this is ever revisited: the auth/session model for real apps
(Basic-only is thin), a maximum request-body size, per-response cache-control,
and where writable app state lives relative to the served tree and the sandbox.
