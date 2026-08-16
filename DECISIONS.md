# Decisions

The closed rulings: what was decided, what was rejected, and what would
reopen each. This file is the canonical in-repo record; the linked issues
hold the deliberation, and [`DESIGN.md`](DESIGN.md) describes what is
built as a result. Entries are compact and present-tense; newest first.
Only the Human closes a decision ([`AGENTS.md`](AGENTS.md)).

## The status code tells the truth; the body does the work

**Ruled (principle).** Servette answers with the status code the situation
actually calls for, and puts its own contribution in the body. `200` is
`200`, `404` is `404`; the difference is that Servette's `404` is useful.
The status is the machine-readable half of the response — caches, crawlers,
uptime monitors — and is never bent to make a signal look better than the
thing it reports. Withholding is not bending: the closed-system miss and
the unserved version endpoint keep a true `404` and say less in the body.
**Scope:** every response Servette sends. It settles, without further
argument, soft-404s that answer `200` with an apology, a `200` at an
unpublished root to keep an uptime check green, and a `404` worn by a
refusal that is really a `403`. Described in
[DESIGN.md](DESIGN.md#the-status-code-tells-the-truth); the diagnostic
error page below is the case that made it explicit. **Reopen:** a standard
or a client Servette must interoperate with requires a status Servette
considers untrue — in which case the conflict is recorded, not resolved by
quietly bending one. *(2026-08-16)*

## The default error page diagnoses; the placeholder is retired

**Ruled:** every server needs an error page, so Servette's earns the
response it spends. Where the operator has written no `404.html`, a miss
is answered by the embedded diagnostic page — the same file served at
`/selftest/`, in a second role at status 404 — reporting that the server
is up, which host answered, the path requested, what the response
carries, and whether anything is published at the site root at all. That
last row separates a visitor who mistyped from an operator whose deploy
never landed. The page drops its Servette feature paragraph in the 404
role: an operator's error page is not this project's billboard. It never
enumerates the filesystem or guesses near-miss names, for the reason the
closed-system 404 stays a bare line — an error page that did would be a
file-discovery oracle. Because this answer covers a site's own root while
nothing is published there, the seeded placeholder page and its whole
`servette:demo` ownership protocol are deleted, superseding
[#70](https://github.com/andy-emerson/Servette/issues/70).
The status stays 404 throughout, per [the status code tells the
truth](DESIGN.md#the-status-code-tells-the-truth): a 404 is what happened,
and the diagnosis is the body's job. **Rejected:** the bare `Not found.`
(a whole response spent saying only that the reader was wrong); serving the
self-test verbatim, branding and feature advertisement included, as the
operator's error page; answering an unpublished root with 200 to restore
what the placeholder used to return — a monitor reading green over a site
with nothing to serve is the signal meaning less, which the principle
forbids. *(2026-08-16)*

## The self-test is server-delivered, client-executed

**Ruled:** the connection self-test ships embedded in the module and is
served at the reserved path `/selftest/` wherever the operator's content
doesn't shadow it — and, in its second role, as the default error page
([above](#the-default-error-page-diagnoses-the-placeholder-is-retired)).
Execution stays in the visitor's browser — only an outside client sees
the browser-trusted cert chain, the real network path, and the provider
firewall. **Rejected:** server-side execution (a server cannot see itself
from outside; `_production_issues()` is already the inside half); the
prior bundle-injected copy (superseded from #42 — it required a
deliberately duplicated page and a network fetch in the publish tool).
*(#79, 2026-08-16)*

## site/pub/ is the operator tools page

**Ruled:** one bookmarkable home for operator services — the publish
tool, the self-test explanation and link, the documented CLI loop. Its
ceiling is a security boundary: it hosts, ships, links, and explains,
and never reaches into a live server (no network admin API) or probes
another origin. `servette sign` (client-side signing verb in the pip
package) is **open**, not ruled. *(#79, 2026-08-16)*

## DECISIONS.md is the canonical decision record

**Ruled:** this file. DESIGN.md stays present-tense — what is built and
why it is shaped this way — pointing here where a ruling settled
something. Open work and deliberation live in GitHub issues.
**Rejected:** recording rulings as permanent narrative inside DESIGN.md
(the bloat mechanism: DESIGN's size tracked history, not the product);
GitHub Discussions (not version-controlled, not in a clone, invisible
offline — the working agreement requires decisions in the repository).
*(#78, 2026-08-16)*

## One home per fact: the site READMEs are deleted

**Ruled:** `site/README.md` and `site/pub/README.md` are gone. The
layout principle lives in DESIGN.md's website section; the publish
tool's load-bearing constraints live in `site/pub/index.html`'s own
header comment, where an editor of the page reads them. **Rejected:**
parallel folder READMEs (the merge-scale review caught them drifting
against DESIGN — two homes, one fact). *(#78, 2026-08-16)*

## No docs/ folder

**Ruled:** documents stay at repository root. README, CONTRIBUTING,
SECURITY, AGENTS.md, and CLAUDE.md are pinned there by platform and
tooling conventions, leaving only DESIGN.md and this file movable — a
folder for two files buys indirection and link-rot for no legibility.
**Reopen:** the movable document set outgrows three. *(#78, 2026-08-16)*

## SECURITY.md and CONTRIBUTING.md stay, slimmed to their cores

**Ruled:** both remain for their GitHub wiring — the Security tab's
private-reporting flow and the first-PR contributor banner — each
carrying only what that wiring puts in front of the right reader: the
reporting path and scope list; the generated-module rule, the
verification bar, and the credit-and-own AI policy. **Rejected:**
deletion (the two load-bearing facts would lose their GitHub-wired
home); folding into README (wrong audience). *(#78, 2026-08-16)*

## Distribution is pip/PyPI — Servette is not its own package manager

**Ruled:** install, upgrade, and rollback are the package manager's job;
the self-management layer (bootstrap, self-update, restore, the pinned
release-signing key, `servette.py.bak`) is deleted. The publish channel
is untouched — it guards operator *content* with per-site keys.
**Rejected:** signed GitHub releases + in-process self-update (hand-rolls
what the ecosystem standardized; its fetch-verify-swap-exec path was the
most dangerous code in the product); additive PyPI alongside it (forked
trust story). **Trade accepted:** code delivery trusts PyPI + Trusted
Publishing instead of a pinned Ed25519 key. **Reopen:** a PyPI
supply-chain incident touching Servette or its dependency, or credible
demand from operators on index-less networks. *(#77, 2026-08-15)*

## The data directory is /var/lib/servette

**Ruled:** state (config, certs, ACME account, site folders) lives in
`BASE_DIR` — `/var/lib/servette` on Linux, `~/.servette` in macOS
session mode, `SERVETTE_HOME` to override — never beside the code. Site
content is owned by the operator with servette-group read. **Rejected:**
beside-the-code (meaningless under pip); under `$HOME` (the 0750
home-traversal trap, root cause of #74). *(#77, 2026-08-15)*

## The CLI is the API

**Ruled:** `servette <command>` one-shot and the interactive shell share
one dispatcher; `status`/`sites --json` are the read half and validated
`set` the write half; SSH is the authentication. Password and domain are
deliberately excluded from `set` (argv leaks; certificate coupling).
**Rejected:** a network admin API — reaffirming the standing refusal;
nothing network-reachable changes the server. *(#77, 2026-08-15)*

## Servette ships as a package; the single-file principle is retired

**Ruled:** the build emits the `servette/` package; the literate `.md`
sources remain the canonical authored form; the identity principle is
**readable in an afternoon** — what an auditor must understand, not file
count. How many modules the package contains is an implementation
detail. **Rejected:** dropping the literate layer (deletes the reading
experience #69 invests in); keeping single-file output as a constraint
(no reader left to serve). *(#77, 2026-08-15)*

## The name is Servette

**Ruled:** appropriate for public release. The `-ette` reads in the
object-diminutive register (kitchenette, diskette) — "the little
server"; no adverse meaning in English or French, no colliding software
product, the Geneva sports clubs are a different domain. PyPI
registration is deliberate and deferred to the first release.
*(#77, 2026-08-15)*

## macOS is session mode; Windows is a non-goal

**Ruled:** Linux with systemd is the production target. macOS runs
everything but service installation. **Rejected:** a launchd port — no
ambient-capability equivalent or systemd sandbox, so a macOS *service*
would run with a weaker posture than the Linux one; session mode keeps
the posture honest. **Reopen (Windows):** credible demand from operators
who cannot run Linux or macOS. *(#64)*

## The publish tool's custody constraints

**Ruled:** the page that handles the operator's signing key is
dependency-free (no third-party script), signing-only (every capability
reduces to "produce a signed artifact the operator chooses to pull"),
and stores nothing extractable — the key is per-session, held as a
non-extractable `CryptoKey`, with IndexedDB remembering opt-in only.
**Accepted residual:** a compromised page could misuse a remembered key
while open, never steal it. **Rejected:** the CDN allowance the other
site pages get; extractable key storage. *(#42)*

## The placeholder page is embedded — *superseded*

**Ruled:** setup seeded an empty site from a page embedded in the module —
no network, no release asset — and the `servette:demo` marker was the
ownership protocol: marked pages were Servette's to refresh, unmarked
pages never touched, deleting the marker adopted the page.
**Rejected:** fetching a demo page from GitHub at setup (network
dependency and a degradation path for the first moment of use) — still
rejected, and the reason still holds for anything embedded.
**Superseded** by [the diagnostic error
page](#the-default-error-page-diagnoses-the-placeholder-is-retired): the
placeholder and the marker protocol are deleted, and setup keeps its
never-finish-with-nothing-to-serve promise without writing a file. *(#70,
superseded 2026-08-16)*

## The transport is stdlib http.server, owned directly

**Ruled:** HTTP/1.1 from the standard library with Servette owning the
hardening an ASGI server would otherwise supply — TLS from
`ssl.SSLContext`, the handshake off the accept loop, per-connection
timeout, connection caps. **Rejected:** an ASGI server (the largest
dependency, serving capability a static site doesn't need). *(recorded
in DESIGN's design-decisions list; migrated here)*
