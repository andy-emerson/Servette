# Decisions

The closed rulings: what was decided, what was rejected, and what would
reopen each. This file is the canonical in-repo record; the linked issues
hold the deliberation, and [`DESIGN.md`](DESIGN.md) describes what is
built as a result. Entries are compact and present-tense; newest first.
Only the Human closes a decision ([`AGENTS.md`](AGENTS.md)).

## The self-test is server-delivered, client-executed

**Ruled:** the connection self-test ships embedded in the module and is
served at the reserved path `/selftest/` wherever the operator's content
doesn't shadow it. Execution stays in the visitor's browser — only an
outside client sees the browser-trusted cert chain, the real network
path, and the provider firewall. **Rejected:** server-side execution (a
server cannot see itself from outside; `_production_issues()` is already
the inside half); the prior bundle-injected copy (superseded from #42 —
it required a deliberately duplicated page and a network fetch in the
publish tool). *(#79, 2026-08-16)*

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

## The placeholder page is embedded

**Ruled:** setup seeds an empty site from a page embedded in the module —
no network, no release asset — and the `servette:demo` marker is the
ownership protocol: marked pages are Servette's to refresh, unmarked
pages are never touched, deleting the marker adopts the page.
**Rejected:** fetching a demo page from GitHub at setup (network
dependency and a degradation path for the first moment of use). *(#70)*

## The transport is stdlib http.server, owned directly

**Ruled:** HTTP/1.1 from the standard library with Servette owning the
hardening an ASGI server would otherwise supply — TLS from
`ssl.SSLContext`, the handshake off the accept loop, per-connection
timeout, connection caps. **Rejected:** an ASGI server (the largest
dependency, serving capability a static site doesn't need). *(recorded
in DESIGN's design-decisions list; migrated here)*
