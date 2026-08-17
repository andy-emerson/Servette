# Decisions

The closed rulings: what was decided, what was rejected, and what would
reopen each. This file is the canonical in-repo record; the linked issues
hold the deliberation, and [`DESIGN.md`](DESIGN.md) describes what is
built as a result. Entries are compact and present-tense; newest first.
Only the Human closes a decision ([`AGENTS.md`](AGENTS.md)).

## Servette asks for root; the operator never types sudo

**Ruled:** privileged commands elevate themselves. `run_command` re-runs the
command as `sudo <sys.executable> -m servette <cmd>` and returns to the prompt;
read-only commands (`status`, `sites`, `log`) stay unprivileged and never
prompt, unless the config is unreadable, when reporting stand-in defaults as the
operator's settings would be a lie.
**Why:** `sudo servette` forced the console script onto sudo's `secure_path`,
which forced the install to put it there — a symlink and a system-wide location,
two of the three lines the install needed. An absolute `sys.executable` needs
neither: sudo resolves it without consulting `PATH`.
**Consequences accepted:** `SERVETTE_HOME` is passed through explicitly, since
sudo resets the environment and losing it would silently point the elevated run
at another data directory. `start` and `stop` elevate only on the systemd path —
a session server lives in the shell's own process, where an elevated child could
neither outlive its own exit nor reach the parent's. The one-shot form exits with
sudo's status so tooling sees a refused password as a failure.
**Rejected:** requiring `sudo` in front of every invocation (the status quo, and
the cause of the install's shape); a setuid helper (a second privileged surface
to audit, for a program whose whole claim is that you can read it).
*(2026-08-17)*

## The service's runtime lives where the service user can read it

**Ruled:** `enable` measures whether the `servette` user can reach the installed
program. Where it cannot, `enable` copies the program and its dependency closure
into `RUNTIME_DIR` under the data directory — root-owned, world-readable, pinned
`ReadOnlyPaths` by the unit — and names that copy in `ExecStart`. `disable`
removes it, and so does an install the service *can* reach.
**Why:** a per-user install, which is what `pip install --user` and pipx
produce, sits under a home directory Debian and Ubuntu create mode 0750. The
service user cannot traverse it, so the unit restart-loops on
`ModuleNotFoundError` after the next reboot — invisible at install time, and the
exact failure Servette exists to prevent (#98).
**What is copied is read from metadata, not from a list here:** a list said
"cryptography" and produced a runtime that could not import it, because
cryptography declares cffi, cffi declares pycparser, and cffi's compiled backend
is a bare `.so` that only its `top_level.txt` names. A checkout has no dist-info
to read, so there the walk seeds from what `pyproject.toml` declares, and the
suite fails if those two lists disagree.
**The inference is executed, not trusted:** before any unit reaches disk,
`_verify_runtime` imports the program and the certificate machinery from the
paths the unit names, as the service user. A failure refuses the write. Every
other part of this ruling is inference about another user's view of a
filesystem, which is the kind of thing that is wrong quietly.
**Rejected:** granting the service user traverse into the operator's home (one
`chmod o+x`, but it weakens a distro default for every local account, against a
stated principle of never setting world bits); documenting a root-owned install
location instead (no code at all, but it puts `sudo` back in the install line,
and `pipx --global` is missing from the pipx Ubuntu 24.04 ships).
**Cost stated plainly:** 315 lines, to keep the install one line. Dropping the
per-user install path would delete all of them.
**Reopen if:** the distributions Servette targets stop creating home directories
unreadable to other accounts, which would make the copy dead weight.
*(#98, 2026-08-17)*

## The error page is inlined, not shipped as a file

**Ruled:** the page is authored as `src/404.html` — real HTML, editable
and openable in a browser — and `build.py` inlines it into the module at build
time. The installed package is Python only: `__init__.py` and `__main__.py`.
**Why:** as package data it was a file an operator could delete, and deleting
it took the default 404 body with it silently — the server would go back to
answering ten bytes of `Not found.` with nothing to say why. A page that is
part of the module cannot be removed without removing the program.
**Rejected:** a Python string literal as the authored form (23 KB of HTML with
every quote escaped, no highlighting, unopenable in a browser) — the
precedent, the deleted placeholder page, showed why that reads badly; and
leaving it as package data with documentation asking operators not to delete
it. **Accounting:** the 576 lines of markup are reported separately by
`build.py --counts`, not folded into the Python figures. The counts back a
claim about reading the *program*; markup the program ships is not markup an
auditor reads to understand it. Stating that split openly is the point —
quietly absorbing 576 lines into "readable in an afternoon" would inflate the
claim. *(2026-08-17)*

## `pip install servette` is the only installation path

**Ruled:** there is one way to install Servette, and every other way is
removed rather than merely discouraged. The documented install is
`pip install servette`; nothing in the repository or its documents describes,
supports, or enables another. **Removed:** the
`git+https://` install and update commands from README; the `pipx`
alternative; and the website, which by living here let a checkout serve
servette.org and so kept clone-and-run alive as the shortest path
([above](#the-website-lives-in-its-own-repository)). **Not enforced in the
server:** an attempt to gate `enable` on the package sitting in
`site-packages` was made and reverted. Running as a supervised service that
survives reboots is one of the five principles — a core function of the
program — and a core function does not answer to a packaging question. The
scope of this ruling is what the project *offers and documents*, not a
capability withheld from a running server. Distribution is closed by having
one documented channel, not by crippling systemd. **Why so absolute:** a
second install path is a second thing to document, test, and support, and the
cheap one gets suggested — repeatedly — precisely because it exists. A
capability that is only discouraged is a capability. **Consequence accepted:**
until the first PyPI release the documented command does not work, and no
fallback is offered in its place. That is the point: the gap is visible
pressure to publish rather than a path that quietly substitutes for it.
**Reopen:** an operator population that genuinely cannot reach PyPI — in which
case the answer is a decided, documented second channel, not the return of an
undocumented one. *(2026-08-17)*

## The website lives in its own repository

**Ruled:** Servette's website moves to
[andy-emerson/websites](https://github.com/andy-emerson/websites) as
`servette.org/`, one directory per hostname, and leaves this repository. The
program repository holds the program. **Why:** while the site sat here as
`site/`, a checkout could serve it under `SERVETTE_HOME=.`, so "clone the
program and serve its own folder" was the shortest path to deploying
servette.org — which put this git repository inside the site's deployment
story and made installing-from-git a standing suggestion. Servette installs
from PyPI. Separation removes the shortcut instead of relying on anyone
declining to take it. **Moved with it:** the front page, the source viewer,
the publish tool, and the viewer's end-to-end harness (kept outside
`servette.org/`, since anything under a hostname directory is served
content). **Stayed:** the diagnostic page, which ships inside the
package because every install serves it. **Costs accepted:** the *exact* per-section
counts the site publishes can no longer be gated from here — the claim and its
source are in different repositories, so `build.py --counts` prints them and
nothing checks the page carries them. `--check-counts` survives, aimed at the
figures this repository still states about itself. And the viewer harness now
needs `SERVETTE_SRC` pointing at a checkout of this repository, so neither
repository tests that page alone. *(2026-08-17)*

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

## The error page is server-delivered, client-executed

**Ruled:** the page ships embedded in the module and is served as the default
404 body wherever the operator has written no `404.html`. Execution stays in the
visitor's browser — only an outside client sees the browser-trusted cert chain,
the real network path, and the provider firewall.
**Rejected:** server-side execution (a server cannot see itself from outside;
`_production_issues()` is already the inside half); the prior bundle-injected
copy (superseded from #42 — it required a deliberately duplicated page and a
network fetch in the publish tool). **Superseded within this ruling:** a second
role at a reserved `/selftest/` path answering 200, retired below.
*(#79, 2026-08-16; narrowed 2026-08-17)*

## The page has one role: there is no reserved path

**Ruled:** the page is Servette's 404 body and nothing else. `/selftest/` is an
ordinary path that 404s like any other, and no directory in a site root shadows
a reserved name.
**Why:** what the 200 role bought was one URL that answered 200 on an install
with nothing published yet. Everything else it did, a missing path already did —
the same page, the same checks, the same trusted padlock, at 404. That did not
pay for a reserved path, a status-code exception in the handler, a role branch
in the page, an override directory, and two names for one thing. Renaming the
file from selftest.html to diagnostics.html had made the naming worse rather
than better: "diagnostic" and "self-test" are synonyms, so the rename bought no
clarity while leaving 143 references pointing at the other name. One role means
one name, and it is the one every web server already uses.
**What is lost, stated plainly:** an operator with nothing published has no URL
on their own site that answers 200, and no monitor-friendly endpoint. That
follows from the status-code principle above rather than working against it: a
site with nothing published has nothing to serve.
**Rejected:** keeping the 200 role and giving it a user-facing name (`/status/`,
pairing with the shell's `status`) — coherent, but it keeps a reserved path and
a second framing to buy a convenience a missing path already provides.
**Reopen if:** operators are found routinely wanting a 200 health endpoint on a
site with no content, in which case it returns as one named thing, not as a
second role for this page. *(2026-08-17)*

## site/pub/ is the operator tools page — *moved*

**Ruled:** one bookmarkable home for operator services — the publish
tool, the self-test explanation and link, the documented CLI loop. Its
ceiling is a security boundary: it hosts, ships, links, and explains,
and never reaches into a live server (no network admin API) or probes
another origin. `servette sign` (client-side signing verb in the pip
package) is **open**, not ruled. The page itself now lives at
`servette.org/pub/` in the websites repository; the ceiling above is a
property of the page and travelled with it. *(#79, 2026-08-16; moved
2026-08-17)*

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

**Ruled:** the website's folder READMEs are gone. The layout principle
lives with the site itself, and the publish tool's load-bearing
constraints live in that page's own header comment, where an editor of
the page reads them. Both files, and the pages they described, are now in
the websites repository. **Rejected:**
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
