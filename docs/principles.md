# Design Principles

The rules of engagement: what Servette is for, what it deliberately refuses to become, and the methodology that keeps it honest. This is the binding philosophy — read it before your first change; it is not background.

How the code is actually built lives in [`architecture.md`](architecture.md); the new-user introduction is [`README.md`](../README.md); the operating mechanics (running, testing, committing, releasing) are in [`AGENTS.md`](../AGENTS.md). Each of those is this philosophy in practice. A document that lags the code is the first step of the next over-claim — so updating these docs is a step *inside* a change, not an afterthought.

## Scope & non-goals

Servette is a **production nanoserver** — a production-ready layer for Python's standard-library `http.server`, turning the stdlib's development server into one fit for the open internet. Its identity is a small set of non-negotiable principles: invariants, not preferences — every design decision serves them, and a change that serves none of them is out of scope by definition. Treat them as the lens for the question "should this exist in Servette?"

| Principle | What it commits us to |
| - | - |
| **Single file** | All of Servette is one `servette.py`, readable and debuggable in an afternoon. No module sprawl, no hidden machinery. |
| **Secure by default** | Trusted TLS, HTTPS-only (HTTP 301s upward), security headers on every response, optional auth, rate limiting, a least-privilege service user. Security is the default state, never an opt-in. |
| **Production-grade** | Makes the stdlib's `http.server` — a development server, by its own docs — fit to serve real sites on the public internet: automatic certificate renewal, auto-restart, survives reboots. Servette is the production layer, not a dev tool. |
| **Zero-friction operation** | Copy one file, run it, follow the wizard. No configuration language, no manual certificate or dependency management. |
| **Minimal footprint** | The standard library — `http.server`, `ssl`, `urllib` — plus a single package, `cryptography`; the transport, TLS, and ACME client are all stdlib or hand-rolled. Nothing installed system-wide; light enough for a Raspberry Pi. |

**Minimalism is the default; the principles above are the only license to add complexity.** General-purpose servers accumulate features — reverse proxying, load balancing, plugins, templating, SPA routing, a live config API. None are needed to satisfy the principles, so each is feature creep: complexity that pulls Servette away from "single file" and "zero-friction" while serving no goal.

The decision rule for any proposed change: **complexity is earned only by serving a non-negotiable principle. Complexity justified solely by capability — "other servers do it" — is rejected.** When principles pull against each other (security features add code, in tension with minimalism), the principle wins over raw line count: HSTS, CSP, ACME, and the rate limiter all cost complexity and all earn it under "secure by default." That is the *only* permitted compromise to minimalism — another principle, never mere feature completeness.

The refusals below are not an exhaustive blocklist; they are the common cases, each an instance of the rule — a feature that serves no principle and is therefore out of scope.

| Out of scope | Why |
| - | - |
| **Dynamic content (`POST` → 405)** | A POST needs a destination — a database, an email, a file. Servette has none. A form's backend lives elsewhere. |
| **SPA deep-link rewriting** | Files are served as-is; `/about` 404s if no such file exists. Client-side routers (React Router, Vue Router) need path→`index.html` rewriting Servette does not do. Use hash routing (`/#/about`) or a platform with rewrite rules. |
| **Reverse proxy, load balancing, live config API** | The bulk of what general-purpose servers carry, serving no principle for a static site. Servette can sit *behind* a single trusted-proxy hop; it does not *become* one. |
| **Plugins, configuration language** | Settings are a handful of defaulted fields in `servette.toml`. Nothing to learn, nothing to extend — by design. |
| **Runtime dependencies beyond the managed venv** | Stdlib (Python 3.11+) plus a single package (`cryptography`) Servette installs into `.servette-env/` itself. The operator never runs pip. |

A request to add any of these is not a feature request; it is a request for a different program. The honest answer is usually to reach for a general-purpose server that does more.

## Status & the claim ladder

Servette is complete within its scope; "where are we?" is mostly "here is the finished shape, and here is what we claim about it." The standing claim is in the tagline — *secure* — and a claim may never sit above its evidence.

| Rung | Meaning | Evidence |
| - | - | - |
| **Stated** | asserted; no evidence yet | — |
| **Tested** | passes our own suite | `tests/test.py` green, server exercised on a real port |
| **Scanned** | clears automated static analysis | CodeQL workflow passing, no open alerts |
| **Reviewed** | a human has read the change for what it claims | code review / security review |

"Secure" is a Reviewed-rung claim and stays honest only while the rungs below it hold: the test suite passes, CodeQL is clean, and security-relevant changes get read. Prefer understatement — `_production_issues()` is the model: it lists what's wrong rather than implying everything's fine. The failure mode to guard against is never fabrication; it's a claim quietly one rung above its evidence ("tests pass" drifting into "secure").

## How we work

Servette is built in human–agent collaboration, and says so. The human holds design authority and is the author of record; the agent writes code and surfaces trade-offs. This works because openness is paired with verification and responsibility — credit is *earned by the rigor*, not granted by a trailer. Energy spent hiding how a security tool is built is the wrong kind of energy; it belongs in the evidence instead. (Mechanics of attribution live in [`AGENTS.md`](../AGENTS.md); the contributor's view in [`CONTRIBUTING.md`](CONTRIBUTING.md).)

The methodology is scaled to the project. A ~2,400-line finished server does not need a dependency frontier or a reference oracle; reproducing that machinery would itself be the scope creep this document exists to prevent. What ports is the principle, not the apparatus.

### The change loop

1. **Pick a scoped change.** One thing. If it argues for a non-goal above, stop — that's a different program.
2. **Make it with a test that can fail.** A bug fix ships in the same commit as the test that would have caught it. (A few areas are intentionally uncovered — see [`AGENTS.md`](../AGENTS.md#tests).)
3. **Run the bar.** `tests/test.py` green; CodeQL clean for security-relevant work; for anything touching auth, TLS, rate limiting, or path resolution, a human read.
4. **Update the docs in the same change.** [`README.md`](../README.md) for user-facing surface, [`architecture.md`](architecture.md) for how it's built, this file for scope or methodology, [`AGENTS.md`](../AGENTS.md) for operating detail. Docs that lag the code are the first step of the next over-claim. Before merging, reconcile the README, `architecture.md`, and this file against the code — names, thread lifecycle, defaults, section line counts.
5. **Open a pull request; merge after checks pass.** Work reaches `main` only through PRs — `main` is protected, and the test and CodeQL checks must be green to merge, which makes the bar in step 3 an enforced gate rather than a habit. Never touch `__version__` here; the version changes only when cutting a release ([`AGENTS.md`](../AGENTS.md#releasing-maintainer-task)). Commit and PR conventions are in [`AGENTS.md`](../AGENTS.md#git-and-commits).

### Audits

Re-ground trust periodically — `/code-review` and `/security-review` — assuming the next pass finds something rather than aiming for a clean one. The goal is an honest ledger, not a spotless report. Treat "tests pass" as the beginning of review, not the end: our own tests can encode the same misunderstanding as the code.
