# HANDOFF.md

Living status for the branch `claude/dreamy-heisenberg-akox2x` — where it stands, what was decided on it, and what to do next. This file is for picking the work up in another session; it is not a durable document and is deleted before the branch merges. Dates are 2026.

## What this branch is

It began on 2026-10-04 as a review of `claude/intelligent-faraday-bxqvtm`, a branch of four admin-page fixes and a first plan for Servette 2.0. The review became a working session: the Human (Andy) and the Agent closed, in conversation, the shape of 2.0 — what the server is, what the admin tool is, how extensions work, and which repositories hold what. Nothing of 2.0 is built. The branch carries ten commits over `main`, all pushed:

| Commit | Pass | What is now true |
| - | - | - |
| `c68d62a` | code | the admin page's live meter waits for each reading before asking again (no stacked requests over a slow tunnel) |
| `4f77c48` | code | the meter reads `/load`, just its figures, not the whole `/status` |
| `722e01a` | doc | docstrings name `/load` and say who polls what |
| `95a8146` | code | the CPU chart's span is read from its readings' clocks |
| `b9b6a5d` | doc | the first `DESIGN-V2.md` (since rewritten twice) |
| `7d9da3f` | code | the CPU line starts over after a gap the meter did not measure |
| `2878b35` | doc | `DESIGN.md` and the page's script map say what the meter reads; the plan says why its forks stay in it |
| `d193182` | doc | `CLAUDE.md` is `@AGENTS.md` and nothing else (one home per fact) |
| `b688023` | doc | `DESIGN-V2.md` rewritten around two products in two repositories |
| `90d91b8` | doc | `DESIGN-V2.md` is the plan's skeleton; each product's story is a README draft under `v2/` |

Evidence at the last commit: `python3 tests/test.py` — 1036/1036 without a browser, 1086/1086 with the preinstalled Chromium (`SERVETTE_TEST_BROWSER=/opt/pw-browsers/chromium-1194/chrome-linux/chrome`); `build.py --check`, `--check-counts`, `--check-docs` all OK.

Session conventions held so far: the Human is the author of record (`Andy Emerson <156483017+andy-emerson@users.noreply.github.com>`); the Agent is co-author by trailer (answered yes on 2026-10-04); each commit is a code pass or a doc pass; commit messages end with an `Evidence:` line.

## What was decided on this branch

Closed by the Human in conversation. Each is recorded in `DESIGN-V2.md` and the `v2/` drafts; none is yet in `DECISIONS.md`, which happens at merge.

1. **CLAUDE.md is the include alone.** Anything every agent needs lives in the repository's own documents; one home per fact.
2. **The open decisions of 2.0 stay in `DESIGN-V2.md`** until the Human confirms the move toward 2.0, expected after 1.x's release; then they become issues.
3. **`pipx install servette` delivers `servette.py` and nothing else.** The retired single-file principle was about config and backup files, not a licence to ship a suite through pipx.
4. **The admin tool is a desktop application, `servette-admin`,** on the operator's own computer: it holds the box list, opens the SSH connection with the operator's own key, drives the server's command line (`--json`), and shows the page on the computer's loopback. The server loses the loopback admin server and `src/admin.html`; `admin` leaves the command list once the app is proven. Rejected on the way: an extension fetched from GitHub; the page hosted on servette.org; a hash-pinned loader; a second module in the wheel; a `servette-admin` package injected into the venv; servette.org as a launcher with pairing; a zero-click `ssh` `Host` entry. The reasons are in `DESIGN-V2.md` under *Rejected on the way here*.
5. **The app's download is built in CI, released with checksum and provenance, signed; servette.org links, never serves it.** The Human's framing: `servette.py` protects the box, the app protects the app; sysadmins use PyPI and the CLI with no new surface, newcomers take the app and its stated extra risk.
6. **Extensions are compiled editions.** An extension is a verb, the hardening that verb requires, and the proof, compiled from the core's published sources plus its own literate files into one module. No runtime plugins; no third-party extensions. The core owes seams only: a verb table, a site kind, the config vocabulary, the suite. `OPTIONS` and CORS live in the core as seam machinery, once. An edition's version names the core it embeds.
7. **`servette-database` is the first extension:** `QUERY` (the IETF HTTP working group's draft method) for read-only embedded databases, engine-agnostic (SQLite first, DuckDB planned, TallyDB — the Human's own — a candidate). No SQL parser in the server, ever: the engine's own read-only mode, external-access switches, deadline, and a row cap are the hardening, proven by one four-refusal battery per engine. Visibility is decided at publish time (a private column is one you did not publish).
8. **The principle hierarchy.** *Simple and secure* at the root; one derived principle per product, as strong as its purpose allows; a lower principle licenses only what the purpose needs ("read-only" admits `QUERY`, not a query cache).
9. **The organization `servette` with four repositories:** `servette` (the server, PyPI name unchanged), `servette-database`, `servette-admin`, `servette-website` (the site moves out of `andy-emerson/websites`). READMEs for all four plus the organization profile are drafted under `v2/`. A GitHub Project is for cross-repository issue tracking later, not a substitute for the organization.

## Open, for the Human

- **Read the five drafts in `v2/`** for what they promise in your name. Each opens by saying nothing it describes is built.
- **The `v2/` folder's placement.** The Agent put other repositories' drafts in a folder, reading the no-docs-folder ruling as governing durable documents only. Say if you read it otherwise and the folder goes.
- **When to create the organization**: now, or after 1.x releases. The drafts are written to be each repository's first file.
- **The open decisions in `DESIGN-V2.md`**: what is core; the three seams exactly; privileged commands from the app (the app has no terminal for `sudo`'s prompt); the command-line contract (`--json` coverage, `publish` from a bundle); the app's technology and first packaging (Python on PyPI first, or a binary installer from the start); the database edition's ledger; the superseded rulings; the transport stays out.
- **Not on this branch's path but noted:** the tunnel slowness the original branch observed (round trips of 21–39 s to the admin page on the operator's box) was never root-caused; the page-side pile-up it exposed is fixed and pinned.

## What to do next, in order

1. Resume with the AGENTS.md open phase: ask the attribution question (last answer: yes) and the refresh question (not asked this branch), then report state from this file and the checks.
2. If the Human ends the branch: the merge-scale review — repo-wide code review, then documentation review with `DESIGN.md`, `DECISIONS.md`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md` all in scope. Expect `DECISIONS.md` to need the rulings above recorded, and `DESIGN.md`'s scope table "plugins" row to be rewritten as "no runtime plugins; extensions are compiled editions". Delete this file in that pass.
3. If the Human continues 2.0 work: nothing is scheduled until 1.x releases. The first build steps named in `DESIGN-V2.md` are the organization and repositories, then the command-line contract in this repository, then the seams and `OPTIONS`.

## How to run the checks

```bash
python3 src/build.py && python3 src/build.py --check && python3 src/build.py --check-counts && python3 src/build.py --check-docs
python3 tests/test.py                                   # 1036 checks without a browser
pip install playwright                                  # once; then the browser section runs too:
SERVETTE_TEST_BROWSER=/opt/pw-browsers/chromium-1194/chrome-linux/chrome python3 tests/test.py   # 1086
```
