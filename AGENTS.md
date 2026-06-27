# AGENTS.md

Operating instructions for any coding agent working in this repository. This is the master agent doc; tool-specific files (e.g. `CLAUDE.md`) defer to it so there is one source of truth.

Everything lives in one file, `servette.py` (Python 3.11+, stdlib plus four packages installed into `.servette-env/`). Settings persist to `servette.toml` beside it. The architecture, scope, and methodology live in [`design.md`](design.md); contributor-facing framing in [`CONTRIBUTING.md`](CONTRIBUTING.md). This file covers the operational mechanics: how we work, run, test, release, and commit.

## How we work here

Read [`design.md`](design.md#how-we-work) before your first change — its methodology is binding, not background. In operational terms:

- **One scoped change at a time.** If a change argues for one of the non-goals in `design.md`, stop and raise it — that's a different program, not a feature.
- **Write a test that can fail** alongside the change; a bug fix ships with the test that would have caught it.
- **Run the bar before calling anything done** — tests green, and CodeQL clean for security-relevant work (auth, TLS, rate limiting, path resolution).
- **Update the docs in the same change** — they're part of the work, not cleanup. A doc that lags the code is the first step of the next over-claim.
- **Prefer understatement.** Report what a change is *verified* to do, not what you hope it does. The recurring failure mode is a claim sitting one rung above its evidence (`design.md`'s claim ladder); the process exists to keep your claims honest.
- **Don't change an agreed plan on your own.** If a plan you and the human settled on hits a snag or new information, bring the revised plan back for approval before acting. An observation or aside from the human is not approval for a new plan.

## Running

```bash
sudo python3 servette.py          # interactive shell (bootstrap re-execs into the venv every time)
python3 servette.py --serve       # non-interactive service mode (used by systemd)
```

First run creates `.servette-env/` (a managed virtualenv), installs `hypercorn cryptography acme josepy` into it, then re-execs inside that environment. Subsequent runs skip straight to the re-exec. `sudo` is needed only for the interactive shell (it writes the systemd unit and calls `useradd`); the service itself runs as the restricted `servette` user.

## Tests

```bash
.servette-env/bin/python3 tests/test.py
```

Requires `openssl` on PATH (used only by test setup to generate a throwaway cert). The suite starts a real Hypercorn server on a test port, runs checks, and tears down. It backs up and restores any existing `servette.toml`.

Three areas are intentionally not covered: the interactive shell and its config commands, systemd integration, and Let's Encrypt cert issuance.

## Git and commits

Remote: `git@github.com:andy-emerson/servette.git`. Development happens on branches merged via pull request — never directly on `main`, which is protected (no direct pushes, no force-pushes, no deletion; the test and CodeQL checks must be green before a PR can merge). Batch a round of related work as separate commits on a single, generically-named branch (e.g. `work`, not `fix-headers`) with one PR — don't open a new branch per change.

**Close issues only on merge.** Reference the issue with `Closes #N` in the PR; it closes when the PR merges to `main`. Never close an issue before its fix has landed on `main`.

**Pushes and merges never touch `__version__`.** The version is a release concept, not a development one; it changes only as part of cutting a release (see below). Everyday work is version-agnostic.

**Commit messages** are an imperative one-line summary (e.g. `Raise default rate_limit from 30 to 120 requests/min`), with a short body when the change needs explaining. Don't enumerate tests or docs unless they are the point of the change.

**Attribution.** Credit yourself — whichever agent you are — as a co-author on every commit containing substantial agent work, the same way you'd credit a person, using your tooling's default trailer. For Claude that is:

```
Co-Authored-By: Claude <noreply@anthropic.com>
```

Other agents use their own identity, not Claude's. This is credit, not a disclaimer: it is paired with the responsibility and verification in [`design.md`](design.md#how-we-work), and the human remains the author of record.

## Releasing (maintainer task)

Servette updates itself from signed GitHub Releases, not from `main` — see [`design.md`](design.md#how-it-works) for the trust model. A release is the one and only place `__version__` changes; it never moves during ordinary development. Publishing requires the private signing key, so it is a maintainer task. Versions are date-based: `0.<yy>.<doy>` — two-digit year and day-of-year, e.g. `0.26.178`.

To publish (maintainer):

1. Bump `__version__` in `servette.py` via its own pull request, and merge it — the only change that ever touches the version.
2. Sign the file with the Ed25519 private key (gitignored):
   ```bash
   .servette-env/bin/python3 -c "
   from cryptography.hazmat.primitives.serialization import load_pem_private_key
   sig_key = load_pem_private_key(open('servette_signing.pem','rb').read(), password=None)
   open('servette.py.sig','wb').write(sig_key.sign(open('servette.py','rb').read()))
   print('Signed.')
   "
   ```
3. Create a GitHub release tagged with the version (e.g. `0.26.176`).
4. Attach `servette.py` and `servette.py.sig` as release assets.
5. Delete `servette.py.sig` locally — it's per-release, not a permanent artifact.

The pinned public key is `_SIGNING_PUBLIC_KEY` in `servette.py`. The private key (`servette_signing.pem`) and all `*.sig` files are gitignored and must never be committed.
