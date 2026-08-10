# Contributing

Contributions are welcome — written by hand, written with an AI agent, or anywhere in between. Use whatever process produces good work; the bar is the same either way, and it's the code that's judged, not who or what typed it.

The detail this one points to lives in a few places: [`DESIGN.md`](DESIGN.md) holds the scope, the non-goals, the verification bar, and how Servette is built, run, and released; [`AGENTS.md`](AGENTS.md) holds the human–agent working agreement (roles, the commit loop, reviews); and the new-user introduction is [`README.md`](README.md).

## Working with AI

AI-assisted contributions are **first-class** here — nothing to hedge, hide, or apologize for. That openness works because it is paired with credit and responsibility, and because the project is built to verify code on its merits.

**Credit your collaborators.** If a commit contains substantial work from an agent, credit it as a co-author, the same way you would credit a person. The exact trailer is in [`AGENTS.md`](AGENTS.md). Co-authorship is acknowledgment, not ownership: the agent is recorded in the project's contributor history, but copyright stays with the human author of record (see [`LICENSE`](LICENSE)).

**Own what you submit.** You — the human — are the author of record. Review and understand every change before you push or open a pull request, and stand behind what merges. "The agent wrote it" is a credit line, never an excuse. For a security tool this matters most exactly where it's tempting to skim: auth, TLS, rate limiting, and path resolution.

**Use the agent well.** Agents do their best work on bounded, well-described tasks, and this repository is structured to provide them — point the agent at [`DESIGN.md`](DESIGN.md) for the scope and how it's built, and [`AGENTS.md`](AGENTS.md) for the change loop. Treat "tests pass" as the start of your review, not the end: a test can encode the same misunderstanding as the code it checks.

## Scope comes first

Before proposing a feature, read [Scope & non-goals](DESIGN.md#scope--non-goals). Servette is a production nanoserver — a production-ready layer over Python's standard-library `http.server` — held to a small set of non-negotiable principles, and most features common to other servers are *deliberately* absent — they serve no principle and are out of scope. A change earns its complexity only by serving a principle. If your idea is one of the documented non-goals, the honest answer is usually to reach for a general-purpose server that does more — and that's not a brush-off, it's the design working as intended.

## Before you push

The verification bar lives in [`DESIGN.md`](DESIGN.md#verification-bar); the commit discipline lives in [`AGENTS.md`](AGENTS.md). In short: one scoped change, a test that can fail, the suite green (and CodeQL clean for security-relevant work), and the docs updated in the same change. Prefer understatement — describe what a change is verified to do, not what you hope it does.

One mechanic worth calling out: `servette.py` is generated. Edit the Markdown sources under `src/`, run `python3 src/build.py`, and commit both — never hand-edit `servette.py`. Run `python3 src/build.py --check` to catch a mismatch before you push; CI runs the same check and fails the build on drift. See [Building](DESIGN.md#building).
