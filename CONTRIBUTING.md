# Contributing

Contributions are welcome — written by hand, written with an AI agent, or anywhere in between. Use whatever process produces good work; the bar is the same either way, and it's the code that's judged, not who or what typed it.

Three documents carry the detail this one points to: [`design.md`](design.md) is the developer's reference (how Servette works, what's in and out of scope, and how we work), [`AGENTS.md`](AGENTS.md) holds the operational mechanics (running, testing, committing), and the new-user introduction is [`README.md`](README.md).

## Working with AI

AI-assisted contributions are **first-class** here — nothing to hedge, hide, or apologize for. That openness works because it is paired with credit and responsibility, and because the project is built to verify code on its merits.

**Credit your collaborators.** If a commit contains substantial work from an agent, credit it as a co-author, the same way you would credit a person. The exact trailer is in [`AGENTS.md`](AGENTS.md#git-and-commits). Co-authorship is acknowledgment, not ownership: the agent is recorded in the project's contributor history, but copyright stays with the human author of record (see [`LICENSE`](LICENSE)).

**Own what you submit.** You — the human — are the author of record. Review and understand every change before you push or open a pull request, and stand behind what merges. "The agent wrote it" is a credit line, never an excuse. For a security tool this matters most exactly where it's tempting to skim: auth, TLS, rate limiting, and path resolution.

**Use the agent well.** Agents do their best work on bounded, well-described tasks, and this repository is structured to provide them — point the agent at [`design.md`](design.md) for the architecture, the scope, and the change loop. Treat "tests pass" as the start of your review, not the end: a test can encode the same misunderstanding as the code it checks.

## Scope comes first

Before proposing a feature, read [Scope & non-goals](design.md#scope--non-goals). Servette is a minimalist nanoserver held to a small set of non-negotiable principles, and most features common to other servers are *deliberately* absent — they serve no principle and are out of scope. A change earns its complexity only by serving a principle. If your idea is one of the documented non-goals, the honest answer is usually "use Caddy" — and that's not a brush-off, it's the design working as intended.

## Before you push

The verification bar and the full pre-push checklist live in [`AGENTS.md`](AGENTS.md#how-we-work-here). In short: one scoped change, a test that can fail, the suite green (and CodeQL clean for security-relevant work), and the docs updated in the same change. Prefer understatement — describe what a change is verified to do, not what you hope it does.
