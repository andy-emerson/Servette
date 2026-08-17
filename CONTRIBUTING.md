# Contributing

Contributions are welcome — written by hand, written with an AI agent, or
anywhere in between. The bar is the same either way: the code is judged,
not who or what typed it. Three things to know before you push:

- **The module is generated.** Never hand-edit (or commit) `servette.py`.
  Edit the Markdown sources under `src/`, run `python3 src/build.py`, and
  commit both; `python3 src/build.py --check` (which CI also runs) fails
  the build on drift. See [Building](DESIGN.md#building).
- **The bar.** One scoped change, a test that can fail, the suite green
  (and CodeQL clean for security-relevant work), docs updated in the same
  branch as their own doc-pass commit. Scope questions are settled by
  [Scope & non-goals](DESIGN.md#scope--non-goals): most features other
  servers carry are *deliberately* absent, and a change earns its
  complexity only by serving one of the stated principles.
- **AI work is first-class — credited and owned.** Credit an agent's
  substantial work with a co-author trailer (format in
  [`AGENTS.md`](AGENTS.md)). You, the human, remain the author of record:
  review and stand behind every line, most carefully exactly where it's
  tempting to skim — auth, TLS, rate limiting, path resolution.

[`DESIGN.md`](DESIGN.md) holds how Servette is built, run, and released;
[`AGENTS.md`](AGENTS.md) the working agreement; [`README.md`](README.md)
the user-facing introduction.
