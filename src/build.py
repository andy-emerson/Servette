#!/usr/bin/env python3
"""Build servette.py from the Markdown sources in this directory.

The module is authored as five literate Markdown files — INIT.md, SERVER.md,
SYSTEM.md, SHELL.md, MAIN.md. Each interleaves three things:

  * fenced ```python blocks — the code, emitted verbatim;
  * blockquotes (`> ...`) — the module's own comment prose, lifted out of the
    code so it reads as prose; each `> ` maps back to a `# ` comment line
    (and a bare `>` back to a bare `#`);
  * everything else — headings, section intros — which is navigation for the
    reader and produces nothing.

This tool reverses that mapping, in file order, to produce the module. Every
output line comes from a code fence, a blockquote, or the one substitution
below: `404.html` is inlined where the sources name it, so the
page ships inside the module instead of beside it. The blockquote/comment
mapping is an exact inverse of the split that created these files, and the
substitution is verbatim, so the build is deterministic.

The generated module is not committed. The package build generates it: pip and
`python -m build` call src/_literate_backend.py (the PEP 517 backend named in
pyproject.toml), which runs build() here and hands the result to setuptools —
so installing from source IS the literate build, with no separate step to
forget. The test suite generates it the same way before importing it.

Usage:
    python build.py                 # write ../servette.py
    python build.py --output PATH   # write somewhere else
    python build.py --stdout        # write to stdout
    python build.py --check         # build in memory and compile; exit 1 if
                                     # the sources do not assemble into a
                                     # valid module
    python build.py --counts        # lines per section, for the website
    python build.py --check-counts  # exit 1 if README's line counts are stale
    python build.py --check-docs    # exit 1 if the docs name something that
                                     # does not exist: a path, an identifier, a
                                     # flag, a command, or a link target
"""

import argparse
import subprocess
import os
import re
import sys

# The sources, in the order they concatenate into the module. MAIN.md is last
# because the entry point it holds — `config = Config()` and the `__main__`
# dispatch — runs on import and calls definitions from every section above it.
SECTION_FILES = ["INIT.md", "SERVER.md", "SYSTEM.md", "SHELL.md", "MAIN.md"]

# The default 404 body is authored as real HTML — editable, highlighted, openable
# in a browser — and inlined into the module at build time, so the shipped
# package is Python only. An operator cannot delete a page that is not a file,
# and the error body cannot go missing with it.
NOT_FOUND_SOURCE = "404.html"
_NOT_FOUND_MARKER = "@@NOT_FOUND_HTML@@"

_FENCE_OPEN  = "```python"
_FENCE_CLOSE = "```"


def _blockquote_to_comment(line):
    """Turn one blockquote line back into the comment line it came from.

    `> text` -> `# text`, and a bare `>` -> a bare `#`. Exactly one space
    after the marker is consumed, mirroring the one space the split inserts,
    so indentation inside a comment round-trips."""
    body = line.rstrip("\n")
    keep = line[len(body):]          # the trailing newline, if any
    body = body[1:]                  # drop the leading '>'
    if body.startswith(" "):
        body = body[1:]              # drop the single marker space
    return ("#" if body == "" else "# " + body) + keep


def md_to_code(md_text, filename):
    """Reconstruct the section's Python source from one Markdown file.

    A line inside a ```python fence is code (verbatim). A line beginning with
    `>` outside a fence is a comment. Any other out-of-fence line — heading,
    intro, blank — is navigation and is dropped. Raises on an unterminated
    fence so a malformed source fails loudly."""
    out = []
    in_fence = False
    for line in md_text.splitlines(keepends=True):
        if in_fence:
            if line.strip() == _FENCE_CLOSE:
                in_fence = False
            else:
                out.append(line)
        elif line.strip() == _FENCE_OPEN:
            in_fence = True
        elif line.startswith(">"):
            out.append(_blockquote_to_comment(line))
        # else: heading / intro / blank — navigation, produces nothing.
    if in_fence:
        raise ValueError(f"{filename}: unterminated ```python block")
    return "".join(out)


def build(src_dir):
    """Concatenate the reconstructed sections, then inline the 404 page.

    The substitution happens here and not in md_to_code, so the per-section
    line counts stay a measure of the program rather than of an embedded
    asset."""
    parts = []
    for name in SECTION_FILES:
        with open(os.path.join(src_dir, name), "r", encoding="utf-8") as f:
            parts.append(md_to_code(f.read(), name))
    out = "".join(parts)

    with open(os.path.join(src_dir, NOT_FOUND_SOURCE), "r", encoding="utf-8") as f:
        html = f.read()
    # The page lands inside a triple-quoted literal. A `"""` in the HTML would
    # close it early and a backslash would be read as an escape, so both fail
    # the build rather than producing a module that is subtly not the page.
    if '"""' in html:
        raise ValueError(f"{NOT_FOUND_SOURCE}: contains \"\"\", which would end the literal")
    if "\\" in html:
        raise ValueError(f"{NOT_FOUND_SOURCE}: contains a backslash, which the literal would escape")
    if out.count(_NOT_FOUND_MARKER) != 1:
        raise ValueError(f"expected exactly one {_NOT_FOUND_MARKER} in the sources, "
                         f"found {out.count(_NOT_FOUND_MARKER)}")
    return out.replace(_NOT_FOUND_MARKER, html)


def section_counts(src_dir):
    """Lines per section, as (name, total, code) plus a ("Total", …) row.

    `code` counts lines that are neither blank nor comment-only. These are the
    numbers the website publishes to back its "readable in an afternoon"
    claim, computed the one way, here, so the page and the program cannot
    disagree about them."""
    rows, tot, tot_code = [], 0, 0
    for name in SECTION_FILES:
        with open(os.path.join(src_dir, name), "r", encoding="utf-8") as f:
            lines = md_to_code(f.read(), name).split("\n")
        if lines and lines[-1] == "":
            lines.pop()                     # trailing newline, not a line
        code = sum(1 for l in lines if l.strip() and not l.strip().startswith("#"))
        rows.append((name[:-3].capitalize(), len(lines), code))
        tot += len(lines)
        tot_code += code
    rows.append(("Total", tot, tot_code))
    return rows


def not_found_lines(src_dir):
    """Lines in the authored 404 page.

    Reported apart from the section counts, not folded into them. The counts
    back a claim about reading the *program*; an embedded HTML page is shipped
    by it, not read as part of it, and burying 630 lines of markup inside the
    Python figure would overstate what an auditor has to work through."""
    with open(os.path.join(src_dir, NOT_FOUND_SOURCE), "r", encoding="utf-8") as f:
        return len(f.read().splitlines())


# Where this repository states its own size, and how to find it. Each entry is
# a (label, regex) whose one capture group is the figure as published. These are
# approximate by design — "~3,900 lines" — so the check is that each rounds to
# the real total, not that it equals it.
#
# The website publishes exact per-section counts and lives in another repository
# now, so those cannot be gated from here; --counts prints them for whoever
# edits that page. What CAN be gated is every claim this repository makes about
# itself, which is what the drift was: a number asserted long after it stopped
# being true.
_README_CLAIMS = [
    ("comparison table", r"\| Readable source \| ~([\d,]+) lines \|"),
    ("who-is-it-for prose", r"one readable module \(~([\d,]+) lines of Python"),
]


def check_readme_counts(src_dir, repo_dir):
    """Verify every line-count figure README states about Servette.

    Rounded to the nearest hundred, matching how the README writes them. A
    reworded sentence fails as loudly as a stale number: moving a claim should
    make someone re-check it rather than drop it out of the gate's view."""
    total = dict((n, t) for n, t, _ in section_counts(src_dir))["Total"]
    expected = round(total / 100) * 100

    path = os.path.join(repo_dir, "README.md")
    try:
        with open(path, "r", encoding="utf-8") as f:
            readme = f.read()
    except OSError as e:
        print(f"count check failed: cannot read {path}: {e}", file=sys.stderr)
        return 1

    problems = []
    for label, pattern in _README_CLAIMS:
        m = re.search(pattern, readme)
        if m is None:
            problems.append(f"  {label}: claim not found "
                            f"(expected ~{expected:,} — was the sentence rewritten?)")
        elif int(m.group(1).replace(",", "")) != expected:
            problems.append(f"  {label}: README says ~{m.group(1)}, "
                            f"src/ is {total:,} which rounds to ~{expected:,}")

    if problems:
        print("STALE COUNTS: README.md disagrees with src/.", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"OK: README's ~{expected:,} lines matches the build of src/ ({total:,}).")
    return 0


# Which documents this checks. AGENTS.md is absent deliberately: it is an
# upstream file replaced whole, not edited here, so a name it uses is not this
# repository's to fix.
_DOC_FILES = ["README.md", "DESIGN.md", "DECISIONS.md", "CONTRIBUTING.md",
              "SECURITY.md", "CLAUDE.md"]

# Backticked names that are real but do not resolve here, each with the reason.
# This list is where the check stays honest: an entry is a claim that something
# is unresolvable ON PURPOSE, so adding one should feel like a decision. Growing
# it to silence a genuine miss is how a gate becomes decoration.
_DOC_ALLOWLIST = {
    # Files that live on an operator's server, not in this repository.
    # 404.html is listed even though src/404.html happens to be tracked: the
    # documents' mentions mean the OPERATOR'S override file, and this entry
    # keeps them passing if the source file is ever renamed again.
    "404.html":      "the operator's own error page, in their site folder",
    "index.html":    "the operator's home page",
    "servette.toml": "written at runtime into the data directory",
    "cert.pem":      "written at runtime into the data directory",
    "key.pem":       "written at runtime into the data directory",
    # Things named for comparison, which are other projects.
    "bottle.py":     "a peer project named in the comparison table",
    # Names belonging to the websites repository, which reads this one.
    "SERVETTE_SRC":  "an env var the websites repo's harness sets, not ours",
    # Metadata inside installed wheels, read via importlib.metadata. Caught by
    # the tracked-files check the moment it landed: this name had been passing
    # only because untracked egg-info litter at the repo root contained one.
    "top_level.txt": "a wheel's own metadata, not a repository file",
    # The program itself: generated by the package build, deliberately not
    # committed — the literate sources in src/ are the tracked form.
    "servette.py":   "the module the build emits; src/ is what is tracked",
}

_IDENT_RE = re.compile(r"^_?[A-Za-z][A-Za-z0-9_]*(\(\))?$")
_PATH_RE  = re.compile(r"^[A-Za-z0-9_./-]+\.(py|md|html|toml|yml|yaml|txt|cfg|pem)$")
_FLAG_RE  = re.compile(r"^--[a-z][a-z0-9-]*$")


def _prose_only(md_text, drop_blockquotes=False):
    """The document minus its fenced code blocks. Code inside a fence is the
    thing being documented, not a claim about it, so a stale name there is the
    build's problem and not this check's. Blockquotes are dropped for src/*.md,
    where they are the module's own comments — code by another spelling."""
    out, in_fence = [], False
    for line in md_text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if drop_blockquotes and line.startswith(">"):
            continue
        out.append(line)
    return "\n".join(out)


def token_problem(token, doc_name, repo_dir, haystack):
    """What is wrong with one backticked name, or None if nothing is.

    Only three shapes are judged — a path with a source extension, a `--flag`,
    and an identifier carrying an underscore or parentheses. Everything else in
    backticks is prose, a header name, a TOML key, a shell word: unjudgeable
    without understanding the sentence, and guessing produces the false
    positives that get a check switched off. An acronym like `HSTS` is why
    identifiers must carry an underscore or parens to be judged at all."""
    if token in _DOC_ALLOWLIST:
        return None
    # Absolute and home-relative paths are runtime locations on a server, not
    # files here.
    if token.startswith(("/", "~", "http://", "https://")):
        return None

    if _PATH_RE.match(token):
        if not _resolves(token, doc_name, repo_dir):
            return "no such file in the repository"
        return None

    if _FLAG_RE.match(token):
        return None if token in haystack else "no tool accepts that flag"

    if _IDENT_RE.match(token) and ("_" in token or token.endswith("()")):
        bare = token[:-2] if token.endswith("()") else token
        if bare not in haystack:
            return "not in the program, the build, or the suite"
    return None


def _command_names(module, list_name):
    """The command names in one of the shell's command lists — the name only,
    with any argument spec dropped, since `log [n]` is the command `log`."""
    m = re.search(rf"^{list_name} = \[(.*?)^\]", module, re.M | re.S)
    if not m:
        return set()
    return {entry.split()[0]
            for entry in re.findall(r'\("([^"]+)"', m.group(1))}


_TRACKED_CACHE = {}


def _tracked_files(repo_dir):
    """The repository's tracked paths, or None outside a usable git checkout.

    Resolving against the working tree let a stale doc name pass because the
    right-named LITTER existed — the suite runs with SERVETTE_HOME set to the
    repository, so a servette.toml and certs materialize at the root on every
    run. What a document claims exists should be judged against what the
    repository ships, which is what git tracks."""
    if repo_dir not in _TRACKED_CACHE:
        try:
            out = subprocess.run(["git", "-C", repo_dir, "ls-files"],
                                 capture_output=True, text=True, timeout=15)
            _TRACKED_CACHE[repo_dir] = (set(out.stdout.splitlines())
                                        if out.returncode == 0 and out.stdout else None)
        except (OSError, subprocess.SubprocessError):
            _TRACKED_CACHE[repo_dir] = None
    return _TRACKED_CACHE[repo_dir]


def _resolves(token, doc_name, repo_dir):
    """Whether a path a document names is a file in this repository.

    Three readings, in the order a human would try them: relative to the
    document doing the naming (src/SHELL.md saying `build.py` means the one
    beside it), relative to the repository root, and finally as a bare basename
    — docs legitimately call the module `__init__.py` without spelling out
    servette/. The last reading is the loosest, which is the point: this check
    exists to catch a name for something that no longer exists anywhere, not to
    police how precisely a sentence spells a path.

    Judged against git's tracked files where there is a checkout to ask, the
    filesystem otherwise (a tarball, a stripped CI workspace)."""
    tracked = _tracked_files(repo_dir)
    doc_dir_rel = os.path.dirname(doc_name)
    if tracked is not None:
        candidates = {os.path.normpath(os.path.join(doc_dir_rel, token)),
                      os.path.normpath(token)}
        if candidates & tracked:
            return True
        if "/" not in token:
            return any(f.rsplit("/", 1)[-1] == token for f in tracked)
        return False
    doc_dir = os.path.dirname(os.path.join(repo_dir, doc_name))
    for base in (doc_dir, repo_dir):
        if os.path.exists(os.path.join(base, token)):
            return True
    if "/" not in token:
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs
                       if d not in (".git", "node_modules", ".venv", "build")]
            if token in files:
                return True
    return False


def _slug(heading):
    """A heading as GitHub anchors it: lowercased, punctuation dropped, then one
    hyphen per space — not per RUN of spaces, which is why "Scope & non-goals"
    anchors as scope--non-goals with the ampersand's gap preserved. Duplicate
    headings (GitHub appends -1, -2) are not modelled; this resolves the
    first."""
    text = heading.strip().lstrip("#").strip()
    text = re.sub(r"`|\*|_", "", text)
    text = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return text.replace(" ", "-")


def _anchors(md_text):
    return {_slug(l) for l in md_text.splitlines() if l.startswith("#")}


def check_docs(src_dir, repo_dir):
    """Verify that every name the documents state can be resolved.

    Five questions, each mechanical, because a check with false positives gets
    switched off and then gates nothing:

      1. a relative path in backticks exists in the repository;
      2. an identifier in backticks appears in the program, the build, or the
         suite;
      3. a `--flag` in backticks is one the tools accept;
      4. every command README documents exists in the shell's own command
         lists, and every command those lists hold is documented;
      5. every internal link resolves, anchor included.

    What it cannot check is whether a true sentence is the right sentence:
    prose that misdescribes working code reads the same to a regex. That limit
    is the reason DESIGN's verification bar names review as well as gates."""
    problems = []

    module = build(src_dir)
    haystack = module
    for extra in (os.path.join(src_dir, "build.py"),
                  os.path.join(repo_dir, "tests", "test.py")):
        try:
            with open(extra, "r", encoding="utf-8") as f:
                haystack += f.read()
        except OSError:
            pass

    docs = {}
    for name in _DOC_FILES:
        try:
            with open(os.path.join(repo_dir, name), "r", encoding="utf-8") as f:
                docs[name] = f.read()
        except OSError:
            continue
    for name in SECTION_FILES:
        with open(os.path.join(src_dir, name), "r", encoding="utf-8") as f:
            docs["src/" + name] = f.read()

    for name, raw in docs.items():
        prose = _prose_only(raw, drop_blockquotes=name.startswith("src/"))

        for token in re.findall(r"`([^`\n]+)`", prose):
            bad = token_problem(token, name, repo_dir, haystack)
            if bad:
                problems.append(f"  {name}: `{token}` — {bad}")

        for text, target in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", prose):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            path, _, anchor = target.partition("#")
            if path:
                if not _resolves(path, name, repo_dir):
                    problems.append(f"  {name}: link [{text}]({target}) — no such file")
                    continue
                full = os.path.join(os.path.dirname(os.path.join(repo_dir, name)), path)
                if anchor and path.endswith(".md") and os.path.exists(full):
                    with open(full, "r", encoding="utf-8") as f:
                        if _slug(anchor) not in _anchors(f.read()):
                            problems.append(f"  {name}: link [{text}]({target}) — "
                                            f"no heading anchors to #{anchor}")
            elif anchor and _slug(anchor) not in _anchors(raw):
                problems.append(f"  {name}: link [{text}]({target}) — "
                                f"no heading in this file anchors to #{anchor}")

    # README's command table is the most-read thing in the repository, and
    # _COMMANDS is the only authority on what the shell answers to. Drift either
    # way is a documented command that does nothing, or a real one nobody is
    # told about. Both sides are read as command NAMES with their argument specs
    # stripped, so `status [--json]` and ("status [--json]", …) are the same
    # claim about the same command.
    # A gate DESIGN claims but CI does not run is the verification bar
    # over-claiming about itself. A check counts as run either as its own
    # workflow step or from inside the suite, which is a workflow step already —
    # so the haystack is both. Only this direction is checked: naming a gate
    # nothing runs fails, while a check CI runs that DESIGN has not caught up to
    # does not.
    enforced = ""
    for path in (os.path.join(repo_dir, ".github", "workflows", "test.yml"),
                 os.path.join(repo_dir, "tests", "test.py")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                enforced += f.read()
        except OSError:
            pass
    bar = docs.get("DESIGN.md", "")
    if "## Verification bar" in bar and enforced:
        bar = bar[bar.index("## Verification bar"):]
        rest = bar[1:]
        bar = bar[:rest.index("\n## ") + 1] if "\n## " in rest else bar
        for flag in sorted(set(re.findall(r"`build\.py (--check[a-z-]*)`", bar))):
            if flag not in enforced and flag.lstrip("-").replace("-", "_") not in enforced:
                problems.append(f"  DESIGN.md: the verification bar names "
                                f"`build.py {flag}` as a gate, but nothing in CI "
                                f"or the suite runs it")

    real = _command_names(module, "_COMMANDS")
    documented = set()
    # Located by its header row, not by row shape: README has other two-column
    # tables of backticked names (the repository layout), and telling them apart
    # by appearance alone reported LICENSE as a missing shell command.
    table = re.search(r"^\| Command \| What it does \|\n\|-+\|-+\|\n((?:\|.*\n)+)",
                      docs.get("README.md", ""), re.M)
    if table:
        for row in re.findall(r"^\|(.+?)\|", table.group(1), re.M):
            for token in re.findall(r"`([^`]+)`", row):
                if "/" not in token:
                    documented.add(token.split()[0])
    else:
        problems.append("  README.md: no `| Command | What it does |` table found — "
                        "was it reshaped? Nothing is gating the command list.")
    for cmd in sorted(documented - real):
        problems.append(f"  README.md: documents a `{cmd}` command the shell does not have")
    for cmd in sorted(real - documented):
        problems.append(f"  README.md: the shell has a `{cmd}` command README's table omits")

    if problems:
        print("STALE DOCS: the documents name things that do not exist.", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        return 1
    print(f"OK: {len(docs)} documents name only things that exist.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build servette.py from src/*.md")
    parser.add_argument("--output", metavar="PATH",
                        help="write here instead of ../servette.py")
    parser.add_argument("--stdout", action="store_true",
                        help="write the built source to stdout")
    parser.add_argument("--check", action="store_true",
                        help="compare the build against the existing module; "
                             "exit 1 if they differ")
    parser.add_argument("--counts", action="store_true",
                        help="print lines per section, for the website's figures")
    parser.add_argument("--check-counts", action="store_true",
                        help="verify the line counts README states against src/; "
                             "exit 1 if any is stale")
    parser.add_argument("--check-docs", action="store_true",
                        help="verify that paths, identifiers, flags, commands and "
                             "links the docs name exist; exit 1 if any is stale")
    args = parser.parse_args(argv)

    src_dir  = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.dirname(src_dir)
    default  = os.path.join(repo_dir, "servette.py")

    # Reads src/ only — no assembled module needed, so it answers even when the
    # build itself is broken.
    if args.check_counts:
        return check_readme_counts(src_dir, repo_dir)

    if args.check_docs:
        return check_docs(src_dir, repo_dir)

    if args.counts:
        for name, total, code in section_counts(src_dir):
            print(f"{name:8} {total:>6,} total  {code:>6,} code")
        print(f"{'':8} {'':>6}         {not_found_lines(src_dir):>6,} "
              f"embedded page ({NOT_FOUND_SOURCE}, not Python)")
        return 0

    built = build(src_dir)

    # Fail loudly on a broken assembly rather than writing (or blessing) a
    # module that won't parse. compile() parses without executing, so this
    # has no side effects; it catches syntax errors, not runtime ones — the test
    # suite covers the rest.
    try:
        compile(built, "servette.py", "exec")
    except SyntaxError as e:
        print(f"build failed: assembled module has a syntax error: {e}", file=sys.stderr)
        return 1

    if args.check:
        # The module is generated at package-build time and never committed, so
        # there is no on-disk copy to diff. What can drift now is only the
        # sources themselves — and build() + the compile() above have already
        # proven they assemble into a valid module, or we would not be here.
        print(f"OK: src/ builds a valid module ({len(built.splitlines()):,} lines).")
        return 0

    if args.stdout:
        sys.stdout.write(built)
        return 0

    target = args.output or default
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        f.write(built)
    print(f"Wrote {target} ({len(built)} bytes) from src/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
