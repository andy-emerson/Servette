#!/usr/bin/env python3
"""Build servette/__init__.py from the Markdown sources in this directory.

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
below: `diagnostics.html` is inlined where the sources name it, so the
page ships inside the module instead of beside it. The blockquote/comment
mapping is an exact inverse of the split that created these files, and the
substitution is verbatim, so the build reproduces the module byte-for-byte —
which `--check` verifies. (`servette/__main__.py` is the one hand-written
file in the package: two lines that call main(), authored directly.)

Usage:
    python build.py                 # write ../servette/__init__.py
    python build.py --output PATH   # write somewhere else
    python build.py --stdout        # write to stdout
    python build.py --check         # build in memory, diff against the
                                     # existing module, exit 1 on drift
    python build.py --counts        # lines per section, for the website
    python build.py --check-counts  # exit 1 if README's line counts are stale
"""

import argparse
import difflib
import os
import re
import sys

# The sources, in the order they concatenate into the module. MAIN.md is last
# because the entry point it holds — `config = Config()` and the `__main__`
# dispatch — runs on import and calls definitions from every section above it.
SECTION_FILES = ["INIT.md", "SERVER.md", "SYSTEM.md", "SHELL.md", "MAIN.md"]

# The diagnostic page is authored as real HTML — editable, highlighted, openable
# in a browser — and inlined into the module at build time, so the shipped
# package is Python only. An operator cannot delete a page that is not a file,
# and the 404 body cannot go missing with it.
DIAGNOSTICS_SOURCE = "diagnostics.html"
_DIAGNOSTICS_MARKER = "@@DIAGNOSTICS_HTML@@"

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
    """Concatenate the reconstructed sections, then inline the diagnostic page.

    The substitution happens here and not in md_to_code, so the per-section
    line counts stay a measure of the program rather than of an embedded
    asset."""
    parts = []
    for name in SECTION_FILES:
        with open(os.path.join(src_dir, name), "r", encoding="utf-8") as f:
            parts.append(md_to_code(f.read(), name))
    out = "".join(parts)

    with open(os.path.join(src_dir, DIAGNOSTICS_SOURCE), "r", encoding="utf-8") as f:
        html = f.read()
    # The page lands inside a triple-quoted literal. A `"""` in the HTML would
    # close it early and a backslash would be read as an escape, so both fail
    # the build rather than producing a module that is subtly not the page.
    if '"""' in html:
        raise ValueError(f"{DIAGNOSTICS_SOURCE}: contains \"\"\", which would end the literal")
    if "\\" in html:
        raise ValueError(f"{DIAGNOSTICS_SOURCE}: contains a backslash, which the literal would escape")
    if out.count(_DIAGNOSTICS_MARKER) != 1:
        raise ValueError(f"expected exactly one {_DIAGNOSTICS_MARKER} in the sources, "
                         f"found {out.count(_DIAGNOSTICS_MARKER)}")
    return out.replace(_DIAGNOSTICS_MARKER, html)


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


def diagnostics_lines(src_dir):
    """Lines in the authored diagnostic page.

    Reported apart from the section counts, not folded into them. The counts
    back a claim about reading the *program*; an embedded HTML page is shipped
    by it, not read as part of it, and burying 630 lines of markup inside the
    Python figure would overstate what an auditor has to work through."""
    with open(os.path.join(src_dir, DIAGNOSTICS_SOURCE), "r", encoding="utf-8") as f:
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


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build servette.py from src/*.md")
    parser.add_argument("--output", metavar="PATH",
                        help="write here instead of ../servette.py")
    parser.add_argument("--stdout", action="store_true",
                        help="write the built source to stdout")
    parser.add_argument("--check", action="store_true",
                        help="compare the build against the existing servette.py; "
                             "exit 1 if they differ")
    parser.add_argument("--counts", action="store_true",
                        help="print lines per section, for the website's figures")
    parser.add_argument("--check-counts", action="store_true",
                        help="verify the line counts README states against src/; "
                             "exit 1 if any is stale")
    args = parser.parse_args(argv)

    src_dir  = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.dirname(src_dir)
    default  = os.path.join(repo_dir, "servette", "__init__.py")

    # Reads src/ only — no assembled module needed, so it answers even when the
    # build itself is broken.
    if args.check_counts:
        return check_readme_counts(src_dir, repo_dir)

    if args.counts:
        for name, total, code in section_counts(src_dir):
            print(f"{name:8} {total:>6,} total  {code:>6,} code")
        print(f"{'':8} {'':>6}         {diagnostics_lines(src_dir):>6,} "
              f"embedded page ({DIAGNOSTICS_SOURCE}, not Python)")
        return 0

    built = build(src_dir)

    # Fail loudly on a broken assembly rather than writing (or blessing) a
    # servette.py that won't parse. compile() parses without executing, so this
    # has no side effects; it catches syntax errors, not runtime ones — the test
    # suite covers the rest.
    try:
        compile(built, "servette/__init__.py", "exec")
    except SyntaxError as e:
        print(f"build failed: assembled module has a syntax error: {e}", file=sys.stderr)
        return 1

    if args.check:
        target = args.output or default
        try:
            with open(target, "r", encoding="utf-8") as f:
                current = f.read()
        except OSError as e:
            print(f"check failed: cannot read {target}: {e}", file=sys.stderr)
            return 1
        if current == built:
            print(f"OK: {os.path.basename(target)} matches the build of src/.")
            return 0
        print(f"DRIFT: {target} differs from the build of src/.", file=sys.stderr)
        diff = difflib.unified_diff(
            current.splitlines(keepends=True), built.splitlines(keepends=True),
            fromfile=f"{os.path.basename(target)} (on disk)",
            tofile="build(src/)", n=2,
        )
        sys.stderr.writelines(diff)
        return 1

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
