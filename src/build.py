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

This tool reverses that mapping, in file order, to produce the module. It
adds nothing of its own: every output line comes from either a code fence or
a blockquote. The blockquote/comment mapping is an exact inverse of the split
that created these files, so the build reproduces the module byte-for-byte —
which `--check` verifies. (`servette/__main__.py` is the one hand-written
file in the package: two lines that call main(), authored directly.)

Usage:
    python build.py                 # write ../servette/__init__.py
    python build.py --output PATH   # write somewhere else
    python build.py --stdout        # write to stdout
    python build.py --check         # build in memory, diff against the
                                     # existing module, exit 1 on drift
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
    """Concatenate the reconstructed source of all four section files."""
    parts = []
    for name in SECTION_FILES:
        with open(os.path.join(src_dir, name), "r", encoding="utf-8") as f:
            parts.append(md_to_code(f.read(), name))
    return "".join(parts)


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


# Where the website states a count, and how to find it. Each entry is a
# (label, regex) whose one capture group is the number as published. A stale
# count fails the gate; a rewritten sentence fails it too, which is correct —
# moving a claim should make someone re-check it rather than silently drop it
# from the gate's view.
def _site_claims(counts):
    by = {name: (total, code) for name, total, code in counts}
    total, code = by["Total"]
    claims = [
        ("prose total",  rf"Servette is ([\d,]+) lines of Python", total),
        ("prose code",   rf"lines of Python, of which ([\d,]+) are code", code),
        ("headline stat", r'class="stat__n">([\d,]+)</p>\s*<p class="stat__what">lines you can read', total),
    ]
    for name in ("Init", "Server", "System", "Shell", "Main", "Total"):
        t, c = by[name]
        row = (rf'<th scope="row">{name}</th>.*?'
               rf'<td class="num">([\d,]+)</td><td class="num">[\d,]+</td>')
        col = (rf'<th scope="row">{name}</th>.*?'
               rf'<td class="num">[\d,]+</td><td class="num">([\d,]+)</td>')
        claims.append((f"table {name} total", row, t))
        claims.append((f"table {name} code",  col, c))
    # The "Four regions" walkthrough repeats the three big section totals.
    for name, stem in (("Server", r"lines\. The only region a network request can reach"),
                       ("System", r"lines\. Everything that runs on its own schedule"),
                       ("Shell",  r"lines, and the largest region of the module")):
        claims.append((f"regions {name}", rf"<p>([\d,]+) {stem}", by[name][0]))
    return claims


def check_site_counts(src_dir, repo_dir):
    """Verify every line count the website publishes against src/.

    The counts drifted unnoticed once (the page claimed 3,896/3,003 while main
    held 4,002/3,034) because nothing re-ran them. This is that check."""
    page_path = os.path.join(repo_dir, "site", "index.html")
    try:
        with open(page_path, "r", encoding="utf-8") as f:
            page = f.read()
    except OSError as e:
        print(f"count check failed: cannot read {page_path}: {e}", file=sys.stderr)
        return 1

    problems = []
    for label, pattern, expected in _site_claims(section_counts(src_dir)):
        m = re.search(pattern, page, re.DOTALL)
        if m is None:
            problems.append(f"  {label}: claim not found on the page "
                            f"(expected {expected:,} — was the sentence rewritten?)")
        elif m.group(1).replace(",", "") != str(expected):
            problems.append(f"  {label}: page says {m.group(1)}, src/ says {expected:,}")

    if problems:
        print("STALE COUNTS: site/index.html disagrees with src/.", file=sys.stderr)
        print("\n".join(problems), file=sys.stderr)
        print("\nCurrent counts from src/:", file=sys.stderr)
        for name, total, code in section_counts(src_dir):
            print(f"  {name:8} {total:>6,} total  {code:>6,} code", file=sys.stderr)
        return 1
    print("OK: site/index.html line counts match the build of src/.")
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
                        help="print lines per section")
    parser.add_argument("--check-counts", action="store_true",
                        help="verify the line counts site/index.html publishes "
                             "against src/; exit 1 if any is stale")
    args = parser.parse_args(argv)

    src_dir  = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.dirname(src_dir)
    default  = os.path.join(repo_dir, "servette", "__init__.py")

    # Both count modes read src/ only — no assembled module needed, so they
    # answer even when the build itself is broken.
    if args.counts:
        for name, total, code in section_counts(src_dir):
            print(f"{name:8} {total:>6,} total  {code:>6,} code")
        return 0

    if args.check_counts:
        return check_site_counts(src_dir, repo_dir)

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
