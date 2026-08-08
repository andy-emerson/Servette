#!/usr/bin/env python3
"""Build servette.py from the Markdown sources in this directory.

servette.py is authored as four literate Markdown files — INIT.md, SERVER.md,
SYSTEM.md, SHELL.md. Each interleaves three things:

  * fenced ```python blocks — the code, emitted verbatim;
  * blockquotes (`> ...`) — the module's own comment prose, lifted out of the
    code so it reads as prose; each `> ` maps back to a `# ` comment line
    (and a bare `>` back to a bare `#`);
  * everything else — headings, section intros — which is navigation for the
    reader and produces nothing.

This tool reverses that mapping, in file order, to produce servette.py. It
adds nothing of its own: every output line comes from either a code fence or
a blockquote. The blockquote/comment mapping is an exact inverse of the split
that created these files, so the build reproduces servette.py byte-for-byte —
which `--check` verifies.

Usage:
    python build.py                 # write ../servette.py
    python build.py --output PATH   # write somewhere else
    python build.py --stdout        # write to stdout
    python build.py --check         # build in memory, diff against the
                                     # existing servette.py, exit 1 on drift
"""

import argparse
import difflib
import os
import sys

# The four sources, in the order they concatenate into servette.py.
SECTION_FILES = ["INIT.md", "SERVER.md", "SYSTEM.md", "SHELL.md"]

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


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build servette.py from src/*.md")
    parser.add_argument("--output", metavar="PATH",
                        help="write here instead of ../servette.py")
    parser.add_argument("--stdout", action="store_true",
                        help="write the built source to stdout")
    parser.add_argument("--check", action="store_true",
                        help="compare the build against the existing servette.py; "
                             "exit 1 if they differ")
    args = parser.parse_args(argv)

    src_dir  = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.dirname(src_dir)
    default  = os.path.join(repo_dir, "servette.py")

    built = build(src_dir)

    # Fail loudly on a broken assembly rather than writing (or blessing) a
    # servette.py that won't parse. compile() parses without executing, so this
    # has no side effects; it catches syntax errors, not runtime ones — the test
    # suite covers the rest.
    try:
        compile(built, "servette.py", "exec")
    except SyntaxError as e:
        print(f"build failed: assembled servette.py has a syntax error: {e}", file=sys.stderr)
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
    with open(target, "w", encoding="utf-8") as f:
        f.write(built)
    print(f"Wrote {target} ({len(built)} bytes) from src/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
