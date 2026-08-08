#!/usr/bin/env python3
"""Build servette.py from the Markdown sources in this directory.

servette.py is authored as four Markdown files — INIT.md, SERVER.md,
SYSTEM.md, SHELL.md — each carrying that section's code in fenced ```python
blocks, with prose headings around them for reading. This tool concatenates
the contents of those fenced blocks, in file order and block order, to
produce servette.py.

It adds nothing. The output is exactly the concatenation of the fenced
``python`` blocks — no header, no banner, no reformatting — so whatever
runs is byte-for-byte what the Markdown holds. Prose outside the fences is
for the reader and never reaches the built file.

Usage:
    python build.py                 # write ../servette.py
    python build.py --output PATH   # write somewhere else
    python build.py --stdout        # write to stdout
    python build.py --check         # build in memory, diff against the
                                     # existing servette.py, exit 1 if they
                                     # differ (the drift guard for CI)
"""

import argparse
import difflib
import os
import sys

# The four sources, in the order they are concatenated into servette.py.
SECTION_FILES = ["INIT.md", "SERVER.md", "SYSTEM.md", "SHELL.md"]

_FENCE_OPEN  = "```python"
_FENCE_CLOSE = "```"


def extract_code(md_text, filename):
    """Return the verbatim concatenation of every ```python fenced block in
    md_text, in order. Lines outside the fences are ignored. Raises on an
    unterminated block so a malformed source fails loudly rather than
    silently dropping code."""
    out = []
    in_block = False
    # keepends=True preserves each line's newline exactly, so the joined
    # result reproduces the original bytes.
    for line in md_text.splitlines(keepends=True):
        marker = line.strip()
        if not in_block:
            if marker == _FENCE_OPEN:
                in_block = True
        else:
            if marker == _FENCE_CLOSE:
                in_block = False
            else:
                out.append(line)
    if in_block:
        raise ValueError(f"{filename}: unterminated ```python block")
    return "".join(out)


def build(src_dir):
    """Concatenate the code from all four section files into the full
    servette.py source string."""
    parts = []
    for name in SECTION_FILES:
        path = os.path.join(src_dir, name)
        with open(path, "r", encoding="utf-8") as f:
            parts.append(extract_code(f.read(), name))
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
