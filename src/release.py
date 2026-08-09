#!/usr/bin/env python3
"""Prepare the assets for a GitHub release — a maintainer tool.

This is the release procedure's signing step made runnable (see DESIGN.md,
"Releasing"): it refuses to sign a tree where servette.py has drifted from
src/, signs the two release artifacts with the maintainer's private key, and
self-checks every signature against the public key pinned inside servette.py
— so signing with the wrong key file fails here, not on an operator's box.

It runs locally, where the private key lives. The key never enters CI; CI
verifies releases, it does not create them.

Usage:
    .servette-env/bin/python3 src/release.py            # key: ./servette_signing.pem
    .servette-env/bin/python3 src/release.py --key PATH

Output: dist/ containing servette.py, servette.py.sig, demo.html,
demo.html.sig — attach all four to the GitHub release. dist/ and *.sig are
gitignored; nothing this tool writes can be committed.
"""

import argparse
import os
import re
import shutil
import sys

import build  # sibling module: the build/--check logic this tool refuses to bypass

_PUBKEY_RE  = re.compile(r"""^_SIGNING_PUBLIC_KEY\s*=\s*['"]([0-9a-f]{64})['"]""", re.M)
_VERSION_RE = re.compile(r"""^__version__\s*=\s*['"]([^'"]+)['"]""", re.M)
_DEMO_MARKER = "servette:demo"


def prepare(repo_dir, key_path, out_dir):
    """Sign the release artifacts into out_dir. Returns the version string.
    Raises SystemExit with a message on any refusal — drift, missing marker,
    wrong key — so the caller can't half-release."""
    servette_path = os.path.join(repo_dir, "servette.py")
    demo_path     = os.path.join(repo_dir, "site", "demo", "index.html")

    with open(servette_path, "rb") as f:
        source = f.read()
    if build.build(os.path.join(repo_dir, "src")).encode() != source:
        raise SystemExit("refused: servette.py has drifted from src/ — run src/build.py first.")

    with open(demo_path, "rb") as f:
        demo = f.read()
    if _DEMO_MARKER.encode() not in demo:
        raise SystemExit(f"refused: {demo_path} lacks the {_DEMO_MARKER} marker — "
                         "a marker-less demo can never be refreshed on an operator's box.")

    text    = source.decode()
    pinned  = _PUBKEY_RE.search(text)
    version = _VERSION_RE.search(text)
    if not pinned or not version:
        raise SystemExit("refused: could not read _SIGNING_PUBLIC_KEY or __version__ from servette.py.")

    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
    except ImportError:
        raise SystemExit("cryptography is not importable — run under .servette-env/bin/python3.")
    try:
        with open(key_path, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
    except OSError as e:
        raise SystemExit(f"cannot read the private key: {e}")

    # The key file must be the pinned key's counterpart. Signing with any other
    # key would produce assets every servette.py on earth rejects.
    derived = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    if derived != pinned.group(1):
        raise SystemExit("refused: this private key does not match the _SIGNING_PUBLIC_KEY "
                         "pinned in servette.py.")

    os.makedirs(out_dir, exist_ok=True)
    shutil.copyfile(servette_path, os.path.join(out_dir, "servette.py"))
    shutil.copyfile(demo_path,     os.path.join(out_dir, "demo.html"))
    for name, data in (("servette.py", source), ("demo.html", demo)):
        with open(os.path.join(out_dir, name + ".sig"), "wb") as f:
            f.write(key.sign(data))
    return version.group(1)


def main(argv=None):
    src_dir  = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.dirname(src_dir)
    parser = argparse.ArgumentParser(description="Sign the release assets into dist/")
    parser.add_argument("--key", default=os.path.join(repo_dir, "servette_signing.pem"),
                        help="Ed25519 private key PEM (default: ./servette_signing.pem)")
    parser.add_argument("--out", default=os.path.join(repo_dir, "dist"),
                        help="output directory (default: ./dist)")
    args = parser.parse_args(argv)

    version = prepare(repo_dir, args.key, args.out)
    print(f"Signed release assets for {version} in {args.out}:")
    for name in ("servette.py", "servette.py.sig", "demo.html", "demo.html.sig"):
        print(f"  {name}")
    print("Draft the GitHub release, attach all four, wait for the verification "
          "workflow to pass, then publish.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
