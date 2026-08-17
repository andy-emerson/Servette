"""The PEP 517 build backend: the literate build, run by the package manager.

pyproject.toml names this module (build-backend = "_literate_backend",
backend-path = ["src"]), so every standards-based build — pip installing from
a checkout or an sdist, `python -m build`, pipx building on install — starts
by importing it. Importing it generates servette.py from the Markdown sources;
everything else is setuptools, re-exported unchanged. That makes installing
from source THE literate build: there is no separate build step to run, and no
generated file to commit, go stale, or hand-edit.

Generation happens at import, not in per-hook wrappers, because the FIRST
thing many front ends call is get_requires_for_build_sdist — and setuptools
answers that by evaluating pyproject's dynamic version, which reads
servette.__version__ from the generated module. A wrapper on the build hooks
alone ran too late; import-time is upstream of every hook there is.

build.py is loaded by file path, not by `import build` — this module runs with
src/ on sys.path, where a bare `import build` is ambiguous with the pypa
`build` package that may be driving this very process.
"""

import importlib.util
import os

# Everything setuptools' backend offers, re-exported so front ends see a
# complete backend: build_wheel, build_sdist, build_editable, the metadata
# and requires hooks — all of them setuptools' own.
from setuptools.build_meta import *          # noqa: F401,F403

_SRC  = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_SRC)

_spec = importlib.util.spec_from_file_location(
    "_servette_literate_build", os.path.join(_SRC, "build.py"))
_build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_build)


def _generate():
    """Write ../servette.py from the sources. Written only when the content
    differs, so repeated backend imports (one per hook subprocess) do not
    churn the file's mtime."""
    text = _build.build(_SRC)
    compile(text, "servette.py", "exec")     # fail the build, not the install
    out = os.path.join(_ROOT, "servette.py")
    try:
        with open(out, "r", encoding="utf-8") as f:
            if f.read() == text:
                return
    except OSError:
        pass
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)


_generate()
