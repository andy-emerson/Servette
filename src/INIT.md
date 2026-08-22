# INIT

*Shebang docstring, version, imports, and module-level constants.*

*Authored here. `servette.py` is generated from the Markdown sources in `src/` — by the package build itself ([`_literate_backend.py`](_literate_backend.py)), or by hand with [`build.py`](build.py). Edit the Markdown, never the module; the committed copy exists to be read, and `--check` holds it equal to the sources.*

> GENERATED FILE — do not edit by hand. servette.py is generated from the
> Markdown sources in src/ — by the package build (src/_literate_backend.py)
> whenever pip or `python -m build` runs, or by hand with src/build.py. Edit
> the sources and regenerate; edits here are overwritten by the next build
> and fail CI's `build.py --check`.

The module opens by introducing itself: what it does, how it is run, and the three sections everything below belongs to. `__version__` is the single version of record — the package build reads it from here.

```python
# The docstring and version
"""
Servette — The Simple Secure Static Site Server

Servette serves a directory of static files over HTTPS with optional Basic Auth
and essential security headers. Run it:

    servette

Architecture:
    Server              — config, rate limiting, file cache, the request handler, and the HTTP servers
    System              — server lifecycle, certificate management, and service management
    Shell               — the interactive terminal interface
"""

__version__ = "0.26.231"

```

Every import is Python standard library. The one third-party dependency, `cryptography`, is imported where it is used, so importing the module itself never requires it — the shell can start, explain itself, and run its read-only commands on a host where the dependency is missing or broken.

```python
# Imports — standard library only
import base64
import collections
import datetime
import getpass
import gzip
import hashlib
import hmac
import http.server
import importlib.metadata
import importlib.util
import io
import ipaddress
import json
import logging
import tarfile
import tomllib
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

```

Where everything lives. `BASE_DIR` is the data directory — config, certificates, the ACME account, and the default site folder — deliberately not the directory holding the code, which the package manager owns and replaces. `SERVETTE_HOME` overrides it: the test suite points it at the repository, and it is how a second instance runs beside a first. The absolute paths are where provisioning writes the systemd units and where the ACME client serves its challenges from.

```python
# Paths
#
# The data directory: state lives here, code lives wherever the package
# manager put it, and the two never share a home. The systemd unit carries
# Environment=SERVETTE_HOME so the service resolves the same directory the
# shell that enabled it did.
BASE_DIR = os.path.abspath(
    os.environ.get("SERVETTE_HOME")
    or (os.path.expanduser("~/.servette") if sys.platform == "darwin"
        else "/var/lib/servette"))

SERVICE_PATH  = "/etc/systemd/system/servette.service"
NETWATCH_PATH = "/etc/systemd/system/servette-netwatch"  # + ".service" / ".timer"
ACME_WEBROOT  = "/var/lib/letsencrypt/webroot"

```

One platform question, asked once. Servette is Linux-first: on macOS it runs in session mode — serving, certificates, and the shell all work, while service installation (systemd) stays Linux-only — and the places that differ key off this flag.

```python
# The platform flag
_IS_MACOS = sys.platform == "darwin"

```

The fallback certificate's home — in `certs/_default`, apart from the per-site certificates.

> The closed-system TLS fallback: presented for connections whose SNI matches no
> configured site (absent, unrecognized, or direct-IP access) when no site is
> itself domainless. Tied to no site's identity, generated once and reused.

```python

# The default-certificate paths
_DEFAULT_CERT_DIR  = os.path.join(BASE_DIR, "certs", "_default")
_DEFAULT_CERT_FILE = os.path.join(_DEFAULT_CERT_DIR, "cert.pem")
_DEFAULT_KEY_FILE  = os.path.join(_DEFAULT_CERT_DIR, "key.pem")


```
