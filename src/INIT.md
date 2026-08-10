# INIT

*Shebang docstring, version, imports, and module-level constants.*

*Authored here. `servette.py` is built from the Markdown sources in `src/` by [`build.py`](build.py) — edit the Markdown, not the generated file.*

> GENERATED FILE — do not edit. servette.py is built from the Markdown
> sources in src/ by src/build.py; edit those and rebuild. Hand edits here
> are overwritten by the next build and fail CI's `build.py --check`.

The file opens by introducing itself: what it does, how it is run, and the three sections everything below belongs to. `__version__` is the single version of record — releases and the self-updater both read it from here.

```python
# The docstring and version
"""
servette.py — The Simple Secure Static Site Server

Servette serves a directory of static files over HTTPS with optional Basic Auth
and essential security headers. Run it:

    sudo python3 servette.py

Architecture:
    Server              — config, rate limiting, file cache, the request handler, and the HTTP servers
    System              — bootstrap, server lifecycle, certificate management, and service management
    Shell               — the interactive terminal interface
"""

__version__ = "0.26.219"

```

Every import is Python standard library. The one third-party dependency, `cryptography`, is imported where it is used — it may not exist until the venv bootstrap has installed it.

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
import io
import ipaddress
import json
import logging
import tarfile
import tomllib
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import unquote, urlsplit, urlunsplit

```

Where everything lives. `BASE_DIR` is the directory holding `servette.py` itself, and the private venv sits beside the file; the absolute paths are where provisioning writes the systemd units and where the ACME client serves its challenges from.

```python
# Paths
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
_VENV_DIR   = os.path.join(BASE_DIR, ".servette-env")
_VENV_PY    = os.path.join(_VENV_DIR, "bin", "python3")

SERVICE_PATH  = "/etc/systemd/system/servette.service"
NETWATCH_PATH = "/etc/systemd/system/servette-netwatch"  # + ".service" / ".timer"
ACME_WEBROOT  = "/var/lib/letsencrypt/webroot"

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
