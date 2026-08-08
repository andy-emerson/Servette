# INIT

*Shebang docstring, version, imports, and module-level constants.*

*Authored here. `servette.py` is built from this file (and its three siblings) by [`build.py`](build.py) — edit the Markdown, not the generated file.*

```python
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


BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
_VENV_DIR   = os.path.join(BASE_DIR, ".servette-env")
_VENV_PY    = os.path.join(_VENV_DIR, "bin", "python3")

SERVICE_PATH  = "/etc/systemd/system/servette.service"
NETWATCH_PATH = "/etc/systemd/system/servette-netwatch"  # + ".service" / ".timer"
ACME_WEBROOT  = "/var/lib/letsencrypt/webroot"

```

> The closed-system TLS fallback: presented for connections whose SNI matches no
> configured site (absent, unrecognized, or direct-IP access) when no site is
> itself domainless. Tied to no site's identity, generated once and reused.

```python
_DEFAULT_CERT_DIR  = os.path.join(BASE_DIR, "certs", "_default")
_DEFAULT_CERT_FILE = os.path.join(_DEFAULT_CERT_DIR, "cert.pem")
_DEFAULT_KEY_FILE  = os.path.join(_DEFAULT_CERT_DIR, "key.pem")


```
