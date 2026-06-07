"""
servette.py — The Simple Secure Static Site Server

Servette serves a directory of static files over HTTPS with optional Basic Auth
and essential security headers. Run it:

    sudo python3 servette.py

Architecture:
    Bootstrap           — creates a virtualenv and installs Hypercorn on first run
    Config              — a Config object holds all settings and reads/writes servette.json
    Logging             — terminal in interactive mode; systemd journal in service mode
    Rate Limiter        — in-memory per-IP request and auth-fail rate limiting
    ASGI Apps           — https_app and redirect_app handle all HTTP traffic via Hypercorn
    Server              — starts/stops Hypercorn in a background thread
    Shell               — the interactive terminal interface
"""

import asyncio
import base64
import datetime
import getpass
import gzip
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from urllib.parse import unquote


# ─────────────────────────────────────────────────────────────────────────────
# BOOTSTRAP
#
# On first run, servette.py creates a virtualenv and installs dependencies into
# it, then re-execs itself inside that environment. The user just runs
# `sudo python3 servette.py` — the environment is managed invisibly.
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
_VENV_DIR   = os.path.join(BASE_DIR, ".servette-env")
_VENV_PY    = os.path.join(_VENV_DIR, "bin", "python3")

SERVICE_PATH = "/etc/systemd/system/servette.service"
ACME_WEBROOT = "/var/lib/letsencrypt/webroot"


def _bootstrap():
    if sys.prefix == _VENV_DIR:
        return  # Already running inside the managed virtualenv

    if not os.path.exists(_VENV_PY):
        print("Setting up Servette...")

        ver = f"python3.{sys.version_info.minor}-venv"
        result = subprocess.run(["apt-get", "install", "-y", ver])
        if result.returncode != 0:
            print(f"  Error: failed to install {ver}")
            sys.exit(1)

        try:
            import venv as _venv_mod
            _venv_mod.create(_VENV_DIR, with_pip=True, clear=True)
        except Exception as e:
            print(f"  Error: failed to create virtual environment: {e}")
            sys.exit(1)

        deps = ["hypercorn", "cryptography", "acme", "josepy"]
        result = subprocess.run([_VENV_PY, "-m", "pip", "install"] + deps)
        if result.returncode != 0:
            print(f"  Error: failed to install dependencies")
            sys.exit(1)
        print()

    os.execv(_VENV_PY, [_VENV_PY] + sys.argv)


# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────


def _resolve(path):
    """Return path as-is if absolute, otherwise anchor it to BASE_DIR."""
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)


def _hash_password(password):
    """Hash a password with a random salt using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260000)
    return key.hex(), salt.hex()


def _check_password(submitted, stored_hash, stored_salt):
    """Return True if submitted matches the stored hash."""
    if not stored_hash or not stored_salt:
        return False
    try:
        salt = bytes.fromhex(stored_salt)
        key  = hashlib.pbkdf2_hmac("sha256", submitted.encode("utf-8"), salt, 260000)
        return hmac.compare_digest(key.hex(), stored_hash)
    except Exception:
        return False


class Config:
    """Holds all Servette settings and handles reading/writing servette.json."""

    CONFIG_FILE = os.path.join(BASE_DIR, "servette.json")

    def __init__(self):
        self._mtime = None
        self._load()

    def _load(self):
        data = {}
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, "r") as f:
                    data = json.load(f)
            except json.JSONDecodeError as e:
                print(f"Error: servette.json is not valid JSON ({e}).")
                print(f"Fix or delete {self.CONFIG_FILE} and try again.")
                sys.exit(1)

        self.serve_dir       = data.get("serve_dir",       data.get("html_file", ""))
        self.port            = data.get("port",            443)
        self.cert_file       = data.get("cert_file",       "cert.pem")
        self.key_file        = data.get("key_file",        "key.pem")
        self.username        = data.get("username",        "")
        self.password_hash   = data.get("password_hash",   "")
        self.password_salt   = data.get("password_salt",   "")
        self.rate_limit      = data.get("rate_limit",      30)
        self.auth_rate_limit = data.get("auth_rate_limit", 6)
        self.cache_policy       = data.get("cache_policy",       "no-cache")
        self.cache_max_age      = data.get("cache_max_age",      3600)
        self.email              = data.get("email",              "")
        self.trusted_proxy      = data.get("trusted_proxy",      "")
        self.tls_min_version    = data.get("tls_min_version",    "1.2")
        self.ciphers            = data.get("ciphers",            "")

        try:
            self._mtime = os.path.getmtime(self.CONFIG_FILE)
        except OSError:
            pass

        try:
            self._cert_mtime = os.path.getmtime(_resolve(self.cert_file))
        except OSError:
            self._cert_mtime = None

        if data.get("password") and not self.password_hash:
            self.password_hash, self.password_salt = _hash_password(data["password"])
            self.save()

    def reload_if_changed(self):
        try:
            mtime = os.path.getmtime(self.CONFIG_FILE)
            if mtime != self._mtime:
                self._load()
                log.info("Config reloaded from disk")
        except OSError:
            pass

    def save(self):
        data = {
            "serve_dir":       self.serve_dir,
            "port":            self.port,
            "cert_file":       self.cert_file,
            "key_file":        self.key_file,
            "username":        self.username,
            "password_hash":   self.password_hash,
            "password_salt":   self.password_salt,
            "rate_limit":      self.rate_limit,
            "auth_rate_limit": self.auth_rate_limit,
            "cache_policy":       self.cache_policy,
            "cache_max_age":      self.cache_max_age,
            "email":              self.email,
            "trusted_proxy":      self.trusted_proxy,
            "tls_min_version":    self.tls_min_version,
            "ciphers":            self.ciphers,
        }
        with open(self.CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(self.CONFIG_FILE, 0o600)
        try:
            self._mtime = os.path.getmtime(self.CONFIG_FILE)
        except OSError:
            pass


config = Config()


# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
#
# In service mode, logs go to systemd journal (StandardOutput=journal).
# In interactive mode, warnings and errors go to the terminal.
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging():
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s")

    stream = logging.StreamHandler()
    stream.setLevel(logging.INFO if "--serve" in sys.argv else logging.WARNING)
    stream.setFormatter(fmt)
    root.addHandler(stream)


log = logging.getLogger(__name__)
setup_logging()


# ─────────────────────────────────────────────────────────────────────────────
# RATE LIMITER
#
# Two independent sliding-window limits per IP address:
#   config.rate_limit      — total requests per minute (default 30)
#   config.auth_rate_limit — failed auth attempts per minute (default 6)
#
# Uses threading.Lock because the critical section is microseconds of dict
# manipulation — not I/O — so it doesn't meaningfully block the event loop.
# ─────────────────────────────────────────────────────────────────────────────

RATE_WINDOW  = 60      # seconds
_RATE_IP_CAP = 10_000  # max IPs tracked per dict; bounds memory under IP-flood attacks

_request_times   = {}
_auth_fail_times = {}
_rate_lock       = threading.Lock()


def _normalize_ip(ip):
    """Normalize IPv6-mapped IPv4 addresses so both forms bucket together."""
    if ip.startswith("::ffff:"):
        return ip[7:]
    return ip


def _rate_sweep():
    """Background thread: evict stale IPs and enforce the IP cap every 30 seconds."""
    while True:
        time.sleep(30)
        with _rate_lock:
            now    = time.monotonic()
            cutoff = now - RATE_WINDOW
            for tracker in (_request_times, _auth_fail_times):
                stale = [k for k, v in tracker.items() if not v or v[-1] < cutoff]
                for k in stale:
                    del tracker[k]
                if len(tracker) > _RATE_IP_CAP:
                    for k in sorted(tracker, key=lambda k: tracker[k][-1])[:len(tracker) - _RATE_IP_CAP]:
                        del tracker[k]

threading.Thread(target=_rate_sweep, daemon=True).start()


def _rate_limit_exceeded(tracker, ip, limit):
    """Record this request for ip and return True if the limit has been exceeded."""
    with _rate_lock:
        now    = time.monotonic()
        cutoff = now - RATE_WINDOW

        timestamps = tracker.get(ip, [])
        timestamps = [t for t in timestamps if t > cutoff]
        timestamps.append(now)
        tracker[ip] = timestamps

        return len(timestamps) > limit


# ─────────────────────────────────────────────────────────────────────────────
# FILE CACHE
#
# Files are read once and held in memory with gzip-compressed and raw copies.
# Modification time is checked on each request so edits take effect immediately.
# ─────────────────────────────────────────────────────────────────────────────

_file_cache      = {}
_file_cache_lock = threading.Lock()


def _get_cached_file(path):
    """Return (raw_bytes, compressed_bytes, etag), reloading only if the file changed."""
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None, None, None

    with _file_cache_lock:
        entry = _file_cache.get(path)
        if entry and entry["mtime"] == mtime:
            return entry["raw"], entry["compressed"], entry["etag"]

        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            return None, None, None

        compressed = gzip.compress(raw, compresslevel=6)
        etag       = '"' + hashlib.sha256(raw).hexdigest()[:16] + '"'
        _file_cache[path] = {"mtime": mtime, "raw": raw, "compressed": compressed, "etag": etag}

        return raw, compressed, etag


MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".js":   "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif":  "image/gif",
    ".svg":  "image/svg+xml",
    ".ico":  "image/x-icon",
    ".webp": "image/webp",
    ".woff": "font/woff",
    ".woff2":"font/woff2",
    ".ttf":  "font/ttf",
    ".pdf":  "application/pdf",
    ".txt":  "text/plain; charset=utf-8",
    ".xml":  "application/xml",
    ".webmanifest": "application/manifest+json",
}

def _mime_type(path):
    ext = os.path.splitext(path)[1].lower()
    return MIME_TYPES.get(ext, "application/octet-stream")

def _resolve_request_path(url_path):
    """Resolve a URL path to an absolute file path within serve_dir. Returns (None, 403) on traversal."""
    serve_dir = os.path.realpath(_resolve(config.serve_dir))
    clean = unquote(url_path.split("?")[0])
    rel   = os.path.normpath(clean.lstrip("/"))
    if rel == ".":
        rel = ""
    abs_path = os.path.realpath(os.path.join(serve_dir, rel) if rel else serve_dir)
    if not abs_path.startswith(serve_dir + os.sep) and abs_path != serve_dir:
        return None, 403
    if os.path.isdir(abs_path):
        abs_path = os.path.realpath(os.path.join(abs_path, "index.html"))
        if not abs_path.startswith(serve_dir + os.sep):
            return None, 403
    if not os.path.isfile(abs_path):
        return None, 404
    return abs_path, 200


def _cache_control_header():
    scope = "private" if config.username else "public"
    if config.cache_policy == "no-store":
        return "no-store"
    if config.cache_policy == "no-cache":
        return f"{scope}, no-cache"
    return f"{scope}, max-age={config.cache_max_age}"


# ─────────────────────────────────────────────────────────────────────────────
# ASGI APPS
# ─────────────────────────────────────────────────────────────────────────────

async def _send_response(send, status, headers_list, body=b""):
    await send({"type": "http.response.start", "status": status, "headers": headers_list})
    await send({"type": "http.response.body",  "body": body})


async def https_app(scope, receive, send):
    """ASGI app — HTTPS server."""

    if scope["type"] == "lifespan":
        while True:
            event = await receive()
            if event["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif event["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    if scope["type"] != "http":
        return

    method  = scope["method"]
    headers = dict(scope["headers"])

    client = scope.get("client")
    ip     = _normalize_ip(client[0] if client else "unknown")
    if config.trusted_proxy:
        xff = headers.get(b"x-forwarded-for", b"").decode()
        # Proxy must overwrite (not append) inbound XFF — otherwise the leftmost value is client-controlled
        if xff and ip == config.trusted_proxy:
            ip = _normalize_ip(xff.split(",")[0].strip())

    send_body = (method != "HEAD")

    if method not in ("GET", "HEAD"):
        await _send_response(send, 405,
            [(b"allow", b"GET, HEAD"), (b"content-length", b"0")])
        return

    config.reload_if_changed()

    # Rate limiting
    if _rate_limit_exceeded(_request_times, ip, config.rate_limit):
        await _send_response(send, 429, [
            (b"retry-after", str(RATE_WINDOW).encode()),
            (b"content-length", b"0"),
        ])
        log.warning("Rate limited %s", ip)
        return

    # Authentication
    if config.username:
        auth                  = headers.get(b"authorization", b"").decode()
        authed                = False
        credentials_submitted = False

        if auth.startswith("Basic "):
            credentials_submitted = True
            try:
                decoded        = base64.b64decode(auth[6:]).decode("utf-8", errors="strict")
                parts          = decoded.split(":", 1)
                submitted_user = parts[0]
                pw             = parts[1] if len(parts) == 2 else ""
                authed = (hmac.compare_digest(submitted_user, config.username) and
                          _check_password(pw, config.password_hash, config.password_salt))
            except (ValueError, UnicodeDecodeError):
                pass

        if not authed:
            if credentials_submitted and _rate_limit_exceeded(_auth_fail_times, ip, config.auth_rate_limit):
                await _send_response(send, 429, [
                    (b"retry-after", str(RATE_WINDOW).encode()),
                    (b"content-length", b"0"),
                ])
                log.warning("Auth rate limited %s", ip)
                return
            await _send_response(send, 401, [
                (b"www-authenticate", b'Basic realm="Access Required"'),
                (b"content-type",     b"text/plain"),
                (b"content-length",   b"12"),
            ], body=b"Unauthorized" if send_body else b"")
            if credentials_submitted:
                log.warning("Failed auth attempt from %s", ip)
            return

    # Resolve request path to a file
    url_path = scope.get("path", "/")
    try:
        file_path, status = _resolve_request_path(url_path)
    except Exception as e:
        log.error("500 resolving %s: %s", url_path, e)
        body_500 = b"Internal server error."
        await _send_response(send, 500,
            [(b"content-type", b"text/plain"), (b"content-length", str(len(body_500)).encode())],
            body=body_500 if send_body else b"")
        return

    if status == 403:
        body_403 = b"Forbidden."
        await _send_response(send, 403,
            [(b"content-type", b"text/plain"), (b"content-length", str(len(body_403)).encode())],
            body=body_403 if send_body else b"")
        log.warning("403 Forbidden %s from %s", url_path, ip)
        return

    if status == 404 or file_path is None:
        # Try custom 404.html in serve_dir root
        custom_404 = os.path.join(_resolve(config.serve_dir), "404.html")
        if os.path.isfile(custom_404):
            raw_404, _, _ = _get_cached_file(custom_404)
            body_404 = raw_404 or b"Not found."
            content_type_404 = b"text/html; charset=utf-8"
        else:
            body_404 = b"Not found."
            content_type_404 = b"text/plain"
        await _send_response(send, 404,
            [(b"content-type", content_type_404), (b"content-length", str(len(body_404)).encode())],
            body=body_404 if send_body else b"")
        log.warning("404 Not Found %s from %s", url_path, ip)
        return

    raw, compressed, etag = _get_cached_file(file_path)
    if raw is None:
        body_500 = b"Internal server error."
        await _send_response(send, 500,
            [(b"content-type", b"text/plain"), (b"content-length", str(len(body_500)).encode())],
            body=body_500 if send_body else b"")
        log.error("500 could not read %s", file_path)
        return

    # 304 Not Modified
    if_none_match = headers.get(b"if-none-match", b"").decode()
    if if_none_match == etag:
        await _send_response(send, 304, [
            (b"etag",          etag.encode()),
            (b"cache-control", _cache_control_header().encode()),
        ])
        log.info("304 Not Modified %s to %s", url_path, ip)
        return

    # Serve
    accept_encoding = headers.get(b"accept-encoding", b"").decode()
    accepts_gzip    = "gzip" in accept_encoding
    mime            = _mime_type(file_path)
    body            = compressed if accepts_gzip else raw

    response_headers = [
        (b"content-type",                mime.encode()),
        (b"content-length",              str(len(body)).encode()),
        (b"etag",                        etag.encode()),
        (b"cache-control",               _cache_control_header().encode()),
        (b"vary",                        b"Accept-Encoding"),
        (b"x-frame-options",             b"DENY"),
        (b"x-content-type-options",      b"nosniff"),
        (b"referrer-policy",             b"no-referrer"),
    ]
    if accepts_gzip:
        response_headers.append((b"content-encoding", b"gzip"))
    if _cert_domain:
        response_headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
    await _send_response(send, 200, response_headers, body=body if send_body else b"")
    log.info("200 %s to %s", url_path, ip)


async def redirect_app(scope, receive, send):
    """ASGI app — HTTP redirect to HTTPS and ACME challenge serving."""

    if scope["type"] == "lifespan":
        while True:
            event = await receive()
            if event["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif event["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    if scope["type"] != "http":
        return

    path      = scope["path"]
    headers   = dict(scope["headers"])
    send_body = (scope["method"] != "HEAD")

    # ACME HTTP-01 challenges arrive on port 80 during Let's Encrypt verification
    prefix = "/.well-known/acme-challenge/"
    if path.startswith(prefix):
        token = path[len(prefix):]
        if not token or "/" in token or ".." in token:
            await _send_response(send, 404, [(b"content-length", b"0")])
            return
        file_path = os.path.join(ACME_WEBROOT, ".well-known", "acme-challenge", token)
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            await _send_response(send, 200, [
                (b"content-type",   b"text/plain"),
                (b"content-length", str(len(data)).encode()),
            ], body=data if send_body else b"")
        except OSError:
            await _send_response(send, 404, [(b"content-length", b"0")])
        return

    # Redirect everything else to HTTPS
    host      = headers.get(b"host", b"localhost").decode().split(":")[0]
    https_url = (f"https://{host}{path}" if config.port == 443
                 else f"https://{host}:{config.port}{path}")

    await _send_response(send, 301, [
        (b"location",       https_url.encode()),
        (b"content-length", b"0"),
    ])
    log.info("Redirected to %s", https_url)


# ─────────────────────────────────────────────────────────────────────────────
# SERVER
#
# Hypercorn runs in a background thread with its own asyncio event loop.
# A threading.Event signals graceful shutdown from the shell thread.
# ─────────────────────────────────────────────────────────────────────────────

_server_thread        = None
_server_start_time    = None
_shutdown_event       = threading.Event()
_watchdog_thread      = None
_last_renewal_attempt = 0.0
_cert_domain          = None  # cached domain from active cert; None means self-signed

_TLS_VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


async def _serve_http_redirect(stop_event):
    """Run only the HTTP redirect server — used as a temporary listener during cert issuance."""
    from hypercorn.config import Config as HypercornConfig
    from hypercorn.asyncio import serve as hypercorn_serve

    cfg      = HypercornConfig()
    cfg.bind = ["0.0.0.0:80"]
    cfg.loglevel = "warning"

    async def trigger():
        await asyncio.get_event_loop().run_in_executor(None, stop_event.wait)

    await hypercorn_serve(redirect_app, cfg, shutdown_trigger=trigger)


async def _run_servers(stop_event):
    from hypercorn.config import Config as HypercornConfig
    from hypercorn.asyncio import serve as hypercorn_serve

    async def trigger():
        await asyncio.get_event_loop().run_in_executor(None, stop_event.wait)

    class _TLSConfig(HypercornConfig):
        def create_ssl_context(self):
            ctx = super().create_ssl_context()
            if ctx is None:
                return ctx
            ctx.minimum_version = _TLS_VERSIONS.get(config.tls_min_version, ssl.TLSVersion.TLSv1_2)
            if config.ciphers:
                ctx.set_ciphers(config.ciphers)
            return ctx

    cert_file = _resolve(config.cert_file)
    key_file  = _resolve(config.key_file)

    https_cfg          = _TLSConfig()
    https_cfg.bind     = [f"0.0.0.0:{config.port}"]
    https_cfg.certfile = cert_file
    https_cfg.keyfile  = key_file
    https_cfg.loglevel = "warning"
    async def run_https():
        try:
            await hypercorn_serve(https_app, https_cfg, shutdown_trigger=trigger)
        except Exception as e:
            log.error("HTTPS server error: %s", e)
            raise

    async def run_http_redirect():
        try:
            http_cfg          = HypercornConfig()
            http_cfg.bind     = ["0.0.0.0:80"]
            http_cfg.loglevel = "warning"
            await hypercorn_serve(redirect_app, http_cfg, shutdown_trigger=trigger)
        except OSError as e:
            log.warning("Could not bind to port 80: %s", e)
            print("Note: could not bind to port 80 (requires root). HTTP redirects unavailable.")

    await asyncio.gather(
        run_https(),
        run_http_redirect(),
        return_exceptions=True,
    )


def _server_running():
    return _server_thread is not None and _server_thread.is_alive()


def _cert_watchdog():
    """Auto-renew Let's Encrypt certs before expiry; detect externally-rotated certs."""
    global _last_renewal_attempt, _cert_domain
    while _server_running():
        time.sleep(60)
        if not _server_running():
            break

        cert_path = _resolve(config.cert_file)

        # Auto-renew: only for Let's Encrypt certs (domain known, not self-signed)
        domain = _domain_from_cert(cert_path)
        if domain:
            days = _cert_days_remaining(cert_path)
            if days is not None and days < 30:
                now = time.monotonic()
                if now - _last_renewal_attempt >= 3600:
                    _last_renewal_attempt = now
                    log.info("Certificate for %s expires in %d days — renewing", domain, days)
                    _run_acme(domain)
                    _cert_domain = domain
                    # Update _cert_mtime so the mtime check below doesn't fire again
                    try:
                        config._cert_mtime = os.path.getmtime(_resolve(config.cert_file))
                    except OSError:
                        pass
                continue

        # Externally-rotated cert: detect mtime change and restart
        try:
            mtime = os.path.getmtime(cert_path)
            if config._cert_mtime is not None and mtime != config._cert_mtime:
                log.info("Certificate changed on disk — reloading server")
                config._cert_mtime = mtime
                _reload_server()
        except OSError:
            pass


def start_server():
    global _server_thread, _server_start_time, _watchdog_thread, _cert_domain

    if _server_running():
        print("Server is already running.")
        return

    for fname in [config.serve_dir, config.cert_file, config.key_file]:
        if not fname:
            print("Not fully configured. Run 'config' to set up the server.")
            if "--serve" in sys.argv:
                sys.exit(1)
            return
        full_path = _resolve(fname)
        if not os.path.exists(full_path):
            print(f"File not found: {full_path}")
            if "--serve" in sys.argv:
                sys.exit(1)
            return

    _shutdown_event.clear()

    def run():
        asyncio.run(_run_servers(_shutdown_event))

    _server_thread = threading.Thread(target=run, daemon=True)
    _server_thread.start()
    time.sleep(0.5)

    if _watchdog_thread is None or not _watchdog_thread.is_alive():
        _watchdog_thread = threading.Thread(target=_cert_watchdog, daemon=True)
        _watchdog_thread.start()
    _server_start_time = time.monotonic()
    _cert_domain = _domain_from_cert(_resolve(config.cert_file))
    log.info("Server started on port %d", config.port)
    print(f"\nServing {config.serve_dir}/ at https://localhost:{config.port}\n")

    cert_path = _resolve(config.cert_file)
    days      = _cert_days_remaining(cert_path)
    if days is not None and days < 30:
        if days <= 0:
            print("Warning: SSL certificate has expired. Browsers will block visitors.")
            print("Run 'config' then 'cert' to renew it.\n")
            log.warning("SSL certificate has expired")
        else:
            print(f"Warning: SSL certificate expires in {days} days.")
            print("Run 'config' then 'cert' to renew it.\n")
            log.warning("SSL certificate expires in %d days", days)


def stop_server():
    global _server_thread, _server_start_time

    if not _server_running():
        return

    _shutdown_event.set()
    _server_thread.join(timeout=10)
    _server_thread     = None
    _server_start_time = None
    log.info("Server stopped")
    print("Session server stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# SHELL
# ─────────────────────────────────────────────────────────────────────────────

HELP = """
Commands:
  setup             — guided walkthrough for getting started
  config            — view and edit settings
  enable            — enable Servette as a system service
  disable           — remove the system service
  start             — start the server
  stop              — stop the server
  status            — show whether the server is running
  log [n]           — show the last n log entries
  update            — download the latest version of servette.py
  help              — show this message
  quit              — exit
"""

CONFIG_HELP = """
  Commands
  ──────────────────────────────────────
    dir       — directory to serve
    port      — HTTPS port
    cert      — SSL certificate and key
    username  — login username
    password  — login password
    email     — email address
    limits    — rate limits
    cache     — browser cache policy
    proxy     — trusted proxy IP for X-Forwarded-For
    tls       — minimum TLS version and cipher suites
    show      — show current settings
    back      — return to main shell
"""


def _service_file_exists():
    return os.path.exists(SERVICE_PATH)


def _service_is_active():
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "servette"],
            capture_output=True, text=True
        )
        return result.stdout.strip() == "active"
    except FileNotFoundError:
        return False


def _prompt(question):
    return input(f"  {question} [y/n]: ").strip().lower() == "y"


# ── Config sub-shell ──────────────────────────────────────────────────────────

def _config_show():
    def val(v):
        return v if v else "(not set)"

    cache_display = config.cache_policy
    if config.cache_policy == "max-age":
        cache_display += f" ({config.cache_max_age}s)"

    print()
    print("  Current Settings")
    print("  " + "─" * 38)
    print(f"  {'Directory':<22}  {val(config.serve_dir)}")
    print(f"  {'HTTPS port':<22}  {config.port}")
    print(f"  {'Certificate':<22}  {val(config.cert_file)}")
    print(f"  {'Key':<22}  {val(config.key_file)}")
    print(f"  {'Username':<22}  {val(config.username)}")
    print(f"  {'Password':<22}  {'(set)' if config.password_hash else '(not set)'}")
    print(f"  {'Email':<22}  {val(config.email)}")
    print(f"  {'Rate limit':<22}  {config.rate_limit} req/min")
    print(f"  {'Auth rate limit':<22}  {config.auth_rate_limit} fails/min")
    print(f"  {'Cache policy':<22}  {cache_display}")
    print(f"  {'Trusted proxy':<22}  {val(config.trusted_proxy)}")
    print(f"  {'TLS min version':<22}  {config.tls_min_version}")
    print(f"  {'Cipher suites':<22}  {config.ciphers or '(system default)'}")
    print()


def _config_dir():
    dirs = sorted(d for d in os.listdir(BASE_DIR) if os.path.isdir(os.path.join(BASE_DIR, d)) and not d.startswith("."))
    if dirs:
        print()
        for d in dirs:
            print(f"    {d}{' ←' if d == config.serve_dir else ''}")
    new_value = input(f"\n  serve_dir [{config.serve_dir}]: ").strip()
    if not new_value:
        print("  → unchanged")
        return
    path = _resolve(new_value)
    if not os.path.isdir(path):
        print(f"  → directory not found: {path}")
        return
    config.serve_dir = new_value
    config.save()
    print("  → saved")


def _config_port():
    current   = config.port
    new_value = input(f"  port [{current}]: ").strip()
    if new_value and new_value != str(current):
        try:
            port = int(new_value)
            if not (1 <= port <= 65535):
                raise ValueError
            config.port = port
            config.save()
            print("  → saved")
        except ValueError:
            print("  → invalid port number, unchanged")
    else:
        print("  → unchanged")


def _config_cert():
    cert_path = _resolve(config.cert_file)
    if os.path.exists(cert_path):
        days = _cert_days_remaining(cert_path)
        if days is not None and days <= 0:
            print("  Current certificate has expired.")
        elif days is not None:
            print(f"  Current certificate expires in {days} days.")
        else:
            print(f"  Current: {config.cert_file}")
    print()

    domain = input("  Domain name (press Enter to skip and use a self-signed certificate): ").strip()

    if domain:
        _run_acme(domain)
    else:
        cert_path = _resolve(config.cert_file or "cert.pem")
        key_path  = _resolve(config.key_file or "key.pem")
        print("  Generating self-signed certificate...")
        _generate_self_signed_cert(cert_path, key_path)
        config.cert_file = config.cert_file or "cert.pem"
        config.key_file  = config.key_file or "key.pem"
        config.save()
        print("  → self-signed certificate generated.")
        print("  Note: your browser will show a security warning until you add a domain.\n")
        if _server_running() or _service_is_active():
            _reload_server()


def _config_username():
    current   = config.username
    new_value = input(f"  username [{current}]: ").strip()
    if new_value == "" and current != "":
        config.username      = ""
        config.password_hash = ""
        config.password_salt = ""
        config.save()
        print("  → auth disabled, password cleared")
    elif new_value and new_value != current:
        config.username = new_value
        config.save()
        print("  → saved")
    else:
        print("  → unchanged")


def _config_password():
    if not config.username:
        print("  Set a username first.")
        return
    pwd = getpass.getpass("  password: ")
    if not pwd:
        print("  → unchanged")
        return
    confirm = getpass.getpass("  confirm: ")
    if pwd != confirm:
        print("  → passwords do not match, unchanged")
        return
    config.password_hash, config.password_salt = _hash_password(pwd)
    config.save()
    print("  → saved")


def _config_limits():
    current   = config.rate_limit
    new_value = input(f"  Requests per minute per IP\n  rate_limit [{current}]: ").strip()
    if new_value and new_value != str(current):
        try:
            config.rate_limit = int(new_value)
            config.save()
            print("  → saved")
        except ValueError:
            print("  → invalid number, unchanged")
    else:
        print("  → unchanged")

    current   = config.auth_rate_limit
    new_value = input(f"  Failed login attempts per minute per IP\n  auth_rate_limit [{current}]: ").strip()
    if new_value and new_value != str(current):
        try:
            config.auth_rate_limit = int(new_value)
            config.save()
            print("  → saved")
        except ValueError:
            print("  → invalid number, unchanged")
    else:
        print("  → unchanged")


def _config_email():
    current   = config.email
    new_value = input(f"  email [{current}]: ").strip()
    if new_value == current or not new_value:
        print("  → unchanged")
        return
    config.email = new_value
    config.save()
    print("  → saved")


def _config_cache():
    print(f"\n  Current: {config.cache_policy}" +
          (f" ({config.cache_max_age}s)" if config.cache_policy == "max-age" else "") + "\n")
    print("    no-store  — never cache, always download fresh")
    print("    no-cache  — cache but always revalidate (ETag makes this a quick check)")
    print("    max-age   — trust cached copy for N seconds without checking\n")
    choice = input("  cache_policy [no-store / no-cache / max-age]: ").strip().lower()
    if not choice:
        print("  → unchanged")
        return
    if choice not in ("no-store", "no-cache", "max-age"):
        print("  → invalid option, unchanged")
        return
    config.cache_policy = choice
    if choice == "max-age":
        age_str = input(f"  cache_max_age seconds [{config.cache_max_age}]: ").strip()
        if age_str:
            try:
                config.cache_max_age = int(age_str)
            except ValueError:
                print("  → invalid number, keeping current max-age")
    config.save()
    print("  → saved")


def _config_trusted_proxy():
    current = config.trusted_proxy
    print(f"\n  Current: {current or '(not set — X-Forwarded-For ignored)'}")
    print("  Set to the IP of your reverse proxy to trust its X-Forwarded-For header.")
    print("  Leave blank to ignore XFF entirely (correct when Servette faces the internet directly).\n")
    new_value = input("  trusted_proxy IP: ").strip()
    if new_value == current:
        print("  → unchanged")
        return
    config.trusted_proxy = new_value
    config.save()
    print("  → saved" if new_value else "  → cleared, X-Forwarded-For will be ignored")


def _config_tls():
    print(f"\n  Current: TLS {config.tls_min_version}, ciphers: {config.ciphers or '(system default)'}\n")
    print("    1.2 — TLS 1.2 minimum, TLS 1.3 also accepted (default)")
    print("    1.3 — TLS 1.3 only; drops support for older clients\n")
    ver = input("  tls_min_version [1.2 / 1.3]: ").strip()
    if ver and ver not in ("1.2", "1.3"):
        print("  → invalid, unchanged")
    elif ver and ver != config.tls_min_version:
        config.tls_min_version = ver
        config.save()
        print("  → saved (takes effect on next server start)")
    else:
        print("  → unchanged")

    print(f"\n  Current cipher suites: {config.ciphers or '(system default)'}")
    print("  OpenSSL cipher string, e.g.: ECDHE+AESGCM:DHE+AESGCM")
    print("  Leave blank to use the system default (recommended unless you have specific requirements).\n")
    ciphers = input("  ciphers: ").strip()
    if ciphers == config.ciphers:
        print("  → unchanged")
        return
    config.ciphers = ciphers
    config.save()
    print("  → saved (takes effect on next server start)" if ciphers else "  → cleared, system default will be used")


def cmd_config():
    _config_show()
    print(CONFIG_HELP)

    while True:
        try:
            raw = input("  config> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue

        cmd = raw.split()[0].lower()

        if cmd == "show":
            _config_show()
        elif cmd in ("dir", "directory"):
            _config_dir()
        elif cmd == "port":
            _config_port()
        elif cmd == "cert":
            _config_cert()
        elif cmd == "username":
            _config_username()
        elif cmd == "password":
            _config_password()
        elif cmd == "email":
            _config_email()
        elif cmd == "limits":
            _config_limits()
        elif cmd == "cache":
            _config_cache()
        elif cmd in ("proxy", "trusted_proxy"):
            _config_trusted_proxy()
        elif cmd == "tls":
            _config_tls()
        elif cmd in ("back", "done", "exit", "quit"):
            break
        elif cmd in ("help", "?"):
            print(CONFIG_HELP)
        else:
            print(f"  Unknown setting: {cmd}")
            print(CONFIG_HELP)


# ── Service management ────────────────────────────────────────────────────────

def cmd_install():
    updating      = _service_file_exists()
    servette_path = os.path.abspath(__file__)
    python_path   = _VENV_PY if os.path.exists(_VENV_PY) else subprocess.run(
        ["which", "python3"], capture_output=True, text=True
    ).stdout.strip()

    service = f"""[Unit]
Description=Servette — The Simple Secure Server
After=network.target

[Service]
ExecStart={python_path} {servette_path} --serve
Restart=always
RestartSec=3
StandardInput=null
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""

    try:
        with open(SERVICE_PATH, "w") as f:
            f.write(service)

        subprocess.run(["systemctl", "daemon-reload"],      check=True)
        subprocess.run(["systemctl", "enable", "servette"], check=True, capture_output=True)

        if updating:
            print("Service file updated.")
            if _service_is_active():
                print("Run 'stop' then 'start' to apply the changes.")
        else:
            print("Servette enabled as a system service.")
            print("It will start automatically on boot and survive SSH disconnects.")
        log.info("Enabled as systemd service")

        if _server_running():
            if _prompt("Server is running in session only. Restart as a service now?"):
                stop_server()
                subprocess.run(["systemctl", "start", "servette"], check=True, capture_output=True)
                print("Server started as a service.")
                log.info("Service started after enable")
                cmd_status()

    except PermissionError:
        print("Error: enable requires sudo. Run: sudo python3 servette.py")
    except FileNotFoundError:
        print("Error: enable requires a Linux server with systemd.")
    except subprocess.CalledProcessError as e:
        print(f"Error during enable: {e}")


def cmd_uninstall():
    if not _service_file_exists():
        cmd_status()
        return

    try:
        if _service_is_active():
            subprocess.run(["systemctl", "stop",    "servette"], check=True, capture_output=True)
        subprocess.run(["systemctl", "disable", "servette"], check=True, capture_output=True)
        os.remove(SERVICE_PATH)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        print("Servette service disabled.")
        log.info("Systemd service disabled")
    except PermissionError:
        print("Error: disable requires sudo. Run: sudo python3 servette.py")
    except FileNotFoundError:
        print("Error: disable requires a Linux server with systemd.")
    except subprocess.CalledProcessError as e:
        print(f"Error during disable: {e}")


def cmd_start():
    if _service_file_exists():
        if _service_is_active():
            cmd_status()
        else:
            try:
                subprocess.run(["systemctl", "start", "servette"], check=True, capture_output=True)
                log.info("Service started")
                cmd_status()
            except PermissionError:
                print("Error: start requires sudo. Run: sudo python3 servette.py")
            except FileNotFoundError:
                print("Error: start requires a Linux server with systemd.")
            except subprocess.CalledProcessError as e:
                print(f"Error starting service: {e}")
    else:
        start_server()
        if _server_running():
            print("Running in session only — server will stop when you quit.")
            if _prompt("Install as a permanent service?"):
                cmd_install()


def cmd_stop():
    stopped = False

    if _service_is_active():
        try:
            subprocess.run(["systemctl", "stop", "servette"], check=True, capture_output=True)
            print("Service stopped.")
            log.info("Service stopped")
            stopped = True
        except PermissionError:
            print("Error: stop requires sudo. Run: sudo python3 servette.py")
        except FileNotFoundError:
            print("Error: stop requires a Linux server with systemd.")
        except subprocess.CalledProcessError as e:
            print(f"Error stopping service: {e}")

    if _server_running():
        stop_server()
        stopped = True

    if not stopped:
        cmd_status()


# ── Certificate management ────────────────────────────────────────────────────

def _spin(message, stop_event):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    i = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\r  {frames[i % len(frames)]}  {message}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write(f"\r  {' ' * (len(message) + 5)}\r")
    sys.stdout.flush()


def _generate_self_signed_cert(cert_path, key_path):
    """Generate a self-signed certificate and write it to cert_path/key_path."""
    import ipaddress as _ipaddress
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    key  = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "servette")])

    san = [_x509.DNSName("localhost"), _x509.IPAddress(_ipaddress.IPv4Address("127.0.0.1"))]
    try:
        import socket as _socket
        ip = _socket.gethostbyname(_socket.gethostname())
        san.append(_x509.IPAddress(_ipaddress.IPv4Address(ip)))
    except Exception:
        pass

    cert = (
        _x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(_x509.SubjectAlternativeName(san), critical=False)
        .sign(key, _hashes.SHA256())
    )

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            _serialization.Encoding.PEM,
            _serialization.PrivateFormat.TraditionalOpenSSL,
            _serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(_serialization.Encoding.PEM))

    log.info("Generated self-signed certificate at %s", cert_path)


def _wait_for_port_free(port, timeout=15):
    import socket as _socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                s.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
            return True
        except OSError:
            time.sleep(0.5)
    log.warning("Port %d did not free up within %ds", port, timeout)
    return False


def _reload_server():
    """Reload the server to pick up a new certificate."""
    if _service_is_active():
        try:
            subprocess.run(["systemctl", "restart", "servette"], check=True, capture_output=True)
            print("  Server restarted.")
        except Exception as e:
            print(f"  Could not restart service: {e}")
    elif _server_running():
        stop_server()
        _wait_for_port_free(config.port)
        start_server()


def _run_acme(domain):
    """Get a trusted SSL certificate from Let's Encrypt using the acme library."""
    from acme import client as _acme_client, challenges as _challenges, messages as _messages
    import josepy as _jose
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _serialization

    ACME_URL        = "https://acme-v02.api.letsencrypt.org/directory"
    ACCOUNT_KEY_FILE = os.path.join(BASE_DIR, ".acme-account.pem")
    CERTS_DIR       = os.path.join(BASE_DIR, "certs", domain)

    print(f"\nGetting a trusted SSL certificate for {domain}...")
    print("Make sure your domain points to this server's IP first.\n")

    os.makedirs(os.path.join(ACME_WEBROOT, ".well-known", "acme-challenge"), exist_ok=True)
    os.makedirs(CERTS_DIR, exist_ok=True)

    # Load or generate ACME account key
    if os.path.exists(ACCOUNT_KEY_FILE):
        with open(ACCOUNT_KEY_FILE, "rb") as f:
            account_key = _jose.JWKRSA.load(f.read())
    else:
        rsa_key     = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        account_key = _jose.JWKRSA(key=rsa_key)
        with open(ACCOUNT_KEY_FILE, "wb") as f:
            f.write(rsa_key.private_bytes(
                _serialization.Encoding.PEM,
                _serialization.PrivateFormat.TraditionalOpenSSL,
                _serialization.NoEncryption()
            ))
        os.chmod(ACCOUNT_KEY_FILE, 0o600)

    # Start a temporary HTTP listener on port 80 if the main server isn't running
    http_started_here = False
    tmp_stop          = None
    tmp_thread        = None
    if not _server_running():
        tmp_stop   = threading.Event()
        tmp_thread = threading.Thread(
            target=lambda: asyncio.run(_serve_http_redirect(tmp_stop)), daemon=True
        )
        tmp_thread.start()
        time.sleep(0.5)
        http_started_here = True

    ACME_RETRIES = 3
    last_error   = None

    for attempt in range(1, ACME_RETRIES + 1):
        stop = threading.Event()
        if sys.stdout.isatty():
            label = f"Requesting certificate for {domain}..." if attempt == 1 else f"Retry {attempt - 1}/{ACME_RETRIES - 1}..."
            t = threading.Thread(target=_spin, args=(label, stop), daemon=True)
            t.start()
        else:
            t = None

        token_path = None
        try:
            net       = _acme_client.ClientNetwork(account_key, user_agent="servette/1.0")
            directory = _messages.Directory.from_json(net.get(ACME_URL).json())
            ac        = _acme_client.ClientV2(directory, net)

            # Register account (no-op if already registered)
            try:
                ac.new_account(_messages.NewRegistration.from_data(
                    email=config.email if config.email else None,
                    terms_of_service_agreed=True
                ))
            except Exception:
                pass

            # Generate domain key and CSR
            domain_key     = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
            domain_key_pem = domain_key.private_bytes(
                _serialization.Encoding.PEM,
                _serialization.PrivateFormat.TraditionalOpenSSL,
                _serialization.NoEncryption()
            )
            csr_pem = (
                _x509.CertificateSigningRequestBuilder()
                .subject_name(_x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, domain)]))
                .add_extension(_x509.SubjectAlternativeName([_x509.DNSName(domain)]), critical=False)
                .sign(domain_key, _hashes.SHA256())
                .public_bytes(_serialization.Encoding.PEM)
            )

            # Order certificate and answer HTTP-01 challenge
            order = ac.new_order(csr_pem)
            for authz in order.authorizations:
                for challenge in authz.body.challenges:
                    if isinstance(challenge.chall, _challenges.HTTP01):
                        token      = challenge.chall.encode("token")
                        key_auth   = challenge.chall.key_authorization(account_key)
                        token_path = os.path.join(ACME_WEBROOT, ".well-known", "acme-challenge", token)
                        with open(token_path, "w") as f:
                            f.write(key_auth)
                        ac.answer_challenge(challenge, challenge.chall.response(account_key))
                        break

            finalized = ac.poll_and_finalize(order)

            cert_path = os.path.join(CERTS_DIR, "fullchain.pem")
            key_path  = os.path.join(CERTS_DIR, "privkey.pem")

            with open(cert_path, "w") as f:
                f.write(finalized.fullchain_pem)
            with open(key_path, "wb") as f:
                f.write(domain_key_pem)
            os.chmod(key_path, 0o600)

            stop.set()
            if t:
                t.join()

            config.cert_file = cert_path
            config.key_file  = key_path
            config.save()
            global _cert_domain
            _cert_domain = domain

            print(f"  Certificate issued for {domain}.")
            log.info("ACME certificate issued for %s", domain)

            if _server_running() or _service_is_active():
                print("  Reloading server...")
                _reload_server()
            last_error = None
            break

        except Exception as e:
            last_error = e
            stop.set()
            if t:
                t.join()
            if token_path and os.path.exists(token_path):
                os.remove(token_path)
            token_path = None
            if attempt < ACME_RETRIES:
                delay = 5 * attempt
                log.warning("ACME attempt %d/%d failed for %s: %s — retrying in %ds", attempt, ACME_RETRIES, domain, e, delay)
                time.sleep(delay)
        finally:
            if token_path and os.path.exists(token_path):
                os.remove(token_path)

    if last_error:
        print(f"  Error getting certificate: {last_error}")
        log.error("ACME failed for %s after %d attempts: %s", domain, ACME_RETRIES, last_error)

    if http_started_here and tmp_stop:
        tmp_stop.set()
        if tmp_thread:
            tmp_thread.join(timeout=5)


# ── Log, status, update, helpers ─────────────────────────────────────────────

UPDATE_URL = "https://raw.githubusercontent.com/andy-emerson/servette/main/servette.py"

def cmd_update():
    servette_path = os.path.abspath(__file__)
    stop = threading.Event()
    t    = threading.Thread(target=_spin, args=("Checking for update...", stop), daemon=True)
    t.start()
    try:
        new_source = urllib.request.urlopen(UPDATE_URL, timeout=15).read()
    except Exception as e:
        stop.set(); t.join()
        print(f"  Update failed: {e}")
        return
    stop.set(); t.join()

    compile(new_source, "servette.py", "exec")  # raises SyntaxError if invalid

    tmp_path = servette_path + ".new"
    with open(tmp_path, "wb") as f:
        f.write(new_source)
    os.chmod(tmp_path, os.stat(servette_path).st_mode)
    os.replace(tmp_path, servette_path)

    print("  Updated. Restart to run the new version ('stop' then 'start', or 'sudo systemctl restart servette').")


def cmd_log(n=20):
    try:
        result = subprocess.run(
            ["journalctl", "-u", "servette", "-o", "cat", "-n", str(n), "--no-pager"],
            capture_output=True, text=True
        )
        output = result.stdout or result.stderr
        print(output, end="")
    except FileNotFoundError:
        print("journalctl not found. Is this a systemd system?")


def _load_cert(cert_path):
    """Return a cryptography X.509 certificate object, or None on failure."""
    try:
        from cryptography import x509 as _x509
        with open(cert_path, "rb") as f:
            return _x509.load_pem_x509_certificate(f.read())
    except Exception:
        return None


def _domain_from_cert(cert_path):
    if not cert_path:
        return None
    # Fast path: parse domain from our certs directory structure
    marker = "/certs/"
    if marker in cert_path:
        part = cert_path.split(marker)[1].split("/")[0]
        if part:
            return part
    cert = _load_cert(cert_path)
    if cert is None:
        return None
    def _is_real_domain(s):
        if s in ("localhost", "servette"):
            return False
        try:
            ipaddress.ip_address(s)
            return False  # it's an IP, not a domain
        except ValueError:
            return bool(s)

    try:
        from cryptography import x509 as _x509
        san = cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
        for name in san.value.get_values_for_type(_x509.DNSName):
            if _is_real_domain(name):
                return name
    except Exception:
        pass
    try:
        from cryptography.x509.oid import NameOID as _NameOID
        cn = cert.subject.get_attributes_for_oid(_NameOID.COMMON_NAME)
        if cn and _is_real_domain(cn[0].value):
            return cn[0].value
    except Exception:
        pass
    return None


def _cert_days_remaining(cert_path):
    cert = _load_cert(cert_path)
    if cert is None:
        return None
    try:
        expiry = cert.not_valid_after_utc
    except AttributeError:
        expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return (expiry - datetime.datetime.now(datetime.timezone.utc)).days


def _format_uptime(seconds):
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    elif s < 3600:
        return f"{s // 60}m {s % 60}s"
    elif s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    else:
        return f"{s // 86400}d {(s % 86400) // 3600}h"


def cmd_status():
    service_active = _service_is_active()
    running        = service_active or _server_running()
    domain         = _domain_from_cert(config.cert_file)
    url            = f"https://{domain}" if domain else f"https://localhost:{config.port}"
    cert_path      = _resolve(config.cert_file)
    W              = 8

    print()
    print("● Running" if running else "○ Stopped")

    if running:
        mode = "System service" if service_active else "Session only"
        print(f"  {'Mode':<{W}} {mode}")

    print(f"  {'URL':<{W}} {url}")
    print(f"  {'Directory':<{W}} {config.serve_dir or '(not configured)'}")
    print(f"  {'Auth':<{W}} {'enabled' if config.username else 'disabled'}")

    days = _cert_days_remaining(cert_path)
    if days is not None:
        cert_str = "expired" if days <= 0 else f"{days} days remaining"
        print(f"  {'Cert':<{W}} {cert_str}")

    if running:
        if service_active:
            try:
                result = subprocess.run(
                    ["systemctl", "show", "servette",
                     "--property=ActiveEnterTimestampMonotonic,MemoryCurrent,MainPID"],
                    capture_output=True, text=True
                )
                props = dict(
                    line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line
                )
                mono = props.get("ActiveEnterTimestampMonotonic", "")
                if mono and mono != "0":
                    try:
                        with open("/proc/uptime") as f:
                            boot_elapsed = float(f.read().split()[0])
                        elapsed = boot_elapsed - int(mono) / 1_000_000
                        if elapsed >= 0:
                            print(f"  {'Uptime':<{W}} {_format_uptime(elapsed)}")
                    except Exception:
                        pass
                mem = props.get("MemoryCurrent", "")
                if mem and mem.isdigit() and int(mem) > 0:
                    print(f"  {'Memory':<{W}} {int(mem) / (1024 * 1024):.1f} MB")
                pid = props.get("MainPID", "")
                if pid and pid != "0":
                    print(f"  {'PID':<{W}} {pid}")
            except Exception:
                pass
        else:
            if _server_start_time is not None:
                print(f"  {'Uptime':<{W}} {_format_uptime(time.monotonic() - _server_start_time)}")
            try:
                with open("/proc/self/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            print(f"  {'Memory':<{W}} {int(line.split()[1]) / 1024:.1f} MB")
                            break
            except Exception:
                pass
            print(f"  {'PID':<{W}} {os.getpid()}")

    print()


# ── Setup wizard ──────────────────────────────────────────────────────────────

def cmd_setup():
    stop = threading.Event()
    t    = threading.Thread(target=_spin, args=("Detecting public IP...", stop), daemon=True)
    t.start()
    try:
        public_ip = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode()
    except Exception:
        public_ip = "your.server.ip"
    finally:
        stop.set()
        t.join()

    print("\n───────────────────────────────────────────────────")
    print("  Getting Started")
    print("───────────────────────────────────────────────────")

    print()
    print("  Step 1 — Choose your directory")
    print("  Copy your directory to the same location as servette.py.")
    _config_dir()

    print()
    print("  Step 2 — Password protection (optional)")
    print("  Leave username blank to disable. Press Enter to keep current value.")
    _config_username()
    if config.username:
        _config_password()

    print()
    print("  Step 3 — SSL certificate")
    print(f"  Your server's IP address is {public_ip}.")
    print("  Enter a domain to get a trusted certificate, or press Enter for self-signed.\n")
    _config_cert()

    print()
    if _prompt("Ready to start?"):
        cmd_install()
        cmd_start()
    else:
        print("  Run 'start' when you're ready.")


# ── Main shell loop ───────────────────────────────────────────────────────────

def shell():
    print("\n───────────────────────────────────────────────────")
    print("  Servette — The Simple Secure Server")
    print("───────────────────────────────────────────────────")
    print(HELP)

    while True:
        try:
            raw = input("servette> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nType 'quit' to exit.")
            continue

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        if cmd == "setup":
            cmd_setup()
        elif cmd == "config":
            cmd_config()
        elif cmd == "enable":
            cmd_install()
        elif cmd == "disable":
            cmd_uninstall()
        elif cmd == "start":
            cmd_start()
        elif cmd == "stop":
            cmd_stop()
        elif cmd == "status":
            cmd_status()
        elif cmd == "log":
            try:
                cmd_log(int(args[0]) if args else 20)
            except ValueError:
                print("Usage: log [number]")
        elif cmd == "update":
            cmd_update()
        elif cmd in ("help", "?"):
            print(HELP)
        elif cmd in ("quit", "exit"):
            stop_server()
            print("Goodbye.")
            break
        else:
            print(f"Unknown command: {cmd}. Type 'help' for a list of commands.")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _bootstrap()  # no-op if already in venv; otherwise re-execs into venv

    if "--serve" in sys.argv:
        start_server()
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            stop_server()
    else:
        shell()
