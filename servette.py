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

__version__ = "0.26.178"

import base64
import collections
import datetime
import getpass
import gzip
import hashlib
import hmac
import http.server
import ipaddress
import json
import logging
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
import urllib.request
from urllib.parse import unquote


BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
_VENV_DIR   = os.path.join(BASE_DIR, ".servette-env")
_VENV_PY    = os.path.join(_VENV_DIR, "bin", "python3")

SERVICE_PATH = "/etc/systemd/system/servette.service"
ACME_WEBROOT = "/var/lib/letsencrypt/webroot"


# ─────────────────────────────────────────────────────────────────────────────
# SERVER
#
# Handles all incoming HTTP(S) requests. Contains config, rate limiting, the file
# cache, the request handler, and the threaded HTTP servers (HTTPS + port-80 redirect).
# ─────────────────────────────────────────────────────────────────────────────


# ── Config ────────────────────────────────────────────────────────────────────


def _resolve(path):
    """Return path as-is if absolute, otherwise anchor it to BASE_DIR."""
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)


# scrypt cost parameters — OWASP baseline (N=2**14, r=8, p=1 ≈ 16 MB per hash).
# scrypt is memory-hard: each guess must hold that much RAM, denying an attacker
# who steals the hash the cheap GPU parallelism that PBKDF2 (CPU-hard) allows.
# ~16 MB and ~30 ms per check stays comfortable even on a Raspberry Pi.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def _hash_password(password):
    """Hash a password with a random salt using scrypt (memory-hard)."""
    salt = os.urandom(16)
    key  = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return key.hex(), salt.hex()


def _check_password(submitted, stored_hash, stored_salt):
    """Return True if submitted matches the stored hash."""
    if not stored_hash or not stored_salt:
        return False
    try:
        salt = bytes.fromhex(stored_salt)
        key  = hashlib.scrypt(submitted.encode("utf-8"), salt=salt,
                              n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
        return hmac.compare_digest(key.hex(), stored_hash)
    except Exception:
        return False


class Config:
    """Holds all Servette settings and handles reading/writing servette.toml."""

    CONFIG_FILE = os.path.join(BASE_DIR, "servette.toml")

    def __init__(self):
        self._mtime = None
        self._load()

    def _load(self):
        data = {}
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, "rb") as f:
                    data = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                print(f"Error: servette.toml is not valid TOML ({e}).")
                print(f"Fix or delete {self.CONFIG_FILE} and try again.")
                sys.exit(1)

        self.serve_dir       = data.get("serve_dir",       data.get("html_file", "site"))
        self.port            = data.get("port",            443)
        self.cert_file       = data.get("cert_file",       "cert.pem")
        self.key_file        = data.get("key_file",        "key.pem")
        self.username        = data.get("username",        "")
        self.password_hash   = data.get("password_hash",   "")
        self.password_salt   = data.get("password_salt",   "")
        self.rate_limit      = data.get("rate_limit",      120)
        self.auth_rate_limit = data.get("auth_rate_limit", 6)
        self.cache_policy       = data.get("cache_policy",       "no-cache")
        self.cache_max_age      = data.get("cache_max_age",      3600)
        self.cache_size_mb      = data.get("cache_size_mb",      128)
        self.email              = data.get("email",              "")
        self.trusted_proxy      = data.get("trusted_proxy",      "")
        self.tls_min_version    = data.get("tls_min_version",    "1.2")
        self.ciphers            = data.get("ciphers",            "")
        self.csp                = data.get("csp",                "default-src 'self' https: data: 'unsafe-inline'; object-src 'none'; base-uri 'self'")
        self.permissions_policy = data.get("permissions_policy", "camera=(), microphone=(), usb=(), midi=(), serial=()")

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
        def s(v):
            return '"' + str(v).replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace('"', '\\"') + '"'

        content = f"""\
# Servette configuration — https://github.com/andy-emerson/servette

serve_dir = {s(self.serve_dir)}
port = {self.port}
cert_file = {s(self.cert_file)}
key_file = {s(self.key_file)}

# Leave username blank to disable password protection
username = {s(self.username)}

# Rate limiting (requests per minute per IP)
rate_limit = {self.rate_limit}
auth_rate_limit = {self.auth_rate_limit}

# Browser cache policy: no-store, no-cache, or max-age
cache_policy = {s(self.cache_policy)}
cache_max_age = {self.cache_max_age}
# In-memory file cache limit in MB — reduce on constrained hardware
cache_size_mb = {self.cache_size_mb}

# Let's Encrypt registration email and optional reverse proxy IP
email = {s(self.email)}
trusted_proxy = {s(self.trusted_proxy)}

# TLS settings
tls_min_version = {s(self.tls_min_version)}
ciphers = {s(self.ciphers)}

# Security headers — use config shell to adjust
csp = {s(self.csp)}
permissions_policy = {s(self.permissions_policy)}

# Machine-generated — do not edit by hand
password_hash = {s(self.password_hash)}
password_salt = {s(self.password_salt)}
"""
        # Write to a temp file in the same directory (mkstemp creates it 0o600), then
        # atomically replace, so a crash mid-write can't truncate the live config.
        d = os.path.dirname(self.CONFIG_FILE) or "."
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".servette.toml.")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.replace(tmp, self.CONFIG_FILE)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            self._mtime = os.path.getmtime(self.CONFIG_FILE)
        except OSError:
            pass


# Config is a module-level singleton. Dependency injection (passing config into
# every function) is the textbook alternative, but the stdlib request handlers have
# fixed signatures and cannot accept extra arguments. In a single-file server that is
# always run as a process, the global is the right call.
config = Config()


# ── Logging ───────────────────────────────────────────────────────────────────
#
# In service mode, logs go to systemd journal (StandardOutput=journal).
# In interactive mode, warnings and errors go to the terminal.

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


def _c(text, color):
    """Wrap text in an ANSI color for interactive (TTY) output; plain text otherwise."""
    codes = {"green": "32", "red": "31", "yellow": "33"}
    if color not in codes or not sys.stdout.isatty():
        return text
    return f"\033[{codes[color]}m{text}\033[0m"


# ── Rate limiter ──────────────────────────────────────────────────────────────
#
# Uses threading.Lock because the critical section is in-memory deque
# manipulation — not I/O — so it's held only briefly and stays barely contended
# even when many connection threads hit it at once.

RATE_WINDOW  = 60      # seconds
_RATE_IP_CAP = 10_000  # max IPs tracked per dict; bounds memory under IP-flood attacks

_request_times   = {}
_auth_fail_times = {}
_rate_lock       = threading.Lock()


def _normalize_ip(ip):
    """Normalize IPv6-mapped IPv4 addresses so both forms bucket together.

    Uses ipaddress so every mapped spelling collapses to the same key — the dotted
    ::ffff:1.2.3.4 and the hex ::ffff:c0a8:0101 are the same address and must share a
    rate-limit bucket. Non-addresses (e.g. "unknown", junk XFF) pass through as-is."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6 and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return ip


def _rate_sweep(stop_event):
    """Background thread: evict stale IPs and enforce the IP cap every 30 seconds."""
    while not stop_event.wait(timeout=30):
        with _rate_lock:
            now    = time.monotonic()
            cutoff = now - RATE_WINDOW
            for tracker in (_request_times, _auth_fail_times):
                stale = [k for k, v in tracker.items() if not v or v[-1] < cutoff]
                for k in stale:
                    del tracker[k]
                if len(tracker) > _RATE_IP_CAP:
                    for k in sorted(tracker, key=lambda ip: tracker[ip][-1])[:len(tracker) - _RATE_IP_CAP]:
                        del tracker[k]


def _rate_limit_exceeded(tracker, ip, limit):
    """Record this request for ip and return True if the limit has been exceeded."""
    with _rate_lock:
        now    = time.monotonic()
        cutoff = now - RATE_WINDOW

        timestamps = tracker.get(ip)
        if timestamps is None:
            timestamps = collections.deque()
            tracker[ip] = timestamps
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        timestamps.append(now)

        return len(timestamps) > limit


# ── File cache ────────────────────────────────────────────────────────────────

_file_cache       = collections.OrderedDict()
_file_cache_lock  = threading.Lock()
_file_cache_bytes = 0

# Text-like types worth gzipping. Already-compressed formats (images, woff/woff2,
# pdf, video, archives) gain nothing, so they're served and stored uncompressed.
_COMPRESSIBLE_EXTS = {
    ".html", ".css", ".js", ".json", ".svg", ".txt", ".xml", ".webmanifest", ".ttf",
}


def _entry_bytes(entry):
    return len(entry["raw"]) + (len(entry["compressed"]) if entry["compressed"] else 0)


def _get_cached_file(path):
    """Return (raw, compressed_or_None, etag), reloading only if the file changed.

    compressed is None for already-compressed types; a file too large to fit in
    the cache is served raw and not stored, so it can't purge everything else.
    """
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None, None, None

    with _file_cache_lock:
        entry = _file_cache.get(path)
        if entry and entry["mtime"] == mtime:
            return entry["raw"], entry["compressed"], entry["etag"]

    # Two threads can race here: both miss the cache check and both read the file. The fix is
    # either holding the lock during I/O (serializes all requests on misses) or double-checked
    # locking (adds complexity for an idempotent result). Both are worse than the rare duplicate read.
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None, None, None

    etag      = '"' + hashlib.sha256(raw).hexdigest()[:16] + '"'
    cache_max = config.cache_size_mb * 1024 * 1024

    # A file too big to cache is re-read on every request regardless; don't also
    # re-compress it each time — serve it raw (uncompressed) and uncached. The etag
    # is still cheap and lets big files benefit from 304s.
    if len(raw) > cache_max:
        return raw, None, etag

    ext        = os.path.splitext(path)[1].lower()
    compressed = gzip.compress(raw, compresslevel=6) if ext in _COMPRESSIBLE_EXTS else None
    new_entry  = {"mtime": mtime, "raw": raw, "compressed": compressed, "etag": etag}

    if _entry_bytes(new_entry) > cache_max:
        return raw, compressed, etag  # rare: raw fit but raw+gzip doesn't — serve, don't store

    with _file_cache_lock:
        global _file_cache_bytes
        old = _file_cache.pop(path, None)
        if old:
            _file_cache_bytes -= _entry_bytes(old)
        _file_cache[path] = new_entry
        _file_cache_bytes += _entry_bytes(new_entry)
        if _file_cache_bytes > cache_max:
            log.warning("File cache full (%d MB) — evicting oldest entries", config.cache_size_mb)
        while _file_cache_bytes > cache_max and _file_cache:
            _, evicted = _file_cache.popitem(last=False)
            _file_cache_bytes -= _entry_bytes(evicted)

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
    """Resolve a URL path to an absolute file path within serve_dir. Returns (None, 403) on traversal, (None, 404) if not found."""
    serve_dir = os.path.realpath(_resolve(config.serve_dir))
    clean = unquote(url_path.split("?")[0])
    rel   = os.path.normpath(clean.lstrip("/"))
    if rel == ".":
        rel = ""  # normpath("") returns "." — treat root request as empty relative path
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


def _parse_range(header, total):
    """Parse a single HTTP byte range against a body of `total` bytes. Returns
    (start, end) inclusive, "invalid" if unsatisfiable, or None if absent or
    unsupported (multi-range / malformed) — caller then serves the full body."""
    if not header.startswith("bytes="):
        return None
    spec = header[len("bytes="):].strip()
    if "," in spec or "-" not in spec:
        return None
    start_s, _, end_s = spec.partition("-")
    try:
        if start_s == "":
            n = int(end_s)                       # suffix: the last n bytes
            if n <= 0:
                return "invalid"
            start, end = max(0, total - n), total - 1
        else:
            start = int(start_s)
            end   = min(int(end_s), total - 1) if end_s else total - 1
    except ValueError:
        return None
    if total == 0 or start > end or start >= total:
        return "invalid"
    return (start, end)


def _security_headers():
    """Security headers sent on every HTTPS response — success or error."""
    headers = [
        (b"x-frame-options",        b"DENY"),
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy",        b"no-referrer"),
    ]
    if config.csp:
        headers.append((b"content-security-policy", config.csp.encode()))
    if config.permissions_policy:
        headers.append((b"permissions-policy", config.permissions_policy.encode()))
    if _cert_domain:
        headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
    return headers


# ── HTTP server ───────────────────────────────────────────────────────────────


def _handle_request(method, url_path, headers, raw_ip):
    """The request core. Given the method, URL path, the parsed request headers (a
    case-insensitive mapping — an http.client.HTTPMessage in production), and the raw
    client IP, returns (status, headers, body), with security headers on every
    response and the body blanked for HEAD. All the decision logic lives here; the
    handler just feeds it what http.server parsed and sends the result back."""
    ip = _normalize_ip(raw_ip)
    if config.trusted_proxy:
        xff = headers.get("X-Forwarded-For", "")
        # Rightmost XFF value is what the single trusted proxy appended.
        # Correct for one-hop topologies (overwrite-style or append-style).
        # Multi-hop chains are not supported — rightmost would be an intermediate proxy.
        if xff and ip == config.trusted_proxy:
            ip = _normalize_ip(xff.split(",")[-1].strip())

    def resp(status, hdrs, body=b""):
        # Security headers (and HSTS) go on every response; HEAD keeps the headers but drops the body.
        return status, _security_headers() + hdrs, (b"" if method == "HEAD" else body)

    if method not in ("GET", "HEAD"):
        return resp(405, [(b"allow", b"GET, HEAD"), (b"content-length", b"0")])

    config.reload_if_changed()

    # Rate limiting
    if _rate_limit_exceeded(_request_times, ip, config.rate_limit):
        log.warning("Rate limited %s", ip)
        return resp(429, [(b"retry-after", str(RATE_WINDOW).encode()), (b"content-length", b"0")])

    # Authentication
    if config.username:
        auth                  = headers.get("Authorization", "")
        authed                = False
        credentials_submitted = False

        if auth.startswith("Basic "):
            credentials_submitted = True
            try:
                decoded        = base64.b64decode(auth[6:]).decode("utf-8", errors="strict")
                parts          = decoded.split(":", 1)
                submitted_user = parts[0]
                pw             = parts[1] if len(parts) == 2 else ""
                # Evaluate both before combining so the password hash always runs, even
                # when the username is wrong — no early-out timing signal for usernames.
                user_ok = hmac.compare_digest(submitted_user, config.username)
                pass_ok = _check_password(pw, config.password_hash, config.password_salt)
                authed  = user_ok and pass_ok
            except (ValueError, UnicodeDecodeError):
                pass

        if not authed:
            if credentials_submitted and _rate_limit_exceeded(_auth_fail_times, ip, config.auth_rate_limit):
                log.warning("Auth rate limited %s", ip)
                return resp(429, [(b"retry-after", str(RATE_WINDOW).encode()), (b"content-length", b"0")])
            if credentials_submitted:
                log.warning("Failed auth attempt from %s", ip)
            return resp(401, [
                (b"www-authenticate", b'Basic realm="Access Required"'),
                (b"content-type",     b"text/plain"),
                (b"content-length",   b"12"),
            ], b"Unauthorized")

    # Resolve request path to a file
    try:
        file_path, status = _resolve_request_path(url_path)
    except Exception as e:
        log.error("500 resolving %s: %s", url_path, e)
        body_500 = b"Internal server error."
        return resp(500, [(b"content-type", b"text/plain"), (b"content-length", str(len(body_500)).encode())], body_500)

    if status == 403:
        log.warning("403 Forbidden %s from %s", url_path, ip)
        body_403 = b"Forbidden."
        return resp(403, [(b"content-type", b"text/plain"), (b"content-length", str(len(body_403)).encode())], body_403)

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
        log.warning("404 Not Found %s from %s", url_path, ip)
        return resp(404, [(b"content-type", content_type_404), (b"content-length", str(len(body_404)).encode())], body_404)

    raw, compressed, etag = _get_cached_file(file_path)
    if raw is None:
        log.error("500 could not read %s", file_path)
        body_500 = b"Internal server error."
        return resp(500, [(b"content-type", b"text/plain"), (b"content-length", str(len(body_500)).encode())], body_500)

    # 304 Not Modified
    if headers.get("If-None-Match", "") == etag:
        log.info("304 Not Modified %s to %s", url_path, ip)
        return resp(304, [(b"etag", etag.encode()), (b"cache-control", _cache_control_header().encode())])

    accept_encoding = headers.get("Accept-Encoding", "")
    use_gzip        = compressed is not None and "gzip" in accept_encoding
    mime            = _mime_type(file_path)
    common = [
        (b"content-type",  mime.encode()),
        (b"etag",          etag.encode()),
        (b"cache-control", _cache_control_header().encode()),
        (b"vary",          b"Accept-Encoding"),
    ]

    if use_gzip:
        # Byte ranges apply to the identity representation, so they aren't combined
        # with gzip; compressible types are small text anyway.
        log.info("200 %s to %s", url_path, ip)
        return resp(200, common + [
            (b"content-length",   str(len(compressed)).encode()),
            (b"content-encoding", b"gzip"),
        ], compressed)

    # Serving raw: advertise and honor byte ranges (needed for media seeking).
    total = len(raw)
    rng   = _parse_range(headers.get("Range", ""), total)
    if rng == "invalid":
        log.info("416 Range Not Satisfiable %s to %s", url_path, ip)
        return resp(416, [
            (b"content-range",  f"bytes */{total}".encode()),
            (b"content-length", b"0"),
            (b"accept-ranges",  b"bytes"),
        ])
    if rng is not None:
        start, end = rng
        chunk = raw[start:end + 1]
        log.info("206 %s [%d-%d] to %s", url_path, start, end, ip)
        return resp(206, common + [
            (b"content-range",  f"bytes {start}-{end}/{total}".encode()),
            (b"content-length", str(len(chunk)).encode()),
            (b"accept-ranges",  b"bytes"),
        ], chunk)

    log.info("200 %s to %s", url_path, ip)
    return resp(200, common + [
        (b"content-length", str(total).encode()),
        (b"accept-ranges",  b"bytes"),
    ], raw)


def _build_ssl_context():
    """TLS context for the HTTPS server — cert/key loaded, minimum version enforced,
    optional cipher override, ALPN pinned to HTTP/1.1. Raises if the cert or key is
    unreadable, so startup can fail closed rather than serve nothing."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _TLS_VERSIONS.get(config.tls_min_version, ssl.TLSVersion.TLSv1_2)
    if config.ciphers:
        ctx.set_ciphers(config.ciphers)
    ctx.load_cert_chain(_resolve(config.cert_file), _resolve(config.key_file))
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves every request through the transport-agnostic _handle_request. Each
    connection gets its own thread (ThreadingHTTPServer), so the synchronous file
    read and gzip run off any shared loop — no request can starve another."""
    protocol_version = "HTTP/1.1"
    timeout          = 30          # drop idle/slow connections (slowloris mitigation)

    def _serve(self):
        # self.headers is already a parsed, case-insensitive http.client.HTTPMessage —
        # hand it straight to the core rather than rebuilding it.
        raw_ip = self.client_address[0] if self.client_address else "unknown"
        status, headers, body = _handle_request(self.command, self.path, self.headers, raw_ip)
        # We never read a request body; on a method that may carry one (all rejected
        # with 405), close rather than let the unread body poison the next keep-alive
        # request on this connection.
        if self.command not in ("GET", "HEAD"):
            self.close_connection = True
        self.send_response_only(status)
        self.send_header("Date", self.date_time_string())
        for k, v in headers:
            self.send_header(k.decode(), v.decode())
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)

    # Route every method here; _handle_request answers non-GET/HEAD with 405.
    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _serve

    def log_message(self, *args):
        pass  # Servette logs through `log`, not stderr


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    """Port-80 handler: serves ACME HTTP-01 challenge tokens during issuance, and
    301-redirects everything else to HTTPS (preserving the query string)."""
    protocol_version = "HTTP/1.1"
    timeout          = 30

    def _serve(self):
        # Body is never read; close on methods that may carry one so it can't poison
        # the next keep-alive request.
        if self.command not in ("GET", "HEAD"):
            self.close_connection = True
        path   = self.path.split("?", 1)[0]
        prefix = "/.well-known/acme-challenge/"
        if path.startswith(prefix):
            token = path[len(prefix):]
            if token and "/" not in token and ".." not in token:
                try:
                    with open(os.path.join(ACME_WEBROOT, ".well-known", "acme-challenge", token), "rb") as f:
                        data = f.read()
                    self.send_response_only(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(data)
                    return
                except OSError:
                    pass
            self.send_response_only(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        host = self.headers.get("Host", "localhost").split(":")[0]
        url  = (f"https://{host}{self.path}" if config.port == 443
                else f"https://{host}:{config.port}{self.path}")
        self.send_response_only(301)
        self.send_header("Location", url)
        self.send_header("Content-Length", "0")
        self.end_headers()
        log.info("Redirected to %s", url)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _serve

    def log_message(self, *args):
        pass


# Ceiling on concurrent connections. Each connection holds one worker thread for its
# lifetime (up to the 30s idle timeout on keep-alive), so the cap bounds thread/memory
# use under a connection flood — light enough for a Raspberry Pi, ample for a static site.
MAX_CONNECTIONS = 128


class _CappedThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer with a ceiling on concurrent connections. Past the cap,
    new connections are closed immediately rather than spawning unbounded threads —
    a connection-exhaustion / slowloris mitigation that pairs with the per-connection
    socket timeout on the handlers (which reaps slow or idle connections)."""
    daemon_threads = True

    def __init__(self, address, handler, max_connections=MAX_CONNECTIONS):
        super().__init__(address, handler)
        self._slots = threading.BoundedSemaphore(max_connections)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)   # at capacity — shed load, don't queue
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        # A public server sees constant aborted handshakes and dropped connections
        # from scanners and impatient clients. Those are expected noise, not faults —
        # log at debug instead of dumping a traceback to stderr.
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError)):
            log.debug("Connection error from %s: %s",
                      client_address[0] if client_address else "?", exc)
            return
        super().handle_error(request, client_address)


class _TLSThreadingHTTPServer(_CappedThreadingHTTPServer):
    """Adds TLS, with the handshake performed in the per-connection worker thread
    (not the accept loop) so a slow handshake can't stall every new connection."""
    def __init__(self, address, handler, ssl_context, max_connections=MAX_CONNECTIONS):
        super().__init__(address, handler, max_connections)
        self._ssl_context = ssl_context

    def get_request(self):
        sock, addr = super().get_request()
        # Defer the handshake to the worker thread's first read (under the handler's
        # socket timeout) rather than doing it here on the single accept loop.
        return self._ssl_context.wrap_socket(sock, server_side=True,
                                             do_handshake_on_connect=False), addr


# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM
#
# Manages the server's environment: bootstrapping the Python runtime, server
# lifecycle, certificate management, and systemd service integration.
# ─────────────────────────────────────────────────────────────────────────────


# ── Bootstrap ─────────────────────────────────────────────────────────────────
#
# Every invocation from the system Python re-execs into the managed virtualenv.
# On first run (or if the venv is missing), the venv is created and deps are
# installed first. The user just runs `sudo python3 servette.py` — the
# environment is managed invisibly.

def _bootstrap():
    if sys.prefix == _VENV_DIR:
        return  # Already running inside the managed virtualenv

    if not os.path.exists(_VENV_PY):
        print("Setting up Servette...")

        try:
            import venv as _venv_mod
        except ImportError:
            _venv_mod = None

        if _venv_mod is None:
            pkg_managers = [
                ("apt-get", f"python3.{sys.version_info.minor}-venv"),
                ("dnf",     "python3-venv"),
                ("apk",     "py3-venv"),
            ]
            for mgr, pkg in pkg_managers:
                if shutil.which(mgr):
                    result = subprocess.run([mgr, "install", "-y", pkg])
                    if result.returncode != 0:
                        print(f"  Error: failed to install {pkg} via {mgr}")
                        sys.exit(1)
                    break
            else:
                print("  Error: no supported package manager found (tried apt-get, dnf, apk)")
                sys.exit(1)
            import venv as _venv_mod

        try:
            _venv_mod.create(_VENV_DIR, with_pip=True, clear=True)
        except Exception as e:
            print(f"  Error: failed to create virtual environment: {e}")
            sys.exit(1)

        deps = ["cryptography>=41.0,<50.0", "acme>=2.0,<6.0", "josepy>=1.10,<3.0"]
        result = subprocess.run([_VENV_PY, "-m", "pip", "install"] + deps)
        if result.returncode != 0:
            print(f"  Error: failed to install dependencies")
            sys.exit(1)
        print()

    os.execv(_VENV_PY, [_VENV_PY] + sys.argv)


# ── Server lifecycle ──────────────────────────────────────────────────────────
#
# Each server is a ThreadingHTTPServer run by serve_forever() in a daemon thread;
# stop_server() calls shutdown() on it from the shell thread to stop gracefully.

_https_server         = None  # the running HTTPS ThreadingHTTPServer (None when stopped)
_http_server          = None  # the port-80 redirect server (None if unavailable)
_server_start_time    = None
_watchdog_thread      = None
_sweep_thread         = None
_sweep_stop           = threading.Event()
_last_renewal_attempt = 0.0
_cert_domain          = None  # cached domain from active cert; None means self-signed

_TLS_VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}
ACME_RETRIES  = 3


def _server_running():
    return _https_server is not None


def _cert_watchdog():
    """Auto-renew Let's Encrypt certs before expiry; detect externally-rotated certs."""
    global _last_renewal_attempt, _cert_domain
    while _server_running():
        time.sleep(60)
        if not _server_running():
            break

        cert_path = _resolve(config.cert_file)

        domain = _domain_from_cert(cert_path)
        if domain:
            # Let's Encrypt cert: auto-renew when fewer than 30 days remain
            days = _cert_days_remaining(cert_path)
            if days is not None and days < 30:
                now = time.monotonic()
                if now - _last_renewal_attempt >= 3600:
                    _last_renewal_attempt = now
                    log.info("Certificate for %s expires in %d days — renewing", domain, days)
                    _run_acme(domain)
                    _cert_domain = domain
        else:
            # Self-signed or externally managed cert: reload if the file changed on disk
            try:
                mtime = os.path.getmtime(cert_path)
                if config._cert_mtime is not None and mtime != config._cert_mtime:
                    log.info("Certificate changed on disk — reloading server")
                    config._cert_mtime = mtime
                    _reload_server()
            except OSError:
                pass


def start_server():
    global _server_start_time, _watchdog_thread, _cert_domain, _sweep_thread, _https_server, _http_server

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

    # Build the HTTPS server, failing closed if the socket can't bind or the cert is
    # unreadable — better than a live process that serves nothing. Both surface here
    # synchronously: the bind happens in the constructor, the cert in _build_ssl_context.
    try:
        https = _TLSThreadingHTTPServer(("0.0.0.0", config.port), _Handler, _build_ssl_context())
    except Exception as e:
        log.error("Server failed to start on port %d: %s", config.port, e)
        print(f"Server failed to start on port {config.port}: {e}")
        if "--serve" in sys.argv:
            sys.exit(1)
        return

    # The port-80 redirect is best-effort (needs privilege and a free port).
    try:
        redirect = _CappedThreadingHTTPServer(("0.0.0.0", 80), _RedirectHandler)
    except OSError as e:
        log.warning("Could not bind to port 80: %s", e)
        print("Note: could not bind to port 80. HTTP redirects unavailable.")
        redirect = None

    _https_server = https
    _http_server  = redirect
    threading.Thread(target=https.serve_forever, daemon=True).start()
    if redirect is not None:
        threading.Thread(target=redirect.serve_forever, daemon=True).start()

    if _watchdog_thread is None or not _watchdog_thread.is_alive():
        _watchdog_thread = threading.Thread(target=_cert_watchdog, daemon=True)
        _watchdog_thread.start()

    if _sweep_thread is None or not _sweep_thread.is_alive():
        _sweep_stop.clear()
        _sweep_thread = threading.Thread(target=_rate_sweep, args=(_sweep_stop,), daemon=True)
        _sweep_thread.start()
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

    for issue in _production_issues():
        print(_c(f"  {issue}", "yellow"))
    for warning in _cache_warnings():
        print(_c(f"  {warning}", "yellow"))


def stop_server():
    global _server_start_time, _sweep_thread, _https_server, _http_server

    if not _server_running():
        return

    for srv in (_https_server, _http_server):
        if srv is not None:
            srv.shutdown()
            srv.server_close()
    _https_server      = None
    _http_server       = None
    _server_start_time = None

    _sweep_stop.set()
    if _sweep_thread is not None:
        _sweep_thread.join(timeout=5)
        _sweep_thread = None
    log.info("Server stopped")
    print("Session server stopped.")


# ── Service management ────────────────────────────────────────────────────────

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


def _servette_user_exists():
    result = subprocess.run(["id", "servette"], capture_output=True)
    return result.returncode == 0


def _chown_servette(path):
    """Chown path to servette:servette if the user exists and the path exists."""
    if _servette_user_exists() and os.path.exists(path):
        subprocess.run(["chown", "-R", "servette:servette", path], check=True)


def _systemd_unit(python_path, servette_path):
    """The systemd unit for the service. Writes are confined to where Servette
    actually writes — its own directory (config, certs, ACME account) and the ACME
    webroot (HTTP-01 challenge files during renewal); ProtectSystem=strict makes the
    rest of the filesystem read-only, and the unit runs as a least-privilege user
    holding only CAP_NET_BIND_SERVICE. The served directory ends up read-write only
    because it lives under the server's own directory; the server never writes it."""
    return f"""[Unit]
Description=Servette — The Simple Secure Server
After=network.target

[Service]
User=servette
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={BASE_DIR} {ACME_WEBROOT}
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
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


def cmd_install():
    updating      = _service_file_exists()
    servette_path = os.path.abspath(__file__)
    python_path   = _VENV_PY if os.path.exists(_VENV_PY) else subprocess.run(
        ["which", "python3"], capture_output=True, text=True
    ).stdout.strip()

    service = _systemd_unit(python_path, servette_path)

    try:
        # Create system user if needed
        if not _servette_user_exists():
            subprocess.run(
                ["useradd", "--system", "--no-create-home", "--shell", "/sbin/nologin", "servette"],
                check=True
            )
            print("Created system user 'servette'.")

        with open(SERVICE_PATH, "w") as f:
            f.write(service)

        subprocess.run(["systemctl", "daemon-reload"],      check=True)
        subprocess.run(["systemctl", "enable", "servette"], check=True, capture_output=True)

        # Chown files the service process needs to read
        _chown_servette(config.CONFIG_FILE)
        if config.cert_file:
            _chown_servette(_resolve(config.cert_file))
        if config.key_file:
            _chown_servette(_resolve(config.key_file))
        _chown_servette(_resolve(config.serve_dir))
        _chown_servette(os.path.join(BASE_DIR, "certs"))
        _chown_servette(os.path.join(BASE_DIR, ".acme-account.pem"))
        # Create the ACME webroot now so it exists when systemd applies ReadWritePaths
        # — a missing ReadWritePaths target makes the unit fail to start.
        os.makedirs(ACME_WEBROOT, exist_ok=True)
        _chown_servette(ACME_WEBROOT)

        # Warn if serve_dir isn't world-readable
        if config.serve_dir:
            serve_path = _resolve(config.serve_dir)
            if os.path.isdir(serve_path):
                mode = os.stat(serve_path).st_mode
                if not (mode & 0o005 == 0o005):  # world read+execute on directory
                    print(f"  Warning: '{serve_path}' may not be readable by the servette user.")
                    print(f"  Fix with: chmod -R a+rX {serve_path}")

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
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    key  = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "servette")])

    san = [_x509.DNSName("localhost"), _x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]
    try:
        import socket as _socket
        ip = _socket.gethostbyname(_socket.gethostname())
        san.append(_x509.IPAddress(ipaddress.IPv4Address(ip)))
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
                # Bind all interfaces (0.0.0.0) by design: Servette is a public-facing
                # server, and this probe must mirror its bind to detect a real conflict.
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
    from acme import client as _acme_client, challenges as _challenges, messages as _messages, errors as _acme_errors
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
    _chown_servette(ACME_WEBROOT)
    _chown_servette(CERTS_DIR)

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
        _chown_servette(ACCOUNT_KEY_FILE)

    # Start a temporary HTTP listener on port 80 if the main server isn't running
    tmp_server = None
    if not _server_running():
        try:
            tmp_server = _CappedThreadingHTTPServer(("0.0.0.0", 80), _RedirectHandler)
            threading.Thread(target=tmp_server.serve_forever, daemon=True).start()
        except OSError as e:
            log.warning("Could not start temporary port-80 listener: %s", e)

    www_domain  = f"www.{domain}"
    last_error  = None
    include_www = True

    while True:
        names               = [domain, www_domain] if include_www else [domain]
        www_dns_only_failure = False

        for attempt in range(1, ACME_RETRIES + 1):
            stop = threading.Event()
            if sys.stdout.isatty():
                if attempt == 1:
                    label = f"Requesting certificate for {domain}..."
                else:
                    label = f"Retry {attempt - 1} of {ACME_RETRIES - 1}..."
                t = threading.Thread(target=_spin, args=(label, stop), daemon=True)
                t.start()
            else:
                t = None

            token_paths = []
            try:
                net       = _acme_client.ClientNetwork(account_key, user_agent="servette/1.0")
                directory = _messages.Directory.from_json(net.get(ACME_URL).json())
                ac        = _acme_client.ClientV2(directory, net)

                # Register account; if key is already registered, fetch the account
                # to load its URL (kid) into the ClientNetwork — without this,
                # all subsequent signed requests fail with "No Key ID in JWS header".
                try:
                    ac.new_account(_messages.NewRegistration.from_data(
                        email=config.email if config.email else None,
                        terms_of_service_agreed=True
                    ))
                except _acme_errors.ConflictError as e:
                    ac.query_registration(_messages.RegistrationResource(
                        body=_messages.Registration(), uri=e.location
                    ))

                domain_key  = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
                domain_key_pem = domain_key.private_bytes(
                    _serialization.Encoding.PEM,
                    _serialization.PrivateFormat.TraditionalOpenSSL,
                    _serialization.NoEncryption()
                )
                csr_pem = (
                    _x509.CertificateSigningRequestBuilder()
                    .subject_name(_x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, domain)]))
                    .add_extension(_x509.SubjectAlternativeName([
                        _x509.DNSName(n) for n in names
                    ]), critical=False)
                    .sign(domain_key, _hashes.SHA256())
                    .public_bytes(_serialization.Encoding.PEM)
                )

                # Order certificate and answer HTTP-01 challenges (one per name)
                order = ac.new_order(csr_pem)
                for authz in order.authorizations:
                    for challenge in authz.body.challenges:
                        if isinstance(challenge.chall, _challenges.HTTP01):
                            token    = challenge.chall.encode("token")
                            key_auth = challenge.chall.key_authorization(account_key)
                            path     = os.path.join(ACME_WEBROOT, ".well-known", "acme-challenge", token)
                            with open(path, "w") as f:
                                f.write(key_auth)
                            token_paths.append(path)
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
                _chown_servette(CERTS_DIR)

                stop.set()
                if t:
                    t.join()

                config.cert_file = cert_path
                config.key_file  = key_path
                config.save()
                global _cert_domain
                _cert_domain = domain

                issued_names = f"{domain} and {www_domain}" if include_www else domain
                print(f"  Certificate issued for {issued_names}.")
                log.info("ACME certificate issued for %s", issued_names)

                if _server_running() or _service_is_active():
                    print("  Reloading server...")
                    _reload_server()
                last_error = None
                break

            except _acme_errors.ValidationError as e:
                last_error = e
                stop.set()
                if t:
                    t.join()
                for path in token_paths:
                    if os.path.exists(path):
                        os.remove(path)
                token_paths = []
                if include_www:
                    failed_domains = {a.body.identifier.value for a in e.failed_authzrs}
                    if failed_domains == {www_domain}:
                        www_dns_only_failure = True
                        break  # don't retry; fall back to bare domain
                if attempt < ACME_RETRIES:
                    delay = 5 * attempt
                    log.warning("ACME attempt %d/%d failed for %s: %s — retrying in %ds", attempt, ACME_RETRIES, domain, e, delay)
                    time.sleep(delay)

            except Exception as e:
                last_error = e
                stop.set()
                if t:
                    t.join()
                for path in token_paths:
                    if os.path.exists(path):
                        os.remove(path)
                token_paths = []
                if attempt < ACME_RETRIES:
                    delay = 5 * attempt
                    log.warning("ACME attempt %d/%d failed for %s: %s — retrying in %ds", attempt, ACME_RETRIES, domain, e, delay)
                    time.sleep(delay)
            finally:
                for path in token_paths:
                    if os.path.exists(path):
                        os.remove(path)

        if last_error is None:
            break  # success

        if www_dns_only_failure:
            include_www = False
            print(f"\n  Note: {www_domain} has no DNS record — certificate issued for {domain} only.")
            print(f"  To add www support later, point {www_domain} to this server and run 'config cert'.\n")
            continue

        break  # real failure

    if last_error:
        print(f"  Error getting certificate: {last_error}")
        log.error("ACME failed for %s after %d attempts: %s", domain, ACME_RETRIES, last_error)

    if tmp_server is not None:
        tmp_server.shutdown()
        tmp_server.server_close()


def _load_cert(cert_path):
    """Return a cryptography X.509 certificate object, or None on failure."""
    try:
        from cryptography import x509 as _x509
        with open(cert_path, "rb") as f:
            return _x509.load_pem_x509_certificate(f.read())
    except Exception:
        return None


def _is_real_domain(s):
    if s in ("localhost", "servette"):
        return False
    try:
        ipaddress.ip_address(s)
        return False  # it's an IP, not a domain
    except ValueError:
        return bool(s)


def _domain_from_cert(cert_path):
    if not cert_path:
        return None
    cert = _load_cert(cert_path)
    if cert is None:
        return None
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


# ─────────────────────────────────────────────────────────────────────────────
# SHELL
#
# The interactive terminal interface. Contains only UI logic — all system work
# is delegated to functions in the SYSTEM section.
# ─────────────────────────────────────────────────────────────────────────────

# Menus are generated so the right-hand column always begins at the same place
# (2-space indent + a 22-wide label) as the status and config displays.
_PAD = 22

_COMMANDS = [
    ("setup",   "guided walkthrough for getting started"),
    ("config",  "view and edit settings"),
    ("enable",  "enable Servette as a system service"),
    ("disable", "remove the system service"),
    ("start",   "start the server"),
    ("stop",    "stop the server"),
    ("status",  "show whether the server is running"),
    ("log [n]", "show the last n log entries"),
    ("update",  "download the latest version of servette.py"),
    ("help",    "show this message"),
    ("quit",    "exit"),
]
HELP = "\nCommands:\n" + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _COMMANDS)

_CONFIG_COMMANDS = [
    ("dir",      "directory to serve"),
    ("port",     "HTTPS port"),
    ("cert",     "SSL certificate and key"),
    ("username", "login username"),
    ("password", "login password"),
    ("email",    "email address"),
    ("limits",   "rate limits"),
    ("cache",    "browser cache policy"),
    ("proxy",    "trusted proxy IP for X-Forwarded-For"),
    ("tls",      "minimum TLS version and cipher suites"),
    ("csp",      "Content-Security-Policy header"),
    ("perms",    "Permissions-Policy header"),
    ("show",     "show current settings"),
    ("back",     "return to main shell"),
]
CONFIG_HELP = ("\n  Commands\n  " + "─" * 38 + "\n"
               + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _CONFIG_COMMANDS))


def _prompt(question):
    return input(f"  {question} [y/n]: ").strip().lower() == "y"


# ── Config sub-shell ──────────────────────────────────────────────────────────

def _config_show():
    def val(v):
        return v if v else "(not set)"

    cache_display = config.cache_policy
    if config.cache_policy == "max-age":
        cache_display += f" ({config.cache_max_age}s)"

    rows = [
        ("Directory",          val(config.serve_dir)),
        ("HTTPS port",         config.port),
        ("Certificate",        val(config.cert_file)),
        ("Key",                val(config.key_file)),
        ("Username",           val(config.username)),
        ("Password",           "(set)" if config.password_hash else "(not set)"),
        ("Email",              val(config.email)),
        ("Rate limit",         f"{config.rate_limit} req/min"),
        ("Auth rate limit",    f"{config.auth_rate_limit} fails/min"),
        ("Cache policy",       cache_display),
        ("Cache size",         f"{config.cache_size_mb} MB"),
        ("Trusted proxy",      val(config.trusted_proxy)),
        ("TLS min version",    config.tls_min_version),
        ("Cipher suites",      config.ciphers or "(system default)"),
        ("CSP",                config.csp or "(disabled)"),
        ("Permissions-Policy", config.permissions_policy or "(disabled)"),
    ]

    print()
    print("  Current Settings")
    print("  " + "─" * 38)
    for label, value in rows:
        print(f"  {label:<{_PAD}} {value}")
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


def _config_set(attr, label, cast=str, validate=None, error="invalid value", hint=None):
    current = getattr(config, attr)
    if hint:
        print(f"  {hint}")
    new_value = input(f"  {label} [{current}]: ").strip()
    if not new_value or new_value == str(current):
        print("  → unchanged")
        return
    try:
        value = cast(new_value)
        if validate and not validate(value):
            raise ValueError
        setattr(config, attr, value)
        config.save()
        print("  → saved")
    except ValueError:
        print(f"  → {error}, unchanged")


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

    domain = input("  Domain name (leave blank for self-signed): ").strip()

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
    _config_set("rate_limit",      "rate_limit",      int, error="invalid number", hint="Requests per minute per IP")
    _config_set("auth_rate_limit", "auth_rate_limit", int, error="invalid number", hint="Failed login attempts per minute per IP")


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
    _config_set("cache_size_mb", "cache_size_mb", int, lambda v: v > 0,
                "invalid number", hint="In-memory file cache limit in MB (e.g. 32 on a Raspberry Pi)")


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
            _config_set("port", "port", int, lambda v: 1 <= v <= 65535, "invalid port number")
        elif cmd == "cert":
            _config_cert()
        elif cmd == "username":
            _config_username()
        elif cmd == "password":
            _config_password()
        elif cmd == "email":
            _config_set("email", "email")
        elif cmd == "limits":
            _config_limits()
        elif cmd == "cache":
            _config_cache()
        elif cmd in ("proxy", "trusted_proxy"):
            _config_trusted_proxy()
        elif cmd == "tls":
            _config_tls()
        elif cmd == "csp":
            _config_set("csp", "csp", hint="  Block what static sites never need; allow what they might. Leave blank to disable.")
        elif cmd in ("perms", "permissions_policy"):
            _config_set("permissions_policy", "permissions_policy", hint="  Deny hardware APIs static sites never need. Leave blank to disable.")
        elif cmd in ("back", "done", "exit", "quit"):
            break
        elif cmd in ("help", "?"):
            print(CONFIG_HELP)
        else:
            print(f"  Unknown setting: {cmd}")
            print(CONFIG_HELP)


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


RELEASES_API_URL    = "https://api.github.com/repos/andy-emerson/servette/releases/latest"
_SIGNING_PUBLIC_KEY = "abb8854be0b82df813f3b052296a26573063fc6314ea2701d54354605e6f15db"
_VERSION_RE         = re.compile(rb"""^__version__\s*=\s*['"]([^'"]+)['"]""", re.M)

def _parse_version(source_bytes):
    """Extract __version__ from servette.py source bytes. Returns the string or None."""
    m = _VERSION_RE.search(source_bytes)
    return m.group(1).decode() if m else None

def cmd_update():
    servette_path = os.path.abspath(__file__)

    # Check latest release via GitHub API
    stop = threading.Event()
    t    = threading.Thread(target=_spin, args=("Checking for update...", stop), daemon=True)
    t.start()
    try:
        req = urllib.request.Request(
            RELEASES_API_URL,
            headers={"User-Agent": f"servette/{__version__}", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            release = json.loads(resp.read())
    except Exception as e:
        stop.set(); t.join()
        print(f"  Update failed: {e}")
        return
    stop.set(); t.join()

    new_version = release.get("tag_name", "").lstrip("v")
    if not new_version:
        print("  Update failed: could not read version from release.")
        return

    if new_version == __version__:
        print(f"  Already up to date ({__version__}).")
        return

    assets = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
    if "servette.py" not in assets or "servette.py.sig" not in assets:
        print("  Update failed: release is missing servette.py or servette.py.sig assets.")
        return

    # Gate on major version bump
    try:
        cur_major = int(__version__.split(".")[0])
        new_major = int(new_version.split(".")[0])
    except (ValueError, IndexError):
        cur_major = new_major = 0

    if new_major != cur_major:
        print(f"  Major version change: {__version__} → {new_version}")
        print("  This may include breaking changes. Review before upgrading.")
        if not _prompt("Continue?"):
            print("  Update cancelled.")
            return

    # Download source and signature
    stop = threading.Event()
    t    = threading.Thread(target=_spin, args=(f"Downloading {new_version}...", stop), daemon=True)
    t.start()
    try:
        new_source = urllib.request.urlopen(assets["servette.py"],     timeout=30).read()
        signature  = urllib.request.urlopen(assets["servette.py.sig"], timeout=15).read()
    except Exception as e:
        stop.set(); t.join()
        print(f"  Update failed: {e}")
        return
    stop.set(); t.join()

    # Verify Ed25519 signature against pinned public key
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(_SIGNING_PUBLIC_KEY))
        pub_key.verify(signature, new_source)
    except InvalidSignature:
        print("  Update failed: signature verification failed.")
        return
    except Exception as e:
        print(f"  Update failed: could not verify signature: {e}")
        return

    file_version = _parse_version(new_source)
    if file_version != new_version:
        print(f"  Update failed: release tag {new_version!r} doesn't match file version {file_version!r}.")
        return

    try:
        compile(new_source, "servette.py", "exec")
    except SyntaxError as e:
        print(f"  Update failed: downloaded file has a syntax error: {e}")
        return

    bak_path = servette_path + ".bak"
    tmp_path = servette_path + ".new"
    with open(tmp_path, "wb") as f:
        f.write(new_source)
    os.chmod(tmp_path, os.stat(servette_path).st_mode)
    shutil.copy2(servette_path, bak_path)
    os.replace(tmp_path, servette_path)

    print(f"  Updated {__version__} → {new_version}.")
    print(f"  Previous version saved to {bak_path}.")

    if _service_is_active():
        if _prompt("Restart the servette service now?"):
            try:
                subprocess.run(["systemctl", "restart", "servette"], check=True, capture_output=True)
                print(f"  Service restarted on {new_version}.")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"  Restart failed — run 'sudo systemctl restart servette' yourself ({e}).")
        else:
            print("  Run 'sudo systemctl restart servette' when ready.")
    elif _server_running():
        # The server is running inside this shell, which still holds the old code in
        # memory; stopping and starting it here would only re-run the old version, so
        # a full relaunch is required to pick up the new file.
        print("  This shell is still running the old version — exit and rerun Servette to apply.")
    else:
        print("  Restart to run the new version: 'start', or 'sudo systemctl restart servette'.")


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


def _production_issues():
    """Return a list of strings describing conditions that prevent production readiness."""
    issues = []
    if not config.serve_dir or not os.path.exists(_resolve(config.serve_dir)):
        issues.append("serve directory not configured — run 'config'")
    if not config.cert_file or not os.path.exists(_resolve(config.cert_file)):
        issues.append("certificate not configured — run 'config cert'")
    elif _domain_from_cert(_resolve(config.cert_file)) is None:
        issues.append("self-signed certificate — run 'config cert' to add a domain")
    if not config.username:
        issues.append("no password protection — run 'config' to set credentials")
    return issues


def _cache_warnings():
    """Warn when the site, or any single file, is too big for the in-memory cache."""
    warnings   = []
    serve_dir  = _resolve(config.serve_dir)
    if not os.path.isdir(serve_dir):
        return warnings
    cache_max = config.cache_size_mb * 1024 * 1024
    total     = 0
    for root, _dirs, files in os.walk(serve_dir):
        for name in files:
            try:
                size = os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
            total += size
            if size > cache_max:
                warnings.append(
                    f"{name} ({size / 1048576:.1f} MB) is larger than the cache "
                    f"({config.cache_size_mb} MB) and is never cached"
                )
    if total > cache_max:
        warnings.append(
            f"site is {total / 1048576:.1f} MB but the cache is {config.cache_size_mb} MB "
            f"— not all of it stays cached at once"
        )
    return warnings


def _runtime_stats(service_active):
    """Runtime stats for the running server as (label, value) rows — uptime, memory,
    PID — omitting any that aren't available. Service mode reads from systemd;
    session mode reads from /proc and the in-process start time."""
    rows = []
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
        except Exception:
            return rows
        mono = props.get("ActiveEnterTimestampMonotonic", "")
        if mono and mono != "0":
            try:
                with open("/proc/uptime") as f:
                    boot_elapsed = float(f.read().split()[0])
                elapsed = boot_elapsed - int(mono) / 1_000_000
                if elapsed >= 0:
                    rows.append(("Uptime", _format_uptime(elapsed)))
            except Exception:
                pass
        mem = props.get("MemoryCurrent", "")
        if mem and mem.isdigit() and int(mem) > 0:
            rows.append(("Memory", f"{int(mem) / (1024 * 1024):.1f} MB"))
        pid = props.get("MainPID", "")
        if pid and pid != "0":
            rows.append(("PID", pid))
    else:
        if _server_start_time is not None:
            rows.append(("Uptime", _format_uptime(time.monotonic() - _server_start_time)))
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rows.append(("Memory", f"{int(line.split()[1]) / 1024:.1f} MB"))
                        break
        except Exception:
            pass
        rows.append(("PID", str(os.getpid())))
    return rows


def cmd_status():
    service_active = _service_is_active()
    running        = service_active or _server_running()
    domain         = _domain_from_cert(config.cert_file)
    url            = f"https://{domain}" if domain else f"https://localhost:{config.port}"
    cert_path      = _resolve(config.cert_file)
    W              = _PAD

    print()
    status_dot = _c("● Running", "green") if running else _c("○ Stopped", "red")
    print(f"{status_dot}  (v{__version__})")

    if running:
        mode = "System service" if service_active else "Session only"
        print(f"  {'Mode':<{W}} {mode}")

    print(f"  {'URL':<{W}} {url}")
    print(f"  {'Directory':<{W}} {config.serve_dir or '(not configured)'}")
    auth_str = _c("enabled", "green") if config.username else _c("disabled", "yellow")
    print(f"  {'Auth':<{W}} {auth_str}")

    days = _cert_days_remaining(cert_path)
    if days is not None:
        if days <= 0:
            cert_str = _c("expired", "red")
        else:
            cert_str = _c(f"{days} days remaining", "yellow" if days < 30 else "green")
        print(f"  {'Cert':<{W}} {cert_str}")

    issues = _production_issues() + _cache_warnings()
    if issues:
        print()
        for issue in issues:
            print(_c(f"  {issue}", "yellow"))

    if running:
        for label, value in _runtime_stats(service_active):
            print(f"  {label:<{W}} {value}")

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
    print("  Step 1 — Password protection (optional)")
    print("  Leave username blank to disable. Press Enter to keep current value.")
    _config_username()
    if config.username:
        _config_password()

    print()
    print("  Step 2 — SSL certificate")
    print(f"  Your public IP is {public_ip}. Point a domain here for a trusted certificate.")
    print("  Leave blank to use a self-signed certificate (browsers will warn visitors).\n")
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
