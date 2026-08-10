# GENERATED FILE — do not edit. servette.py is built from the Markdown
# sources in src/ by src/build.py; edit those and rebuild. Hand edits here
# are overwritten by the next build and fail CI's `build.py --check`.
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

# Paths
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
_VENV_DIR   = os.path.join(BASE_DIR, ".servette-env")
_VENV_PY    = os.path.join(_VENV_DIR, "bin", "python3")

SERVICE_PATH  = "/etc/systemd/system/servette.service"
NETWATCH_PATH = "/etc/systemd/system/servette-netwatch"  # + ".service" / ".timer"
ACME_WEBROOT  = "/var/lib/letsencrypt/webroot"

# The closed-system TLS fallback: presented for connections whose SNI matches no
# configured site (absent, unrecognized, or direct-IP access) when no site is
# itself domainless. Tied to no site's identity, generated once and reused.

# The default-certificate paths
_DEFAULT_CERT_DIR  = os.path.join(BASE_DIR, "certs", "_default")
_DEFAULT_CERT_FILE = os.path.join(_DEFAULT_CERT_DIR, "cert.pem")
_DEFAULT_KEY_FILE  = os.path.join(_DEFAULT_CERT_DIR, "key.pem")


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
#
# That same memory-hardness is a lever pointed back at the server: the per-IP
# auth-fail limit bounds one address, but many distinct IPs each get a first
# hash before their own limiter engages, and concurrent requests are otherwise
# bounded only by `MAX_CONNECTIONS` — up to ~128 × 16 MB ≈ 2 GB transient, an
# OOM on the 512 MB-class hosts Servette targets. `_SCRYPT_SLOTS` bounds the
# spike: at most 4 verification hashes run at once (≤ 64 MB); requests past
# that *block* rather than fail. The worst case is arithmetic, not luck — ~40
# hashes/s drain against at most `MAX_CONNECTIONS` waiters is a ~3 s ceiling —
# so an attack degrades login to slow, never to unavailable (a shed-with-503
# design would hand attackers a deterministic denial of every legitimate login).
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1
_SCRYPT_MAX_CONCURRENT          = 4
_SCRYPT_SLOTS                   = threading.BoundedSemaphore(_SCRYPT_MAX_CONCURRENT)


def _hash_password(password):
    """Hash a password with a random salt using scrypt (memory-hard)."""
    salt = os.urandom(16)
    key  = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                          n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return key.hex(), salt.hex()


def _check_password(submitted, stored_hash, stored_salt):
    """Return True if submitted matches the stored hash.

    This is the request-time hash, so it acquires a _SCRYPT_SLOTS permit —
    blocking, deliberately: see the note above. _hash_password stays outside
    the semaphore; it runs only from the single-threaded interactive shell."""
    if not stored_hash or not stored_salt:
        return False
    try:
        salt = bytes.fromhex(stored_salt)
        with _SCRYPT_SLOTS:
            key = hashlib.scrypt(submitted.encode("utf-8"), salt=salt,
                                 n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
        return hmac.compare_digest(key.hex(), stored_hash)
    except Exception:
        return False


class Site:
    """One `[[site]]` block: everything that varies per hosted domain — the domain
    itself, its folder, its own certificate, its visitor auth, its publish channel.
    Host-level settings (port, TLS, rate limits, cache, ACME email, security headers,
    ...) live once on Config, not here: every field lives at exactly one level, no
    fallback lookup between them."""

    def __init__(self, data=None):
        data = data or {}
        self.domain         = data.get("domain",         "")
        self.serve_dir      = data.get("serve_dir",      "site")
        self.cert_file      = data.get("cert_file",      "cert.pem")
        self.key_file       = data.get("key_file",       "key.pem")
        self.username       = data.get("username",       "")
        self.password_hash  = data.get("password_hash",  "")
        self.password_salt  = data.get("password_salt",  "")
        self.publish_url    = data.get("publish_url",    "")
        self.publish_key    = data.get("publish_key",    "")
        self._cert_mtime    = None  # populated by Config._load(); externally-rotated-cert detection


class _ConfigInvalid(Exception):
    """servette.toml cannot be safely applied — unparseable TOML, or a
    serve_dir that would publish Servette's own secrets. At startup this is
    fatal (fail closed); on the per-request reload the previous configuration
    stays in force — see reload_if_changed."""


class Config:
    """Holds all Servette settings and handles reading/writing servette.toml."""

    CONFIG_FILE = os.path.join(BASE_DIR, "servette.toml")

    def __init__(self):
        self._mtime = None
        try:
            self._load()
        except _ConfigInvalid as e:
            print(f"Error: {e}.")
            print(f"Fix or delete {self.CONFIG_FILE} and try again.")
            sys.exit(1)

    def _load(self):
        # Everything that can be refused is parsed and validated before any
        # attribute of self changes: _load also runs against the LIVE config on
        # the reload path, and raising after a partial mutation would leave the
        # server on a config that never existed on disk.
        data = {}
        existed = os.path.exists(self.CONFIG_FILE)
        if existed:
            try:
                with open(self.CONFIG_FILE, "rb") as f:
                    data = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                raise _ConfigInvalid(f"servette.toml is not valid TOML ({e})")

        site_tables = data.get("site", [])
        migrating   = existed and not site_tables
        if site_tables:
            sites = [Site(t) for t in site_tables]
        else:
            # No [[site]] tables: either a fresh install (data is empty, defaults
            # apply) or a pre-multi-site flat config being migrated in place —
            # both produce the same single default/legacy-derived Site.
            legacy = Site({
                "serve_dir":     data.get("serve_dir",     "site"),
                "cert_file":     data.get("cert_file",     "cert.pem"),
                "key_file":      data.get("key_file",      "key.pem"),
                "username":      data.get("username",      ""),
                "password_hash": data.get("password_hash", ""),
                "password_salt": data.get("password_salt", ""),
                "publish_url":   data.get("publish_url",   ""),
                "publish_key":   data.get("publish_key",   ""),
            })
            if data.get("password") and not legacy.password_hash:
                legacy.password_hash, legacy.password_salt = _hash_password(data["password"])
            if migrating:
                # Domain was never a stored field pre-migration — it lived only in
                # the certificate. _domain_from_cert is defined later in the file
                # (Certificate management); by the time _load() actually runs
                # (module-level `config = Config()` sits at the bottom of the
                # file, after every function is defined) it's available.
                cert_path = _resolve(legacy.cert_file)
                if os.path.exists(cert_path):
                    try:
                        import cryptography  # noqa — availability probe only
                        legacy.domain = _domain_from_cert(cert_path) or ""
                    except ImportError:
                        # Running under the system Python, before _bootstrap()
                        # re-execs into the venv: _domain_from_cert would return
                        # None and the migration would persist an empty domain,
                        # silently demoting the site to the domainless catch-all
                        # (no HSTS, no renewal). Defer the migration entirely;
                        # the re-exec'd process runs it with cryptography there.
                        migrating = False
            sites = [legacy]

        # The shell refuses these serve_dirs at edit time, but the file is also
        # hand-editable — enforce where the value actually takes effect, so a
        # reload can never start serving the config file or the TLS keys.
        for site in sites:
            if _serve_dir_exposes_secrets(_resolve(site.serve_dir)):
                raise _ConfigInvalid(
                    f"serve_dir {site.serve_dir!r} holds Servette's own config or TLS keys — "
                    "serving it would publish them")
        self.sites = sites

        self.port            = data.get("port",            443)
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

        for site in self.sites:
            try:
                site._cert_mtime = os.path.getmtime(_resolve(site.cert_file))
            except OSError:
                site._cert_mtime = None

        if migrating:
            self.save()

    def reload_if_changed(self):
        try:
            mtime = os.path.getmtime(self.CONFIG_FILE)
        except OSError:
            return
        if mtime == self._mtime:
            return
        try:
            self._load()
            log.info("Config reloaded from disk")
        except _ConfigInvalid as e:
            # Keep serving on the last good configuration: this runs on request
            # threads, where an escape would kill the request mid-flight and a
            # process exit would take the whole server down over a typo. Stamp
            # the mtime so the bad file isn't re-parsed — and the warning isn't
            # repeated — on every request until the file changes again.
            self._mtime = mtime
            log.warning("Config NOT reloaded (%s) — still serving the previous configuration", e)

    def save(self):
        def s(v):
            # TOML basic string: backslash and quote escaped, the common control
            # characters given their named escapes, and every other control char
            # (NUL, ESC, vertical tab, DEL, …) escaped as \uXXXX. An unescaped
            # control character writes a file tomllib then refuses to load, so a
            # value carrying one would otherwise make Servette fail to start.
            out = str(v).replace("\\", "\\\\").replace('"', '\\"')
            out = (out.replace("\b", "\\b").replace("\f", "\\f")
                      .replace("\n", "\\n").replace("\r", "\\r"))
            out = "".join(c if c == "\t" or (c >= " " and c != "\x7f")
                          else f"\\u{ord(c):04x}" for c in out)
            return '"' + out + '"'

        sites_content = "\n".join(f"""\
[[site]]
# Leave domain blank for a self-signed certificate (browsers will warn visitors)
domain = {s(site.domain)}
serve_dir = {s(site.serve_dir)}
cert_file = {s(site.cert_file)}
key_file = {s(site.key_file)}

# Leave username blank to disable password protection
username = {s(site.username)}

# Site publish channel: where signed content bundles are pulled from, and the
# public key (distinct from Servette's own release-signing key) that verifies
# them. Leave blank to disable — no polling happens without both set.
publish_url = {s(site.publish_url)}
publish_key = {s(site.publish_key)}

# Machine-generated — do not edit by hand
password_hash = {s(site.password_hash)}
password_salt = {s(site.password_salt)}
""" for site in self.sites)

        content = f"""\
# Servette configuration — https://github.com/andy-emerson/servette
#
# Host-level settings below apply to every site on this box. Each [[site]]
# block below is one hosted domain — its own folder, certificate, auth, and
# publish channel.

port = {self.port}

# Rate limiting (requests per minute per IP, shared across all sites)
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

{sites_content}"""
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


def _rate_limit_exceeded(tracker, ip, limit, record=True):
    """Return True if ip is over `limit` within the window.

    record=True (the default) counts this request before deciding — the normal
    "note this hit, am I over?" call. record=False only peeks: it reports whether
    ip is already over without adding a hit, so an expensive operation can be
    gated on the limit without the check itself counting as traffic."""
    with _rate_lock:
        now    = time.monotonic()
        cutoff = now - RATE_WINDOW

        timestamps = tracker.get(ip)
        if timestamps is None:
            if not record:
                return False   # nothing tracked for this ip yet — not over
            # Bounded: past the limit the exact count stops mattering, only that
            # it is over. Without maxlen one IP's deque grows with everything it
            # sends inside the window — a client already being refused still
            # appends on every 429 — so _RATE_IP_CAP would bound how many IPs
            # are tracked while a single IP grew without limit. Dropping the
            # oldest keeps the deque at limit + 1 in-window entries, which is
            # still over the limit, so the verdict is unchanged.
            timestamps = collections.deque(maxlen=limit + 1)
            tracker[ip] = timestamps
        elif timestamps.maxlen != limit + 1:
            # The limit was reconfigured while this IP was live. A deque keeps
            # the maxlen it was born with, and a *raised* limit makes the old,
            # smaller maxlen a permanent exemption: len can never reach the new
            # limit + 1, so this IP would never be throttled again. Rebuild at
            # the current limit, keeping the newest entries.
            timestamps = collections.deque(timestamps, maxlen=limit + 1)
            tracker[ip] = timestamps
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if record:
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

def _within(base, target):
    """True if `target` is `base` or sits inside it. commonpath on already-resolved
    absolute paths means a traversal or symlink escape lands outside `base` and fails."""
    try:
        return os.path.commonpath([base, target]) == base
    except ValueError:   # different drives / mixed absolute-relative — treat as outside
        return False


def _hidden_segment(segments):
    """True if any path segment names a dotfile, other than the one dotdir the
    web reserves for public content — .well-known (security.txt, ACME). Shared
    by the request-path and resolved-target checks in _resolve_request_path so
    both refuse exactly the same set."""
    return any(seg.startswith(".") and seg != ".well-known" for seg in segments if seg)


def _resolve_request_path(url_path, serve_dir):
    """Resolve a URL path to an absolute file path within the matched site's
    serve_dir. Returns (None, 403) on traversal or a hidden path, (None, 404) if
    not found."""
    serve_dir = os.path.realpath(_resolve(serve_dir))
    clean     = unquote(url_path.split("?")[0]).lstrip("/")   # lstrip: never an absolute path
    # Refuse hidden files and directories. A dotfile is never meant to be public,
    # and a static deploy routinely leaves sensitive ones under serve_dir — a
    # .git checkout, a .env, an editor backup — so serving them leaks source and
    # secrets. This first pass reads the *requested* segments, closing the direct
    # case (GET /.git/config); the ".." of a traversal is caught here too, with
    # _within below as the backstop.
    if _hidden_segment(clean.split("/")):
        return None, 403
    abs_path  = os.path.realpath(os.path.join(serve_dir, clean))
    if not _within(serve_dir, abs_path):
        return None, 403
    if os.path.isdir(abs_path):
        abs_path = os.path.realpath(os.path.join(abs_path, "index.html"))
        if not _within(serve_dir, abs_path):
            return None, 403
    # Re-check the *resolved* target's segments. The pass above reads the name
    # the client asked for; a symlink inside serve_dir whose own name is not a
    # dotfile can still resolve to a hidden target (serve_dir/x -> serve_dir/.git
    # /config), and realpath keeps it within serve_dir, so _within passes.
    # Applying the same rule to the resolved path refuses a hidden target by
    # whatever name it was reached. abs_path is at or under serve_dir here, so
    # the slice yields the relative segments (empty at the root — no dotfile).
    if _hidden_segment(abs_path[len(serve_dir):].split(os.sep)):
        return None, 403
    if not os.path.isfile(abs_path):
        return None, 404
    return abs_path, 200


def _cache_control_header(username):
    """Cache-Control for the matched site. A site behind Basic Auth gets
    `private`, so a shared cache never holds a response only some visitors
    are entitled to."""
    scope = "private" if username else "public"
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


def _security_headers(site):
    """Security headers sent on every HTTPS response — success or error. site is
    the matched site (whose domain gates HSTS — a real Let's Encrypt cert backs
    the pin) or None for the closed-system case (no site matched: no HSTS, no
    per-site information of any kind)."""
    headers = [
        (b"x-frame-options",        b"DENY"),
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy",        b"no-referrer"),
    ]
    if config.csp:
        headers.append((b"content-security-policy", config.csp.encode()))
    if config.permissions_policy:
        headers.append((b"permissions-policy", config.permissions_policy.encode()))
    if site is not None and site.domain:
        headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
    return headers


# ── HTTP server ───────────────────────────────────────────────────────────────

_WELL_KNOWN_VERSION_PATH = "/.well-known/servette"


def _backup_version():
    """The version string inside servette.py.bak (left by the last 'update' or
    'restore'), or None if no backup exists or it can't be read/parsed."""
    bak_path = os.path.abspath(__file__) + ".bak"
    try:
        with open(bak_path, "rb") as f:
            return _parse_version(f.read())
    except OSError:
        return None


def _loggable(s):
    """Escape control characters in a string bound for the logs. A request path
    reaches the journal and, from there, an operator's terminal — an unescaped
    ANSI/control sequence could move the cursor, clear the screen, or hide text.
    Printable characters (including non-ASCII) pass through unchanged."""
    return "".join(c if c >= " " and c != "\x7f" else f"\\x{ord(c):02x}" for c in s)


def _handle_request(method, url_path, headers, raw_ip):
    """The request core. Given the method, URL path, the parsed request headers (a
    case-insensitive mapping — an http.client.HTTPMessage in production), and the raw
    client IP, returns (status, headers, body), with security headers on every
    response and the body blanked for HEAD. All the decision logic lives here; the
    handler just feeds it what http.server parsed and sends the result back."""
    ip = _normalize_ip(raw_ip)
    log_path = _loggable(url_path)   # request path, escaped for the log lines below
    if config.trusted_proxy:
        xff = headers.get("X-Forwarded-For", "")
        # Rightmost XFF value is what the single trusted proxy appended.
        # Correct for one-hop topologies (overwrite-style or append-style).
        # Multi-hop chains are not supported — rightmost would be an intermediate proxy.
        if xff and ip == config.trusted_proxy:
            ip = _normalize_ip(xff.split(",")[-1].strip())

    site = None  # resolved below by Host header; None until then, and if nothing matches

    def resp(status, hdrs, body=b""):
        # Security headers (and HSTS, gated on `site`) go on every response;
        # HEAD keeps the headers but drops the body. `site` is read fresh at
        # call time (Python closures are late-binding), so this is correct
        # whether called before or after site selection below.
        return status, _security_headers(site) + hdrs, (b"" if method == "HEAD" else body)

    config.reload_if_changed()

    # Rate limiting — host-level, shared across every site on the box. Ahead of
    # site selection so a flood of requests carrying random/unmatched Host
    # headers still gets throttled rather than dodging the limiter under the
    # closed-system 404 below; the cost is that a rate-limited response never
    # carries HSTS even for a real site's domain.
    if _rate_limit_exceeded(_request_times, ip, config.rate_limit):
        log.warning("Rate limited %s", ip)
        return resp(429, [(b"retry-after", str(RATE_WINDOW).encode()), (b"content-length", b"0")])

    # Site selection — uniform regardless of site count (see _select_site). No
    # match: the closed-system miss. Bare 404, no site-specific information of
    # any kind (no HSTS either, since `site` stays None for resp() above) —
    # deliberately ahead of the method check below, so a POST/PUT/etc. to an
    # unmatched Host gets the same undifferentiated 404 a GET would, rather
    # than a 405 that would leak "something is here, it just doesn't take this
    # method."
    site = _select_site(headers.get("Host", ""))
    if site is None:
        log.warning("404 (no matching site) Host=%r from %s", headers.get("Host", ""), ip)
        body_404 = b"Not found."
        return resp(404, [(b"content-type", b"text/plain"), (b"content-length", str(len(body_404)).encode())], body_404)

    if method not in ("GET", "HEAD"):
        return resp(405, [(b"allow", b"GET, HEAD"), (b"content-length", b"0")])

    # Authentication — the matched site's own username/password; per the closed
    # decision, purely per-site, no fallback to any other level.
    if site.username:
        auth                  = headers.get("Authorization", "")
        authed                = False
        credentials_submitted = auth.startswith("Basic ")

        # Gate the scrypt hash behind the auth rate limiter BEFORE it runs, not
        # after. scrypt is memory-hard by design (~16 MB and ~30 ms per check), so
        # hashing first and rate-limiting only the response lets a flood of Basic
        # credentials burn CPU and RAM on every attempt no matter the limit. The
        # peek (record=False) decides whether to spend the hash at all; an actual
        # failure below is what records a strike toward the limit.
        if credentials_submitted and _rate_limit_exceeded(_auth_fail_times, ip, config.auth_rate_limit, record=False):
            log.warning("Auth rate limited %s", ip)
            return resp(429, [(b"retry-after", str(RATE_WINDOW).encode()), (b"content-length", b"0")])

        if credentials_submitted:
            try:
                decoded        = base64.b64decode(auth[6:]).decode("utf-8", errors="strict")
                parts          = decoded.split(":", 1)
                submitted_user = parts[0]
                pw             = parts[1] if len(parts) == 2 else ""
                # Compare as UTF-8 bytes: hmac.compare_digest raises TypeError on a
                # non-ASCII str, so a crafted non-ASCII username would otherwise escape
                # this try and crash the request. Evaluate both before combining so the
                # password hash always runs even when the username is wrong — no
                # early-out timing signal for usernames.
                user_ok = hmac.compare_digest(submitted_user.encode("utf-8"), site.username.encode("utf-8"))
                pass_ok = _check_password(pw, site.password_hash, site.password_salt)
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

    # Version discovery: what this box is running, and its update backup (if
    # any) — the publish tool's "current vs. latest / current vs. backup"
    # prompts read this. Deliberately reports only what THIS box knows;
    # "latest available" comes from GitHub, which the tool queries directly.
    # Host-level (one servette.py process, one version).
    #
    # Gated on the site having auth, so the exact version reaches only a party
    # that already holds the site's password — never an anonymous scanner, for
    # whom a precise version is a targeting oracle the moment any version-specific
    # hole is disclosed. A site with no password does not serve it at all: the
    # path falls through to a normal 404, leaving the endpoint invisible to the
    # public. (A remote tool for a no-auth site reads the version another way; a
    # local operator has it from 'status'.)
    if site.username and url_path.split("?", 1)[0] == _WELL_KNOWN_VERSION_PATH:
        body = json.dumps({"running": __version__, "backup": _backup_version()}).encode()
        return resp(200, [(b"content-type", b"application/json"),
                          (b"content-length", str(len(body)).encode())], body)

    # Resolve request path to a file within the matched site's own serve_dir
    try:
        file_path, status = _resolve_request_path(url_path, site.serve_dir)
    except Exception as e:
        log.error("500 resolving %s: %s", log_path, e)
        body_500 = b"Internal server error."
        return resp(500, [(b"content-type", b"text/plain"), (b"content-length", str(len(body_500)).encode())], body_500)

    if status == 403:
        log.warning("403 Forbidden %s from %s", log_path, ip)
        body_403 = b"Forbidden."
        return resp(403, [(b"content-type", b"text/plain"), (b"content-length", str(len(body_403)).encode())], body_403)

    if status == 404 or file_path is None:
        # Try custom 404.html in serve_dir root
        custom_404 = os.path.join(_resolve(site.serve_dir), "404.html")
        if os.path.isfile(custom_404):
            raw_404, _, _ = _get_cached_file(custom_404)
            body_404 = raw_404 or b"Not found."
            content_type_404 = b"text/html; charset=utf-8"
        else:
            body_404 = b"Not found."
            content_type_404 = b"text/plain"
        log.warning("404 Not Found %s from %s", log_path, ip)
        return resp(404, [(b"content-type", content_type_404), (b"content-length", str(len(body_404)).encode())], body_404)

    raw, compressed, etag = _get_cached_file(file_path)
    if raw is None:
        log.error("500 could not read %s", file_path)
        body_500 = b"Internal server error."
        return resp(500, [(b"content-type", b"text/plain"), (b"content-length", str(len(body_500)).encode())], body_500)

    # 304 Not Modified
    if headers.get("If-None-Match", "") == etag:
        log.info("304 Not Modified %s to %s", log_path, ip)
        return resp(304, [(b"etag", etag.encode()), (b"cache-control", _cache_control_header(site.username).encode())])

    accept_encoding = headers.get("Accept-Encoding", "")
    use_gzip        = compressed is not None and "gzip" in accept_encoding
    mime            = _mime_type(file_path)
    common = [
        (b"content-type",  mime.encode()),
        (b"etag",          etag.encode()),
        (b"cache-control", _cache_control_header(site.username).encode()),
        (b"vary",          b"Accept-Encoding"),
    ]

    if use_gzip:
        # Byte ranges apply to the identity representation, so they aren't combined
        # with gzip; compressible types are small text anyway.
        log.info("200 %s to %s", log_path, ip)
        return resp(200, common + [
            (b"content-length",   str(len(compressed)).encode()),
            (b"content-encoding", b"gzip"),
        ], compressed)

    # Serving raw: advertise and honor byte ranges (needed for media seeking).
    total = len(raw)
    rng   = _parse_range(headers.get("Range", ""), total)
    if rng == "invalid":
        log.info("416 Range Not Satisfiable %s to %s", log_path, ip)
        return resp(416, [
            (b"content-range",  f"bytes */{total}".encode()),
            (b"content-length", b"0"),
            (b"accept-ranges",  b"bytes"),
        ])
    if rng is not None:
        start, end = rng
        chunk = raw[start:end + 1]
        log.info("206 %s [%d-%d] to %s", log_path, start, end, ip)
        return resp(206, common + [
            (b"content-range",  f"bytes {start}-{end}/{total}".encode()),
            (b"content-length", str(len(chunk)).encode()),
            (b"accept-ranges",  b"bytes"),
        ], chunk)

    log.info("200 %s to %s", log_path, ip)
    return resp(200, common + [
        (b"content-length", str(total).encode()),
        (b"accept-ranges",  b"bytes"),
    ], raw)


def _select_site(host):
    """Match a Host/SNI value (bare hostname, port stripped if present) against
    configured sites — uniform regardless of site count. Exact domain match
    first; else the first domainless site, which acts as the catch-all (any
    Host reaches a self-signed/LAN site with no domain configured). No
    domainless site and no domain match: None, the closed-system miss."""
    host = (host or "").split(":")[0].strip().lower()
    for site in config.sites:
        if site.domain and site.domain.lower() == host:
            return site
    # www.<domain> reaches the site configured as <domain>. _obtain_trusted_cert
    # deliberately issues one certificate covering both names, so routing has to
    # honour the same pair or the www name gets a certificate and then a 404.
    # Only after the exact loop above, so a site explicitly configured as
    # www.<domain> still wins its own traffic rather than being shadowed.
    if host.startswith("www."):
        bare = host[4:]
        for site in config.sites:
            if site.domain and site.domain.lower() == bare:
                return site
    for site in config.sites:
        if not site.domain:
            return site
    return None


def _domain_in_use(domain, excluding=None):
    """True if some other configured site already claims this domain
    (case-insensitive). Two sites sharing a domain would make TLS and HTTP
    routing silently disagree about which site is being served:
    _build_site_ssl_contexts keys its SNI table by domain, so the later site
    registered wins there, while _select_site above returns the first
    matching site — a visitor would get one site's certificate and the
    other's content."""
    domain = domain.lower()
    return any(s is not excluding and s.domain and s.domain.lower() == domain for s in config.sites)


def _build_ssl_context(cert_path, key_path):
    """TLS context for one certificate — minimum version enforced, optional cipher
    override, ALPN pinned to HTTP/1.1. Raises if the cert or key is unreadable, so
    startup can fail closed rather than serve nothing."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _TLS_VERSIONS.get(config.tls_min_version, ssl.TLSVersion.TLSv1_2)
    if config.ciphers:
        ctx.set_ciphers(config.ciphers)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def _ensure_default_cert():
    """The generic, no-domain cert behind the closed-system TLS fallback — used
    only when no configured site is itself domainless (which would otherwise
    serve as the natural default). Generated once, lazily, the same way a
    self-signed site cert is."""
    if not os.path.exists(_DEFAULT_CERT_FILE):
        os.makedirs(_DEFAULT_CERT_DIR, exist_ok=True)
        _generate_self_signed_cert(_DEFAULT_CERT_FILE, _DEFAULT_KEY_FILE)
        _chown_servette(_DEFAULT_CERT_DIR)
    return _DEFAULT_CERT_FILE, _DEFAULT_KEY_FILE


def _build_site_ssl_contexts():
    """Build one SSLContext per configured site, plus the default/base context the
    listening socket is constructed with and that's presented whenever SNI doesn't
    match any site (absent, unrecognized, or direct-IP access) — the closed
    system. A domainless site's own context serves as that default when one
    exists; otherwise _ensure_default_cert() supplies one tied to no site's
    identity. Returns the default context, already carrying sni_callback —
    the per-site contexts live only inside its closure."""
    domain_ctx  = {}
    default_ctx = None
    for site in config.sites:
        ctx = _build_ssl_context(_resolve(site.cert_file), _resolve(site.key_file))
        if site.domain:
            d = site.domain.lower()
            domain_ctx[d] = ctx
            # The issued certificate covers www.<domain> too, so the SNI table
            # has to answer for that name as well — otherwise a www connection
            # falls through to the default context and is served a certificate
            # for nothing it asked for, before routing ever runs. setdefault,
            # and exact matches assign unconditionally, so a site explicitly
            # configured as www.<domain> keeps its own context regardless of
            # which order the two sites appear in.
            domain_ctx.setdefault(f"www.{d}", ctx)
        elif default_ctx is None:
            default_ctx = ctx  # first domainless site is the catch-all/default

    if default_ctx is None:
        cert_path, key_path = _ensure_default_cert()
        default_ctx = _build_ssl_context(cert_path, key_path)

    def _sni_callback(ssl_socket, server_name, ssl_context):
        ctx = domain_ctx.get((server_name or "").lower())
        if ctx is not None:
            ssl_socket.context = ctx
        # else: leave the default context in place — closed system

    default_ctx.sni_callback = _sni_callback
    return default_ctx


class _Handler(http.server.BaseHTTPRequestHandler):
    """Serves every request through the transport-agnostic _handle_request. Each
    connection runs in its own thread (ThreadingHTTPServer), so one request's
    synchronous file read and gzip can't stall any other."""
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
            # ACME HTTP-01 tokens are base64url (RFC 8555); anything outside that
            # charset is not a challenge and gets no filesystem lookup at all. The
            # realpath-prefix check is belt over those braces, in the guard shape
            # static analyzers verify.
            token      = path[len(prefix):]
            chall_dir  = os.path.realpath(os.path.join(ACME_WEBROOT, ".well-known", "acme-challenge"))
            chall_path = os.path.realpath(os.path.join(chall_dir, token))
            if re.fullmatch(r"[A-Za-z0-9_-]+", token) and chall_path.startswith(chall_dir + os.sep):
                try:
                    with open(chall_path, "rb") as f:
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
        url  = url.replace("\r", "").replace("\n", "")   # never let the header carry CRLF
        self.send_response_only(301)
        self.send_header("Location", url)
        self.send_header("Content-Length", "0")
        self.end_headers()
        log.info("Redirected to %s", url)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _serve

    def log_message(self, *args):
        pass


# Ceilings on concurrent connections — one global, one per source IP. Each connection
# holds one worker thread for its lifetime (up to the 30s idle timeout on keep-alive),
# so the global cap bounds thread/memory use under a connection flood — light enough
# for a Raspberry Pi, ample for a static site. The per-IP cap stops one source from
# holding every slot: monopolizing the pool takes cooperating addresses, not one client.
MAX_CONNECTIONS        = 128
MAX_CONNECTIONS_PER_IP = 32


class _CappedThreadingHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer with ceilings on concurrent connections: a global cap,
    and a per-source-IP cap so one source cannot monopolize the pool. Past either,
    new connections are closed immediately rather than spawning unbounded threads —
    a connection-exhaustion / slowloris mitigation that pairs with the per-connection
    socket timeout on the handlers (which reaps slow or idle connections).

    The per-IP cap is enforced at accept time, keyed on the socket address: that is
    before any bytes are read, so it catches connections that never send a request —
    the slowloris case a request-time check would miss. Behind a declared
    trusted_proxy every connection carries the proxy's address and the count would
    cap the whole site, so enforcement is skipped there: connection policing in that
    topology belongs to the proxy, the only party that sees per-client connections.
    Counting itself runs unconditionally, so a trusted_proxy edit mid-connection can
    never unbalance the increment/decrement pairing."""
    daemon_threads = True

    def __init__(self, address, handler, max_connections=MAX_CONNECTIONS,
                 max_per_ip=MAX_CONNECTIONS_PER_IP):
        super().__init__(address, handler)
        self._slots      = threading.BoundedSemaphore(max_connections)
        self._max_per_ip = max_per_ip
        self._ip_counts  = {}
        self._ip_lock    = threading.Lock()

    @staticmethod
    def _ip_key(client_address):
        return _normalize_ip(client_address[0]) if client_address else "?"

    def _ip_acquire(self, ip):
        """Count a connection against ip. Returns False — without counting — when
        the source is at its cap and enforcement is on."""
        with self._ip_lock:
            count = self._ip_counts.get(ip, 0)
            if not config.trusted_proxy and count >= self._max_per_ip:
                return False
            self._ip_counts[ip] = count + 1
            return True

    def _ip_release(self, ip):
        with self._ip_lock:
            count = self._ip_counts.get(ip, 0) - 1
            if count > 0:
                self._ip_counts[ip] = count
            else:
                self._ip_counts.pop(ip, None)   # drop zeroed keys — dict stays bounded

    def process_request(self, request, client_address):
        ip = self._ip_key(client_address)
        if not self._ip_acquire(ip):
            self.shutdown_request(request)   # source at its per-IP cap — shed, don't queue
            return
        if not self._slots.acquire(blocking=False):
            self._ip_release(ip)
            self.shutdown_request(request)   # at capacity — shed load, don't queue
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()    # the worker thread never started — reclaim
            self._ip_release(ip)     # both reservations
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()
            self._ip_release(self._ip_key(client_address))

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

        def _create_venv():
            """Create the venv, returning the failure instead of raising.
            `import venv` succeeding proves nothing on its own: Debian/Ubuntu
            ship the venv module in the stdlib but split ensurepip's wheels
            into the python3-venv package, so create(with_pip=True) is what
            actually fails on a minimal host — recovery must key on that."""
            try:
                import venv as _venv_mod
                _venv_mod.create(_VENV_DIR, with_pip=True, clear=True)
                return None
            except Exception as e:
                return e

        error = _create_venv()
        if error is not None:
            # Install the distro package that completes venv support, then try
            # once more. Each manager gets its own argv — apk's subcommand is
            # 'add' and it has no '-y' flag.
            pkg_managers = [
                (("apt-get", "install", "-y"), f"python3.{sys.version_info.minor}-venv"),
                (("dnf",     "install", "-y"), "python3-venv"),
                (("apk",     "add"),           "py3-venv"),
            ]
            for argv, pkg in pkg_managers:
                if shutil.which(argv[0]):
                    result = subprocess.run([*argv, pkg])
                    if result.returncode != 0:
                        print(f"  Error: failed to install {pkg} via {argv[0]}")
                        sys.exit(1)
                    break
            else:
                print(f"  Error: failed to create virtual environment: {error}")
                print("  No supported package manager found to fix it (tried apt-get, dnf, apk).")
                sys.exit(1)
            error = _create_venv()
            if error is not None:
                print(f"  Error: failed to create virtual environment: {error}")
                sys.exit(1)

        deps = ["cryptography>=41.0,<50.0"]
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
_https_thread         = None  # the thread running its serve_forever loop
_http_server          = None  # the port-80 redirect server (None if unavailable)
_server_start_time    = None
_watchdog_thread      = None
_sweep_thread         = None
_sweep_stop           = threading.Event()
_last_renewal_attempt = {}  # domain -> monotonic timestamp of the last renewal attempt;
                            # per-domain so one site's failure-triggered backoff
                            # can't delay another's renewal

_TLS_VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}
ACME_RETRIES  = 3


def _server_running():
    """True when the HTTPS server is actually serving — the thread must be alive,
    not merely the server object constructed, so a crashed serve loop reads as
    stopped instead of running."""
    return _https_thread is not None and _https_thread.is_alive()


def _cert_watchdog_tick():
    """One renewal/reload pass over every configured site's certificate. Each
    site's pass is wrapped in its own try/except: one site's failure can't skip
    the rest, and nothing here can kill the watchdog thread — a dead watchdog
    would silently end renewals for every site, for the life of the process;
    the next pass simply retries."""
    for site in config.sites:
        try:
            cert_path = _resolve(site.cert_file)

            if site.domain:
                # Let's Encrypt cert: auto-renew when fewer than 30 days remain
                days = _cert_days_remaining(cert_path)
                if days is not None and days < 30:
                    now  = time.monotonic()
                    last = _last_renewal_attempt.get(site.domain, 0.0)
                    if now - last >= 3600:
                        _last_renewal_attempt[site.domain] = now
                        log.info("Certificate for %s expires in %d days — renewing", site.domain, days)
                        _obtain_trusted_cert(site.domain, site)
            else:
                # Self-signed or externally managed cert: reload if the file changed on disk
                try:
                    mtime = os.path.getmtime(cert_path)
                    if site._cert_mtime is not None and mtime != site._cert_mtime:
                        log.info("Certificate changed on disk — reloading server")
                        site._cert_mtime = mtime
                        _reload_server()
                except OSError:
                    pass
        except Exception:
            log.exception("Cert watchdog pass failed for %s — will retry on the next pass",
                          site.domain or "a self-signed site")


def _cert_watchdog():
    """Auto-renew Let's Encrypt certs before expiry; detect externally-rotated certs."""
    while _server_running():
        time.sleep(60)
        if not _server_running():
            break
        _cert_watchdog_tick()


def start_server():
    global _server_start_time, _watchdog_thread, _sweep_thread, \
        _https_server, _https_thread, _http_server

    if _server_running():
        print("Server is already running.")
        return

    for site in config.sites:
        for fname in [site.serve_dir, site.cert_file, site.key_file]:
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

    # Build the HTTPS server, failing closed if the socket can't bind or a cert is
    # unreadable — better than a live process that serves nothing. Both surface here
    # synchronously: the bind happens in the constructor, the certs in _build_site_ssl_contexts.
    try:
        https = _TLSThreadingHTTPServer(("0.0.0.0", config.port), _Handler, _build_site_ssl_contexts())
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
    _https_thread = threading.Thread(target=https.serve_forever, daemon=True)
    _https_thread.start()
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
    log.info("Server started on port %d", config.port)
    for site in config.sites:
        host_display = site.domain or "localhost"
        print(f"\nServing {site.serve_dir}/ at https://{host_display}:{config.port}\n")

        days = _cert_days_remaining(_resolve(site.cert_file))
        if days is not None and days < 30:
            label = site.domain or "this site"
            if days <= 0:
                print(f"Warning: SSL certificate for {label} has expired. Browsers will block visitors.")
                print("Run 'config' then 'cert' to renew it.\n")
                log.warning("SSL certificate for %s has expired", label)
            else:
                print(f"Warning: SSL certificate for {label} expires in {days} days.")
                print("Run 'config' then 'cert' to renew it.\n")
                log.warning("SSL certificate for %s expires in %d days", label, days)

    for issue in _production_issues():
        print(_c(f"  {issue}", "yellow"))
    for warning in _cache_warnings():
        print(_c(f"  {warning}", "yellow"))


def stop_server():
    global _server_start_time, _sweep_thread, _https_server, _https_thread, _http_server

    # Keyed on the server objects, not liveness: a crashed serve loop still needs
    # its sockets closed, which _server_running() (thread liveness) would skip.
    if _https_server is None and _http_server is None:
        return

    for srv in (_https_server, _http_server):
        if srv is not None:
            srv.shutdown()
            srv.server_close()
    if _https_thread is not None:
        _https_thread.join(timeout=10)
    _https_server      = None
    _https_thread      = None
    _http_server       = None
    _server_start_time = None

    _sweep_stop.set()
    if _sweep_thread is not None:
        _sweep_thread.join(timeout=5)
        _sweep_thread = None
    log.info("Server stopped")
    print("Session server stopped.")


def _watch_server(poll=5, grace=30):
    """Block until the HTTPS server has been dead for `grace` seconds.

    --serve exits non-zero when this returns, so systemd's Restart=always brings
    the service back. Without the watch, a dead server thread leaves a living
    process: systemd reports active while nothing is listening. The grace period
    spans the stop/start window of an in-process certificate reload, so a reload
    doesn't read as a death."""
    deadline = None
    while True:
        t = _https_thread
        if t is not None and t.is_alive():
            deadline = None
            t.join(timeout=poll)
            continue
        now = time.monotonic()
        if deadline is None:
            deadline = now + grace
        elif now >= deadline:
            return
        time.sleep(poll)


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
    because it lives under the server's own directory; the server never writes it.
    The service's own code (servette.py and its .bak) and the managed venv are
    pinned read-only on top of that writable directory — the serving process never
    rewrites them, so a compromised one cannot patch the program it re-execs into."""
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
ReadOnlyPaths={servette_path} -{_VENV_DIR} -{servette_path}.bak
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


def _netwatch_units():
    """The (service, timer) unit pair for the network watchdog.

    Every 5 minutes: if the host has no route out, ask the network manager to
    start over. Recovers the observed failure where a netlink timeout leaves the
    link permanently 'Failed' — networkd never retries on its own, so the host
    stays dark until reboot. try-restart only touches a unit that is actually
    running, so of the three known managers (systemd-networkd on Ubuntu,
    NetworkManager on Raspberry Pi OS, dhcpcd on older Pi OS) exactly one acts;
    the whole check is a no-op while the route is healthy."""
    service = """[Unit]
Description=Servette network watchdog — recover a dropped default route

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'ip route get 1.1.1.1 >/dev/null 2>&1 && exit 0; for u in systemd-networkd NetworkManager dhcpcd; do systemctl try-restart "$u.service" 2>/dev/null || true; done'
"""
    timer = """[Unit]
Description=Run the Servette network watchdog every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
"""
    return service, timer


_SWAP_PATH = "/swapfile"


def _meminfo():
    """Return (mem_total_kb, mem_available_kb, swap_total_kb) from /proc/meminfo,
    or (None, None, None) where it can't be read (non-Linux)."""
    try:
        fields = {}
        with open("/proc/meminfo") as f:
            for line in f:
                key, _, rest = line.partition(":")
                fields[key.strip()] = int(rest.split()[0])  # values are in kB
        return fields["MemTotal"], fields["MemAvailable"], fields["SwapTotal"]
    except (OSError, KeyError, ValueError, IndexError):
        return None, None, None


# The unpredictable part of demand: an allowance for the single-process spike
# nobody plans for, sized to the largest one observed in production (fwupd
# ballooning to ~656 MB virtual on a 414 MB host, hourly, for weeks).
_SPIKE_ALLOWANCE_KB = 700 * 1024
_SWAP_MIN_MB        = 512
_SWAP_MAX_MB        = 2048


def _round_up_2sig(n):
    """Round a positive integer up to two significant digits (1148 → 1200).

    The swap default is an estimate; a round number says so, where an
    exact-looking one would overstate its precision."""
    mag = 10 ** max(len(str(int(n))) - 2, 0)
    return -(-int(n) // mag) * mag


def _swap_recommendation(mem_kb, avail_kb, cache_mb):
    """Recommended total swap in bytes for this host, or None when demand fits in RAM.

    Supply is measured (MemTotal). Demand is what's resident now (MemTotal −
    MemAvailable), plus Servette's configured cache, plus the spike allowance.
    When demand exceeds supply, the deficit is doubled for margin, rounded up to
    two significant digits, floored at 512 MB and capped at 2 GB — the threshold
    emerges from the measurement rather than a hardcoded RAM ceiling. Whether to
    act on the recommendation is _swap_offer's decision."""
    if mem_kb is None or avail_kb is None:
        return None
    demand_kb  = (mem_kb - avail_kb) + cache_mb * 1024 + _SPIKE_ALLOWANCE_KB
    deficit_kb = demand_kb - mem_kb
    if deficit_kb <= 0:
        return None
    size_mb = _round_up_2sig(-(-2 * deficit_kb // 1024))
    return min(max(size_mb, _SWAP_MIN_MB), _SWAP_MAX_MB) * 1024 ** 2


def _swap_offer(rec_mb, ours, active_mb):
    """(description, skip_hint) for the swap prompt, or None when no offer is due.

    Only Servette's own /swapfile is ever offered a resize; swap Servette didn't
    create (a partition, a distro-managed file) is left alone — resizing it would
    fight whatever manages it. Enter always takes the recommendation; the skip
    hint says what declining preserves, so no two options in the prompt are
    redundant."""
    if rec_mb is None:
        return None
    if active_mb > 0 and not ours:
        return None
    if not ours:
        return "no swapfile", "skip"
    if active_mb == 0:
        return "an inactive swapfile", "skip"
    if active_mb >= rec_mb:
        return None
    return f"a {active_mb} MB swapfile", f"keep {active_mb}"


def _root_on_sd_card():
    """True when the root filesystem sits on an SD/eMMC device (/dev/mmcblk*),
    where swap writes add flash wear worth mentioning before the operator decides."""
    try:
        dev = os.stat("/").st_dev
        with open(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}/uevent") as f:
            return "DEVNAME=mmcblk" in f.read()
    except OSError:
        return False


def _ensure_swap():
    """Offer to create — or grow — Servette's swapfile where demand can outrun RAM."""
    mem_kb, avail_kb, swap_kb = _meminfo()
    rec       = _swap_recommendation(mem_kb, avail_kb, config.cache_size_mb)
    rec_mb    = rec // (1024 * 1024) if rec else None
    ours      = os.path.exists(_SWAP_PATH)
    active_mb = (swap_kb or 0) // 1024  # total active swap; ≈ ours when ours is the only one
    offer     = _swap_offer(rec_mb, ours, active_mb)
    if offer is None:
        return
    swap_desc, skip_hint = offer
    print(f"  This system has {mem_kb // 1024} MB of RAM ({avail_kb // 1024} MB free) and {swap_desc}.")
    print("  A spike past free RAM can knock the host offline, but a swapfile absorbs spikes to disk.")
    print(f"  Recommended swapfile size for the estimated spike: {rec_mb} MB")
    if _root_on_sd_card():
        print("  Note: root storage is an SD/eMMC card — swap writes add flash wear.")
    resp = _input(f"  Swapfile size in MB [Enter = {rec_mb}, any size, n = {skip_hint}]: ",
                  default="n").strip().lower()
    if resp in ("n", "no"):
        return
    mb = rec_mb
    if resp:
        try:
            mb = max(64, int(resp))
        except ValueError:
            print("  Not a number — skipping swap setup.")
            return
    if ours and mb == active_mb:
        return  # keeping the current size — nothing to do
    size = mb * 1024 * 1024
    try:
        st        = os.statvfs("/")
        reclaimed = os.path.getsize(_SWAP_PATH) if ours else 0
        if st.f_bavail * st.f_frsize + reclaimed < size + 1024 ** 3:  # keep 1 GB free
            print(f"  Not enough free disk for a {mb} MB swapfile plus 1 GB margin — skipping.")
            return
    except OSError:
        return
    if ours and active_mb > 0:
        r = subprocess.run(["swapoff", _SWAP_PATH], capture_output=True)
        if r.returncode != 0:
            print("  Could not deactivate the current swapfile (heavily in use?) — try again later.")
            return
    try:
        with open(_SWAP_PATH, "wb") as f:
            os.chmod(_SWAP_PATH, 0o600)  # before content exists — never world-readable
            os.posix_fallocate(f.fileno(), 0, size)
        subprocess.run(["mkswap", _SWAP_PATH], check=True, capture_output=True)
        subprocess.run(["swapon", _SWAP_PATH], check=True, capture_output=True)
        with open("/etc/fstab") as f:
            fstab = f.read()
        if _SWAP_PATH not in fstab.split():
            with open("/etc/fstab", "a") as f:
                f.write(f"{_SWAP_PATH} none swap sw 0 0\n")
        print(f"  Swapfile active ({mb} MB), persistent across reboots.")
        log.info("Swapfile active: %d MB at %s", mb, _SWAP_PATH)
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"  Could not set up swapfile: {e}")
        try:
            subprocess.run(["swapoff", _SWAP_PATH], capture_output=True)
            os.remove(_SWAP_PATH)
        except OSError:
            pass


def _write_unit_files():
    """Write (or refresh) the systemd unit, the network watchdog unit pair, and
    the file ownership they depend on. Returns True if a service file already
    existed (a refresh) or False if this is a fresh enable. Contains no prompts,
    so it is safe to call silently — shared by cmd_enable (interactive) and
    the post-update path (silent), so a release that changes what the unit
    should contain reaches an already-enabled host without a separate manual
    'enable'."""
    updating      = _service_file_exists()
    servette_path = os.path.abspath(__file__)
    python_path   = _VENV_PY if os.path.exists(_VENV_PY) else subprocess.run(
        ["which", "python3"], capture_output=True, text=True
    ).stdout.strip()

    service = _systemd_unit(python_path, servette_path)

    # Create system user if needed
    if not _servette_user_exists():
        subprocess.run(
            ["useradd", "--system", "--no-create-home", "--shell", "/sbin/nologin", "servette"],
            check=True
        )
        print("Created system user 'servette'.")

    with open(SERVICE_PATH, "w") as f:
        f.write(service)

    netwatch_service, netwatch_timer = _netwatch_units()
    with open(NETWATCH_PATH + ".service", "w") as f:
        f.write(netwatch_service)
    with open(NETWATCH_PATH + ".timer", "w") as f:
        f.write(netwatch_timer)

    subprocess.run(["systemctl", "daemon-reload"],      check=True)
    subprocess.run(["systemctl", "enable", "servette"], check=True, capture_output=True)
    subprocess.run(["systemctl", "enable", "--now", "servette-netwatch.timer"],
                   check=True, capture_output=True)

    # Chown files the service process needs to read, across every site
    _chown_servette(config.CONFIG_FILE)
    for site in config.sites:
        if site.cert_file:
            _chown_servette(_resolve(site.cert_file))
        if site.key_file:
            _chown_servette(_resolve(site.key_file))
        _chown_servette(_resolve(site.serve_dir))
    _chown_servette(os.path.join(BASE_DIR, "certs"))
    _chown_servette(os.path.join(BASE_DIR, ".acme-account.pem"))
    # Create the ACME webroot now so it exists when systemd applies ReadWritePaths
    # — a missing ReadWritePaths target makes the unit fail to start.
    os.makedirs(ACME_WEBROOT, exist_ok=True)
    _chown_servette(ACME_WEBROOT)

    # Warn if any site's serve_dir isn't world-readable
    for site in config.sites:
        if not site.serve_dir:
            continue
        serve_path = _resolve(site.serve_dir)
        if os.path.isdir(serve_path):
            mode = os.stat(serve_path).st_mode
            if not (mode & 0o005 == 0o005):  # world read+execute on directory
                print(f"  Warning: '{serve_path}' may not be readable by the servette user.")
                print(f"  Fix with: chmod -R a+rX {serve_path}")

    return updating


def cmd_enable():
    try:
        updating = _write_unit_files()

        if updating:
            print("Service file updated.")
        else:
            print("Servette enabled as a system service.")
            print("It will start automatically on boot and survive SSH disconnects.")
        print("Network watchdog timer enabled (recovers a dropped default route).")
        log.info("Enabled as systemd service")

        _ensure_swap()

        if updating and _service_is_active():
            _reload_server()   # apply the refreshed unit — no manual stop/start needed
        elif _server_running():
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


def cmd_disable():
    if not _service_file_exists():
        cmd_status()
        return

    try:
        if _service_is_active():
            subprocess.run(["systemctl", "stop",    "servette"], check=True, capture_output=True)
        subprocess.run(["systemctl", "disable", "servette"], check=True, capture_output=True)
        subprocess.run(["systemctl", "disable", "--now", "servette-netwatch.timer"],
                       capture_output=True)  # best-effort: may predate the watchdog
        os.remove(SERVICE_PATH)
        for suffix in (".service", ".timer"):
            try:
                os.remove(NETWATCH_PATH + suffix)
            except OSError:
                pass
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


class _spinner:
    """Context manager that runs _spin(message) for the duration of the block —
    TTY only, so non-interactive runs (service renewals, pipes) stay clean."""

    def __init__(self, message):
        self._message = message
        self._stop    = threading.Event()
        self._thread  = None

    def __enter__(self):
        if sys.stdout.isatty():
            self._thread = threading.Thread(target=_spin, args=(self._message, self._stop), daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        return False


def _write_private_key(path, data):
    """Write key material with 0600 set at file creation, not chmod'd after:
    under a permissive umask, write-then-chmod leaves a window where another
    local user can open the key (an open fd survives the chmod), and a crash
    between the two leaves it world-readable permanently. Same pattern the
    swapfile creation uses — the mode exists before the content does."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


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

    _write_private_key(key_path, key.private_bytes(
        _serialization.Encoding.PEM,
        _serialization.PrivateFormat.TraditionalOpenSSL,
        _serialization.NoEncryption()
    ))

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
    if "--serve" in sys.argv:
        # Inside the service, the sandboxed unit user can't systemctl restart
        # (NoNewPrivileges, least privilege). Stop serving instead: _watch_server
        # sees the dead thread, --serve exits non-zero, and Restart=always
        # relaunches the service with the new certificate loaded.
        log.info("Stopping to load the new certificate — systemd restarts the service")
        stop_server()
    elif _service_is_active():
        try:
            subprocess.run(["systemctl", "restart", "servette"], check=True, capture_output=True)
            print("  Server restarted.")
        except Exception as e:
            print(f"  Could not restart service: {e}")
    elif _server_running():
        stop_server()
        _wait_for_port_free(config.port)
        start_server()


def _b64url(data):
    """base64url without padding — the encoding JOSE/ACME uses everywhere."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_int(n):
    """A non-negative integer as a base64url big-endian byte string (for JWK n/e)."""
    return _b64url(n.to_bytes((n.bit_length() + 7) // 8 or 1, "big"))


class _Resp:
    """A tiny HTTP response holder so the ACME client can read status/headers/body
    uniformly whether urllib returned success or raised HTTPError."""
    __slots__ = ("status", "headers", "body")

    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        return json.loads(self.body)

    @property
    def text(self):
        return self.body.decode()


class _ACMEError(Exception):
    """An ACME failure. `failed` holds the DNS names whose authorization was rejected,
    so the caller can decide whether to fall back (e.g. drop a www with no DNS)."""

    def __init__(self, message, failed=None):
        super().__init__(message)
        self.failed = failed or set()


class _ACMEClient:
    """A minimal ACME (RFC 8555) client — just enough of the protocol for HTTP-01
    issuance with a single account key, replacing the certbot `acme` + `josepy`
    libraries with stdlib urllib + cryptography. Deliberately narrow: HTTP-01 only,
    no revocation, no key rollover. Requests are RS256-signed JWS; the replay nonce
    is tracked from each response's Replay-Nonce header. The directory is fetched
    lazily, so constructing a client touches no network (and stays unit-testable)."""

    def __init__(self, directory_url, account_key):
        self._url   = directory_url
        self._key   = account_key   # a cryptography RSA private key
        self._nonce = None
        self._kid   = None          # account URL; until set, requests carry the JWK
        self._dir   = None

    def _directory(self):
        if self._dir is None:
            self._dir = self._request(self._url).json()
        return self._dir

    # ── HTTP + nonce ──
    def _request(self, url, data=None, method=None):
        headers = {"User-Agent": "servette"}
        if data is not None:
            headers["Content-Type"] = "application/jose+json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            r    = urllib.request.urlopen(req, timeout=30)
            resp = _Resp(r.status, r.headers, r.read())
        except urllib.error.HTTPError as e:
            resp = _Resp(e.code, e.headers, e.read())
        if resp.headers.get("Replay-Nonce"):
            self._nonce = resp.headers["Replay-Nonce"]
        return resp

    # ── JWS ──
    def _jwk(self):
        nums = self._key.public_key().public_numbers()
        return {"e": _b64url_int(nums.e), "kty": "RSA", "n": _b64url_int(nums.n)}

    def thumbprint(self):
        canon = json.dumps(self._jwk(), sort_keys=True, separators=(",", ":")).encode()
        return _b64url(hashlib.sha256(canon).digest())

    def key_authorization(self, token):
        return f"{token}.{self.thumbprint()}"

    def _sign(self, url, payload):
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.asymmetric import padding as _padding
        protected = {"alg": "RS256", "nonce": self._nonce, "url": url}
        protected["kid" if self._kid else "jwk"] = self._kid or self._jwk()
        p = _b64url(json.dumps(protected, separators=(",", ":")).encode())
        # payload=None is ACME "POST-as-GET" (empty string); {} is a real empty object.
        y = "" if payload is None else _b64url(json.dumps(payload, separators=(",", ":")).encode())
        sig = self._key.sign(f"{p}.{y}".encode(), _padding.PKCS1v15(), _hashes.SHA256())
        return json.dumps({"protected": p, "payload": y, "signature": _b64url(sig)}).encode()

    def _post(self, url, payload):
        # Two attempts: a badNonce is the one error worth retrying, because the failing
        # response hands back a fresh nonce. Any other error fails immediately.
        for attempt in range(2):
            if self._nonce is None:
                self._request(self._directory()["newNonce"], method="HEAD")
            resp = self._request(url, data=self._sign(url, payload))
            if resp.status < 400:
                return resp
            problem = {}
            try:
                problem = resp.json()
            except Exception:
                pass
            if attempt == 0 and problem.get("type", "").endswith("badNonce"):
                continue
            raise _ACMEError(problem.get("detail") or f"ACME error {resp.status} at {url}")
        raise _ACMEError("ACME request failed after a nonce retry")

    def _post_as_get(self, url):
        return self._post(url, None)

    # ── protocol steps ──
    def new_account(self, email):
        payload = {"termsOfServiceAgreed": True}
        if email:
            payload["contact"] = [f"mailto:{email}"]
        resp = self._post(self._directory()["newAccount"], payload)
        self._kid = resp.headers.get("Location")
        if not self._kid:
            raise _ACMEError("ACME did not return an account URL")

    def _poll(self, url, tries=20, delay=2):
        """POST-as-GET a resource until it settles (valid/invalid) or we give up."""
        for _ in range(tries):
            obj = self._post_as_get(url).json()
            if obj.get("status") in ("valid", "invalid"):
                return obj
            time.sleep(delay)
        return obj

    def issue(self, names, csr_der, challenge_dir):
        """Run one HTTP-01 issuance for `names`, writing challenge files under
        challenge_dir and returning the PEM certificate chain. Raises _ACMEError on
        failure, with `.failed` set to the names whose validation was rejected."""
        resp      = self._post(self._directory()["newOrder"],
                               {"identifiers": [{"type": "dns", "value": n} for n in names]})
        order     = resp.json()
        order_url = resp.headers.get("Location")

        written = []
        try:
            for authz_url in order["authorizations"]:
                authz = self._post_as_get(authz_url).json()
                chall = next(c for c in authz["challenges"] if c["type"] == "http-01")
                path  = os.path.join(challenge_dir, chall["token"])
                with open(path, "w") as f:
                    f.write(self.key_authorization(chall["token"]))
                written.append(path)
                self._post(chall["url"], {})   # tell the server the file is in place

            failed = set()
            for authz_url in order["authorizations"]:
                authz = self._poll(authz_url)
                if authz.get("status") != "valid":
                    failed.add(authz["identifier"]["value"])
            if failed:
                raise _ACMEError("domain validation failed", failed=failed)

            self._post(order["finalize"], {"csr": _b64url(csr_der)})
            final = self._poll(order_url)
            if final.get("status") != "valid":
                raise _ACMEError(f"order did not complete (status: {final.get('status')})")
            return self._post_as_get(final["certificate"]).text
        finally:
            for p in written:
                try:
                    os.remove(p)
                except OSError:
                    pass


def _obtain_trusted_cert(domain, site):
    """Get a trusted certificate from Let's Encrypt over HTTP-01, using Servette's own
    minimal ACME client (_ACMEClient) on stdlib urllib + cryptography, and store it
    on `site`."""
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _serialization

    ACME_URL         = "https://acme-v02.api.letsencrypt.org/directory"
    ACCOUNT_KEY_FILE = os.path.join(BASE_DIR, ".acme-account.pem")
    CERTS_DIR        = os.path.join(BASE_DIR, "certs", domain)
    challenge_dir    = os.path.join(ACME_WEBROOT, ".well-known", "acme-challenge")

    print(f"\nGetting a trusted SSL certificate for {domain}...")
    print("Make sure your domain points to this server's IP first.\n")

    os.makedirs(challenge_dir, exist_ok=True)
    os.makedirs(CERTS_DIR, exist_ok=True)
    _chown_servette(ACME_WEBROOT)
    _chown_servette(CERTS_DIR)

    # Load or create the ACME account key — a standard RSA PEM (any existing
    # .acme-account.pem from the old josepy path loads unchanged).
    if os.path.exists(ACCOUNT_KEY_FILE):
        with open(ACCOUNT_KEY_FILE, "rb") as f:
            account_key = _serialization.load_pem_private_key(f.read(), password=None)
    else:
        account_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write_private_key(ACCOUNT_KEY_FILE, account_key.private_bytes(
            _serialization.Encoding.PEM,
            _serialization.PrivateFormat.TraditionalOpenSSL,
            _serialization.NoEncryption()
        ))
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
            label = (f"Requesting certificate for {domain}..." if attempt == 1
                     else f"Retry {attempt - 1} of {ACME_RETRIES - 1}...")
            try:
                with _spinner(label):
                    domain_key     = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    domain_key_pem = domain_key.private_bytes(
                        _serialization.Encoding.PEM,
                        _serialization.PrivateFormat.TraditionalOpenSSL,
                        _serialization.NoEncryption()
                    )
                    csr_der = (
                        _x509.CertificateSigningRequestBuilder()
                        .subject_name(_x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, domain)]))
                        .add_extension(_x509.SubjectAlternativeName([
                            _x509.DNSName(n) for n in names
                        ]), critical=False)
                        .sign(domain_key, _hashes.SHA256())
                        .public_bytes(_serialization.Encoding.DER)
                    )

                    client = _ACMEClient(ACME_URL, account_key)
                    client.new_account(config.email if config.email else None)
                    fullchain = client.issue(names, csr_der, challenge_dir)

                    cert_path = os.path.join(CERTS_DIR, "fullchain.pem")
                    key_path  = os.path.join(CERTS_DIR, "privkey.pem")

                    with open(cert_path, "w") as f:
                        f.write(fullchain)
                    _write_private_key(key_path, domain_key_pem)
                    _chown_servette(CERTS_DIR)

                site.cert_file = cert_path
                site.key_file  = key_path
                site.domain    = domain
                config.save()

                issued_names = f"{domain} and {www_domain}" if include_www else domain
                print(f"  Certificate issued for {issued_names}.")
                log.info("ACME certificate issued for %s", issued_names)

                if _server_running() or _service_is_active():
                    print("  Reloading server...")
                    _reload_server()
                last_error = None
                break

            except Exception as e:
                last_error = e
                if isinstance(e, _ACMEError) and include_www and e.failed == {www_domain}:
                    www_dns_only_failure = True
                    break  # don't retry; fall back to bare domain
                if attempt < ACME_RETRIES:
                    delay = 5 * attempt
                    log.warning("ACME attempt %d/%d failed for %s: %s — retrying in %ds", attempt, ACME_RETRIES, domain, e, delay)
                    time.sleep(delay)

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
#
# Menus are generated so the right-hand column always begins at the same place
# (2-space indent + a 22-wide label) as the status and config displays.
_PAD = 22


def _banner(title):
    """Full-width entry banner — the visual weight reserved for the two moments
    a user is entering a new mode: the shell launching, the setup wizard."""
    rule = "─" * 51
    print(f"\n{rule}\n  {title}\n{rule}")


def _section_text(title):
    """The two-line header used by every command list and settings display: an
    indented title over a shorter, indented rule. Returned rather than printed
    so it can be spliced into a precomputed help string as well as printed
    directly via _section()."""
    return f"\n  {title}\n  " + "─" * 38 + "\n"


def _section(title):
    print(_section_text(title), end="")


# Ordered like systemctl's own manual: runtime control (start/stop) before
# persistence (enable/disable) — Servette wraps systemd, and its audience
# already has that convention's intuition. Onboarding, then runtime control,
# then persistence, then observability, then maintenance, then meta.
_COMMANDS = [
    ("setup",            "guided walkthrough for getting started"),
    ("config",           "view and edit settings"),
    ("start",            "start the server"),
    ("stop",             "stop the server"),
    ("enable",           "enable Servette as a system service"),
    ("disable",          "remove the system service"),
    ("status",           "show whether the server is running"),
    ("log [n]",          "show the last n log entries"),
    ("update",           "download the latest version of servette.py"),
    ("restore",          "roll back to the previous version (undoes the last update)"),
    ("pull [n]",         "check a site's publish channel and pull new content now"),
    ("restore-site [n]", "roll back a site's content (undoes its last pull)"),
    ("help",             "show this message"),
    ("quit",             "exit"),
]
HELP = _section_text("Commands") + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _COMMANDS)

# Ordered: sites first (list/add/remove — the multi-site entry points), then
# what a site serves and how it's reached (dir/port/cert/email — email is the
# ACME registration address, grouped with the certificate it belongs to), then
# access control, then traffic shaping, then advanced/rarely-touched security
# tuning, then meta. dir/cert/publish/username/password take an optional site
# index (default 0) — same [n] convention as the top-level 'log [n]'.
_CONFIG_COMMANDS = [
    ("sites",           "list configured sites"),
    ("add-site",        "add a new site (folder, domain, password, publish channel)"),
    ("remove-site <n>", "remove a site"),
    ("dir [n]",         "directory to serve"),
    ("port",            "HTTPS port"),
    ("cert [n]",        "SSL certificate and key"),
    ("email",           "email address"),
    ("publish [n]",     "site publish channel (watch URL and signing key)"),
    ("username [n]",    "login username"),
    ("password [n]",    "login password"),
    ("limits",          "rate limits"),
    ("cache",           "browser cache policy"),
    ("proxy",           "trusted proxy IP for X-Forwarded-For"),
    ("tls",             "minimum TLS version and cipher suites"),
    ("csp",             "Content-Security-Policy header"),
    ("perms",           "Permissions-Policy header"),
    ("show",            "show current settings"),
    ("back",            "return to main shell"),
]
CONFIG_HELP = _section_text("Commands") + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _CONFIG_COMMANDS)


def _input(prompt, default=""):
    """input() that answers `default` on Ctrl-D / Ctrl-C instead of letting the
    exception traceback out of a command and kill the shell. The default lets
    prompts that would modify the host fail safe (e.g. 'n')."""
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def _prompt(question):
    return _input(f"  {question} [y/n]: ").strip().lower() == "y"


# ── Config sub-shell ──────────────────────────────────────────────────────────

def _config_show():
    def val(v):
        return v if v else "(not set)"

    cache_display = config.cache_policy
    if config.cache_policy == "max-age":
        cache_display += f" ({config.cache_max_age}s)"

    host_rows = [
        ("HTTPS port",         config.port),
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

    _section("Current Settings")
    for label, value in host_rows:
        print(f"  {label:<{_PAD}} {value}")

    for i, site in enumerate(config.sites):
        print(f"\n  Site {i}: {site.domain or '(self-signed)'}")
        site_rows = [
            ("Directory",   val(site.serve_dir)),
            ("Certificate", val(site.cert_file)),
            ("Key",         val(site.key_file)),
            ("Publish URL", val(site.publish_url)),
            ("Publish key", val(site.publish_key)),
            ("Username",    val(site.username)),
            ("Password",    "(set)" if site.password_hash else "(not set)"),
        ]
        for label, value in site_rows:
            print(f"    {label:<{_PAD - 2}} {value}")
    print()


def _config_sites():
    _section("Sites")
    for i, site in enumerate(config.sites):
        auth = "password-protected" if site.username else "no password"
        print(f"  {i}: {site.domain or '(self-signed)'} — {site.serve_dir}, {auth}")
    print()
    print("  Edit one with e.g. 'dir 1', 'cert 1', 'publish 1' (index defaults to 0).")
    print("  'add-site' adds one; 'remove-site <n>' removes one.\n")


def _is_within_base_dir(path):
    """True if path (already resolved) is BASE_DIR itself or somewhere under
    it. serve_dir must satisfy this: the publish pipeline's atomic swap
    renames within the same filesystem, and the systemd unit's
    ReadWritePaths only grants write access under BASE_DIR — a serve_dir
    outside it breaks the swap silently under the sandboxed service even
    though a manual, unsandboxed run would never show the problem.

    Defers to _within so containment is decided in exactly one place: two
    implementations of the same security predicate can drift apart, and only
    one of them would be the one anybody reads."""
    return _within(os.path.realpath(BASE_DIR), os.path.realpath(path))


def _serve_dir_exposes_secrets(path):
    """True when serving `path` would hand out Servette's own secrets. serve_dir
    is already required to sit inside BASE_DIR (see _is_within_base_dir); the
    danger left is a folder that also holds the config (password hashes), the
    ACME account key, or the TLS private keys under certs/. BASE_DIR itself holds
    all three; the certs tree is the keys. Either would be served as plain file
    reads, so both are refused as a serve_dir."""
    real  = os.path.realpath(path)
    base  = os.path.realpath(BASE_DIR)
    certs = os.path.join(base, "certs")
    return real == base or real == certs or real.startswith(certs + os.sep)


def _config_add_site():
    """Add a site — the same questions cmd_setup asks for the very first one
    (domain, password), plus the folder question the first site gets for free
    (its default, 'site', is baked in and can't also serve a second site)."""
    print("\n  Adding a new site.\n")
    dirs = sorted(d for d in os.listdir(BASE_DIR) if os.path.isdir(os.path.join(BASE_DIR, d)) and not d.startswith("."))
    if dirs:
        print("  Existing folders:")
        for d in dirs:
            print(f"    {d}")
        print()
    folder = _input("  serve_dir: ").strip()
    if not folder or not os.path.isdir(_resolve(folder)):
        print(f"  → directory not found: {_resolve(folder or '(blank)')}. Create it first, then try again.")
        return
    if not _is_within_base_dir(_resolve(folder)):
        print(f"  → serve_dir must be inside {BASE_DIR} — the publish channel and the systemd sandbox both depend on it.")
        return
    if _serve_dir_exposes_secrets(_resolve(folder)):
        print("  → that folder holds Servette's own config or TLS keys — serving it would publish them. Pick another.")
        return
    # The same seeding offer setup makes for the first site (#37): a new site
    # with no index.html would 404 on its own domain with no way to tell the
    # server from the content. Declining, or a failed fetch, blocks nothing.
    if not os.path.exists(os.path.join(_resolve(folder), "index.html")):
        if _prompt("No index.html here — fetch Servette's demo page so the site works immediately?"):
            if _seed_demo(folder):
                print("  Demo page installed as index.html — replace it with your own site when ready.")

    site = Site({"serve_dir": folder})
    config.sites.append(site)
    idx = len(config.sites) - 1
    # A unique self-signed cert/key pair, so a second self-signed site doesn't
    # collide with the first's cert.pem/key.pem — overwritten if a domain is
    # obtained below, which uses the domain-scoped certs/<domain>/ path instead.
    # Suffixed with randomness, not the site's list position: a position-based
    # name (cert-{idx}.pem) collides with a surviving site's own files after a
    # remove-site/add-site sequence shifts indices, silently overwriting that
    # site's live certificate.
    suffix = os.urandom(4).hex()
    site.cert_file = f"cert-{suffix}.pem"
    site.key_file  = f"key-{suffix}.pem"
    # Generated unconditionally, before the domain is even asked about: if a
    # domain is given below and ACME issuance fails, cert_file/key_file must
    # still point at real files on disk rather than a placeholder name that
    # was config.save()'d but never written — start_server()'s pre-flight
    # existence check refuses to start the WHOLE server, for every site, the
    # next time anything restarts it, if a site's cert_file is missing.
    print("  Generating self-signed certificate...")
    _generate_self_signed_cert(_resolve(site.cert_file), _resolve(site.key_file))
    _chown_servette(_resolve(site.cert_file))
    _chown_servette(_resolve(site.key_file))
    config.save()
    print(f"  → site {idx} added.\n")

    domain = _input("  Domain name (leave blank for self-signed): ").strip()
    if domain and _domain_in_use(domain):
        print(f"  → {domain} is already used by another site on this box — using a self-signed certificate instead.")
        domain = ""

    reloaded = False
    if domain:
        placeholder = (_resolve(site.cert_file), _resolve(site.key_file))
        _obtain_trusted_cert(domain, site)  # reloads the server itself on success
        # site.domain is only assigned inside _obtain_trusted_cert on the
        # success path, so this distinguishes a real reload from a failed
        # ACME attempt that left the self-signed fallback (already generated
        # above) as the site's live cert.
        if site.domain == domain:
            reloaded = True
            # The placeholder pair was insurance against ACME failing; issuance
            # succeeded and repointed the site at certs/<domain>/, so nothing
            # references these any more. Compared against the site's current
            # paths rather than deleted blind — if issuance somehow left the
            # site pointing at them, they are live files, not litter.
            for stale in placeholder:
                if stale not in (_resolve(site.cert_file), _resolve(site.key_file)):
                    try:
                        os.remove(stale)
                    except OSError:
                        pass
        else:
            print("  → keeping the self-signed certificate for now. Browsers will show a security warning until you retry the domain.\n")
    else:
        print("  Note: browsers will show a security warning until you add a domain.\n")

    print("  Password protection (optional). Leave username blank to disable.")
    _config_username(site)
    if site.username:
        _config_password(site)

    print(f"\n  Site {idx} added. Run 'publish {idx}' to set up its publish channel.")
    if not reloaded and (_server_running() or _service_is_active()):
        _reload_server()


def _config_remove_site(args):
    if not args:
        print("  Usage: remove-site <site index>")
        return
    try:
        idx = int(args[0])
    except ValueError:
        print("  Usage: remove-site <site index>")
        return
    if not (0 <= idx < len(config.sites)):
        print(f"  No site {idx} — run 'sites' to list them.")
        return
    if len(config.sites) == 1:
        print("  Can't remove the only site — a box needs at least one.")
        return

    site  = config.sites[idx]
    label = site.domain or site.serve_dir
    if not _prompt(f"Remove site {idx} ({label})? Its config is discarded; its files on disk are not touched."):
        print("  Cancelled.")
        return

    del config.sites[idx]
    config.save()
    print(f"  → site {idx} removed.")
    if _server_running() or _service_is_active():
        _reload_server()


def _config_dir(site):
    dirs = sorted(d for d in os.listdir(BASE_DIR) if os.path.isdir(os.path.join(BASE_DIR, d)) and not d.startswith("."))
    if dirs:
        print()
        for d in dirs:
            print(f"    {d}{' ←' if d == site.serve_dir else ''}")
    new_value = _input(f"\n  serve_dir [{site.serve_dir}]: ").strip()
    if not new_value:
        print("  → unchanged")
        return
    path = _resolve(new_value)
    if not os.path.isdir(path):
        print(f"  → directory not found: {path}")
        return
    if not _is_within_base_dir(path):
        print(f"  → serve_dir must be inside {BASE_DIR} — the publish channel and the systemd sandbox both depend on it.")
        return
    if _serve_dir_exposes_secrets(path):
        print("  → that folder holds Servette's own config or TLS keys — serving it would publish them. Pick another.")
        return
    site.serve_dir = new_value
    config.save()
    print("  → saved")


def _config_set(attr, label, cast=str, validate=None, error="invalid value", hint=None):
    current = getattr(config, attr)
    if hint:
        print(f"  {hint}")
    new_value = _input(f"  {label} [{current}]: ").strip()
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


def _config_cert(site):
    cert_path = _resolve(site.cert_file)
    if os.path.exists(cert_path):
        days = _cert_days_remaining(cert_path)
        if days is not None and days <= 0:
            print("  Current certificate has expired.")
        elif days is not None:
            print(f"  Current certificate expires in {days} days.")
        else:
            print(f"  Current: {site.cert_file}")
    print()

    domain = _input("  Domain name (leave blank for self-signed): ").strip()

    if domain and _domain_in_use(domain, excluding=site):
        print(f"  → {domain} is already used by another site on this box, unchanged")
        return

    if domain:
        _obtain_trusted_cert(domain, site)
    else:
        cert_path = _resolve(site.cert_file or "cert.pem")
        key_path  = _resolve(site.key_file or "key.pem")
        print("  Generating self-signed certificate...")
        _generate_self_signed_cert(cert_path, key_path)
        _chown_servette(cert_path)
        _chown_servette(key_path)
        site.cert_file = site.cert_file or "cert.pem"
        site.key_file  = site.key_file or "key.pem"
        site.domain    = ""
        config.save()
        print("  → self-signed certificate generated.")
        print("  Note: your browser will show a security warning until you add a domain.\n")
        if _server_running() or _service_is_active():
            _reload_server()


def _config_username(site):
    current   = site.username
    new_value = _input(f"  username [{current}]: ").strip()
    if new_value == "" and current != "":
        site.username      = ""
        site.password_hash = ""
        site.password_salt = ""
        config.save()
        print("  → auth disabled, password cleared")
    elif new_value and new_value != current:
        site.username = new_value
        config.save()
        print("  → saved")
    else:
        print("  → unchanged")


def _config_password(site):
    if not site.username:
        print("  Set a username first.")
        return
    try:
        pwd = getpass.getpass("  password: ")
        if not pwd:
            print("  → unchanged")
            return
        confirm = getpass.getpass("  confirm: ")
    except (EOFError, KeyboardInterrupt):
        print("\n  → unchanged")
        return
    if pwd != confirm:
        print("  → passwords do not match, unchanged")
        return
    site.password_hash, site.password_salt = _hash_password(pwd)
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
    choice = _input("  cache_policy [no-store / no-cache / max-age]: ").strip().lower()
    if not choice:
        print("  → unchanged")
        return
    if choice not in ("no-store", "no-cache", "max-age"):
        print("  → invalid option, unchanged")
        return
    config.cache_policy = choice
    if choice == "max-age":
        age_str = _input(f"  cache_max_age seconds [{config.cache_max_age}]: ").strip()
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
    new_value = _input("  trusted_proxy IP: ").strip()
    if new_value == current:
        print("  → unchanged")
        return
    config.trusted_proxy = new_value
    config.save()
    print("  → saved" if new_value else "  → cleared, X-Forwarded-For will be ignored")


def _config_publish(site):
    print(f"\n  Current watch URL: {site.publish_url or '(not set)'}")
    print("  Where signed content bundles (a .tar.gz plus its .sig) are pulled from —")
    print("  typically a GitHub release. Leave blank to disable publishing.\n")
    url = _input("  publish_url: ").strip()
    if url and not url.startswith("https://"):
        print("  → must be an https:// URL, unchanged")
    elif url != site.publish_url:
        site.publish_url = url
        config.save()
        print("  → saved" if url else "  → cleared, publishing disabled")
    else:
        print("  → unchanged")

    print(f"\n  Current signing key: {site.publish_key or '(not set)'}")
    print("  The public half of the content-signing keypair generated by the publish")
    print("  tool — 64 hex characters (a 32-byte Ed25519 public key). Leave blank to clear.\n")
    key = _input("  publish_key: ").strip().lower()
    if key and not re.fullmatch(r"[0-9a-f]{64}", key):
        print("  → not a 64-character hex string, unchanged")
    elif key != site.publish_key:
        site.publish_key = key
        config.save()
        print("  → saved" if key else "  → cleared")
    else:
        print("  → unchanged")


def _config_tls():
    print(f"\n  Current: TLS {config.tls_min_version}, ciphers: {config.ciphers or '(system default)'}\n")
    print("    1.2 — TLS 1.2 minimum, TLS 1.3 also accepted (default)")
    print("    1.3 — TLS 1.3 only; drops support for older clients\n")
    ver = _input("  tls_min_version [1.2 / 1.3]: ").strip()
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
    ciphers = _input("  ciphers: ").strip()
    if ciphers == config.ciphers:
        print("  → unchanged")
        return
    config.ciphers = ciphers
    config.save()
    print("  → saved (takes effect on next server start)" if ciphers else "  → cleared, system default will be used")


def _config_site_arg(args):
    """Resolve dir/cert/username/password/publish's optional site-index
    argument to a Site, defaulting to site 0 — same [n] convention as the
    top-level 'log [n]'. Prints its own error and returns None if given but
    invalid, so callers can just no-op on None."""
    if not args:
        return config.sites[0]
    try:
        idx = int(args[0])
    except ValueError:
        print(f"  Not a site index: {args[0]!r}")
        return None
    if not (0 <= idx < len(config.sites)):
        print(f"  No site {idx} — run 'sites' to list them.")
        return None
    return config.sites[idx]


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

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        if cmd == "show":
            _config_show()
        elif cmd == "sites":
            _config_sites()
        elif cmd == "add-site":
            _config_add_site()
        elif cmd == "remove-site":
            _config_remove_site(args)
        elif cmd in ("dir", "directory"):
            site = _config_site_arg(args)
            if site is not None:
                _config_dir(site)
        elif cmd == "port":
            _config_set("port", "port", int, lambda v: 1 <= v <= 65535, "invalid port number")
        elif cmd == "cert":
            site = _config_site_arg(args)
            if site is not None:
                _config_cert(site)
        elif cmd == "username":
            site = _config_site_arg(args)
            if site is not None:
                _config_username(site)
        elif cmd == "password":
            site = _config_site_arg(args)
            if site is not None:
                _config_password(site)
        elif cmd == "email":
            _config_set("email", "email")
        elif cmd == "publish":
            site = _config_site_arg(args)
            if site is not None:
                _config_publish(site)
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
                cmd_enable()


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
# Ceiling on a downloaded release asset — servette.py or the demo page. Both are
# orders of magnitude under this; the cap exists so a hostile or broken response
# is bounded before the signature check, not to constrain growth.
_MAX_SOURCE_BYTES   = 4 * 1024 * 1024

def _parse_version(source_bytes):
    """Extract __version__ from servette.py source bytes. Returns the string or None."""
    m = _VERSION_RE.search(source_bytes)
    return m.group(1).decode() if m else None


def _is_downgrade(current, candidate):
    """True when candidate is an older version than current. Versions compare as
    tuples of their dot-separated integers; if either carries a non-numeric part
    it can't be ordered, so this returns False — an uncomparable version never
    blocks an update."""
    def parse(v):
        try:
            return tuple(int(p) for p in v.split("."))
        except ValueError:
            return None
    a, b = parse(current), parse(candidate)
    return a is not None and b is not None and b < a


def _release_asset_url_ok(url):
    """True when a release-asset URL is HTTPS on github.com. Update downloads are
    pinned to the release host so a poisoned API response can't redirect the fetch
    elsewhere — the Ed25519 signature is the real gate; this narrows the fetch."""
    parts = urlsplit(url)
    return parts.scheme == "https" and parts.netloc == "github.com"


def _fetch_release():
    """The latest-release JSON from the GitHub API. Returns (release, None) on
    success, (None, why) on failure — quiet either way, so each caller keeps
    its own spinner and message prefix."""
    try:
        req = urllib.request.Request(
            RELEASES_API_URL,
            headers={"User-Agent": f"servette/{__version__}", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read()), None
    except Exception as e:
        return None, str(e)


def _download_verified_asset(release, name):
    """Download release asset `name` and its .sig companion and verify the
    signature. Returns (bytes, None) on success, (None, why) on failure.

    This is the one copy of the trust chain every release artifact goes
    through — servette.py for 'update', demo.html for the seeded demo: asset
    URLs pinned to github.com, the download capped at _MAX_SOURCE_BYTES
    *before* the Ed25519 check against the pinned _SIGNING_PUBLIC_KEY."""
    assets   = {a["name"]: a["browser_download_url"] for a in release.get("assets", [])}
    sig_name = name + ".sig"
    if name not in assets or sig_name not in assets:
        return None, f"release is missing {name} or {sig_name} assets"
    if not all(_release_asset_url_ok(assets[n]) for n in (name, sig_name)):
        return None, "asset URL is not on github.com"
    try:
        data = urllib.request.urlopen(assets[name], timeout=30).read(_MAX_SOURCE_BYTES + 1)
        if len(data) > _MAX_SOURCE_BYTES:
            return None, f"{name} asset exceeds {_MAX_SOURCE_BYTES // 1024} KB"
        sig = urllib.request.urlopen(assets[sig_name], timeout=15).read(4096)
    except Exception as e:
        return None, str(e)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(_SIGNING_PUBLIC_KEY)).verify(sig, data)
    except InvalidSignature:
        return None, "signature verification failed"
    except Exception as e:
        return None, f"could not verify signature: {e}"
    return data, None

def _offer_restart(version):
    """Apply a freshly swapped servette.py (from update or restore): restart the
    service if it's managed, otherwise tell the user how — this shell still holds the
    old code in memory, so it can't relaunch itself into the new file."""
    if _service_is_active():
        if _prompt("Restart the servette service now?"):
            try:
                subprocess.run(["systemctl", "restart", "servette"], check=True, capture_output=True)
                print(f"  Service restarted on {version}.")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"  Restart failed — run 'sudo systemctl restart servette' yourself ({e}).")
        else:
            print("  Run 'sudo systemctl restart servette' when ready.")
    elif _server_running():
        print("  This shell is still running the old version — exit and rerun Servette to apply.")
    else:
        print(f"  Restart to run version {version}: 'start', or 'sudo systemctl restart servette'.")


def cmd_update():
    servette_path = os.path.abspath(__file__)

    with _spinner("Checking for update..."):
        release, why = _fetch_release()
    if release is None:
        print(f"  Update failed: {why}")
        return

    new_version = release.get("tag_name", "").lstrip("v")
    if not new_version:
        print("  Update failed: could not read version from release.")
        return

    if new_version == __version__:
        print(f"  Already up to date ({__version__}).")
        return

    # 'update' only moves forward. A signed but older release — a stale "latest"
    # from the API, or a downgrade a network attacker slipped past TLS — must not
    # roll the server back to a version with known holes. 'restore' is the
    # deliberate path back to the previous version.
    if _is_downgrade(__version__, new_version):
        print(f"  Update declined: {new_version} is older than the running {__version__}.")
        print("  Use 'restore' to roll back to the previous version on purpose.")
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

    # Download and verify through the shared trust chain (asset presence,
    # github.com pinning, size cap before the Ed25519 check).
    with _spinner(f"Downloading {new_version}..."):
        new_source, why = _download_verified_asset(release, "servette.py")
    if new_source is None:
        print(f"  Update failed: {why}.")
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

    if _server_running() and not _service_is_active():
        # A session-mode server runs in this very process; re-executing would
        # kill it without warning, so fall back to telling the operator how to
        # apply the update themselves.
        print("  This shell is still running the old version — exit and rerun Servette to apply.")
        return

    print("  Reloading...")
    os.execv(_VENV_PY, [_VENV_PY, servette_path, "--post-update"])


def _apply_post_update():
    """Runs once, immediately after 'update' re-execs into the freshly swapped
    file — the first thing this fresh process does. If the service was already
    enabled, silently refresh its unit (and the network watchdog's) to this
    version's shape and restart it: an update should never leave an enabled
    host on a stale unit, and should never need a separate manual 'enable' to
    pick up host-provisioning changes a release adds."""
    print(f"  Reloaded as v{__version__}.")
    if _service_file_exists():
        try:
            _write_unit_files()
            if _service_is_active():
                _reload_server()
        except (PermissionError, FileNotFoundError, subprocess.CalledProcessError) as e:
            print(f"  Could not refresh the service unit: {e}")
    # Refresh any site still serving the marked demo placeholder, so a release
    # that changes the demo reaches hosts that never published their own page.
    # One fetch seeds every marked site; operator pages (no marker) are untouched.
    marked = [s for s in config.sites
              if _demo_is_placeholder(os.path.join(_resolve(s.serve_dir), "index.html"))]
    if marked:
        page = _fetch_demo()
        if page is not None:
            for s in marked:
                if _seed_demo(s.serve_dir, page):
                    print(f"  Demo page refreshed in {s.serve_dir}.")


_DEMO_MARKER = "servette:demo"


def _fetch_demo():
    """Fetch and verify demo.html from the latest GitHub release, through the
    same _download_verified_asset trust chain 'update' uses — one trust domain
    with the code, deliberately not the per-site publish key. Returns the page
    bytes, or None after printing why: a failed fetch is information ("could
    not reach GitHub" matters at setup time), never an exception, and never
    fails the caller's flow."""
    release, why = _fetch_release()
    if release is None:
        print(f"  Demo page not fetched: {why}.")
        return None
    page, why = _download_verified_asset(release, "demo.html")
    if page is None:
        print(f"  Demo page not fetched: {why}.")
        return None
    if _DEMO_MARKER.encode() not in page:
        # Without its marker the page could never be recognized for refresh —
        # a marker-less asset is malformed, not adoptable.
        print("  Demo page refused: fetched page lacks the servette:demo marker.")
        return None
    return page


def _demo_is_placeholder(index_path):
    """True when index_path exists and carries the servette:demo marker — i.e. it
    is Servette's own placeholder, safe to refresh. An operator's page (no marker)
    is never touched; an operator who deletes the marker has adopted the page
    permanently. The rule is visible in the file itself, not hidden in state."""
    try:
        with open(index_path, "rb") as f:
            return _DEMO_MARKER.encode() in f.read(_MAX_SOURCE_BYTES)
    except OSError:
        return False


def _seed_demo(serve_dir, page=None):
    """Write the demo page as serve_dir/index.html when that is safe: the file is
    absent, or still the marked placeholder. Returns True when it was written.
    page=None fetches from the latest release; passing bytes lets one fetch seed
    several sites. Written via rename so a reader never sees a partial file."""
    index_path = os.path.join(_resolve(serve_dir), "index.html")
    if os.path.exists(index_path) and not _demo_is_placeholder(index_path):
        return False   # operator content — never overwrite
    if page is None:
        page = _fetch_demo()
        if page is None:
            return False
    tmp = index_path + ".new"
    try:
        with open(tmp, "wb") as f:
            f.write(page)
        os.replace(tmp, index_path)
    except OSError as e:
        print(f"  Could not write the demo page: {e}")
        return False
    return True


def cmd_restore():
    """Roll back to the version saved by the last 'update'. The backup is single-shot:
    only ever one servette.py.bak exists, and a successful restore consumes it."""
    servette_path = os.path.abspath(__file__)
    bak_path      = servette_path + ".bak"

    if not os.path.exists(bak_path):
        print("  Nothing to restore — no servette.py.bak. ('update' saves one each time it runs.)")
        return

    try:
        with open(bak_path, "rb") as f:
            bak_source = f.read()
    except OSError as e:
        print(f"  Restore failed: cannot read {bak_path} ({e}).")
        return

    # Refuse to restore a corrupt backup — better to keep the working file in place.
    try:
        compile(bak_source, "servette.py", "exec")
    except SyntaxError as e:
        print(f"  Restore failed: the backup has a syntax error ({e}).")
        return

    bak_version = _parse_version(bak_source) or "unknown"
    if not _prompt(f"Restore {__version__} → {bak_version} from servette.py.bak? The backup is then removed."):
        print("  Restore cancelled.")
        return

    # Atomically move the backup into place (keeping the live file's mode). The rename
    # consumes the backup, so only ever one is kept and it's spent on use.
    os.chmod(bak_path, os.stat(servette_path).st_mode)
    os.replace(bak_path, servette_path)

    print(f"  Restored {__version__} → {bak_version}.")
    _offer_restart(bak_version)


# ── Site content publishing ─────────────────────────────────────────────────
#
# The content-side sibling of self-update: a signed tar.gz bundle, pulled from
# publish_url, verified against publish_key (a keypair distinct from
# Servette's own release-signing key), and swapped into serve_dir with the
# same single-shot .bak/restore pattern 'update'/'restore' already give the
# code. Pull-only — this box never accepts an inbound push of content, only
# fetches from a URL it already trusts.

_MAX_BUNDLE_BYTES = 500 * 1024 * 1024  # generous for a static site; bounds a decompression-bomb bundle


def _extract_bundle(data, dest_dir):
    """Extract a tar.gz byte string into dest_dir (must not yet exist).

    Every entry's resolved path is checked against dest_dir, every entry must
    be a plain file or directory (no symlinks/devices), and the total
    uncompressed size is capped — all validated before anything is written,
    so a bad bundle leaves no partial extraction behind. filter='data' is
    passed to extractall() too: defense in depth, not the only guard — it
    independently enforces the same containment and rejects the same entry
    types at the library level."""
    os.makedirs(dest_dir)
    dest_real = os.path.realpath(dest_dir)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        members = tf.getmembers()
        total = 0
        for m in members:
            if not (m.isfile() or m.isdir()):
                raise ValueError(f"unsupported entry type in bundle: {m.name}")
            target = os.path.realpath(os.path.join(dest_dir, m.name))
            if not (target == dest_real or target.startswith(dest_real + os.sep)):
                raise ValueError(f"entry escapes the target directory: {m.name}")
            total += m.size
            if total > _MAX_BUNDLE_BYTES:
                raise ValueError(f"bundle exceeds {_MAX_BUNDLE_BYTES} bytes uncompressed")
        tf.extractall(dest_dir, members=members, filter="data")


def _swap_site_content(new_dir, serve_dir):
    """Atomically replace the live serve_dir with new_dir's contents, keeping
    a single-shot backup — the same one-step-back pattern as servette.py.bak.
    new_dir must be on the same filesystem as serve_dir (both under BASE_DIR)
    so the renames are atomic; the only unavoidable risk window is the two
    renames themselves, each a single fast syscall back to back — proportionate
    to Servette's scale, not a high-QPS system where that window would matter."""
    live_dir = _resolve(serve_dir).rstrip(os.sep)
    bak_dir  = live_dir + ".bak"
    shutil.rmtree(bak_dir, ignore_errors=True)
    if os.path.isdir(live_dir):
        os.rename(live_dir, bak_dir)
    os.rename(new_dir, live_dir)


_publish_lock = threading.Lock()  # serializes site-content mutation across every
                                   # site: 'pull' and 'restore-site' can run from
                                   # two shell sessions at once, and the swap is
                                   # multiple unguarded filesystem ops, not one.


def _publish_sig_url(url):
    """url's own '.sig' companion, with '.sig' appended to the path rather than
    the whole URL — naive string concatenation breaks for a publish_url that
    carries a query string (e.g. a pre-signed download link), landing '.sig'
    after the query instead of after the file extension."""
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=parts.path + ".sig"))


def _check_for_content_update(site):
    """Pull, verify, and swap in a new site bundle for `site` if its publish
    channel is configured. No-ops silently (not an error) if publish_url/
    publish_key aren't both set on it — publishing is opt-in, per site. Called
    by the interactive 'pull' command, which turns the returned status into a
    printed line.

    Returns a short status string: "not-configured", "invalid-key",
    "fetch-failed", "too-large", "bad-signature", "rejected", or "published"."""
    if not (site.publish_url and site.publish_key):
        return "not-configured"

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    try:
        pub_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(site.publish_key))
    except ValueError:
        log.error("publish_key is not a valid Ed25519 public key — publishing disabled")
        return "invalid-key"

    with _publish_lock:
        try:
            # Capped read: bounds memory to _MAX_BUNDLE_BYTES regardless of what
            # the response claims or how much data is actually sent.
            bundle = urllib.request.urlopen(site.publish_url, timeout=30).read(_MAX_BUNDLE_BYTES + 1)
            if len(bundle) > _MAX_BUNDLE_BYTES:
                log.error("Publish bundle exceeds %d bytes — rejecting before signature check", _MAX_BUNDLE_BYTES)
                return "too-large"
            signature = urllib.request.urlopen(_publish_sig_url(site.publish_url), timeout=15).read(4096)
        except Exception as e:
            log.warning("Could not fetch publish bundle: %s", e)
            return "fetch-failed"

        try:
            pub_key.verify(signature, bundle)
        except InvalidSignature:
            log.error("Publish bundle signature verification failed — rejecting")
            return "bad-signature"

        staging = _resolve(site.serve_dir).rstrip(os.sep) + ".new"
        shutil.rmtree(staging, ignore_errors=True)
        try:
            _extract_bundle(bundle, staging)
            _swap_site_content(staging, site.serve_dir)
        except Exception as e:
            log.error("Publish bundle rejected: %s", e)
            shutil.rmtree(staging, ignore_errors=True)
            return "rejected"

    log.info("Published new content for %s from %s", site.domain or site.serve_dir, site.publish_url)
    return "published"


def cmd_pull(site):
    """Manually check the publish channel for new site content and pull it in."""
    if not (site.publish_url and site.publish_key):
        print("  No publish channel configured — run 'config publish' first.")
        return
    with _spinner("Checking for new site content..."):
        result = _check_for_content_update(site)
    messages = {
        "invalid-key":   "Pull failed: publish_key is not a valid Ed25519 public key.",
        "fetch-failed":  "Pull failed: could not fetch the publish bundle. See 'log' for details.",
        "too-large":     f"Pull failed: bundle exceeds {_MAX_BUNDLE_BYTES} bytes.",
        "bad-signature": "Pull failed: bundle signature verification failed — rejecting.",
        "rejected":      "Pull failed: bundle was rejected. See 'log' for details.",
        "published":     "New site content published.",
    }
    print(f"  {messages[result]}")


def cmd_restore_site(site):
    """Roll back to the content saved by the last successful publish. Mirrors
    cmd_restore exactly: single-shot, consumed on use."""
    live_dir = _resolve(site.serve_dir).rstrip(os.sep)
    bak_dir  = live_dir + ".bak"

    if not os.path.isdir(bak_dir):
        print("  Nothing to restore — no site backup. (Publishing saves one each time it swaps in new content.)")
        return

    if not _prompt("Restore site content from backup? The backup is then removed."):
        print("  Restore cancelled.")
        return

    with _publish_lock:
        if not os.path.isdir(bak_dir):
            print("  Nothing to restore — a publish ran while you were deciding and consumed the backup.")
            return
        if os.path.isdir(live_dir):
            shutil.rmtree(live_dir)
        os.rename(bak_dir, live_dir)
    print("  Site content restored from backup.")


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
    """Return a list of strings describing conditions that prevent production
    readiness, across every configured site. Single-site installs (still the
    common case) see exactly today's unlabeled messages; a labeled site name
    is added only once there's more than one to tell apart."""
    issues  = []
    labeled = len(config.sites) > 1
    for site in config.sites:
        tag = f" ({site.domain or site.serve_dir})" if labeled else ""
        if not site.serve_dir or not os.path.exists(_resolve(site.serve_dir)):
            issues.append(f"serve directory not configured{tag} — run 'config'")
        if not site.cert_file or not os.path.exists(_resolve(site.cert_file)):
            issues.append(f"certificate not configured{tag} — run 'config cert'")
        elif not site.domain:
            # Keyed on the configured domain rather than the certificate's
            # subject: a site with no domain is the catch-all whatever its cert
            # contains, gets no HSTS, and is not reachable by name — so 'add a
            # domain' is the advice that actually changes any of that.
            issues.append(f"self-signed certificate{tag} — run 'config cert' to add a domain")
        if not site.username:
            issues.append(f"no password protection{tag} — run 'config' to set credentials")
        if bool(site.publish_url) != bool(site.publish_key):
            issues.append(f"publish channel partially configured{tag} — run 'config publish' to finish setup")
    mem_kb, avail_kb, swap_kb = _meminfo()
    rec       = _swap_recommendation(mem_kb, avail_kb, config.cache_size_mb)
    active_mb = (swap_kb or 0) // 1024
    offer     = _swap_offer(rec // (1024 * 1024) if rec else None,
                            os.path.exists(_SWAP_PATH), active_mb)
    if offer is not None:
        if active_mb:
            issues.append(f"swapfile {active_mb} MB but {rec // (1024 * 1024)} MB "
                          "recommended — run 'enable' to resize")
        else:
            issues.append(f"no swap ({mem_kb // 1024} MB RAM) — run 'enable' to add a swapfile")
    return issues


def _cache_warnings():
    """Warn when a site, or any single file within it, is too big for the shared
    in-memory cache. Single-site installs see exactly today's unlabeled messages;
    a labeled site name is added only once there's more than one to tell apart."""
    warnings  = []
    cache_max = config.cache_size_mb * 1024 * 1024
    labeled   = len(config.sites) > 1
    for site in config.sites:
        serve_dir = _resolve(site.serve_dir)
        if not os.path.isdir(serve_dir):
            continue
        tag   = f" in {site.domain or site.serve_dir}" if labeled else ""
        total = 0
        for root, _dirs, files in os.walk(serve_dir):
            for name in files:
                try:
                    size = os.path.getsize(os.path.join(root, name))
                except OSError:
                    continue
                total += size
                if size > cache_max:
                    warnings.append(
                        f"{name}{tag} ({size / 1048576:.1f} MB) is larger than the cache "
                        f"({config.cache_size_mb} MB) and is never cached"
                    )
        if total > cache_max:
            warnings.append(
                f"site{tag} is {total / 1048576:.1f} MB but the cache is {config.cache_size_mb} MB "
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
    W              = _PAD

    print()
    status_dot = _c("● Running", "green") if running else _c("○ Stopped", "red")
    print(f"{status_dot}  (v{__version__})")

    if running:
        mode = "System service" if service_active else "Session only"
        print(f"  {'Mode':<{W}} {mode}")

    for i, site in enumerate(config.sites):
        cert_path = _resolve(site.cert_file)
        # site.domain, not the certificate's subject: routing, TLS selection and
        # HSTS all key off the configured domain, so reporting anything else can
        # print a URL that does not actually reach this site.
        url       = f"https://{site.domain}" if site.domain else f"https://localhost:{config.port}"
        if len(config.sites) > 1:
            print(f"\n  Site {i}")
        print(f"  {'URL':<{W}} {url}")
        print(f"  {'Directory':<{W}} {site.serve_dir or '(not configured)'}")
        auth_str = _c("enabled", "green") if site.username else _c("disabled", "yellow")
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
    with _spinner("Detecting public IP..."):
        try:
            public_ip = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode()
        except Exception:
            public_ip = "your.server.ip"

    _banner("Getting Started")

    site = config.sites[0]  # the site setup provisions; 'add-site' handles the rest

    # Step 1 — the folder. Setup must never finish with nothing to serve (#37):
    # create the folder if missing, and offer the signed demo page when it has
    # no index.html — the demo diagnoses server/cert/redirect health before the
    # operator's own files enter the picture. A failed fetch degrades with its
    # own message and does not fail setup.
    print()
    print("  Step 1 — Site folder")
    serve_path = _resolve(site.serve_dir)
    if not os.path.isdir(serve_path):
        if _is_within_base_dir(serve_path):
            try:
                os.makedirs(serve_path, exist_ok=True)
                print(f"  Created {serve_path}.")
            except OSError as e:
                print(f"  Could not create {serve_path}: {e}")
        else:
            print(f"  serve_dir {serve_path} is outside {BASE_DIR} — fix it with 'config' > 'dir' first.")
    if os.path.isdir(serve_path):
        if os.path.exists(os.path.join(serve_path, "index.html")):
            print(f"  Serving {serve_path}.")
        else:
            print(f"  {serve_path} has no index.html yet.")
            if _prompt("Fetch Servette's demo page so the site works immediately?"):
                if _seed_demo(site.serve_dir):
                    print("  Demo page installed as index.html — replace it with your own site when ready.")

    print()
    print("  Step 2 — SSL certificate")
    print(f"  Your public IP is {public_ip}. Point a domain here for a trusted certificate.")
    print("  Leave blank to use a self-signed certificate (browsers will warn visitors).\n")
    _config_cert(site)

    print()
    print("  Step 3 — Password protection (optional)")
    print("  Leave username blank to disable. Press Enter to keep current value.")
    _config_username(site)
    if site.username:
        _config_password(site)

    print()
    if _prompt("Ready to start?"):
        cmd_enable()
        cmd_start()
    else:
        print("  Run 'start' when you're ready.")


# ── Main shell loop ───────────────────────────────────────────────────────────

def shell():
    _banner("Servette — The Simple Secure Server")
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
            cmd_enable()
        elif cmd == "disable":
            cmd_disable()
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
        elif cmd == "restore":
            cmd_restore()
        elif cmd == "pull":
            site = _config_site_arg(args)
            if site is not None:
                cmd_pull(site)
        elif cmd == "restore-site":
            site = _config_site_arg(args)
            if site is not None:
                cmd_restore_site(site)
        elif cmd in ("help", "?"):
            print(HELP)
        elif cmd in ("quit", "exit"):
            stop_server()
            print("Goodbye.")
            break
        else:
            print(f"Unknown command: {cmd}. Type 'help' for a list of commands.")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
#
# Config is a module-level singleton, instantiated here (not at its class
# definition, near the top) because migrating a pre-multi-site flat config
# calls _domain_from_cert() to backfill the migrated site's domain, and that
# function is defined much later, in Certificate management. Dependency
# injection (passing config into every function) is the textbook alternative,
# but the stdlib request handlers have fixed signatures and cannot accept
# extra arguments. In a single-file server that is always run as a process,
# the global is the right call.

# The config singleton
config = Config()

# The entry point
if __name__ == "__main__":
    _bootstrap()  # no-op if already in venv; otherwise re-execs into venv

    if "--serve" in sys.argv:
        start_server()
        try:
            _watch_server()
        except KeyboardInterrupt:
            stop_server()
        else:
            log.error("HTTPS server stopped unexpectedly — exiting so systemd restarts the service")
            sys.exit(1)
    elif "--post-update" in sys.argv:
        _apply_post_update()
        shell()
    else:
        shell()
