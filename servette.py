# GENERATED FILE — do not edit by hand. servette.py is generated from the
# Markdown sources in src/ — by the package build (src/_literate_backend.py)
# whenever pip or `python -m build` runs, or by hand with src/build.py. Edit
# the sources and regenerate; edits here are overwritten by the next build
# and fail CI's `build.py --check`.
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

__version__ = "0.26.234"

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
from urllib.parse import parse_qs, unquote, urlsplit

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

# The platform flag
_IS_MACOS = sys.platform == "darwin"

# The closed-system TLS fallback: presented for connections whose SNI matches no
# configured site (absent, unrecognized, or direct-IP access) when no site is
# itself domainless. Tied to no site's identity, generated once and reused.

# The default-certificate paths
_DEFAULT_CERT_DIR  = os.path.join(BASE_DIR, "certs", "_default")
_DEFAULT_CERT_FILE = os.path.join(_DEFAULT_CERT_DIR, "cert.pem")
_DEFAULT_KEY_FILE  = os.path.join(_DEFAULT_CERT_DIR, "key.pem")


# Resolving data paths
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
# Password hashing
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


# A site
_MAX_REDIRECTS      = 200
_MAX_REDIRECT_CHARS = 2000


def _clean_redirects(raw):
    """The site's redirect table, validated once at load so serving one is a
    dict lookup and nothing else.

    A source is a site-absolute path; a target is another site-absolute path
    or an absolute http(s) URL. Anything else is dropped with a log line
    rather than raised: one bad entry in a hand-edited table must not take a
    whole site down, and a redirect that quietly did something other than
    what it said would be worse than one that does nothing.

    Two of the checks are load-bearing rather than tidy. A target is
    narrowed to path-or-http(s) because a redirect is an open door by
    nature, and `javascript:` or `data:` in a Location is a way to run
    script on the operator's own origin. Control characters are refused on
    both sides because a Location carrying CR or LF is response splitting —
    the value reaches a header, and this is where that is stopped."""
    out = {}
    if not isinstance(raw, dict):
        log.warning("redirects is not a table — ignoring it")
        return out
    if len(raw) > _MAX_REDIRECTS:
        log.warning("more than %d redirects — only the first %d are loaded",
                    _MAX_REDIRECTS, _MAX_REDIRECTS)
    for key, target in list(raw.items())[:_MAX_REDIRECTS]:
        src, dst = str(key).strip(), str(target).strip()
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in src + dst):
            log.warning("redirect with a control character in it — ignored")
            continue
        if not src.startswith("/") or len(src) > _MAX_REDIRECT_CHARS:
            log.warning("redirect source %r is not a site path — ignored", src[:80])
            continue
        if len(dst) > _MAX_REDIRECT_CHARS or not (
                dst.startswith("/") or dst.startswith("http://")
                or dst.startswith("https://")):
            log.warning("redirect target %r is not a path or http(s) URL — ignored",
                        dst[:80])
            continue
        # One rule covers /old and /old/, on both sides of the lookup.
        norm = src.rstrip("/") or "/"
        if norm == (dst.rstrip("/") or "/"):
            log.warning("redirect %s points at itself — ignored", norm)
            continue
        out[norm] = dst
    return out


def _redirect_toml(site):
    """The site's redirect table as TOML, or nothing at all when it is empty.

    Written LAST inside each [[site]] block, because a TOML sub-table
    swallows every key that follows it: a scalar written after
    [site.redirects] would be read back as part of the table, not as a
    field of the site."""
    if not site.redirects:
        return ""
    def q(value):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    lines = "\n".join(f"{q(src)} = {q(dst)}"
                      for src, dst in sorted(site.redirects.items()))
    return ("\n# A path on this site = where a visitor asking for it is sent.\n"
            "# Answered with a 301, before any file is looked for.\n"
            "[site.redirects]\n" + lines + "\n")


class Site:
    """One `[[site]]` block: everything that varies per hosted domain — the domain
    itself, whether it is served, its folder, its own certificate, its visitor
    auth, its redirects.
    Host-level settings (port, TLS, rate limits, cache, ACME email, security headers,
    ...) live once on Config, not here: every field lives at exactly one level, no
    fallback lookup between them."""

    def __init__(self, data=None):
        data = data or {}
        self.domain         = data.get("domain",         "")
        # Deactivated sites keep their config and files but are invisible to
        # request routing — the pause between serving and deleting.
        self.active         = bool(data.get("active",    True))
        self.serve_dir      = data.get("serve_dir",      "site")
        self.cert_file      = data.get("cert_file",      "cert.pem")
        self.key_file       = data.get("key_file",       "key.pem")
        self.username       = data.get("username",       "")
        self.password_hash  = data.get("password_hash",  "")
        self.password_salt  = data.get("password_salt",  "")
        # Old path -> new path, validated once here so the request path is a
        # dict lookup and nothing more. A file in the site folder would be
        # content, and content is read at request time — which is the whole
        # reason this is a setting.
        self.redirects      = _clean_redirects(data.get("redirects", {}))
        self._cert_mtime    = None  # populated by Config._load(); externally-rotated-cert detection


# The invalid-config signal
class _ConfigInvalid(Exception):
    """servette.toml cannot be safely applied — unparseable TOML, or a
    serve_dir that would publish Servette's own secrets. At startup this is
    fatal (fail closed); on the per-request reload the previous configuration
    stays in force — see reload_if_changed."""


class _ConfigUnreadable(_ConfigInvalid):
    """servette.toml exists but this process may not read it. A subclass
    because every _ConfigInvalid handler treats it the same way — except the
    reload, where the distinction is load-bearing: an invalid file stays
    invalid until someone edits it, but an unreadable one is usually a save
    caught mid-flight (os.replace has installed the temp file, _chown_config
    has not yet run) and becomes readable again moments later, so the reload
    must keep trying rather than write the state off until the next edit."""


# Config
class Config:
    """Holds all Servette settings and handles reading/writing servette.toml."""

    CONFIG_FILE = os.path.join(BASE_DIR, "servette.toml")

    def __init__(self):
        self._mtime        = None
        self._warned_mtime = None  # throttles the unreadable-reload warning
        try:
            # Only construction tolerates an unreadable file: it must reach the
            # dispatcher so a privileged command can elevate and read again as
            # root. The reload path (below) must not, or it would swap a
            # protected site's live config for no-auth defaults.
            self._load(tolerate_unreadable=True)
        except _ConfigInvalid as e:
            print(f"Error: {e}.")
            print(f"Fix or delete {self.CONFIG_FILE} and try again.")
            sys.exit(1)

    def _load(self, tolerate_unreadable=False):
        # Everything that can be refused is parsed and validated before any
        # attribute of self changes: _load also runs against the LIVE config on
        # the reload path, and raising after a partial mutation would leave the
        # server on a config that never existed on disk.
        data = {}
        existed    = os.path.exists(self.CONFIG_FILE)
        unreadable = False   # local until validation passes: _load runs against
        read_mtime = None    # the LIVE config on the reload path, and a raise
        #                      below must leave every attribute — this flag
        #                      included — exactly as it found it
        if existed:
            try:
                with open(self.CONFIG_FILE, "rb") as f:
                    # The mtime of the bytes actually read, from the open
                    # handle. Stat'ing the path again later would race a
                    # concurrent save: its os.replace landing between this
                    # read and that stat would stamp the NEW file's mtime
                    # over the OLD file's content, and the change detector
                    # would then see nothing to reload, ever.
                    read_mtime = os.fstat(f.fileno()).st_mtime
                    data = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                raise _ConfigInvalid(f"servette.toml is not valid TOML ({e})")
            except OSError:
                # The file is there and we may not read it. On construction
                # this is not fatal: defaults stand in so the program can
                # reach its dispatcher, which elevates and asks again as
                # root, and the flag stops those defaults being reported as
                # the operator's settings. But on the live reload path
                # adopting defaults would silently drop this site's auth and
                # every other setting because a file's ownership broke — so
                # there it is refused like an invalid file, keeping the last
                # good config — under the subclass, because unlike a bad
                # edit this state is usually a save caught mid-replace and
                # the reload must keep trying.
                if not tolerate_unreadable:
                    raise _ConfigUnreadable("servette.toml exists but cannot be read")
                unreadable = True

        site_tables = data.get("site", [])
        migrating   = existed and not site_tables and not unreadable
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
                        # cryptography is missing — a broken or partial install.
                        # _domain_from_cert would return None and the migration
                        # would persist an empty domain, silently demoting the
                        # site to the domainless catch-all (no HSTS, no
                        # renewal). Defer the migration entirely; a later run
                        # with the dependency present performs it.
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

        self.unreadable = unreadable
        if read_mtime is not None:
            self._mtime = read_mtime
        else:
            # No handle to fstat — the file was absent or unreadable-tolerated.
            # The path stat is fine here: there is no content for a racing
            # save to divorce the stamp from.
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
            # Guarded: save() needs write permission on the data directory,
            # which an unprivileged operator or the sandboxed service does not
            # have. The in-memory state above is fully migrated either way —
            # only the file on disk waits, and the next root-elevated command
            # (every settings write elevates) performs the same migration and
            # persists it. Letting the OSError escape would instead crash any
            # unprivileged run — including the service, at import, in a
            # systemd restart loop — over a file it was never going to write.
            try:
                self.save()
            except OSError as e:
                log.warning("Config migration not yet saved (%s) — a root "
                            "command will persist it", e)

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
        except _ConfigUnreadable as e:
            # Unreadable is (almost always) transient: a save's os.replace has
            # landed and its _chown_config has not yet run, so the very next
            # request will likely read the file fine. Do NOT stamp the mtime —
            # stamping was the bug that made this state permanent: the later
            # chown/chmod that restore readability touch only ctime, so a
            # stamped reload never fired again and the server sat on the old
            # config until the next save. The warning is throttled by mtime
            # instead, so a file that stays unreadable costs one failed open
            # per request and one log line per change, not a log flood.
            if mtime != self._warned_mtime:
                self._warned_mtime = mtime
                log.warning("Config NOT reloaded (%s) — retrying on the next request", e)
        except _ConfigInvalid as e:
            # A bad edit, by contrast, stays bad until someone edits again.
            # Keep serving on the last good configuration: this runs on
            # request threads, where an escape would kill the request
            # mid-flight and a process exit would take the whole server down
            # over a typo. Stamp the mtime so the bad file isn't re-parsed —
            # and the warning isn't repeated — on every request until the
            # file changes again.
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
# Set active to false to keep the site configured and its files kept, but
# stop serving it
active = {'true' if site.active else 'false'}
serve_dir = {s(site.serve_dir)}
cert_file = {s(site.cert_file)}
key_file = {s(site.key_file)}

# Leave username blank to disable password protection
username = {s(site.username)}

# Machine-generated — do not edit by hand
password_hash = {s(site.password_hash)}
password_salt = {s(site.password_salt)}
{_redirect_toml(site)}""" for site in self.sites)

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
        # The replace installs the temp file's root:root 0600 — unreadable by
        # both the service user (whose per-request reload would die, crash-
        # looping the next restart) and the operator (whose read-only commands
        # would elevate to read their own settings). Restore the ownership
        # enable establishes; a no-op where the servette user doesn't exist
        # (session mode, tests, macOS). Late import shape as with
        # _domain_from_cert: _chown_config is defined in System.
        _chown_config(self.CONFIG_FILE)
        try:
            self._mtime = os.path.getmtime(self.CONFIG_FILE)
        except OSError:
            pass


# Logging setup
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


# Terminal color
def _c(text, color):
    """Wrap text in an ANSI color for interactive (TTY) output; plain text otherwise."""
    codes = {"green": "32", "red": "31", "yellow": "33"}
    if color not in codes or not sys.stdout.isatty():
        return text
    return f"\033[{codes[color]}m{text}\033[0m"


# Rate state
RATE_WINDOW  = 60      # seconds
_RATE_IP_CAP = 10_000  # max IPs tracked per dict; bounds memory under IP-flood attacks

_request_times   = {}
_auth_fail_times = {}
_rate_lock       = threading.Lock()


# Normalizing addresses
def _normalize_ip(ip):
    """Normalize IPv6-mapped IPv4 addresses so both forms read the same.

    Uses ipaddress so every mapped spelling collapses to the same string — the
    dotted ::ffff:1.2.3.4 and the hex ::ffff:c0a8:0101 are the same address.
    Non-addresses (e.g. "unknown", junk XFF) pass through as-is. This is the
    address as logged; the limiters key on _bucket_key below."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6 and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return ip


def _bucket_key(ip):
    """The rate/connection bucket an address belongs to.

    IPv4 buckets per address. Native IPv6 buckets by its /64: providers hand
    a subscriber at least a /64 (RFC 6177), so one visitor holds 2^64
    addresses — keyed individually, rotating the low bits gave every request
    a fresh bucket, quietly switching off the request rate limit, the
    auth-failure throttle, and the per-IP connection cap for any IPv6
    client. /64 is the finest bucket that is still one subscriber's, so a
    visitor can neither dodge the limits nor exhaust a neighbor's. Logs keep
    the full address (_normalize_ip); only the limiters see this key."""
    ip = _normalize_ip(ip)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return ip


# The sweep
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


# The limit check
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


# Cache state
_file_cache       = collections.OrderedDict()
_file_cache_lock  = threading.Lock()
_file_cache_bytes = 0

# Text-like types worth gzipping. Already-compressed formats (images, woff/woff2,
# pdf, video, archives) gain nothing, so they're served and stored uncompressed.
# Compressible types
_COMPRESSIBLE_EXTS = {
    ".html", ".css", ".js", ".json", ".svg", ".txt", ".xml", ".webmanifest", ".ttf",
}


# An entry's cost
def _entry_bytes(entry):
    return len(entry["raw"]) + (len(entry["compressed"]) if entry["compressed"] else 0)


# Reading through the cache
def _get_cached_file(path):
    """Return (raw, compressed_or_None, etag), reloading only if the file changed.

    "Changed" is judged on (mtime_ns, size, inode) from one stat call — not
    mtime alone, which the publish pipeline can hold constant across content
    changes: tar restores each member's archived mtime at whole-second
    granularity, so two pulls of a file edited and repacked within the same
    second (or built by any pinned-timestamp tooling) carried identical
    mtimes with different bytes, and the cache served the old bytes
    indefinitely. The swap extracts fresh files, so the inode always moves;
    size and nanosecond mtime guard direct in-place edits too.

    compressed is None for already-compressed types; a file too large to fit in
    the cache is served raw and not stored, so it can't purge everything else.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None, None, None
    stamp = (st.st_mtime_ns, st.st_size, st.st_ino)

    with _file_cache_lock:
        entry = _file_cache.get(path)
        if entry and entry["stamp"] == stamp:
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
    new_entry  = {"stamp": stamp, "raw": raw, "compressed": compressed, "etag": etag}

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


# MIME types
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


# Containment
def _within(base, target):
    """True if `target` is `base` or sits inside it. commonpath on already-resolved
    absolute paths means a traversal or symlink escape lands outside `base` and
    fails. Used by the config-time serve_dir checks; the REQUEST path's
    containment is inlined in _resolve_request_path instead — see there."""
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


# Resolving a request path
def _resolve_request_path(url_path, serve_dir):
    """Resolve a URL path to an absolute file path within the matched site's
    serve_dir. Returns (None, 403) on traversal or a hidden path, (None, 404) if
    not found.

    The containment guards are written out inline — realpath, then a literal
    startswith check on every continuing path — rather than through _within, on
    purpose: this is the one place attacker-controlled text becomes a
    filesystem path, and the guard must be verifiable at the boundary itself,
    by a reader without chasing a helper and by a taint analyzer that checks
    the guard dominates every path to every use. That domination requirement is
    why the site root is resolved to its index BEFORE the guard rather than
    exempted by an equality test beside it: `x == serve_dir or
    x.startswith(...)` short-circuits past the startswith on the root path,
    and a guard some path can skip is, to an analyzer and strictly speaking,
    not a guard."""
    serve_dir = os.path.realpath(_resolve(serve_dir))
    clean     = unquote(url_path.split("?")[0]).lstrip("/")   # lstrip: never an absolute path
    # Refuse hidden files and directories. A dotfile is never meant to be public,
    # and a static deploy routinely leaves sensitive ones under serve_dir — a
    # .git checkout, a .env, an editor backup — so serving them leaks source and
    # secrets. This first pass reads the *requested* segments, closing the direct
    # case (GET /.git/config); the ".." of a traversal is caught here too, with
    # the containment check below as the backstop.
    if _hidden_segment(clean.split("/")):
        return None, 403
    abs_path  = os.path.realpath(os.path.join(serve_dir, clean))
    if abs_path == serve_dir:
        # The site root itself ("/", or an alias resolving to it) — its
        # document is the index, resolved here so the guard below covers it.
        abs_path = os.path.realpath(os.path.join(serve_dir, "index.html"))
    if not abs_path.startswith(serve_dir + os.sep):
        return None, 403
    if os.path.isdir(abs_path):
        abs_path = os.path.realpath(os.path.join(abs_path, "index.html"))
        if not abs_path.startswith(serve_dir + os.sep):
            return None, 403
    # Re-check the *resolved* target's segments. The pass above reads the name
    # the client asked for; a symlink inside serve_dir whose own name is not a
    # dotfile can still resolve to a hidden target (serve_dir/x -> serve_dir/.git
    # /config), and realpath keeps it within serve_dir, so containment passes.
    # Applying the same rule to the resolved path refuses a hidden target by
    # whatever name it was reached. abs_path is at or under serve_dir here, so
    # the slice yields the relative segments (empty at the root — no dotfile).
    if _hidden_segment(abs_path[len(serve_dir):].split(os.sep)):
        return None, 403
    if not os.path.isfile(abs_path):
        return None, 404
    return abs_path, 200


# Cache-Control
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


# Byte ranges
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


# Security headers
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


# Reserved paths. The connection test's URL keeps the older word: the page
# was renamed, the address cannot be (DECISIONS.md, "It is a connection
# test") — a published URL outlives the name someone gave the page.
_WELL_KNOWN_VERSION_PATH = "/.well-known/servette"
_CONNECTION_PATH         = "/.well-known/servette-check"

# The default 404 body (DECISIONS.md: "The error page is server-delivered,
# client-executed"): authored as src/404.html and inlined by build.py, so it is
# part of the module rather than a file beside it. That is deliberate — a page
# shipped as package data can be deleted on the box, and deleting it would
# silently take the default 404 body with it. There is no read at import and no
# missing-file case to degrade through.
_NOT_FOUND_PAGE = """<!DOCTYPE html>
<!-- src/404.html — Servette's default 404 body, inlined into the module by
     build.py (see DECISIONS.md, "The error page is server-delivered,
     client-executed"). Served for any miss where the site publishes no
     404.html of its own.

     Every server needs an error page, and a bare "Not found." spends a
     whole response saying only that the reader was wrong. This one leads
     with the path and says the true thing: the server is up and answered —
     only the path is missing. The full diagnosis lives on its own page at
     the reserved path /.well-known/servette-check, linked below; splitting
     the two keeps this page a real 404 and keeps the check reachable even
     after an operator's own 404.html takes this role over.

     The requested path is attacker-controlled text: written with
     textContent, never innerHTML. -->
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect x='2' y='2' width='60' height='60' rx='13' fill='%230e0e0e' stroke='%235A8466' stroke-width='4'/><text x='14' y='45' font-family='ui-monospace,Menlo,monospace' font-size='36' font-weight='600' fill='%235A8466'>S</text><rect x='35' y='39' width='16' height='6' rx='1.5' fill='%235A8466'/></svg>">
  <title>404 — not found</title>
  <style>
    /* ── Theme and reset ─────────────────────────────────────────────── */
    :root {
      --bg:      #0e0e0e;
      --surface: #161616;
      --border:  #2a2a2a;
      --text:    #e8e8e8;
      --muted:   #555;
      --green:   #4ade80;
      --red:     #f87171;
      /* No web fonts: a page that demonstrates a self-hosted server has no
         business fetching anything from a third party. */
      --mono: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas,
              'Liberation Mono', 'Courier New', monospace;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    /* ── Page frame: centred column over a faint noise wash ──────────── */
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--mono);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 2rem;
    }

    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E");
      pointer-events: none;
      opacity: 0.4;
      z-index: 0;
    }

    .container {
      position: relative;
      z-index: 1;
      max-width: 480px;
      width: 100%;
    }

    /* ── Wordmark and tagline ────────────────────────────────────────── */
    .header {
      margin-bottom: 3rem;
    }

    .servette-logo {
      font-family: var(--mono);
      font-weight: 500;
      font-size: 3rem;
      letter-spacing: 0;
      color: var(--text);
      line-height: 1;
    }

    .servette-logo .ette   { color: #5A8466; }
    .servette-logo .cursor { color: inherit; animation: servette-blink 1.1s steps(1) infinite; }

    @keyframes servette-blink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }

    .tagline {
      margin-top: 0.5rem;
      color: var(--muted);
      font-size: 0.75rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .dot {
      display: inline-block;
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--green);
      margin-right: 0.5rem;
      animation: pulse 2s ease infinite;
      vertical-align: middle;
      position: relative;
      top: -1px;
    }

    .dot.red { background: var(--red); animation: none; }

    /* ── The miss itself: code, path, and why you are seeing this ────── */
    .notfound {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--surface);
      padding: 1.25rem;
      margin-bottom: 1.5rem;
    }

    .notfound-head {
      display: flex;
      align-items: baseline;
      gap: 0.6rem;
      flex-wrap: wrap;
    }

    .notfound-code {
      font-size: 1.5rem;
      font-weight: 500;
      color: var(--text);
      line-height: 1;
    }

    .notfound-msg {
      color: var(--muted);
      font-size: 0.75rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    /* The requested path is attacker-controlled text. It is written with
       textContent and wrapped here rather than truncated, so a long path
       cannot push the layout sideways. */
    .notfound-path {
      margin-top: 0.85rem;
      font-size: 0.8rem;
      color: var(--text);
      overflow-wrap: anywhere;
      word-break: break-all;
    }

    .notfound-why {
      margin-top: 0.85rem;
      color: var(--muted);
      font-size: 0.75rem;
      line-height: 1.7;
    }

    .notfound-why code {
      color: var(--text);
      font-size: 0.72rem;
    }

    .notfound-links {
      margin-top: 0.85rem;
      display: flex;
      gap: 1.25rem;
      flex-wrap: wrap;
    }

    /* ── Connection card: the one live judgment this page keeps ──────── */
    .verified {
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }

    .verified-header {
      background: var(--surface);
      padding: 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }

    .verified-label {
      font-size: 0.7rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 0.25rem;
    }

    .verified-value { font-size: 0.9rem; color: var(--text); }

    .badge {
      font-size: 0.7rem;
      font-weight: 500;
      padding: 0.3rem 0.7rem;
      border-radius: 4px;
      letter-spacing: 0.05em;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .badge-green { background: rgba(74,222,128,0.12); color: var(--green); border: 1px solid rgba(74,222,128,0.2); }
    .badge-red   { background: rgba(248,113,113,0.12); color: var(--red);  border: 1px solid rgba(248,113,113,0.2); }

    .verified-links {
      padding: 0.75rem 1.25rem;
      border-top: 1px solid var(--border);
      background: var(--surface);
    }

    /* Every link on the page is a Servette link — one rule for all of them. */
    .notfound-links a, .verified-links a, .note a {
      font-size: 0.75rem;
      color: #5A8466;
      text-decoration: none;
    }
    .notfound-links a:hover, .verified-links a:hover, .note a:hover {
      text-decoration: underline;
    }

    /* ── Footer ──────────────────────────────────────────────────────── */
    .note {
      font-size: 0.7rem;
      color: var(--muted);
      line-height: 1.7;
    }
    .note a { font-size: inherit; }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.3; }
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation: none !important; opacity: 1 !important; }
    }
  </style>
</head>
<body>

<div class="container">

  <div class="header">
    <div class="servette-logo">Serv<span class="ette">ette</span><span class="cursor">_</span></div>
    <div class="tagline">
      <span class="dot" id="dot"></span><span id="tagline-text">THE SERVER IS RUNNING — THIS PATH IS NOT</span>
    </div>
  </div>

  <!-- The connection card leads: whether the server answered, and whether
       the wire is encrypted, are true of the whole site and settle a
       reader's first question. What is missing is the narrower fact, and
       follows it. -->
  <div class="verified">
    <div class="verified-header">
      <div>
        <div class="verified-label">Connection</div>
        <div class="verified-value" id="url">—</div>
      </div>
      <div class="badge" id="badge">—</div>
    </div>
    <div class="verified-links">
      <a href="/.well-known/servette-check">run the connection test →</a>
    </div>
  </div>

  <!-- The server is up and answered — the path is what is missing — so this
       leads with the path rather than with blame. -->
  <div class="notfound">
    <div class="notfound-head">
      <span class="notfound-code">404</span>
      <span class="notfound-msg">Nothing published here</span>
    </div>
    <div class="notfound-path" id="notfound-path">—</div>
    <p class="notfound-why">
      The server is running and answered this request, so the connection is
      fine — only the path is missing. You are seeing this page because the
      site publishes no <code>404.html</code> of its own.
    </p>
    <div class="notfound-links">
      <a href="/">← the site's home page</a>
    </div>
  </div>

  <div class="note">
    Served by
    <a href="https://servette.org">Servette</a> —
    The Simple, Secure, Static-Site Server.
  </div>

</div>

<script>
  const $ = (id) => document.getElementById(id);

  // ── The address the reader asked for ──────────────────────────────
  // The complete URL, not the bare path: a miss at the site root would
  // otherwise display as a lone "/", which reads as a typo rather than an
  // address. textContent, never innerHTML — the path half is whatever the
  // client asked for. decodeURI so an escaped path reads as the reader
  // typed it, with the raw value kept when malformed enough to throw.
  let shown = location.href.split('#')[0];
  try { shown = decodeURI(shown); } catch (e) { /* keep the raw form */ }
  $('notfound-path').textContent = shown;

  // The one live judgment this page keeps: whether the connection carrying
  // it is encrypted. Everything deeper belongs to the connection test,
  // linked on the card below.
  $('url').textContent = location.protocol + '//' + location.host;
  if (location.protocol === 'https:') {
    $('badge').textContent = '✓ Verified encrypted';
    $('badge').className   = 'badge badge-green';
  } else {
    $('badge').textContent = '⚠ Not encrypted';
    $('badge').className   = 'badge badge-red';
    $('dot').className     = 'dot red';
    $('tagline-text').textContent = 'Connection is not secure';
  }
</script>

</body>
</html>
""".encode()
_NOT_FOUND_ETAG = '"' + hashlib.sha256(_NOT_FOUND_PAGE).hexdigest()[:16] + '"'

# The connection test (src/connection.html), served on every site at a
# reserved path under /.well-known/ — the one namespace the hidden-path rule
# already sets apart, so an operator's content never shadows the outside
# vantage the way a custom 404.html takes over the miss body.
_CONNECTION_PAGE = """<!DOCTYPE html>
<!-- src/connection.html — inlined into the module by build.py and
     served at the reserved path /.well-known/servette-check (DECISIONS.md,
     "The connection test has its own reserved page"). The URL keeps the
     older word on purpose: the page was renamed, the address cannot be.
     Linked from the default 404 body, and from each site's card on the
     admin page.

     Same-origin by construction, so it can read what a cross-origin probe
     never could: it checks the connection it was itself loaded over. It
     never enumerates the filesystem — no "did you mean" suggestions —
     because that would turn a public page into a file-discovery oracle for
     strangers. It does not report the server's version: on a public site
     that endpoint answers 404 by design, so the row could only ever say
     "withheld" while costing a miss in the log on every run, and the
     operator reads the version from `status` or the admin page. Because
     this file ships with the server, its checks can never drift from the
     features they check — and because its path is reserved, an operator's
     own content never takes it over, so the outside vantage survives a
     custom 404.html.

     No triple double-quote and no backslash anywhere in this file: it lands
     inside a triple-quoted Python literal, and the build refuses both. -->
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect x='2' y='2' width='60' height='60' rx='13' fill='%230e0e0e' stroke='%235A8466' stroke-width='4'/><text x='14' y='45' font-family='ui-monospace,Menlo,monospace' font-size='36' font-weight='600' fill='%235A8466'>S</text><rect x='35' y='39' width='16' height='6' rx='1.5' fill='%235A8466'/></svg>">
  <title>Connection test</title>
  <style>
    /* ── Theme and reset ─────────────────────────────────────────────── */
    :root {
      --bg:      #0e0e0e;
      --surface: #161616;
      --border:  #2a2a2a;
      --text:    #e8e8e8;
      --muted:   #555;
      --green:   #4ade80;
      --red:     #f87171;
      /* No web fonts: a page that demonstrates a self-hosted server has no
         business fetching anything from a third party. */
      --mono: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas,
              'Liberation Mono', 'Courier New', monospace;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    /* ── Page frame: centred column over a faint noise wash ──────────── */
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--mono);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 2rem;
    }

    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E");
      pointer-events: none;
      opacity: 0.4;
      z-index: 0;
    }

    .container {
      position: relative;
      z-index: 1;
      max-width: 480px;
      width: 100%;
    }

    /* ── Wordmark and tagline ────────────────────────────────────────── */
    .header {
      margin-bottom: 3rem;
    }

    .servette-logo {
      font-family: var(--mono);
      font-weight: 500;
      font-size: 3rem;
      letter-spacing: 0;
      color: var(--text);
      line-height: 1;
    }

    .servette-logo .ette   { color: #5A8466; }
    .servette-logo .cursor { color: inherit; animation: servette-blink 1.1s steps(1) infinite; }

    @keyframes servette-blink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }

    .tagline {
      margin-top: 0.5rem;
      color: var(--muted);
      font-size: 0.75rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .dot {
      display: inline-block;
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--green);
      margin-right: 0.5rem;
      animation: pulse 2s ease infinite;
      vertical-align: middle;
      position: relative;
      top: -1px;
    }

    .dot.red { background: var(--red); animation: none; }

    /* ── Connection card: the headline verdict ───────────────────────── */
    .verified {
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 1.5rem;
    }

    .verified-header {
      background: var(--surface);
      padding: 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }

    .verified-label {
      font-size: 0.7rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 0.25rem;
    }

    .verified-value { font-size: 0.9rem; color: var(--text); }

    .badge {
      font-size: 0.7rem;
      font-weight: 500;
      padding: 0.3rem 0.7rem;
      border-radius: 4px;
      letter-spacing: 0.05em;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .badge-green { background: rgba(74,222,128,0.12); color: var(--green); border: 1px solid rgba(74,222,128,0.2); }
    .badge-red   { background: rgba(248,113,113,0.12); color: var(--red);  border: 1px solid rgba(248,113,113,0.2); }

    /* ── The report: one row per finding, evidence underneath ────────── */
    .checks {
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      background: var(--surface);
      margin-bottom: 1.5rem;
    }

    .checks-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.75rem 1.25rem;
      border-bottom: 1px solid var(--border);
    }

    .checks-title {
      font-size: 0.7rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--muted);
    }

    .run-again {
      font-family: inherit;
      font-size: 0.7rem;
      color: var(--muted);
      background: none;
      border: none;
      cursor: pointer;
      letter-spacing: 0.05em;
      white-space: nowrap;
    }
    .run-again:hover { color: var(--text); }

    .t-log { padding: 0.6rem 1.25rem; }

    .t-row {
      display: flex;
      gap: 0.85rem;
      padding: 0.32rem 0;
      font-size: 0.72rem;
      line-height: 1.45;
    }

    /* Rows render all at once in the pending state and resolve in place —
       dim, then verdict — so the report never appears to assemble itself. */
    .t-row.pending .t-req, .t-row.pending .t-obs, .t-row.pending .t-ev { opacity: 0.45; }

    .t-st       { flex: 0 0 2.6em; font-weight: 500; }
    .t-pass     { color: var(--green); }
    .t-fail     { color: var(--red); }
    .t-skip     { color: var(--muted); }
    .t-pending  { color: var(--muted); }

    .t-body { flex: 1; min-width: 0; }
    .t-req  { color: var(--text); }
    .t-obs  { color: var(--muted); }
    /* The evidence that earned the finding, kept where it belongs: under
       the finding, in the smaller voice of a footnote. */
    .t-ev   { color: #3d3d3d; font-size: 0.66rem; margin-top: 0.15rem;
              overflow-wrap: anywhere; }

    .t-summary {
      padding: 0.75rem 1.25rem;
      border-top: 1px solid var(--border);
      font-size: 0.72rem;
      color: var(--muted);
    }
    .t-summary b { color: var(--text); font-weight: 500; }

    /* ── Footer ── */
    .note {
      font-size: 0.7rem;
      color: var(--muted);
      line-height: 1.7;
    }
    .note a { color: #5A8466; text-decoration: none; }
    .note a:hover { text-decoration: underline; }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.3; }
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation: none !important; opacity: 1 !important; }
    }
  </style>
</head>
<body>

<div class="container">

  <div class="header">
    <div class="servette-logo">Serv<span class="ette">ette</span><span class="cursor">_</span></div>
    <div class="tagline">
      <span class="dot" id="dot"></span><span id="tagline-text">checking...</span>
    </div>
  </div>

  <div class="verified">
    <div class="verified-header">
      <div>
        <div class="verified-label">Connection</div>
        <div class="verified-value" id="url">—</div>
      </div>
      <div class="badge" id="badge">—</div>
    </div>
  </div>

  <div class="checks">
    <div class="checks-head">
      <span class="checks-title">Connection test</span>
      <button class="run-again" id="run-again" type="button">↻ run again</button>
    </div>
    <div class="t-log" id="t-log"></div>
    <div class="t-summary" id="t-summary">running…</div>
  </div>

  <div class="note">
    Served by
    <a href="https://servette.org">Servette</a> —
    The Simple, Secure, Static-Site Server.
  </div>

</div>

<script>
  const $ = (id) => document.getElementById(id);

  // ── Connection card ───────────────────────────────────────────────
  const isHttps = location.protocol === 'https:';
  $('url').textContent = location.protocol + '//' + location.host;

  if (isHttps) {
    $('badge').textContent = '✓ Verified encrypted';
    $('badge').className    = 'badge badge-green';
    // Just the verdict. The vantage needs no announcing: the reader is
    // holding the browser this page ran its checks from.
    $('tagline-text').textContent = 'THE SERVER IS RUNNING';
  } else {
    $('badge').textContent = '⚠ Not encrypted';
    $('badge').className    = 'badge badge-red';
    $('dot').className      = 'dot red';
    $('tagline-text').textContent = 'Connection is not secure';
  }

  // ── The checks ────────────────────────────────────────────────────
  // Each check makes a real request and reports the value it observed.
  // ok: true = PASS, false = FAIL, null = SKIP.
  //
  // A SKIP is never faked as a pass — and, just as importantly, never
  // faked as a fail. Several of these headers are optional and can be
  // switched off in config; an operator who turned one off made a
  // choice, and reporting that choice as a defect would be a lie in the
  // other direction.
  const here = location.href.split('#')[0];
  const P = '/.well-known/servette-check';

  let _hdrs = null;
  const H = async () => (_hdrs ||= (await fetch(here, { cache: 'no-store' })).headers);
  const seen = (v) => v || '(absent)';

  // Each row is a finding in the reader's language, with the evidence that
  // earned it underneath. The requests are the same ones as ever; what
  // changed is that the report leads with what they mean, and several
  // probes that answer one question now share one row.
  const checks = [
    { name: 'Encrypted', run: async () => {
        const r = await fetch(here, { cache: 'no-store' });
        const ct = r.headers.get('Content-Type') || '(absent)';
        return { ok: isHttps && r.status === 200,
                 obs: isHttps
                   ? 'HTTPS, and this browser accepted the certificate'
                   : 'served over plain HTTP — visitors are unprotected',
                 ev: 'GET ' + P + ' → ' + r.status + ', ' + ct }; } },

    // Is anything published? A working home page and a passworded one both
    // count as answers; anything else is the deploy-never-landed signal.
    { name: 'Home page', run: async () => {
        const s = (await fetch('/', { cache: 'no-store' })).status;
        if (s === 200)
          return { ok: true, obs: 'published and answering', ev: 'GET / → 200' };
        if (s === 401)
          return { ok: true, obs: 'published, behind the site login',
                   ev: 'GET / → 401' };
        return { ok: false, obs: 'nothing is published at the site root',
                 ev: 'GET / → ' + s }; } },

    // Five headers, one question: is the browser being told how to behave?
    // Two of the five are optional in config, so their absence is reported
    // as a choice rather than a defect.
    { name: 'Security headers', run: async () => {
        const h = await H();
        const want = [['X-Frame-Options', 'DENY'], ['X-Content-Type-Options', 'nosniff'],
                      ['Referrer-Policy', null]];
        const missing = want.filter(([k, v]) => {
          const got = h.get(k);
          return v ? got !== v : !got;
        }).map(([k]) => k);
        const optional = [['Content-Security-Policy', 'CSP'],
                          ['Permissions-Policy', 'Permissions-Policy']]
          .filter(([k]) => !h.get(k)).map(([, name]) => name);
        return { ok: !missing.length,
                 obs: missing.length ? 'missing: ' + missing.join(', ')
                      : optional.length ? 'sent (' + optional.join(' and ') +
                                          ' switched off in config)'
                      : 'all sent',
                 ev: want.concat([['Content-Security-Policy'], ['Permissions-Policy']])
                        .map(([k]) => k + ': ' + seen(h.get(k))).join(' · ') }; } },

    // HSTS is only sent for a site with a real domain certificate, so on a
    // self-signed or LAN server its absence is correct.
    { name: 'HTTPS enforced', run: async () => {
        const v = (await H()).get('Strict-Transport-Security');
        return v
          ? { ok: true, obs: 'browsers are told to refuse plain HTTP here',
              ev: 'Strict-Transport-Security: ' + v }
          : { ok: null, obs: 'needs a domain certificate (this one is self-signed)',
              ev: 'Strict-Transport-Security: (absent)' }; } },

    { name: 'Caching', run: async () => {
        const h = await H();
        const etag = h.get('ETag');
        if (!etag || !h.get('Cache-Control'))
          return { ok: false, obs: 'no validator — every visit re-downloads',
                   ev: 'Cache-Control: ' + seen(h.get('Cache-Control')) +
                       ' · ETag: ' + seen(etag) };
        const r = await fetch(here, { cache: 'no-store', headers: { 'If-None-Match': etag } });
        return r.status === 304
          ? { ok: true, obs: 'unchanged files are revalidated, not re-sent',
              ev: 'If-None-Match ' + etag + ' → 304' }
          : { ok: null, obs: 'validator sent; this browser re-downloaded anyway',
              ev: 'If-None-Match ' + etag + ' → ' + r.status }; } },

    // Three refusals, one question: does the server say no where it should?
    { name: 'Refusals', run: async () => {
        const post = (await fetch(here, { method: 'POST' })).status;
        const miss = (await fetch('/__servette_probe_' + Date.now())).status;
        const trav = (await fetch('/%2e%2e%2f%2e%2e%2fetc%2fpasswd')).status;
        const bad = [];
        if (post !== 405) bad.push('POST answered ' + post + ', not 405');
        if (miss !== 404) bad.push('unknown path answered ' + miss + ', not 404');
        if (trav !== 403) bad.push('path traversal answered ' + trav + ', not 403');
        return { ok: !bad.length,
                 obs: bad.length ? bad.join('; ')
                      : 'uploads, unknown paths, and traversal all refused',
                 ev: 'POST → ' + post + ' · unknown → ' + miss +
                     ' · traversal → ' + trav }; } },

  ];

  // ── Rendering the report ──────────────────────────────────────────
  const LABEL = { pass: 'PASS', fail: 'FAIL', skip: 'SKIP', pending: '····' };
  const logEl = $('t-log');

  function addRow(name) {
    const st  = document.createElement('span'); st.className  = 't-st t-pending'; st.textContent = LABEL.pending;
    const req = document.createElement('span'); req.className = 't-req';  req.textContent = name;
    const obs = document.createElement('span'); obs.className = 't-obs';  obs.textContent = '';
    const ev  = document.createElement('div');  ev.className  = 't-ev';   ev.textContent  = '';
    const body = document.createElement('span'); body.className = 't-body';
    body.append(req, document.createTextNode('  '), obs, ev);
    const row = document.createElement('div'); row.className = 't-row pending';
    row.append(st, body);
    logEl.appendChild(row);
    return { row, st, obs, ev };
  }

  function paint(row, st, state) {
    st.textContent = LABEL[state];
    st.className = 't-st t-' + state;
    row.classList.remove('pending');
  }

  async function runTests() {
    _hdrs = null;                 // force fresh requests on each run
    logEl.innerHTML = '';
    $('t-summary').textContent = 'running…';
    let pass = 0, fail = 0, skip = 0;
    // Every row exists before any check runs — the full report is visible
    // immediately, dimmed, and each row resolves in place.
    const rows = checks.map((c) => ({ c, el: addRow(c.name) }));
    for (const { c, el } of rows) {
      let r;
      // A check that throws is a skip, not a failure — the request never
      // completed, so nothing was observed. What went wrong becomes the
      // evidence, the same as for a check that did complete.
      try { r = await c.run(); }
      catch (e) { r = { ok: null, obs: 'could not run', ev: String(e) }; }
      el.obs.textContent = r.obs;
      el.ev.textContent = r.ev || '';
      if (r.ok === true)       { paint(el.row, el.st, 'pass'); pass++; }
      else if (r.ok === false) { paint(el.row, el.st, 'fail'); fail++; }
      else                     { paint(el.row, el.st, 'skip'); skip++; }
    }
    // Green leads when nothing failed — the pitch and the test coincide on a
    // healthy site. A failure count is never hidden: suppressing it would
    // make the page lie by omission to the operator it exists to help.
    $('t-summary').innerHTML = fail
      ? '<b>' + pass + '</b> passed · <b>' + fail + '</b> failed · <b>' + skip + '</b> skipped'
      : 'All <b>' + pass + '</b> checks passed' +
        (skip ? ' · <b>' + skip + '</b> skipped' : '');
  }

  $('run-again').addEventListener('click', runTests);
  runTests();
</script>

</body>
</html>
""".encode()
_CONNECTION_ETAG = '"' + hashlib.sha256(_CONNECTION_PAGE).hexdigest()[:16] + '"'


# Log escaping
def _loggable(s):
    """Escape control characters in a string bound for the logs. A request path
    reaches the journal and, from there, an operator's terminal — an unescaped
    ANSI/control sequence could move the cursor, clear the screen, or hide text.
    Printable characters (including non-ASCII) pass through unchanged."""
    return "".join(c if c >= " " and c != "\x7f" else f"\\x{ord(c):02x}" for c in s)


# The request core
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

    site = None  # bound by Host below; None until then, and if nothing matches

    def resp(status, hdrs, body=b""):
        # Security headers (and HSTS, gated on `site`) go on every response;
        # HEAD keeps the headers but drops the body. `site` is read fresh at
        # call time (Python closures are late-binding), so this is correct
        # whether called before or after site selection below.
        return status, _security_headers(site) + hdrs, (b"" if method == "HEAD" else body)

    config.reload_if_changed()

    # Site selection — uniform regardless of site count (see _select_site).
    # Selected BEFORE the rate limiter, deliberately: selection is a cheap
    # in-memory comparison, and with `site` already bound, a matched host's
    # 429 below carries its HSTS header like every other response — the old
    # order left rate-limited responses as the one un-pinned path a browser
    # could be downgraded on. An unmatched Host still reaches the limiter
    # (site stays None, no HSTS — the closed system gives it nothing), so a
    # flood of random Hosts throttles exactly as before.
    site = _select_site(headers.get("Host", ""))

    # Rate limiting — host-level, shared across every site on the box.
    bucket = _bucket_key(ip)   # /64 for IPv6 — logs keep the full address
    if _rate_limit_exceeded(_request_times, bucket, config.rate_limit):
        log.warning("Rate limited %s", ip)
        return resp(429, [(b"retry-after", str(RATE_WINDOW).encode()), (b"content-length", b"0")])

    # No match: the closed-system miss. Bare 404, no site-specific information
    # of any kind (no HSTS either, since `site` is None for resp() above) —
    # deliberately ahead of the method check below, so a POST/PUT/etc. to an
    # unmatched Host gets the same undifferentiated 404 a GET would, rather
    # than a 405 that would leak "something is here, it just doesn't take this
    # method."
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
        if credentials_submitted and _rate_limit_exceeded(_auth_fail_times, bucket, config.auth_rate_limit, record=False):
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
            if credentials_submitted and _rate_limit_exceeded(_auth_fail_times, bucket, config.auth_rate_limit):
                log.warning("Auth rate limited %s", ip)
                return resp(429, [(b"retry-after", str(RATE_WINDOW).encode()), (b"content-length", b"0")])
            if credentials_submitted:
                log.warning("Failed auth attempt from %s", ip)
            return resp(401, [
                (b"www-authenticate", b'Basic realm="Access Required"'),
                (b"content-type",     b"text/plain"),
                (b"content-length",   b"12"),
            ], b"Unauthorized")

    # Version discovery: what this box is running — the embedded error page
    # reads this to show the served version. Deliberately
    # reports only what THIS box knows; "latest available" is the package
    # index's business, not Servette's. Host-level (one process, one version).
    #
    # Gated on the site having auth, so the exact version reaches only a party
    # that already holds the site's password — never an anonymous scanner, for
    # whom a precise version is a targeting oracle the moment any version-specific
    # hole is disclosed. A site with no password does not serve it at all: the
    # path falls through to a normal 404, leaving the endpoint invisible to the
    # public. (A remote tool for a no-auth site reads the version another way; a
    # local operator has it from 'status'.)
    if site.username and url_path.split("?", 1)[0] == _WELL_KNOWN_VERSION_PATH:
        body = json.dumps({"running": __version__}).encode()
        return resp(200, [(b"content-type", b"application/json"),
                          (b"content-length", str(len(body)).encode())], body)

    # The connection test, on its reserved path — code-first, so it answers
    # whatever the site publishes: an operator's 404.html takes the miss body
    # by existing, but it can never take the outside vantage with it. Behind
    # the site's own auth like everything else, and carrying the same
    # revalidate-always caching contract as the 404 body, for the same
    # reason: the page's checks probe the URL it was served from.
    if url_path.split("?", 1)[0] == _CONNECTION_PATH:
        cache = _cache_control_header(site.username)
        if "max-age" in cache:
            cache = ("private" if site.username else "public") + ", no-cache"
        if headers.get("If-None-Match", "") == _CONNECTION_ETAG:
            log.info("304 Not Modified %s to %s", log_path, ip)
            return resp(304, [(b"etag", _CONNECTION_ETAG.encode()),
                              (b"cache-control", cache.encode())])
        log.info("200 %s (connection test) to %s", log_path, ip)
        return resp(200, [
            (b"content-type",   b"text/html; charset=utf-8"),
            (b"content-length", str(len(_CONNECTION_PAGE)).encode()),
            (b"etag",           _CONNECTION_ETAG.encode()),
            (b"cache-control",  cache.encode()),
        ], _CONNECTION_PAGE)

    # Redirects, before the filesystem is touched at all. One dict lookup on
    # a table loaded with the config — never a file read, which is what the
    # _redirects-file convention other hosts use would cost at request time
    # (DECISIONS.md, "Redirects are a setting, not a file in the site").
    # Query strings ride along: a redirect names a path, and dropping the
    # query would silently break every campaign link pointed at the old one.
    if site.redirects:
        bare, sep, query = url_path.partition("?")
        target = site.redirects.get(bare.rstrip("/") or "/")
        if target:
            if sep and "?" not in target:
                target += sep + query
            log.info("301 %s to %s", log_path, ip)
            return resp(301, [
                (b"location",       target.encode("ascii", "ignore")),
                (b"content-length", b"0"),
                (b"cache-control",  b"no-cache"),
            ])

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
        # Every server needs an error page, and a bare "Not found." spends a
        # whole response telling the reader only that they were wrong. This one
        # leads with the path, says the server is up and answered, and links
        # the connection test on its reserved path above — the split that
        # keeps this a real 404 while the diagnosis survives an operator's
        # own 404.html, which wins this role by simply existing.
        #
        # It also covers a site's own root while nothing is published there: no
        # index.html means the root is itself a miss, so the domain reports on
        # itself instead of answering with ten bytes of text.
        #
        # The response keeps the caching contract (ETag, Cache-Control, 304),
        # with any positive lifetime downgraded below.
        site_root  = _resolve(site.serve_dir)
        custom_404 = os.path.join(site_root, "404.html")
        if not os.path.isfile(custom_404):
            # A positive lifetime is downgraded to revalidate-always. Under
            # cache_policy = "max-age" an error page would otherwise sit in a
            # shared cache for max_age seconds and keep answering 404 for a path
            # *after* the operator publishes the very file that was missing.
            cache = _cache_control_header(site.username)
            if "max-age" in cache:
                cache = ("private" if site.username else "public") + ", no-cache"
            if headers.get("If-None-Match", "") == _NOT_FOUND_ETAG:
                log.info("304 Not Modified %s to %s", log_path, ip)
                return resp(304, [(b"etag", _NOT_FOUND_ETAG.encode()),
                                  (b"cache-control", cache.encode())])
            log.info("404 %s (embedded error page) to %s", log_path, ip)
            return resp(404, [
                (b"content-type",   b"text/html; charset=utf-8"),
                (b"content-length", str(len(_NOT_FOUND_PAGE)).encode()),
                (b"etag",           _NOT_FOUND_ETAG.encode()),
                (b"cache-control",  cache.encode()),
            ], _NOT_FOUND_PAGE)

        # The operator's own 404.html: the embedded page returned above unless
        # this file exists, so it is the only way to reach here. Unreadable
        # (bad permissions, a race with a deploy) falls back to the plain body
        # rather than serving an empty one.
        raw_404, _, _ = _get_cached_file(custom_404)
        if raw_404 is None:
            body_404, content_type_404 = b"Not found.", b"text/plain"
        else:
            body_404, content_type_404 = raw_404, b"text/html; charset=utf-8"
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


# Site selection
def _select_site(host):
    """Match a Host/SNI value (bare hostname, port stripped if present) against
    configured sites — uniform regardless of site count. Exact domain match
    first; else the first domainless site, which acts as the catch-all (any
    Host reaches a self-signed/LAN site with no domain configured). No
    domainless site and no domain match: None, the closed-system miss."""
    host = (host or "").split(":")[0].strip().lower()
    # A deactivated site is invisible to routing everywhere below: its Host
    # gets the closed-system miss (over a still-valid certificate), which is
    # what "kept but not served" means on the wire.
    for site in config.sites:
        if site.active and site.domain and site.domain.lower() == host:
            return site
    # www.<domain> reaches the site configured as <domain>. _obtain_trusted_cert
    # deliberately issues one certificate covering both names, so routing has to
    # honour the same pair or the www name gets a certificate and then a 404.
    # Only after the exact loop above, so a site explicitly configured as
    # www.<domain> still wins its own traffic rather than being shadowed.
    if host.startswith("www."):
        bare = host[4:]
        for site in config.sites:
            if site.active and site.domain and site.domain.lower() == bare:
                return site
    for site in config.sites:
        if site.active and not site.domain:
            return site
    return None


# Domain collisions
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


# One certificate's context
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


# The default certificate
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


# The SNI table
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


# The HTTPS handler
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


# The redirect handler
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
# Connection ceilings
MAX_CONNECTIONS        = 128
MAX_CONNECTIONS_PER_IP = 32


# The capped server
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
        # The connection cap shares the limiters' bucketing (/64 for IPv6) —
        # per-address keying let one subscriber's 2^64 addresses each claim a
        # fresh slot allowance, unmaking the cap for IPv6 sources.
        return _bucket_key(client_address[0]) if client_address else "?"

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


# The TLS server
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


# Server state

_https_server         = None  # the running HTTPS ThreadingHTTPServer (None when stopped)
_https_thread         = None  # the thread running its serve_forever loop
_http_server          = None  # the port-80 redirect server (None if unavailable)
_server_start_time    = None
_watchdog_thread      = None
_sweep_thread         = None
_sweep_stop           = threading.Event()
_last_renewal_attempt = {}  # domain -> monotonic timestamp of the last renewal attempt

_TLS_VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}
ACME_RETRIES  = 3


# The liveness test
def _server_running():
    """True when the HTTPS server is actually serving — the thread must be alive,
    not merely the server object constructed, so a crashed serve loop reads as
    stopped instead of running."""
    return _https_thread is not None and _https_thread.is_alive()


# The watchdog pass
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
                    # None means never attempted — attempt immediately. The old
                    # default of 0.0 read as "attempted at boot": monotonic IS
                    # seconds since boot, so a host up less than an hour
                    # refused every renewal until the clock caught up.
                    last = _last_renewal_attempt.get(site.domain)
                    if last is None or now - last >= 3600:
                        _last_renewal_attempt[site.domain] = now
                        log.info("Certificate for %s expires in %d days — renewing", site.domain, days)
                        if _obtain_trusted_cert(site.domain, site) == "refused":
                            # The CA answered no (failed authorization, refused
                            # order) — the cause is on our side of the fence
                            # (usually DNS) and rarely changes within the hour,
                            # while each hourly re-ask burns validation
                            # attempts against LE's per-hostname limits. Cool
                            # down six hours; a transient network failure
                            # keeps the ordinary hourly retry. With renewal
                            # starting 30 days out, even the long cool-down
                            # allows ~120 more attempts before expiry.
                            _last_renewal_attempt[site.domain] = now + 5 * 3600
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


# The watchdog thread
def _cert_watchdog():
    """Auto-renew Let's Encrypt certs before expiry; detect externally-rotated certs."""
    while _server_running():
        time.sleep(60)
        if not _server_running():
            break
        _cert_watchdog_tick()


# Starting
def start_server():
    global _server_start_time, _watchdog_thread, _sweep_thread, \
        _https_server, _https_thread, _http_server

    if _server_running():
        print("  Server is already running.")
        return

    for site in config.sites:
        for fname in [site.serve_dir, site.cert_file, site.key_file]:
            if not fname:
                print("  Not fully configured. Run 'config' to set up the server.")
                if "--serve" in sys.argv:
                    sys.exit(1)
                return
            full_path = _resolve(fname)
            if not os.path.exists(full_path):
                print(f"  File not found: {full_path}")
                if "--serve" in sys.argv:
                    sys.exit(1)
                return

    # fail closed: a bad bind or an unreadable cert surfaces here, synchronously
    try:
        https = _TLSThreadingHTTPServer(("0.0.0.0", config.port), _Handler, _build_site_ssl_contexts())
    except Exception as e:
        log.error("Server failed to start on port %d: %s", config.port, e)
        print(f"  Server failed to start on port {config.port}: {e}")
        if "--serve" in sys.argv:
            sys.exit(1)
        return

    # the port-80 redirect is best-effort (needs privilege and a free port)
    try:
        redirect = _CappedThreadingHTTPServer(("0.0.0.0", 80), _RedirectHandler)
    except OSError as e:
        log.warning("Could not bind to port 80: %s", e)
        print("  Note: could not bind to port 80. HTTP redirects unavailable.")
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
                print(f"  Warning: SSL certificate for {label} has expired. Browsers will block visitors.")
                print("  Run 'config' then 'cert' to renew it.\n")
                log.warning("SSL certificate for %s has expired", label)
            else:
                print(f"  Warning: SSL certificate for {label} expires in {days} days.")
                print("  Run 'config' then 'cert' to renew it.\n")
                log.warning("SSL certificate for %s expires in %d days", label, days)

    for issue in _production_issues():
        print(_c(f"  {issue}", "yellow"))
    for warning in _cache_warnings():
        print(_c(f"  {warning}", "yellow"))


# Stopping
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
    print("  Session server stopped.")


# The service watch
def _watch_server(poll=2, grace=5):
    """Block until the HTTPS server has been dead for `grace` seconds.

    --serve exits non-zero when this returns, so systemd's Restart=always brings
    the service back. Without the watch, a dead server thread leaves a living
    process: systemd reports active while nothing is listening.

    Under --serve nothing ever restarts the server in-process — a certificate
    reload deliberately stops it and lets systemd relaunch — so every dead
    thread this sees ends in an exit, and the grace only sets how long the
    site stays down before the restart begins. It was 30 seconds, justified
    by an in-process reload window that cannot occur in this mode: every
    certificate rotation cost ~35 seconds of downtime where stop, exit, and
    RestartSec add up to well under ten. The small grace that remains
    absorbs stop_server's own teardown ordering, nothing more."""
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


# The spinner
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


# Writing private keys
def _write_private_key(path, data):
    """Write key material with 0600 set at file creation, not chmod'd after:
    under a permissive umask, write-then-chmod leaves a window where another
    local user can open the key (an open fd survives the chmod), and a crash
    between the two leaves it world-readable permanently. Same pattern the
    swapfile creation uses — the mode exists before the content does."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


# The self-signed certificate
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


# Waiting for the port
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


# Reloading
_reload_requested = False  # lets --serve's exit log a restart as a restart


def _reload_server():
    """Reload the server to pick up a new certificate."""
    global _reload_requested
    if "--serve" in sys.argv:
        # Inside the service, the sandboxed unit user can't systemctl restart
        # (NoNewPrivileges, least privilege). Stop serving instead: _watch_server
        # sees the dead thread, --serve exits non-zero, and Restart=always
        # relaunches the service with the new certificate loaded. The flag
        # keeps the journal honest: without it every deliberate reload logged
        # "stopped unexpectedly", teaching the operator that the error line
        # is routine.
        _reload_requested = True
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


# base64url
def _b64url(data):
    """base64url without padding — the encoding JOSE/ACME uses everywhere."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_int(n):
    """A non-negative integer as a base64url big-endian byte string (for JWK n/e)."""
    length = max(_ceil_div(n.bit_length(), 8), 1)   # zero still encodes as one byte
    return _b64url(n.to_bytes(length, "big"))


# The response holder
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


# The ACME client
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

    # HTTP + nonce
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

    # JWS
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

    # protocol steps
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


# Issuance
def _obtain_trusted_cert(domain, site):
    """Get a trusted certificate from Let's Encrypt over HTTP-01, using Servette's own
    minimal ACME client (_ACMEClient) on stdlib urllib + cryptography, and store it
    on `site`.

    Returns None on success, else the failure's class for the watchdog's
    backoff: "refused" (the CA answered no — retrying soon just burns its
    rate limits) or "transient" (the network ate a request — retry freely)."""
    from cryptography import x509 as _x509
    from cryptography.x509.oid import NameOID as _NameOID
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _serialization

    ACME_URL         = "https://acme-v02.api.letsencrypt.org/directory"
    ACCOUNT_KEY_FILE = os.path.join(BASE_DIR, ".acme-account.pem")
    CERTS_DIR        = os.path.join(BASE_DIR, "certs", domain)
    challenge_dir    = os.path.join(ACME_WEBROOT, ".well-known", "acme-challenge")

    print(f"\nGetting a trusted SSL certificate for {domain}...")
    print("  Make sure your domain points to this server's IP first.\n")

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

    # start a temporary port-80 listener if the main server isn't running
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
    issued      = None   # (fullchain, key_pem) once Let's Encrypt has signed

    # The retry loop retries exactly one thing: the ACME exchange. Local work
    # — writing files, saving config, reloading — stays outside it, because a
    # local failure (the sandboxed service cannot write the data directory)
    # retried as an exchange failure is a fresh issuance per "retry": three
    # duplicate certificates burned per pass against the 5-per-week duplicate
    # limit, the reload never reached, and the renewed certificate sits on
    # disk while the server serves the old one to expiry.
    # Persistence now happens once, after the loop, and its failures are its
    # own, not the protocol's.
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

                issued     = (fullchain, domain_key_pem)
                last_error = None
                break

            except Exception as e:
                last_error = e
                if isinstance(e, _ACMEError) and include_www and e.failed == {www_domain}:
                    www_dns_only_failure = True
                    break  # don't retry; fall back to bare domain
                if isinstance(e, _ACMEError):
                    # Let's Encrypt ANSWERED, and the answer was no — a failed
                    # authorization, a refused order. Asking the same question
                    # again ten seconds later gets the same no, and each retry
                    # burns a fresh order and a validation attempt against
                    # LE's own rate limits (~5 failed validations per hostname
                    # per hour) while the underlying cause — usually DNS not
                    # yet pointed here — hasn't changed. Retries are for the
                    # network eating a request, not for the CA declining it.
                    break
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

    if tmp_server is not None:
        tmp_server.shutdown()
        tmp_server.server_close()

    if last_error:
        print(f"  Error getting certificate: {last_error}")
        log.error("ACME failed for %s: %s", domain, last_error)
        # The failure's class, for the watchdog's backoff: "refused" is the CA
        # answering no (not retried above either — same reasoning), "transient"
        # is the network eating a request (retried above, hourly hereafter).
        return "refused" if isinstance(last_error, _ACMEError) else "transient"

    _persist_issued_cert(domain, site, CERTS_DIR, issued[0], issued[1],
                         f"{domain} and {www_domain}" if include_www else domain)
    return None


def _persist_issued_cert(domain, site, certs_dir, fullchain, key_pem, issued_names):
    """Store an issued certificate and put it into service: write the pair,
    point the site at it, persist the config where possible, reload.

    Written through temp files and two os.replace calls, so a crash leaves
    either the old pair or the new pair on disk in all but the instant
    between the renames — the old code wrote both files in place, and a kill
    landing between (or during) the writes left a fullchain that did not
    match its privkey, which fails load_cert_chain at the next start and
    restart-loops the whole box over one site's half-written renewal. Two
    files can't be replaced in one atomic step, so a two-rename window
    remains; it is two syscalls wide, down from a network exchange.

    The config save is a no-op skip on renewal (the site already points at
    these exact paths) and best-effort otherwise: the sandboxed service may
    not write the data directory, and a certificate that IS on disk and
    about to be served must not be reported as a failure over a bookkeeping
    write the next root command will repeat anyway."""
    cert_path = os.path.join(certs_dir, "fullchain.pem")
    key_path  = os.path.join(certs_dir, "privkey.pem")

    with open(cert_path + ".tmp", "w") as f:
        f.write(fullchain)
    _write_private_key(key_path + ".tmp", key_pem)
    os.replace(key_path + ".tmp", key_path)
    os.replace(cert_path + ".tmp", cert_path)
    _chown_servette(certs_dir)

    changed = (site.cert_file, site.key_file, site.domain) != (cert_path, key_path, domain)
    site.cert_file = cert_path
    site.key_file  = key_path
    site.domain    = domain
    if changed:
        try:
            config.save()
        except OSError as e:
            log.error("Certificate stored but config not saved (%s) — "
                      "run 'config cert' as root to persist it", e)

    print(f"  Certificate issued for {issued_names}.")
    log.info("ACME certificate issued for %s", issued_names)

    if _server_running() or _service_is_active():
        print("  Reloading server...")
        _reload_server()


# Loading a certificate
def _load_cert(cert_path):
    """Return a cryptography X.509 certificate object, or None on failure."""
    try:
        from cryptography import x509 as _x509
        with open(cert_path, "rb") as f:
            return _x509.load_pem_x509_certificate(f.read())
    except Exception:
        return None


# The domain a certificate names
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


# Days to expiry
def _cert_days_remaining(cert_path):
    cert = _load_cert(cert_path)
    if cert is None:
        return None
    try:
        expiry = cert.not_valid_after_utc
    except AttributeError:
        expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return (expiry - datetime.datetime.now(datetime.timezone.utc)).days


# Service probes
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


def _servette_uid():
    """The servette user's uid, or None when it does not exist."""
    try:
        import pwd as _pwd
        return _pwd.getpwnam("servette").pw_uid
    except (ImportError, KeyError):
        return None


def _servette_gid():
    """The servette group's gid, or None when it does not exist."""
    try:
        import grp as _grp
        return _grp.getgrnam("servette").gr_gid
    except (ImportError, KeyError):
        return None


def _serve_dir_readable(path):
    """Whether the service could plausibly read this serve_dir: world r+x, or
    group r+x where the group actually is servette. The old check demanded
    world bits and told the operator to add them with a+rX — advice that undid
    the deliberate group-only grant _operator_chown_plan had just applied."""
    st = os.stat(path)
    if st.st_mode & 0o005 == 0o005:
        return True
    return st.st_mode & 0o050 == 0o050 and st.st_gid == _servette_gid()


# Ownership: the service user
def _chown_config(path):
    """Give the config to the service user, readable by the operator: owner
    servette, group the operator's own, mode 0640.

    servette.toml is the operator's file about the operator's box, and the
    read-only commands (status, sites, log) read it to report a URL and a
    certificate expiry. Owning it 0600 to the service user made those commands
    elevate on every configured host — a password to look at your own server —
    and left config.unreadable permanently true, so the fail-closed reload
    guard fired during correct operation. A guard that trips in normal use is
    one people learn to ignore.

    The group is the operator's, so the widening is from one system user to
    exactly one more: them. World bits stay off, as they do for site content —
    the file carries a password HASH and salt, which is material for an offline
    attack and never something to hand to every local account.

    Failure must degrade toward the service, not away from it. The chown can
    fail — a SUDO_USER deleted since the sudo, an NSS outage naming a group
    that doesn't resolve — and the file it would leave behind is whatever
    save()'s os.replace installed: root:root, which the service cannot read,
    which kills the per-request reload and makes the next restart refuse to
    serve. So a failed operator chown falls back to servette:servette — the
    operator loses their no-password read until the next enable, the service
    loses nothing, and the site stays up. The chmod runs unconditionally
    (0640 under servette:servette grants read to a user that already had it).

    The service user is a legitimate caller — a deferred config migration on
    a host where it can write — but not one that can grant the operator
    anything: a non-root owner may only chgrp to groups it belongs to, and
    servette belongs only to servette. Its saves therefore leave
    servette:servette 0640, and the operator's group read returns with the
    next root-elevated save or enable, both of which run this function as
    root. save() runs at import on every configured host — check=True
    anywhere here would be the crash _chown_servette already learned to
    avoid."""
    if not (_servette_user_exists() and os.path.exists(path)):
        return
    if os.geteuid() != 0 and os.geteuid() != _servette_uid():
        return
    r = subprocess.run(["chown", f"servette:{_operator_group()}", path],
                       check=False, capture_output=True)
    if r.returncode != 0:
        subprocess.run(["chown", "servette:servette", path],
                       check=False, capture_output=True)
    os.chmod(path, 0o640)


def _operator_group():
    """The operator's own group, for the config's group ownership. Their primary
    group by name; the operator's username where that cannot be resolved, which
    is correct on the user-private-group distributions Servette targets."""
    user = _operator_user()
    try:
        import grp as _grp, pwd as _pwd
        return _grp.getgrgid(_pwd.getpwnam(user).pw_gid).gr_name
    except (ImportError, KeyError):
        return user


def _chown_servette(path):
    """Chown path to servette:servette if the user exists and the path exists."""
    if not (_servette_user_exists() and os.path.exists(path)):
        return
    # Only root and the service user itself may actually run this: root gives
    # the file away, and the service user's own call is a permitted same-owner
    # no-op (renewal re-chowns what it already owns). Any other caller is an
    # unprivileged session or dev context where chown cannot succeed — found
    # when a non-root save() crashed the whole program at Config() import,
    # because check=True turned "cannot give files away" into a fatal error on
    # any host where the servette user exists. Best-effort even for the
    # permitted callers: the service's renewal runs this over the ACME webroot
    # and the certs tree, and one stray root-owned file in either (an
    # interrupted root issuance's leftover token) would otherwise turn every
    # future renewal into a CalledProcessError before Let's Encrypt was even
    # contacted, hourly, until the certificate expired.
    if os.geteuid() != 0 and os.geteuid() != _servette_uid():
        return
    subprocess.run(["chown", "-R", "servette:servette", path],
                   check=False, capture_output=True)


# Ownership: the operator
def _operator_user():
    """The human behind sudo: SUDO_USER when present, else the current user."""
    return os.environ.get("SUDO_USER") or getpass.getuser()


def _operator_chown_plan(path, strip_world=False):
    """The chown/chmod invocations _chown_operator runs, as argv lists —
    separated from the running so the decision is testable without root.
    Owner is the human behind sudo; group is `servette` with g+rX, which is
    all the read-only serving path needs, granted to exactly one system user
    instead of the world — a .env or .git a deploy drags in is never flipped
    world-readable on the filesystem (the request path already refuses to
    serve dotfiles; this keeps other local accounts out too). Explicit
    `:servette` rather than the operator's own group, which need not exist
    on hosts without user-private groups. Before the service user exists
    (setup before enable, macOS session mode) ownership alone is set;
    enable re-runs this once the user exists.

    strip_world removes world bits as well. For a tree the OPERATOR filled,
    modes are theirs and only the group grant is added — but a tree Servette
    itself wrote (a pulled bundle, extracted at 644/755) must also honour the
    promise above, and leaving extraction's world bits in place would be this
    program handing every local account what it deliberately scopes to one."""
    user = _operator_user()
    if _servette_user_exists():
        return [["chown", "-R", f"{user}:servette", path],
                ["chmod", "-R", "g+rX,o-rwx" if strip_world else "g+rX", path]]
    return [["chown", "-R", user, path]]


def _chown_operator(path, strip_world=False):
    """Apply _operator_chown_plan. Best-effort: a host without chown
    semantics (macOS session mode) serves fine without it."""
    if os.path.exists(path):
        for argv in _operator_chown_plan(path, strip_world):
            subprocess.run(argv, check=False, capture_output=True)


# The systemd unit
def _systemd_unit(python_path, module_path):
    """The systemd unit for the service. Writes are confined to where Servette
    actually writes — the data directory (config, certs, ACME account) and the ACME
    webroot (HTTP-01 challenge files during renewal); ProtectSystem=strict makes the
    rest of the filesystem read-only, and the unit runs as a least-privilege user
    holding only CAP_NET_BIND_SERVICE. The served directory ends up read-write only
    because it lives under the data directory; the server never writes it.
    The module is pinned read-only on top: normally the code lives outside
    the data directory and strict mode already covers it, but two deployments
    put the code inside the writable tree — a checkout (SERVETTE_HOME=.) and
    the runtime copy made when the service user cannot read where Servette is
    installed — and the pin holds for both, so a compromised serving process
    cannot patch the program systemd will restart it into. PYTHONPATH names the
    module's directory ONLY when it sits outside the interpreter's own
    site-packages (a checkout, or that same runtime copy) — a pip-installed
    module the service can reach resolves without it, and an unconditional
    PYTHONPATH would put a path entry ahead of the stdlib for no benefit,
    widening what a write anywhere on that entry could shadow.

    The remaining restrictions cost the service nothing it uses: no devices
    beyond the private stubs, no clock/hostname changes, no kernel log reads,
    no other processes' /proc entries, no realtime scheduling, no namespaces,
    one syscall architecture. PYTHONDONTWRITEBYTECODE stops the interpreter
    attempting __pycache__ writes into the read-only pin. Deliberately absent,
    pending validation on real hardware: MemoryDenyWriteExecute and
    SystemCallFilter (cffi loads a compiled extension), ProtectHome (breaks an
    install that IS reachable under /home), and UMask=0077 (a renewed
    certificate would become unreadable to the unelevated status command).

    The leading version stamp is load-bearing, not decoration: a pip upgrade
    changes no directive, so without the stamp an upgraded host's units would
    never read as stale and the running service would keep the old code. With
    it, any upgrade drifts every unit's text and the startup refresh restarts
    the service onto the version the shell is running."""
    parent = os.path.dirname(module_path)
    pythonpath = ("" if os.path.basename(parent) in ("site-packages", "dist-packages")
                  else f"Environment=PYTHONPATH={parent}\n")
    # For the runtime copy the pin covers the whole of it: the copied
    # dependencies and the PYTHONPATH root are exactly as much "the program
    # systemd will restart the service into" as the module beside them, and a
    # pin on the module alone would leave them outside it.
    readonly = parent if parent == RUNTIME_DIR else module_path
    return f"""# generated by servette {__version__}
[Unit]
Description=Servette — The Simple Secure Server
After=network.target

[Service]
User=servette
Environment=SERVETTE_HOME={BASE_DIR}
Environment=PYTHONDONTWRITEBYTECODE=1
{pythonpath}AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={BASE_DIR} {ACME_WEBROOT}
ReadOnlyPaths={readonly}
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
PrivateDevices=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectProc=invisible
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
ExecStart={python_path} -m servette --serve
Restart=always
RestartSec=3
StandardInput=null
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""


# The network watchdog units
def _netwatch_units():
    """The (service, timer) unit pair for the network watchdog.

    Every minute: if the host has no route out, ask the network manager to
    start over. Recovers the observed failure where a netlink timeout leaves the
    link permanently 'Failed' — networkd never retries on its own, so the host
    stays dark until reboot. try-restart only touches a unit that is actually
    running, so of the three known managers (systemd-networkd on Ubuntu,
    NetworkManager on Raspberry Pi OS, dhcpcd on older Pi OS) exactly one acts;
    the whole check is a no-op while the route is healthy.

    One minute rather than the original five because the check costs nothing
    to run often: despite appearances, `ip route get` sends no packets — it
    asks the local routing table which route it WOULD use — so the interval
    buys only recovery time, and the route drill measured the cost of five
    (dark until the next firing, ~5 minutes; now ~1). One minute is also
    systemd's default timer accuracy, so a shorter interval would be fiction.

    A run that acts says so via logger. Without that line the run that saved
    the host logged exactly like the hundred no-ops around it — the route
    drill's journal could not show WHAT recovered the box, which is below the
    project's own evidence bar."""
    service = f"""# generated by servette {__version__}
[Unit]
Description=Servette network watchdog — recover a dropped default route

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'ip route get 1.1.1.1 >/dev/null 2>&1 && exit 0; logger -t servette-netwatch "default route missing — restarting the network manager"; for u in systemd-networkd NetworkManager dhcpcd; do systemctl try-restart "$u.service" 2>/dev/null || true; done'
"""
    timer = f"""# generated by servette {__version__}
[Unit]
Description=Run the Servette network watchdog every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
"""
    return service, timer


# Reading /proc/meminfo
_SWAP_PATH = "/swapfile"


def _meminfo():
    """Return (mem_total_kb, mem_available_kb, committed_kb) from /proc/meminfo,
    or (None, None, None) where it can't be read (non-Linux).

    Committed_AS is the kernel's own answer to the question the swap sizing
    asks: how much memory this host would need if every allocation it has
    handed out were actually used. MemAvailable comes along for the prompt,
    which reports free memory to the operator, not for the arithmetic.
    SwapTotal is deliberately absent — it lumps every swap device together,
    and the sizes that matter come per-device from _swap_sizes."""
    try:
        fields = {}
        with open("/proc/meminfo") as f:
            for line in f:
                key, _, rest = line.partition(":")
                fields[key.strip()] = int(rest.split()[0])  # values are in kB
        return fields["MemTotal"], fields["MemAvailable"], fields["Committed_AS"]
    except (OSError, KeyError, ValueError, IndexError):
        return None, None, None


# The unpredictable part of demand: an allowance for the single-process spike
# nobody plans for, sized to the largest one observed in production (fwupd
# ballooning to ~656 MB virtual on a 414 MB host, hourly, for weeks).
# The swap bounds
_SPIKE_ALLOWANCE_KB = 700 * 1024
_SWAP_MIN_MB        = 512
_SWAP_MAX_MB        = 2048
_SWAP_SLACK_MB      = 8


# Ceiling division
def _ceil_div(a, b):
    """Integer division of a by b, rounding up instead of down."""
    quotient, remainder = divmod(a, b)
    return quotient + 1 if remainder else quotient


# Rounding an estimate
def _round_up_2sig(n):
    """Round a positive integer up to two significant digits (1148 → 1200).

    The swap default is an estimate; a round number says so, where an
    exact-looking one would overstate its precision."""
    mag = 10 ** max(len(str(int(n))) - 2, 0)
    return _ceil_div(int(n), mag) * mag


# The cache's share of demand
def _cache_headroom_mb(cache_mb):
    """How much of the configured file cache is NOT already in Committed_AS.

    The cache holds file bytes on the Python heap, so a warm cache is
    anonymous memory the kernel has already committed — measured: 200 MB of
    cached files raised Committed_AS by 201 MB. Adding the configured ceiling
    on top of that counts the same megabytes twice, and the doubling below
    turns a 128 MB default into 256 MB of swap this host does not need.

    So the ceiling is charged only where no live process is holding it yet: a
    host being set up or enabled with nothing serving. Where a server IS
    running, whatever its cache has taken is in the signal already and its
    unfilled remainder is charged to nobody — deliberately, because that
    keeps the two callers ordered. The offer (service down, ceiling charged)
    can only ever be larger than the later status check (service up, ceiling
    in the signal), so a host that accepts the offer is never afterwards told
    to resize. The old formula had this backwards: the cache entered the
    measurement between setup and status, so the check drifted upward past
    the size the operator had just chosen, and nagged forever."""
    return 0 if (_server_running() or _service_is_active()) else cache_mb


# The recommendation
def _swap_recommendation(mem_kb, committed_kb, cache_headroom_mb):
    """Recommended total swap in bytes for this host, or None when demand fits in RAM.

    Supply is measured (MemTotal). Demand is Committed_AS — the kernel's own
    worst case, what this host needs if every allocation it has handed out is
    actually used — plus the cache ceiling not yet inside it
    (_cache_headroom_mb), plus the spike allowance. When demand exceeds
    supply, the deficit is doubled for margin, rounded up to two significant
    digits, floored at 512 MB and capped at 2 GB, so the threshold emerges
    from the measurement rather than a hardcoded RAM ceiling. Whether to act
    on the recommendation is _swap_offer's decision.

    Committed_AS rather than resident usage (MemTotal − MemAvailable), for
    two reasons found by measuring both: it is what swap actually backs
    (commitments are anonymous; page cache is written back to its own file
    and never swapped), and it holds still — sampled every two seconds for
    thirty, resident usage wandered 9 MB while Committed_AS did not move at
    all. Nine megabytes is nothing until the doubling and the two-significant
    -digit rounding turn it into a 100 MB step, which is how a host that had
    just taken the recommended size came to be told to resize. The honest
    cost of the swap: Committed_AS counts address space that may never be
    touched, so a process that reserves generously and writes little makes
    this estimate high. Recommending too much swap wastes disk; recommending
    too little loses the host."""
    if mem_kb is None or committed_kb is None:
        return None
    demand_kb  = committed_kb + cache_headroom_mb * 1024 + _SPIKE_ALLOWANCE_KB
    deficit_kb = demand_kb - mem_kb
    if deficit_kb <= 0:
        return None
    size_mb = _round_up_2sig(_ceil_div(2 * deficit_kb, 1024))
    return min(max(size_mb, _SWAP_MIN_MB), _SWAP_MAX_MB) * 1024 ** 2


def _swap_sizes():
    """(ours_mb, foreign_mb) of ACTIVE swap, from /proc/swaps: the size of
    Servette's own swapfile when active (else None), and the total of every
    other active swap device. SwapTotal from /proc/meminfo lumps them
    together, and using it as "the swapfile's size" printed a wrong number
    whenever a partition coexisted — and let a resize conclude 'nothing to
    do' because partition + file happened to sum near the request. (None, 0)
    where /proc/swaps can't be read (non-Linux)."""
    ours, foreign = None, 0
    try:
        with open("/proc/swaps") as f:
            next(f, None)  # the header line
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                if parts[0] == _SWAP_PATH:
                    ours = int(parts[2]) // 1024
                else:
                    foreign += int(parts[2]) // 1024
    except (OSError, ValueError):
        pass
    return ours, foreign


def _swap_offer(rec_mb, ours, ours_mb, foreign_mb):
    """(description, skip_hint) for the swap prompt, or None when no offer is due.
    `ours` is whether /swapfile exists on disk; `ours_mb` its active size (None
    when inactive); `foreign_mb` every other active swap device's total.

    Only Servette's own /swapfile is ever offered a resize; swap Servette didn't
    create (a partition, a distro-managed file) is left alone — resizing it would
    fight whatever manages it, and its presence also suppresses the create offer,
    since the host's swap is already someone else's decision. Enter always takes
    the recommendation; the skip hint says what declining preserves, so no two
    options in the prompt are redundant.

    A swapfile within _SWAP_SLACK_MB of the recommendation counts as meeting it,
    so a host that took the offer is not asked again for the megabyte mkswap
    spends on its header."""
    if rec_mb is None:
        return None
    if not ours:
        return None if foreign_mb else ("no swapfile", "skip")
    if not ours_mb:
        return "an inactive swapfile", "skip"
    if ours_mb >= rec_mb - _SWAP_SLACK_MB:
        return None
    return f"a {ours_mb} MB swapfile", f"keep {ours_mb}"


# The flash-wear note
def _root_on_sd_card():
    """True when the root filesystem sits on an SD/eMMC device (/dev/mmcblk*),
    where swap writes add flash wear worth mentioning before the operator decides."""
    try:
        dev = os.stat("/").st_dev
        with open(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}/uevent") as f:
            return "DEVNAME=mmcblk" in f.read()
    except OSError:
        return False


# Making the swapfile
def _make_swapfile(size):
    """Allocate, format, and activate /swapfile at `size` bytes; raises on any
    failure. Mode 0600 is set before content exists — never world-readable."""
    with open(_SWAP_PATH, "wb") as f:
        os.chmod(_SWAP_PATH, 0o600)
        os.posix_fallocate(f.fileno(), 0, size)
    subprocess.run(["mkswap", _SWAP_PATH], check=True, capture_output=True)
    subprocess.run(["swapon", _SWAP_PATH], check=True, capture_output=True)


# The swap offer
def _ensure_swap():
    """Offer to create — or grow — Servette's swapfile where demand can outrun RAM."""
    if _IS_MACOS:
        return  # macOS manages its own swap; mkswap/swapon/fallocate do not exist there
    mem_kb, avail_kb, committed_kb = _meminfo()
    rec       = _swap_recommendation(mem_kb, committed_kb,
                                     _cache_headroom_mb(config.cache_size_mb))
    rec_mb    = rec // (1024 * 1024) if rec else None
    ours      = os.path.exists(_SWAP_PATH)
    ours_mb, foreign_mb = _swap_sizes()
    active_mb = ours_mb or 0            # OUR file's active size, not the host total
    offer     = _swap_offer(rec_mb, ours, ours_mb, foreign_mb)
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
    err = _apply_swapfile(mb)
    if err:
        print(f"  {err}")
    else:
        print(f"  Swapfile active ({mb} MB), persistent across reboots.")


def _apply_swapfile(mb):
    """Create or resize Servette's swapfile to `mb` MB — the mechanical half
    of the swap offer, shared by the terminal's prompt and the admin page's
    field so the two cannot drift. Returns an error sentence, empty on
    success (including the no-op where the size asked for is already
    active). Never raises: every failure path ends in a sentence."""
    if _IS_MACOS:
        return "macOS manages its own swap"
    ours              = os.path.exists(_SWAP_PATH)
    ours_mb, _foreign = _swap_sizes()
    active_mb         = ours_mb or 0
    if ours and abs(mb - active_mb) <= _SWAP_SLACK_MB:
        return ""  # the size asked for is the size already active
    size = mb * 1024 * 1024
    try:
        st        = os.statvfs("/")
        reclaimed = os.path.getsize(_SWAP_PATH) if ours else 0
        if st.f_bavail * st.f_frsize + reclaimed < size + 1024 ** 3:  # keep 1 GB free
            return f"Not enough free disk for a {mb} MB swapfile plus 1 GB margin."
    except OSError as e:
        return f"Could not read free disk space ({e})."
    if ours and active_mb > 0:
        r = subprocess.run(["swapoff", _SWAP_PATH], capture_output=True)
        if r.returncode != 0:
            return "Could not deactivate the current swapfile (heavily in use?) — try again later."
    try:
        _make_swapfile(size)
        with open("/etc/fstab") as f:
            fstab = f.read()
        if _SWAP_PATH not in fstab.split():
            with open("/etc/fstab", "a") as f:
                f.write(f"{_SWAP_PATH} none swap sw 0 0" + chr(10))
        log.info("Swapfile active: %d MB at %s", mb, _SWAP_PATH)
        return ""
    except (OSError, subprocess.CalledProcessError) as e:
        # A failed RESIZE has already truncated the old file, so try to give
        # the host back the swap it walked in with — a memory-tight host that
        # accepted a grow offer must not end up worse than it started. Swap
        # content is scratch (it was swapoff'd above), so rebuilding at the
        # old size restores the prior state in full.
        if ours and active_mb > 0:
            try:
                _make_swapfile(active_mb * 1024 * 1024)
                return f"Could not set up the swapfile ({e}) — restored the previous {active_mb} MB."
            except (OSError, subprocess.CalledProcessError):
                pass
        # Nothing to restore (or the restore failed): remove the dead file AND
        # its fstab line — a line pointing at a missing or unformatted file is
        # a failed swap unit at every boot from here on.
        try:
            subprocess.run(["swapoff", _SWAP_PATH], capture_output=True)
            os.remove(_SWAP_PATH)
        except OSError:
            pass
        try:
            with open("/etc/fstab") as f:
                lines = f.readlines()
            kept = [l for l in lines if _SWAP_PATH not in l.split()]
            if kept != lines:
                with open("/etc/fstab", "w") as f:
                    f.writelines(kept)
        except OSError:
            pass
        return f"Could not set up the swapfile ({e})."


# The service runtime
# Where the program is copied when the service user cannot reach where it is
# installed. Under the data directory, so it is covered by the same backup and
# the same removal as everything else Servette owns.
RUNTIME_DIR = os.path.join(BASE_DIR, "runtime")

# The program's own distribution name, for telling it apart from its
# dependencies. A literal, not derived from __name__: under `python -m
# servette` — which is exactly how the unit's ExecStart runs — a single-file
# module executes as __main__, and deriving the name from that would make the
# service look up the metadata of a distribution called __main__.
_SELF = "servette"

# What the program is written against, for the one case where installed metadata
# cannot say: a checkout, which has no dist-info of its own to read. It must
# match pyproject.toml's dependencies exactly, and the suite checks that it does
# — a dependency added there and not here would give a service whose runtime
# copy is missing a module.
_DECLARED_DEPENDENCIES = ("cryptography",)


def _reachable_by_service(path):
    """Whether the unprivileged servette user could read path.

    It owns nothing and belongs to no group but its own, so the question is
    only about the world bits: execute on every directory along the way, read
    on the file itself. Conservative by construction — a false 'no' costs a
    copy into the data directory, while a false 'yes' costs a service that
    cannot start, which is the failure this exists to prevent."""
    path = os.path.abspath(path)
    try:
        if not os.stat(path).st_mode & 0o004:      # world-readable leaf
            return False
        while True:
            parent = os.path.dirname(path)
            if parent == path:                     # reached the root
                return True
            if not os.stat(parent).st_mode & 0o001:   # world-traversable
                return False
            path = parent
    except OSError:
        return False


def _installed_runtime_reachable():
    """Whether the service could run the program exactly where it is installed.
    Both halves must hold: the interpreter systemd would exec, and the module
    file it would import."""
    return (_reachable_by_service(sys.executable)
            and _reachable_by_service(os.path.abspath(__file__)))


_python_minor_cache = {}


def _python_minor(path):
    """The 'major.minor' an interpreter reports, or None if it cannot be run.

    Cached per path: an interpreter's version cannot change within one process
    run, and the staleness chain asks several times per shell launch — without
    the cache, a host on the runtime copy re-spawned every candidate
    interpreter each time."""
    if path not in _python_minor_cache:
        try:
            out = subprocess.run(
                [path, "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
                capture_output=True, text=True, timeout=10)
            _python_minor_cache[path] = (out.stdout.strip()
                                         if out.returncode == 0 else None)
        except (OSError, subprocess.SubprocessError):
            _python_minor_cache[path] = None
    return _python_minor_cache[path]


def _system_python():
    """A reachable interpreter of the same minor version as this one, or None.

    Same minor version is not a preference: cryptography ships a compiled
    extension built against one ABI, and the runtime copy carries that build.
    An interpreter that cannot load it would give a service that starts and
    then fails on the first certificate operation, so no match is a refusal
    rather than a best effort."""
    want = "%d.%d" % sys.version_info[:2]
    seen = set()
    for cand in (getattr(sys, "_base_executable", None),
                 f"/usr/bin/python{want}",
                 f"/usr/local/bin/python{want}",
                 "/usr/bin/python3"):
        if not cand or cand in seen:
            continue
        seen.add(cand)
        if os.path.isfile(cand) and _reachable_by_service(cand) \
                and _python_minor(cand) == want:
            return cand
    return None


def _required_distributions():
    """Every distribution the program needs at run time, transitively.

    Read from installed metadata rather than a list kept here, because a
    dependency's own dependencies are not this program's to remember:
    cryptography declares cffi, cffi declares pycparser, and cffi's compiled
    backend is a bare .so beside the packages. A list would have named
    cryptography and stopped.

    Two exclusions. Requirements guarded by an extra are for building or
    testing a dependency, not running it. Requirements that are not installed
    were excluded by their own environment markers when pip resolved them —
    pip has already evaluated those, so absence is the answer.

    A checkout has no dist-info of its own, so there the walk starts from what
    the program is written against instead; every dependency of THAT still comes
    from metadata, which is where the transitive ones live."""
    try:
        importlib.metadata.distribution(_SELF)
        want = [_SELF]
    except importlib.metadata.PackageNotFoundError:
        want = list(_DECLARED_DEPENDENCIES)
    seen, out = set(), []
    while want:
        name = want.pop(0)
        key = re.sub(r"[-_.]+", "-", name).lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            reqs = importlib.metadata.distribution(name).requires or []
        except importlib.metadata.PackageNotFoundError:
            continue        # not installed: a marker ruled it out, or a checkout
        if name != _SELF:
            out.append(name)
        for req in reqs:
            if "extra ==" in req:
                continue
            # maxsplit spelled as a keyword: Python 3.13 deprecated the
            # positional form, and `python -m servette` runs this module as
            # __main__, where deprecation warnings print to the operator.
            dep = re.split(r"[<>=!~;\[\s(]", req, maxsplit=1)[0].strip()
            if dep:
                want.append(dep)
    return out


def _distribution_paths(name):
    """Where a distribution's importable top-level names live on disk.

    top_level.txt when the wheel carries one — that is what names cffi's
    _cffi_backend.so, which no package directory would reveal — and the
    normalized distribution name when it does not, which is the modern wheel's
    case. find_spec resolves each without importing it, so locating a
    dependency never runs its module-level code."""
    try:
        dist = importlib.metadata.distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return []
    tops = (dist.read_text("top_level.txt") or "").split() \
        or [re.sub(r"[-.]+", "_", name)]
    paths = []
    for top in tops:
        try:
            spec = importlib.util.find_spec(top)
        except (ImportError, ValueError):
            continue
        if spec is None:
            continue
        locations = getattr(spec, "submodule_search_locations", None)
        if locations:
            paths.append(locations[0])          # a package directory
        elif spec.origin and os.path.isfile(spec.origin):
            paths.append(spec.origin)           # a single module, .py or .so
    return paths


def _runtime_sources():
    """Every path the runtime copy must contain: the program — one module
    file — then each top-level name of each distribution it requires."""
    paths = [os.path.abspath(__file__)]
    for name in _required_distributions():
        paths.extend(_distribution_paths(name))
    return paths


def _build_runtime():
    """Copy the program and everything it imports into a staging tree beside
    the live runtime, and return its path. Building and committing are split
    so verification can run between them: the staged copy is proved usable by
    the service user before anything the service depends on is touched.

    Root-owned, world-readable, writable by nobody but root — the service reads
    it and the unit pins it ReadOnlyPaths on top, so a compromised serving
    process cannot patch the program systemd will restart it into."""
    new = RUNTIME_DIR + ".new"
    shutil.rmtree(new, ignore_errors=True)
    os.makedirs(new)
    for src in _runtime_sources():
        dest = os.path.join(new, os.path.basename(src))
        if os.path.isdir(src):
            shutil.copytree(src, dest)
        else:
            shutil.copy2(src, dest)

    for root, _dirs, files in os.walk(new):
        os.chmod(root, 0o755)
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)
    os.chmod(new, 0o755)
    return new


def _commit_runtime(new):
    """Swap a verified staging tree into place as the live runtime.

    Called only after _verify_runtime has passed against the staged copy —
    the old code swapped first and verified after, so a refused runtime was
    already installed when the refusal printed, the known-good copy already
    destroyed, and the next restart (reboot, certificate rotation) landed the
    service on the very thing verification rejected. The swap is two renames,
    so a lazy import landing exactly between them would fail — the service is
    restarted onto this runtime immediately afterwards, which is the same
    moment it would have picked up the new code anyway."""
    old = RUNTIME_DIR + ".old"
    shutil.rmtree(old, ignore_errors=True)
    if os.path.exists(RUNTIME_DIR):
        os.replace(RUNTIME_DIR, old)
    os.replace(new, RUNTIME_DIR)
    shutil.rmtree(old, ignore_errors=True)


def _verify_runtime(python_path, module_path):
    """Run the program the way the unit will, as the user the unit will use.
    None when it works, else what went wrong, in the child's own words.

    This is the check that makes the rest of this section safe to trust. Every
    part of it is inference — which paths the service user can read, which
    distributions are required, which interpreter matches the compiled
    extension — and inference about another user's view of the filesystem is
    exactly the kind of thing that is wrong quietly. So before a unit is
    written, the conclusion is executed: import the program and the certificate
    machinery, from the paths the unit names, as `servette`. A host where that
    fails is a host that would have restart-looped after the next reboot.

    Falls back to running as this user when nothing can drop privileges, which
    still proves the imports resolve; the path permissions are then covered
    only by _reachable_by_service."""
    parent = os.path.dirname(module_path)
    # SERVETTE_HOME matches what the unit will carry: importing servette loads
    # the config, and without this the probe reads the DEFAULT data directory —
    # judging the service against a config it will never see.
    env = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
           "SERVETTE_HOME": BASE_DIR}
    if os.path.basename(parent) not in ("site-packages", "dist-packages"):
        env["PYTHONPATH"] = parent
    probe = [python_path, "-c", "import servette, cryptography.x509"]
    quoted = " ".join(shlex.quote(a) for a in probe)
    # As the service user by whichever means the host has, unprivileged last so a
    # host with neither still gets the import checked. Each dropper is named by
    # absolute path: they live in /usr/sbin, which the probe's own minimal PATH
    # does not carry, and a PATH miss would read as the runtime being broken.
    # No dropper is tried at all without root — runuser and su cannot drop
    # privilege the process does not hold, and their refusals ("may not be used
    # by non-root users") would be reported as the runtime's problem.
    candidates = []
    if os.geteuid() == 0:
        for tool, argv in (("runuser", ["-u", "servette", "--"] + probe),
                           ("su", ["-s", "/bin/sh", "servette", "-c", quoted])):
            found = shutil.which(tool) or shutil.which(tool, path="/usr/sbin:/sbin:/bin:/usr/bin")
            if found:
                candidates.append([found] + argv)
    candidates.append(probe)

    last = "could not run the program as the servette user"
    for argv in candidates:
        try:
            r = subprocess.run(argv, env=env, cwd="/", capture_output=True,
                               text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            last = str(e)
            continue          # this way of dropping privilege is unavailable
        if r.returncode == 0:
            return None
        err = (r.stderr or r.stdout).strip().splitlines()
        if not err:
            last = f"exited {r.returncode} without saying why"
            continue
        # A tool that cannot become the service user is this method failing, not
        # the runtime failing — fall through and try the next one.
        if any(t in err[-1] for t in ("user servette", "unknown user", "may not run",
                                      "Authentication", "must be run from a terminal")):
            last = err[-1]
            continue
        return err[-1]
    return last


# The unit interpreter
def _unit_python_path():
    """The interpreter the unit's ExecStart names: normally the one running
    this shell. Under a pip/venv install that is the environment's own python,
    and the service must use the same one to see the same installed packages.
    Shared by the writer and the drift check — two computations of this path
    could disagree and manufacture phantom drift.

    Where the service user cannot reach that interpreter, the shell's own
    cannot be named at all and a same-version system one stands in, against the
    runtime copy. None means there is none to stand in, which refuses the
    write."""
    if _installed_runtime_reachable():
        return sys.executable
    return _system_python()


def _unit_module_path():
    """The module file the unit imports the program from, and pins read-only:
    where it is installed when the service can read that, otherwise the copy in
    the data directory."""
    here = os.path.abspath(__file__)
    return here if _installed_runtime_reachable() else os.path.join(RUNTIME_DIR, "servette.py")


# A systemd directive value splits on whitespace, so a path carrying any would
# silently become two wrong grants — and a newline would inject an arbitrary
# directive into the sandbox definition. Servette refuses to write units for
# such a path rather than encode it wrongly.
# The whitespace refusal
def _unsafe_unit_path():
    """The first unit-embedded path (data dir, module file, interpreter)
    carrying whitespace, or None. systemd directive values split on whitespace,
    so such a path would silently become two wrong grants — and a newline would
    inject an arbitrary directive into the sandbox definition. Servette
    refuses to write units for one rather than encode it wrongly. The
    interpreter is in scope because ExecStart names it, and it is the one of
    the three that can sit under a home directory the operator named."""
    for p in (BASE_DIR, _unit_module_path(), _unit_python_path()):
        if p and re.search(r"\s", p):
            return p
    return None


# The desired units
def _desired_units():
    """What every unit file should contain, as {path: text}, computed from
    this version of the code."""
    netwatch_service, netwatch_timer = _netwatch_units()
    return {
        SERVICE_PATH:               _systemd_unit(_unit_python_path(),
                                                    _unit_module_path()),
        NETWATCH_PATH + ".service": netwatch_service,
        NETWATCH_PATH + ".timer":   netwatch_timer,
    }


def _stale_units():
    """Unit files that differ from what this version would write — including
    ones missing entirely, so a release that adds a unit flags as stale on
    hosts enabled before it existed. Empty when the service isn't installed
    at all: nothing to refresh on a session-only host."""
    if not _service_file_exists() or _unsafe_unit_path() \
            or _unit_python_path() is None:
        return []   # no units to manage — or units this environment must not write
    stale = []
    for path, text in _desired_units().items():
        try:
            with open(path) as f:
                current = f.read()
        except OSError:
            current = None
        if current != text:
            stale.append(path)
    return stale


# The environment-drift gate
def _service_env_drift():
    """Ways the enabled unit's environment differs from this shell's, as
    human-readable strings; empty when they agree or no unit exists. A stale
    unit is only auto-refreshed when this is empty: text drift with matching
    environment means a version or shape change (safe to adopt silently),
    while a different data directory or interpreter means the operator
    launched from an environment the service was never enabled from — a
    silent rewrite would repoint a live site's data or crash-loop it onto
    another interpreter, so that adoption belongs to an explicit 'enable'.
    A unit with no SERVETTE_HOME line predates the data directory and is
    treated as drift for the same reason: migration is a decision."""
    try:
        with open(SERVICE_PATH) as f:
            text = f.read()
    except OSError:
        return []
    drift = []
    m = re.search(r"^Environment=SERVETTE_HOME=(.*)$", text, re.M)
    if m is None:
        drift.append("the service unit predates the data directory")
    elif m.group(1) != BASE_DIR:
        drift.append(f"data directory: service uses {m.group(1)}, this shell uses {BASE_DIR}")
    m = re.search(r"^ExecStart=(\S+)", text, re.M)
    wanted = _unit_python_path()
    # None is not drift: this environment cannot name an interpreter the service
    # could reach, so it has nothing to compare — the refusal belongs to the
    # writer, which says so in words.
    if m and wanted and m.group(1) != wanted:
        drift.append(f"interpreter: service uses {m.group(1)}, this shell runs {wanted}")
    # A pinned interpreter an OS upgrade removed is worse than drift — the
    # service is not merely stale, it cannot START: systemd retries 203/EXEC
    # every few seconds without ever parking in 'failed' where monitoring
    # would notice, and the journal is the only symptom. Say what is actually
    # wrong, not just that the environments differ.
    if m and not os.path.exists(m.group(1)):
        drift.append(f"service interpreter {m.group(1)} no longer exists "
                     "(removed by an OS upgrade?) — the service cannot start "
                     "until 'enable' re-provisions it")
    return drift


# Writing the units
def _write_unit_files():
    """Write (or refresh) the systemd unit, the network watchdog unit pair, and
    the file ownership they depend on. Returns True if a service file already
    existed (a refresh) or False if this is a fresh enable. Contains no prompts,
    so it is safe to call silently — shared by cmd_enable (interactive) and
    the post-update path (silent), so a release that changes what the unit
    should contain reaches an already-enabled host without a separate manual
    'enable'."""
    bad = _unsafe_unit_path()
    if bad:
        print(f"  Error: {bad!r} contains whitespace — a systemd unit cannot")
        print("  carry such a path safely. Use a whitespace-free data directory")
        print("  and install path.")
        raise ValueError("unit path contains whitespace")

    # Root, checked before anything is touched. Everything below mutates the
    # host — the runtime swap included — and an unprivileged caller (the
    # startup refresh in a checkout the operator owns) would otherwise get
    # exactly as far as its permissions allow: swapping the runtime copy,
    # then failing at the unit write — a version-skewed, operator-owned
    # runtime behind a unit that still describes the old one.
    # macOS is exempt: there is no systemd to write for, and the
    # FileNotFoundError from the tools below is the message that says so.
    if not _IS_MACOS and os.geteuid() != 0:
        raise PermissionError("writing unit files requires root")

    updating = _service_file_exists()

    if not _servette_user_exists():
        subprocess.run(
            ["useradd", "--system", "--no-create-home", "--shell", "/sbin/nologin", "servette"],
            check=True
        )
        print("  Created system user 'servette'.")

    # The runtime is settled before the unit texts, which name what it decides —
    # and proved before it replaces anything, so a copy the service could not
    # import is discarded with the known-good runtime still in place, rather
    # than installed for the next reboot to discover.
    if _installed_runtime_reachable():
        # Nothing to copy — and a copy left by an earlier install the service
        # could not reach would now be a second, stale program on the host.
        shutil.rmtree(RUNTIME_DIR, ignore_errors=True)
    else:
        if _unit_python_path() is None:
            want = "%d.%d" % sys.version_info[:2]
            print("  Error: Servette is installed where the service user cannot read")
            print(f"  it, and no Python {want} was found outside it to run a copy with.")
            print(f"  Install Servette for a Python this system also has outside your")
            print("  home directory, or into a virtual environment under /opt.")
            raise ValueError("no reachable interpreter for the service")
        print(f"  Copying Servette to {RUNTIME_DIR} — the service user cannot read")
        print("  where it is installed.")
        staged  = _build_runtime()
        problem = _verify_runtime(_unit_python_path(),
                                  os.path.join(staged, "servette.py"))
        if problem:
            shutil.rmtree(staged, ignore_errors=True)
            print("  Error: the service user cannot run the copied Servette:")
            print(f"    {problem}")
            print("  Refusing to install it. The existing runtime and service are unchanged.")
            raise ValueError(f"runtime unusable by the service user: {problem}")
        _commit_runtime(staged)

    problem = _verify_runtime(_unit_python_path(), _unit_module_path())
    if problem:
        print("  Error: the service user cannot run Servette from")
        print(f"  {_unit_module_path()}:")
        print(f"    {problem}")
        print("  Refusing to install a service that would fail to start. ")
        raise ValueError(f"runtime unusable by the service user: {problem}")

    # one computation of the unit texts, shared with the staleness check
    for path, text in _desired_units().items():
        with open(path, "w") as f:
            f.write(text)

    subprocess.run(["systemctl", "daemon-reload"],      check=True)
    subprocess.run(["systemctl", "enable", "servette"], check=True, capture_output=True)
    subprocess.run(["systemctl", "enable", "--now", "servette-netwatch.timer"],
                   check=True, capture_output=True)

    # chown files the service process needs to read, across every site
    _chown_config(config.CONFIG_FILE)
    for site in config.sites:
        if site.cert_file:
            _chown_servette(_resolve(site.cert_file))
        if site.key_file:
            _chown_servette(_resolve(site.key_file))
        _chown_operator(_resolve(site.serve_dir))
    _chown_servette(os.path.join(BASE_DIR, "certs"))
    _chown_servette(os.path.join(BASE_DIR, ".acme-account.pem"))
    # Create the ACME webroot now so it exists when systemd applies ReadWritePaths
    # — a missing ReadWritePaths target makes the unit fail to start.
    os.makedirs(ACME_WEBROOT, exist_ok=True)
    _chown_servette(ACME_WEBROOT)

    # warn if any site's serve_dir isn't readable by the service — through its
    # group, or world bits the operator chose themselves
    for site in config.sites:
        if not site.serve_dir:
            continue
        serve_path = _resolve(site.serve_dir)
        if os.path.isdir(serve_path) and not _serve_dir_readable(serve_path):
            print(f"  Warning: '{serve_path}' may not be readable by the servette user.")
            print(f"  Fix with: chown -R :servette {serve_path} && chmod -R g+rX {serve_path}")

    return updating


# enable
def cmd_enable():
    try:
        updating = _write_unit_files()

        if updating:
            # A refresh says what changed and stops. The watchdog was armed
            # by the first enable and is still armed; repeating it on every
            # re-run made a two-line result look like a four-line one.
            print("  Service file updated.")
        else:
            print("  Servette enabled as a system service.")
            print("  It will start automatically on boot and survive SSH disconnects.")
            print("  A watchdog timer recovers a dropped default route.")
        log.info("Enabled as systemd service")

        _ensure_swap()

        if updating and _service_is_active():
            _reload_server()   # apply the refreshed unit — no manual stop/start needed
        elif _server_running():
            if _prompt("Server is running in session only. Restart as a service now?"):
                stop_server()
                subprocess.run(["systemctl", "start", "servette"], check=True, capture_output=True)
                print("  Server started as a service.")
                log.info("Service started after enable")
                cmd_status()

    except ValueError:
        pass  # the writer already printed the path refusal
    except PermissionError:
        print("  Error: enable needs root, and sudo is unavailable — re-run as root.")
    except FileNotFoundError:
        print("  Error: enable requires a Linux server with systemd.")
    except subprocess.CalledProcessError as e:
        print(f"  Error during enable: {e}")


# disable
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
        # The runtime copy exists for the service; with no service it is a
        # second program sitting on the host with nothing running it.
        shutil.rmtree(RUNTIME_DIR, ignore_errors=True)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        print("  Servette service disabled.")
        log.info("Systemd service disabled")
    except PermissionError:
        print("  Error: disable needs root, and sudo is unavailable — re-run as root.")
    except FileNotFoundError:
        print("  Error: disable requires a Linux server with systemd.")
    except subprocess.CalledProcessError as e:
        print(f"  Error during disable: {e}")


# Menu metrics
_PAD = 22

# When free disk is worth saying out loud. Two thresholds because one does
# not fit both a 4 GB Pi card and a 200 GB VPS: an absolute floor a publish
# plus its kept versions can exhaust, and a fraction that catches a large
# disk filling steadily.
_DISK_LOW_MB       = 512
_DISK_LOW_FRACTION = 0.10


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


# The commands
_COMMANDS = [
    ("setup",            "guided walkthrough for getting started"),
    ("config",           "view and edit settings"),
    ("start",            "start the server"),
    ("stop",             "stop the server"),
    ("enable",           "enable Servette as a system service"),
    ("disable",          "remove the system service"),
    ("status [--json]",  "show whether the server is running"),
    ("sites [--json]",   "list configured sites"),
    ("set [n] k=v ...",  "change settings non-interactively"),
    ("log [n]",          "show the last n log entries"),
    ("traffic",          "requests, statuses, and top paths from the last 7 days"),
    ("admin",            "open the browser admin page over your SSH tunnel"),
    ("publish",          "one guided flow for site content"),
    ("restore-site [n]", "roll back a site's content to a kept version"),
    ("help",             "show this message"),
    ("quit",             "exit"),
]
HELP = _section_text("Commands") + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _COMMANDS)

# The config commands
_CONFIG_COMMANDS = [
    ("sites",           "list configured sites"),
    ("add-site",        "add a new site (domain and password)"),
    ("remove-site <n>", "remove a site"),
    ("move-site <n> <to>", "reorder sites (the first domainless one answers unmatched Hosts)"),
    ("port",            "HTTPS port"),
    ("cert [n]",        "SSL certificate and key"),
    ("email",           "email address"),
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


# The publish commands
_PUBLISH_COMMANDS = [
    ("restore-site [n]", "roll back a site's content to a kept version"),
    ("show",             "show each site's kept versions"),
    ("back",             "return to main shell"),
]
PUBLISH_HELP = _section_text("Commands") + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _PUBLISH_COMMANDS)


# Safe input
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


# The settings display
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
            ("Username",    val(site.username)),
            ("Password",    "(set)" if site.password_hash else "(not set)"),
        ]
        for label, value in site_rows:
            print(f"    {label:<{_PAD - 2}} {value}")
    print()


def _config_sites():
    _section("Sites")
    for i, site in enumerate(config.sites):
        auth = "private" if site.username else "public"
        state = "" if site.active else ", DEACTIVATED (set active=yes to serve)"
        print(f"  {i}: {site.domain or '(self-signed)'} — {site.serve_dir}, {auth}{state}")
    print()
    print("  Edit one with e.g. 'cert 1', 'username 1' (index defaults to 0).")
    print("  'add-site' adds one; 'remove-site <n>' removes one.\n")


# serve_dir containment
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


# add-site
def _invent_site_dir():
    """Create and own an empty folder for a new site. Servette names it: the
    folder is where publishes land, not a question an operator answers
    ([the folder is not a setting](../DECISIONS.md#the-folder-is-not-a-setting-serve_dir-is-retiring-from-the-vocabulary)).
    Both doors — the page's add-card and the terminal's add-site — come
    here, so neither can invent a folder the other would not."""
    name = f"site-{os.urandom(3).hex()}"
    os.makedirs(_resolve(name), exist_ok=True)
    _chown_operator(_resolve(name))
    return name


def _append_site(serve_dir):
    """Append a new site serving `serve_dir` (a path the caller has already
    validated or created) and give it its own certificate identity. The one
    site-creation core, shared by the terminal's add-site prompts and the
    page's add-card. Returns the new site's index.

    The self-signed pair is suffixed with randomness, not the site's list
    position: a position-based name (cert-{idx}.pem) collides with a
    surviving site's own files after a remove/add sequence shifts indices,
    silently overwriting that site's live certificate. It is generated
    unconditionally, before any domain enters the picture: if ACME issuance
    later fails, cert_file/key_file must still point at real files on disk —
    start_server()'s pre-flight existence check refuses to start the WHOLE
    server, for every site, if any site's cert_file is missing."""
    site = Site({"serve_dir": serve_dir})
    config.sites.append(site)
    suffix = os.urandom(4).hex()
    site.cert_file = f"cert-{suffix}.pem"
    site.key_file  = f"key-{suffix}.pem"
    _generate_self_signed_cert(_resolve(site.cert_file), _resolve(site.key_file))
    _chown_servette(_resolve(site.cert_file))
    _chown_servette(_resolve(site.key_file))
    config.save()
    return len(config.sites) - 1


def _config_add_site():
    """Add a site — the same two questions cmd_setup asks for the very first
    one, domain and password. The folder is not among them: Servette names
    and creates it, the same way the page's add-card does."""
    print("\n  Adding a new site.\n")
    # Nothing is written into it and nothing is offered: a site with no
    # index.html answers its own domain with the embedded error page, which
    # says the server is up and that nothing is published yet. Setup still
    # never leaves a site with nothing to serve (#37) — it just no longer
    # needs to put a file in a folder to keep that promise.
    folder = _invent_site_dir()
    print(f"  Content will land in {_resolve(folder)} — Servette's to manage.")
    print("  Until you publish, the site answers with Servette's error page.")

    # The self-signed pair keeps a second site from colliding with the
    # first's cert.pem/key.pem — overwritten if a domain is obtained below,
    # which uses the domain-scoped certs/<domain>/ path instead.
    print("  Generating self-signed certificate...")
    idx  = _append_site(folder)
    site = config.sites[idx]
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


# remove-site
def _remove_site(idx):
    """Drop site `idx` and delete its server copies — the content tree, the
    publish slots, and the one-step backup. The operator's originals live in
    their own local storage; everything here is a derived copy, which is what
    makes deletion the honest meaning of 'remove' (deactivation is the
    keep-everything alternative). The site's certificate files are kept, and
    a folder another site still points at is left alone. Returns an error
    sentence, empty on success. Shared by the terminal's remove-site and the
    page's cards."""
    if not (0 <= idx < len(config.sites)):
        return f"no site {idx}"
    if len(config.sites) == 1:
        return "can't remove the only site — a box needs at least one"
    victim = config.sites[idx]
    base   = _resolve(victim.serve_dir)
    del config.sites[idx]
    config.save()
    shared = any(os.path.realpath(_resolve(s.serve_dir)) == os.path.realpath(base)
                 for s in config.sites)
    if not shared and _is_within_base_dir(base):
        for suffix in ("", ".a", ".b", ".bak", ".new"):
            path = base + suffix
            try:
                if os.path.islink(path):
                    os.unlink(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
            except OSError:
                pass  # a copy that resists deletion must not block the removal
    if _server_running() or _service_is_active():
        _reload_server()
    return ""


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
    if not _prompt(f"Remove site {idx} ({label})? Its server copies are deleted — "
                   f"originals in your local storage are untouched "
                   f"('set {idx} active=no' deactivates without deleting)."):
        print("  Cancelled.")
        return

    err = _remove_site(idx)
    print(f"  {err}" if err else f"  → site {idx} removed.")


# move-site
def _move_site(frm, to):
    """Reorder: lift site `frm` out and reinsert it at position `to`.
    Returns an error sentence, empty on success. Shared by the terminal's
    move-site and the page's card drag."""
    n = len(config.sites)
    if not (0 <= frm < n and 0 <= to < n):
        return f"site indexes must be 0-{n - 1}"
    if frm != to:
        config.sites.insert(to, config.sites.pop(frm))
        config.save()
        if _server_running() or _service_is_active():
            _reload_server()
    return ""


def _config_move_site(args):
    if len(args) != 2 or not all(a.isdigit() for a in args):
        print("  Usage: move-site <from> <to>")
        return
    err = _move_site(int(args[0]), int(args[1]))
    print(f"  {err}" if err else "  → moved.")


# The generic setter
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


# cert
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


# username and password
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


# limits and cache
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
                # Non-negative, same rule 'set' enforces: a negative max-age
                # is not a shorter cache, it is a malformed Cache-Control
                # header sent on every response.
                age = int(age_str)
                if age < 0:
                    raise ValueError
                config.cache_max_age = age
            except ValueError:
                print("  → invalid number, keeping current max-age")
    config.save()
    print("  → saved")
    _config_set("cache_size_mb", "cache_size_mb", int, lambda v: v > 0,
                "invalid number", hint="In-memory file cache limit in MB (e.g. 32 on a Raspberry Pi)")


# proxy
def _config_trusted_proxy():
    current = config.trusted_proxy
    print(f"\n  Current: {current or '(not set — X-Forwarded-For ignored)'}")
    print("  Set to the IP of your reverse proxy to trust its X-Forwarded-For header.")
    print("  Leave blank to ignore XFF entirely (correct when Servette faces the internet directly).\n")
    new_value = _input("  trusted_proxy IP: ").strip()
    if new_value == current:
        print("  → unchanged")
        return
    if new_value:
        # The same rule 'set' enforces. A typo saved here was worse than a
        # refusal: the peer-address comparison then never matches, XFF is
        # never trusted, and every proxied visitor shares the proxy's single
        # rate-limit bucket — the whole site throttles as one client.
        try:
            ipaddress.ip_address(new_value)
        except ValueError:
            print("  → must be an IP address, unchanged")
            return
    config.trusted_proxy = new_value
    config.save()
    print("  → saved" if new_value else "  → cleared, X-Forwarded-For will be ignored")


# tls
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


# The site-index argument
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


# config
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
        elif cmd == "move-site":
            _config_move_site(args)
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


# start
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
                print("  Error: start needs root, and sudo is unavailable — re-run as root.")
            except FileNotFoundError:
                print("  Error: start requires a Linux server with systemd.")
            except subprocess.CalledProcessError as e:
                print(f"  Error starting service: {e}")
    else:
        start_server()
        if _server_running():
            # The macOS line carries only what the line above does not: there
            # is no service to install here, and tmux is the substitute. It
            # does not restate that quitting stops the server.
            print("  Running in session only — server will stop when you quit.")
            if _IS_MACOS:
                print("  A permanent service needs Linux; here, run it under tmux or screen.")
            elif _prompt("Install as a permanent service?"):
                cmd_enable()


# stop
def cmd_stop():
    stopped = False

    if _service_is_active():
        try:
            subprocess.run(["systemctl", "stop", "servette"], check=True, capture_output=True)
            print("  Service stopped.")
            log.info("Service stopped")
            stopped = True
        except PermissionError:
            print("  Error: stop needs root, and sudo is unavailable — re-run as root.")
        except FileNotFoundError:
            print("  Error: stop requires a Linux server with systemd.")
        except subprocess.CalledProcessError as e:
            print(f"  Error stopping service: {e}")

    if _server_running():
        stop_server()
        stopped = True

    if not stopped:
        cmd_status()


# log
def cmd_log(n=20):
    try:
        result = subprocess.run(
            ["journalctl", "-u", "servette", "-o", "cat", "-n", str(n), "--no-pager"],
            capture_output=True, text=True
        )
        output = result.stdout or result.stderr
        print(output, end="")
    except FileNotFoundError:
        if _IS_MACOS:
            print("  No journal on macOS — in session mode the log is this terminal's own output.")
        else:
            print("  journalctl not found. Is this a systemd system?")


# Traffic
def _traffic_lines(days=7):
    """The journal's lines for the window, timestamped (short-iso), oldest
    first; [] where no journal answers (macOS session mode, or a journal
    that needs privileges this shell doesn't hold)."""
    try:
        result = subprocess.run(
            ["journalctl", "-u", "servette", "-o", "short-iso",
             "--since", f"-{days}d", "--no-pager"],
            capture_output=True, text=True)
        return result.stdout.splitlines()
    except FileNotFoundError:
        return []


_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def _parse_traffic(lines, days=7):
    """Tally journal lines into the traffic summary: requests per day,
    status counts, top paths. Pure, so the suite can feed it real log
    lines. Each line carries two prefixes — the journal's own
    ('<iso> <host> servette[pid]:') and then setup_logging's format
    ('<date> <time>  LEVEL  <message>') — so the level name is the anchor
    the message begins after. Anchoring on the unit token instead was the
    bug that made this count nothing at all: the Python timestamp sat
    where the status was expected. Only response lines count — every
    served response logs as '<status> <path> … to <ip>' (or 'from' on
    refusals) — and systemd's own lines, carrying no level, are skipped.
    Paths are tallied from content responses (200/206/304). IPs are never
    carried into the result."""
    per_day, statuses, paths = {}, {}, {}
    stamp = (lambda p: p[:13].replace("T", " ")) if days <= 2 else (lambda p: p[:10])
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or len(parts[0]) < 10 or parts[0][4:5] != "-":
            continue
        day = stamp(parts[0])
        lvl = next((i for i, p in enumerate(parts) if p in _LOG_LEVELS), None)
        if lvl is None:
            continue
        msg = parts[lvl + 1:]
        if not msg or len(msg[0]) != 3 or not msg[0].isdigit():
            continue
        statuses[msg[0]] = statuses.get(msg[0], 0) + 1
        per_day[day] = per_day.get(day, 0) + 1
        if msg[0] in ("200", "206", "304"):
            path = next((p for p in msg[1:] if p.startswith("/")), None)
            if path:
                paths[path] = paths.get(path, 0) + 1
    top = sorted(paths.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    return {"days": sorted(per_day.items()), "statuses": dict(sorted(statuses.items())),
            "top_paths": top, "window_days": days,
            "bucket": "hour" if days <= 2 else "day",
            "total": sum(statuses.values())}


def _traffic_summary(days=7):
    return _parse_traffic(_traffic_lines(days), days)


def cmd_traffic():
    """`traffic` — requests, statuses, and top paths from the last 7 days,
    read from the journal. The page's Traffic tab renders this same
    summary; the raw log (IPs included) stays with `log`."""
    t = _traffic_summary()
    if not t["days"]:
        print("  No traffic in the window — or no readable journal on this host.")
        return
    _section("Traffic — last 7 days")
    print(f"  Requests: {sum(n for _, n in t['days'])}")
    for day, n in t["days"]:
        print(f"    {day}  {n}")
    print("  Statuses: " + ", ".join(f"{s} x{n}" for s, n in t["statuses"].items()))
    print("  Top paths:")
    for path, n in t["top_paths"]:
        print(f"    {n:>6}  {path}")
    print()


# The update channel for a site's *content*: a tar.gz bundle the operator
# uploads over their own SSH tunnel, extracted into a staging tree and made
# live with one atomic link flip, the tree it replaces kept in the ring for
# 'restore-site' to flip back to. Nothing arrives from the network unasked —
# the door is the loopback page, reachable only through the operator's
# tunnel. (Servette's own code updates travel through the package manager,
# not through Servette.)
# The bundle ceiling
_MAX_BUNDLE_BYTES = 500 * 1024 * 1024  # generous for a static site; bounds a decompression-bomb bundle


# Extracting a bundle
def _extract_bundle(data, dest_dir):
    """Extract a tar.gz byte string into dest_dir (must not yet exist).

    Every entry's resolved path is checked against dest_dir, every entry must
    be a plain file or directory (no symlinks/devices), and the total
    uncompressed size is capped — all validated before anything is written,
    so a bad bundle leaves no partial extraction behind. Where the interpreter
    has it (3.11.4+), filter='data' is passed to extractall() too: defense in
    depth, not the only guard — it independently enforces the same containment
    and rejects the same entry types at the library level."""
    os.makedirs(dest_dir)
    dest_real = os.path.realpath(dest_dir)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        # Members are walked with next() rather than getmembers(): walking a
        # gzip stream decompresses it, so getmembers() paid the FULL
        # decompression cost before the size cap ever ran — the cap bounded
        # what was written, not the CPU a bomb burns. next() lets the walk
        # abort at the ceiling. (Only a bundle the operator uploaded over
        # their own tunnel gets here at all, so this bounds a buggy build of
        # their own site, not the anonymous internet.)
        members = []
        total   = 0
        while (m := tf.next()) is not None:
            if not (m.isfile() or m.isdir()):
                raise ValueError(f"unsupported entry type in bundle: {m.name}")
            target = os.path.realpath(os.path.join(dest_dir, m.name))
            if not (target == dest_real or target.startswith(dest_real + os.sep)):
                raise ValueError(f"entry escapes the target directory: {m.name}")
            total += m.size
            if total > _MAX_BUNDLE_BYTES:
                raise ValueError(f"bundle exceeds {_MAX_BUNDLE_BYTES} bytes uncompressed")
            members.append(m)
        # The PEP 706 feature probe: data_filter exists exactly when
        # extractall() accepts filter=. Debian 12's 3.11.2 predates the
        # backport — there the checks above are the (sufficient) guard.
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest_dir, members=members, filter="data")
        else:
            tf.extractall(dest_dir, members=members)


# The kept versions
_KEEP_VERSIONS = 5   # trees kept per site, the live one included


def _content_slots(serve_dir):
    """The two sibling trees the pre-ring design flipped between. Kept only
    so a site published under it can be adopted into the ring."""
    base = _resolve(serve_dir).rstrip(os.sep)
    return base + ".a", base + ".b"


def _drop_backup(bak):
    """Remove the single-shot backup marker the pre-ring design left: a
    symlink from the flip era (the tree it names is adopted separately), or
    a real directory from before that."""
    if os.path.islink(bak):
        os.remove(bak)
    elif os.path.isdir(bak):
        shutil.rmtree(bak, ignore_errors=True)


def _version_dirs(serve_dir):
    """Every kept tree for this site, newest first, as (path, epoch).

    A name that does not parse is not a version and is left alone — the
    scan is a filter over siblings, never a prefix match that could sweep
    up a directory Servette did not create."""
    base = _resolve(serve_dir).rstrip(os.sep)
    head, tail = os.path.split(base)
    try:
        names = os.listdir(head or ".")
    except OSError:
        return []
    out = []
    for name in names:
        if not name.startswith(tail + ".v"):
            continue
        stamp, _dot, extra = name[len(tail) + 2:].partition(".")
        path = os.path.join(head, name)
        if not (stamp.isdigit() and os.path.isdir(path) and not os.path.islink(path)):
            continue
        # Two publishes inside one second share an epoch and are told apart
        # by the sequence suffix — which must sort with the clock, not
        # against it, or the newer of the two would read as the older.
        out.append((path, int(stamp), int(extra) if extra.isdigit() else 1))
    out.sort(key=lambda r: (-r[1], -r[2]))
    return [(path, stamp) for path, stamp, _seq in out]


def _new_version_dir(serve_dir, when=None):
    """An unused version-directory path for a tree published at `when`
    (default now). Two publishes inside one second take '.2', '.3': the
    name must be unique, or the second would land on top of the first."""
    base  = _resolve(serve_dir).rstrip(os.sep)
    stamp = int(when if when is not None else time.time())
    path  = f"{base}.v{stamp}"
    n = 2
    while os.path.lexists(path):
        path = f"{base}.v{stamp}.{n}"
        n += 1
    return path


def _adopt_legacy_slots(serve_dir):
    """Bring a two-slot site's trees into the ring, after the flip that made
    them idle. Renaming a tree the live symlink points at would break the
    link, so the live one is skipped — it is adopted on the publish after
    this one, when it is no longer live. The `.bak` symlink goes: the ring
    is the history now."""
    base = _resolve(serve_dir).rstrip(os.sep)
    _drop_backup(base + ".bak")
    live = os.path.realpath(base)
    for slot in _content_slots(serve_dir):
        if not os.path.isdir(slot) or os.path.islink(slot):
            continue
        if os.path.realpath(slot) == live:
            continue
        try:
            os.rename(slot, _new_version_dir(serve_dir, os.path.getmtime(slot)))
        except OSError:
            pass          # a slot that will not move is left, never deleted


def _prune_versions(serve_dir, keep=None):
    """Drop the oldest trees past the ring's depth. The live tree is never a
    candidate however old it is: an operator who restored a year-old version
    is serving it, and content being served is not garbage."""
    keep = _KEEP_VERSIONS if keep is None else keep
    live = os.path.realpath(_resolve(serve_dir).rstrip(os.sep))
    for path, _stamp in _version_dirs(serve_dir)[keep:]:
        if os.path.realpath(path) != live:
            shutil.rmtree(path, ignore_errors=True)


# The content swap
def _swap_site_content(new_dir, serve_dir):
    """Make new_dir the live content behind serve_dir, keeping the trees
    behind it as the ring `restore-site` chooses from.

    new_dir's tree is renamed to a fresh `<link>.v<epoch>` sibling and one
    atomic os.replace flips the link — no window, crash-safe. Pruning runs
    after the flip, so a publish that fills the disk fails in staging with
    every kept version still there.

    A legacy real directory at serve_dir is converted on its first swap: the
    old content becomes a version and the link lands — the one swap that
    still carries the old rename gap, once per site ever, with the same
    rollback the old design had (a failed conversion must never leave NO
    live directory — every request a 404 — while the caller reports merely
    'rejected')."""
    if not os.path.isdir(new_dir):
        # A dangling symlink would "succeed" — the old rename raised here,
        # and the flip must fail just as loudly rather than serve nothing.
        raise FileNotFoundError(f"new content tree missing: {new_dir}")
    live = _resolve(serve_dir).rstrip(os.sep)
    dest = _new_version_dir(serve_dir)

    if os.path.islink(live):
        os.rename(new_dir, dest)
        flip = live + ".flip"
        if os.path.lexists(flip):
            os.remove(flip)                      # a crash's leftover, harmless
        os.symlink(dest, flip)
        os.replace(flip, live)                   # the swap: one atomic syscall
        _adopt_legacy_slots(serve_dir)
        _prune_versions(serve_dir)
        return

    # Legacy: a real directory (or nothing yet) at serve_dir — convert.
    had_live = os.path.isdir(live)
    os.rename(new_dir, dest)
    kept = None
    if had_live:
        # Dated by its own mtime, not by now: it is the older content, and
        # the ring sorts on the name.
        kept = _new_version_dir(serve_dir, os.path.getmtime(live))
        os.rename(live, kept)
    try:
        os.symlink(dest, live)
    except OSError:
        if had_live:
            os.rename(kept, live)
        raise
    _adopt_legacy_slots(serve_dir)
    _prune_versions(serve_dir)


_publish_lock = threading.Lock()  # serializes site-content mutation across every
                                   # site: a page publish and 'restore-site' can
                                   # run from two sessions at once, and the swap
                                   # is several unguarded filesystem ops, not one.


# Landing a bundle
def _land_bundle(site, bundle, source):
    """Extract `bundle` into staging and swap it live for `site`, keeping the
    previous trees in the ring, with ownership repair — the shared tail of
    every content channel. `source` is only for the log line. Returns
    "rejected" or "published"."""
    with _publish_lock:
        staging = _resolve(site.serve_dir).rstrip(os.sep) + ".new"
        shutil.rmtree(staging, ignore_errors=True)
        try:
            _extract_bundle(bundle, staging)
            # Extracted by this process — root, since every content channel
            # elevates — so re-establish what enable establishes BEFORE the
            # tree goes live: the operator owns their content, the service
            # reads through its group. strip_world because the extraction's
            # own 644/755 modes are Servette's writing, not the operator's,
            # (kept versions need nothing: each was the live tree once and
            # keeps the ownership it already has)
            # and must honour the never-world-bits promise. The backup needs
            # nothing: it was the live tree a moment ago and keeps the
            # ownership it already has. A failed extraction dies here, in
            # staging, with the live content and its backup untouched.
            _chown_operator(staging, strip_world=True)
            _swap_site_content(staging, site.serve_dir)
        except Exception as e:
            log.error("Publish bundle rejected: %s", e)
            shutil.rmtree(staging, ignore_errors=True)
            return "rejected"

    log.info("Published new content for %s from %s", site.domain or site.serve_dir, source)
    return "published"


# preview
def _preview_dir(site):
    """Where a staged preview lives: a sibling of the site's tree, never
    inside it. Inside, the public server would serve the unpublished draft
    to the internet."""
    return _resolve(site.serve_dir).rstrip(os.sep) + ".preview"


def _stage_preview(site, bundle):
    """Extract `bundle` where the loopback server can serve it, without
    going near the live tree. Returns "staged" or "rejected".

    The same _extract_bundle every content channel runs, so a bundle the
    publish door would refuse the preview refuses identically — a preview
    that accepted more than a publish would be a preview of something that
    can never ship."""
    dest = _preview_dir(site)
    shutil.rmtree(dest, ignore_errors=True)
    try:
        _extract_bundle(bundle, dest)
    except Exception as e:
        log.error("Preview bundle rejected: %s", e)
        shutil.rmtree(dest, ignore_errors=True)
        return "rejected"
    log.info("Staged a preview for %s", site.domain or site.serve_dir)
    return "staged"


def _clear_previews():
    """Drop every staged preview. A preview belongs to one `admin` run: it is
    a draft nobody published, and leaving it on disk would keep an
    unpublished tree beside a live site indefinitely."""
    for site in config.sites:
        shutil.rmtree(_preview_dir(site), ignore_errors=True)


def _tar_live_site(site, cap=_MAX_BUNDLE_BYTES):
    """The site's live tree as gzipped tar bytes, or None if it is too big to
    hold in memory. Content leaves the box the same way it arrived — same
    format, same cap — so a downloaded archive is a bundle the publish door
    would accept back.

    Paths are relative to the site root and the hidden-path rule applies on
    the way out as it does on the way in: a dot-directory is not served, so
    it is not handed over either."""
    root = os.path.realpath(_resolve(site.serve_dir).rstrip(os.sep))
    if not os.path.isdir(root):
        return None
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for base, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if not d.startswith(".") or d == ".well-known"]
            for name in sorted(names):
                if name.startswith("."):
                    continue
                full = os.path.join(base, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue        # only regular files, as _extract_bundle accepts
                rel = os.path.relpath(full, root)
                try:
                    tf.add(full, arcname=rel, recursive=False)
                except OSError:
                    continue
                if buf.tell() > cap:
                    return None
    return buf.getvalue()


def _tree_size(path):
    """(files, bytes) under path. A file that vanishes mid-walk is skipped,
    not raised: this is a description, and a racing publish must not make
    describing the site an error."""
    files = total = 0
    for root, _dirs, names in os.walk(path):
        for name in names:
            try:
                total += os.path.getsize(os.path.join(root, name))
                files += 1
            except OSError:
                pass
    return files, total


def _site_versions(site):
    """The kept trees of one site as rows both surfaces render: the name to
    restore by, when it was published, how many files and bytes it holds, and
    which one is live.

    The live tree is ALWAYS reported, ring member or not. A site published
    before the ring existed serves a tree the ring does not hold — it joins
    on its next publish — and reporting an empty list would tell an operator
    with a live, working site that nothing is published, which is both false
    and alarming. That tree carries its own mtime as its date and is never
    offered for restore, because it is already live.

    Walking every tree is why this is its own call rather than part of the
    status snapshot — it runs when an operator asks to see the history, not
    on every poll of a page that refreshes itself."""
    live_link = _resolve(site.serve_dir).rstrip(os.sep)
    live      = os.path.realpath(live_link)
    rows, in_ring = [], False
    for path, stamp in _version_dirs(site.serve_dir):
        files, total = _tree_size(path)
        is_live = os.path.realpath(path) == live
        in_ring = in_ring or is_live
        rows.append({"name": os.path.basename(path), "published": stamp,
                     "files": files, "bytes": total, "live": is_live})
    if not in_ring and os.path.isdir(live):
        files, total = _tree_size(live)
        try:
            stamp = int(os.path.getmtime(live))
        except OSError:
            stamp = 0
        rows.insert(0, {"name": os.path.basename(live), "published": stamp,
                        "files": files, "bytes": total, "live": True})
    return rows


def _restore_site(site, version=None):
    """Serve a kept version again. `version` is a name as _site_versions
    reports it; None means the newest tree that is not already live — plain
    'undo the last publish'. Returns "" on success, or a sentence saying why
    not.

    The flip is the publish's flip, so a restore has no window either. The
    tree is NOT consumed: it stays in the ring, so restoring the wrong one
    is itself undoable. That is the whole difference from the single-shot
    backup this replaced."""
    live_path = _resolve(site.serve_dir).rstrip(os.sep)
    versions  = _version_dirs(site.serve_dir)
    if not versions:
        return ("Nothing to restore — a kept version appears the first time "
                "new content replaces old.")
    if not os.path.islink(live_path):
        return ("This site's folder is not yet behind the version link — "
                "publish once, and the content it replaces joins the ring.")

    live = os.path.realpath(live_path)
    if version is None:
        target = next((p for p, _ in versions if os.path.realpath(p) != live), None)
        if target is None:
            return "Nothing to restore — the only kept version is the live one."
    else:
        # Matched by base name against the ring, never taken as a path: the
        # page's version name arrives over the wire, and a caller must not be
        # able to name a directory the ring does not hold.
        target = next((p for p, _ in versions
                       if os.path.basename(p) == version), None)
        if target is None:
            return f"No kept version named {version}."
        if os.path.realpath(target) == live:
            return "That version is already the live one."

    with _publish_lock:
        if not os.path.isdir(target):
            return "That version was removed while you were deciding."
        flip = live_path + ".flip"
        if os.path.lexists(flip):
            os.remove(flip)
        os.symlink(target, flip)
        os.replace(flip, live_path)              # the restore: one atomic flip
        # The tree may date from a publish that extracted as root — the same
        # ownership repair as a publish, for the same reason.
        _chown_operator(os.path.realpath(live_path), strip_world=True)
    log.info("Restored content for %s to %s",
             site.domain or site.serve_dir, os.path.basename(target))
    return ""


def _version_line(row):
    """One kept version as a line for the terminal: when, how big, and
    whether it is the one being served."""
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["published"]))
    size = (f"{row['bytes'] / (1024 * 1024):.1f} MB" if row["bytes"] >= 1024 * 1024
            else f"{row['bytes'] / 1024:.0f} KB")
    files = f"{row['files']} file" + ("" if row["files"] == 1 else "s")
    return f"{when} — {files}, {size}" + ("  (live)" if row["live"] else "")


def cmd_restore_site(site):
    """Roll back to a kept version. One choice is a yes/no; several are a
    numbered list, newest first. Nothing is consumed — the version being
    rolled away stays in the ring, so this is undoable in its own terms."""
    rows = _site_versions(site)
    kept = [r for r in rows if not r["live"]]
    if not kept:
        # One line, and it says when that changes rather than explaining the
        # ring: "no kept versions yet" alone leaves a reader wondering what
        # would make one.
        print("  Nothing to restore — a kept version appears the first time")
        print("  new content replaces old.")
        return

    if len(kept) == 1:
        print(f"\n  Kept: {_version_line(kept[0])}")
        if not _prompt("Restore this content?"):
            print("  Restore cancelled.")
            return
        choice = kept[0]
    else:
        print()
        for n, row in enumerate(kept, 1):
            print(f"  {n}. {_version_line(row)}")
        raw = _input("\n  Restore which? [number, Enter = cancel]: ").strip()
        if not raw.isdigit() or not (1 <= int(raw) <= len(kept)):
            print("  Restore cancelled.")
            return
        choice = kept[int(raw) - 1]

    err = _restore_site(site, choice["name"])
    print(f"  {err}" if err else "  Site content restored.")

# The publish display
def _publish_show():
    _section("Publish")
    for i, site in enumerate(config.sites):
        rows = _site_versions(site)
        print(f"  [{i}] {site.domain or site.serve_dir}")
        if not rows:
            print("      nothing published yet")
            continue
        # Newest first, live one marked by _version_line — the same ordering
        # and the same line the restore prompt lists, so a version reads
        # identically wherever the operator meets it.
        for row in rows:
            print(f"      {_version_line(row)}")
    print()


# publish
def cmd_publish():
    _publish_show()
    # The commands come first, unbroken: they are what the operator came for
    # and there is no guessing them. The browser pointer follows rather than
    # interrupts, and drops the tunnel detail — 'admin' explains its own
    # tunnel when it runs.
    print(PUBLISH_HELP)
    print("  Prefer a browser? 'admin' opens these jobs as a page.")
    print()

    while True:
        try:
            raw = input("  publish> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()
        args  = parts[1:]

        if cmd == "show":
            _publish_show()
        elif cmd == "restore-site":
            site = _config_site_arg(args)
            if site is not None:
                cmd_restore_site(site)
        elif cmd in ("back", "done", "exit", "quit"):
            break
        elif cmd in ("help", "?"):
            print(PUBLISH_HELP)
        else:
            print(f"  Unknown command: {cmd}")
            print(PUBLISH_HELP)


# The loopback server's shape
_UI_HOST          = "127.0.0.1"
_UI_PORT          = 8377  # the LocalForward line in the operator's ssh config names it
_UI_MAX_BAD_CODES = 5     # then the run stops authenticating anyone: a six-character
                          # code holds against five guesses, not against a local
                          # process free to try millions over loopback


# The login page
_UI_LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Servette — Log in</title>
<style>
  body { background: #0e0e0e; color: #e8e8e8; min-height: 100vh; margin: 0;
         display: flex; flex-direction: column; align-items: center;
         justify-content: center; padding: 2rem; box-sizing: border-box;
         font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo,
                      Consolas, 'Liberation Mono', 'Courier New', monospace; }
  /* The cursor is absolute so it adds no width: the page centers on
     "Servette", not "Servette_". */
  .logo { font-size: 3rem; font-weight: 500; line-height: 1; position: relative; }
  .logo .ette { color: #5A8466; }
  .logo .cursor { position: absolute; animation: blink 1.1s steps(1) infinite; }
  @keyframes blink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }
  .tagline { margin-top: 0.5rem; color: #555; font-size: 0.75rem;
             letter-spacing: 0.08em; text-transform: uppercase; }
  .card { margin-top: 3rem; width: 100%; max-width: 26rem; background: #161616;
          border: 1px solid #2a2a2a; border-radius: 8px; padding: 1.25rem; }
  label { display: block; color: #555; font-size: 0.7rem;
          letter-spacing: 0.1em; text-transform: uppercase;
          margin-bottom: 0.35rem; }
  input { width: 100%; box-sizing: border-box; font-family: inherit;
          font-size: 0.9rem; color: #e8e8e8; background: #0e0e0e;
          border: 1px solid #2a2a2a; border-radius: 4px;
          padding: 0.6rem 0.7rem; }
  input:focus { outline: none; border-color: rgba(90,132,102,0.8);
                box-shadow: 0 0 0 2px rgba(90,132,102,0.25); }
  button { margin-top: 0.75rem; font-family: inherit; font-size: 0.75rem;
           color: #e8e8e8; background: rgba(90,132,102,0.15);
           border: 1px solid rgba(90,132,102,0.6); border-radius: 4px;
           padding: 0.5rem 0.9rem; cursor: pointer; }
  .hint { margin-top: 0.75rem; color: #555; font-size: 0.72rem;
          line-height: 1.7; }
</style></head>
<body>
<div class="logo">Serv<span class="ette">ette</span><span class="cursor">_</span></div>
<div class="tagline">Login</div>
<div class="card">
  <form method="get" action="/">
    <label for="t">Passcode</label>
    <input id="t" name="t" autofocus autocomplete="off">
    <button>Log in</button>
  </form>
  <p class="hint">Run 'servette admin' in your SSH console to generate a
  one-time passcode.</p>
</div>
</body></html>
"""


# The admin page
_UI_ADMIN_PAGE = """<!DOCTYPE html>
<!-- src/admin.html — the operator's page, the browser half of the paired
     surfaces. Served only by the loopback page server (127.0.0.1, reached
     through the operator's SSH tunnel via `servette admin`), never by the
     public site. One page, three tabs: Sites (one card per site, carrying
     everything about it — publish, domain, certificate, access), Server
     (what the box is doing and how it is set), and Statistics (traffic
     counted across every site, and the box's own load).

     The stylesheet and the script each open with their own map of what
     follows, in the order a reader meets it.

     Constraints, all load-bearing:

     - No signature, no key. Being here IS the authentication: only the
       holder of the operator's SSH key can reach this address, so the
       page carries none of the pub tool's key custody machinery
       (DECISIONS.md, "Tunnel uploads are authenticated by SSH").
     - Dependency-free. Browser primitives only (CompressionStream, a
       hand-rolled ustar writer emitting only the entry types
       _extract_bundle accepts); its only requests are to the same
       loopback server that served it.
     - The page never borrows the browser's voice: no alert, confirm, or
       prompt anywhere. A question is asked in the page's own words, in a
       panel, with the choices spelled out.
     - Inlined into servette.py by build.py, like 404.html: no triple
       double-quote and no backslash anywhere in this file, or the build
       fails rather than emit a broken literal. -->
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect x='2' y='2' width='60' height='60' rx='13' fill='%230e0e0e' stroke='%235A8466' stroke-width='4'/><text x='14' y='45' font-family='ui-monospace,Menlo,monospace' font-size='36' font-weight='600' fill='%235A8466'>S</text><rect x='35' y='39' width='16' height='6' rx='1.5' fill='%235A8466'/></svg>">
  <title>Servette — Admin</title>
  <style>
    /* ═══════════════════════════════════════════════════════════════════
       Theme, then the page's furniture in the order it is built from:
       frame, wordmark, tabs, cards, badges, buttons, fact rows, prose,
       forms, site cards, charts. One rule per thing, in the section that
       owns it — a variant of a button lives with the button.
       ═══════════════════════════════════════════════════════════════════ */

    /* ── Theme and reset ─────────────────────────────────────────────── */
    :root {
      --bg:      #0e0e0e;
      --surface: #161616;
      --border:  #2a2a2a;
      --text:    #e8e8e8;
      --muted:   #555;
      --green:   #4ade80;
      --red:     #f87171;
      --amber:   #fbbf24;
      /* Servette green, the one accent: available actions, links, and the
         running dot. Kept literal rather than tokenised only where it
         appears inside an rgba() tint. */
      --brand:   #5A8466;
      --mono: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas,
              'Liberation Mono', 'Courier New', monospace;
    }

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    /* ── Page frame: a single column over a faint noise wash ─────────── */
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--mono);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 3rem 2rem;
    }

    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.04'/%3E%3C/svg%3E");
      pointer-events: none;
      opacity: 0.4;
      z-index: 0;
    }

    .container {
      position: relative;
      z-index: 1;
      /* The reading width the public pages use: once the rows became facts
         and the forms sat beside their labels, 760px was empty space
         rather than room. */
      max-width: 560px;
      width: 100%;
    }

    /* ── Wordmark and tagline ────────────────────────────────────────── */
    .header { margin-bottom: 1.75rem; }

    .servette-logo {
      font-family: var(--mono);
      font-weight: 500;
      font-size: 3rem;
      letter-spacing: 0;
      color: var(--text);
      line-height: 1;
    }

    .servette-logo .ette   { color: var(--brand); }
    .servette-logo .cursor { color: inherit; animation: servette-blink 1.1s steps(1) infinite; }

    @keyframes servette-blink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }

    .tagline {
      margin-top: 0.5rem;
      color: var(--muted);
      font-size: 0.75rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    /* ── Tabs ────────────────────────────────────────────────────────── */
    .tabs {
      display: flex;
      gap: 0.4rem;
      margin-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
    }

    button.tab {
      font-family: inherit;
      font-size: 0.75rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      background: none;
      border: none;
      border-bottom: 2px solid transparent;
      padding: 0.55rem 0.9rem;
      cursor: pointer;
    }
    button.tab:hover { color: var(--text); }
    button.tab.active {
      color: var(--text);
      border-bottom-color: var(--brand);
    }

    /* ── Cards: the one container every panel is built from ──────────── */
    .card {
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      background: var(--surface);
      margin-bottom: 1.5rem;
    }

    .card-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.75rem 1.25rem;
      border-bottom: 1px solid var(--border);
    }

    .card-title {
      font-size: 0.7rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--muted);
    }

    .card-body { padding: 1rem 1.25rem; }

    /* A rule between two parts of one card. */
    .split { border-top: 1px solid var(--border); margin: 1rem 0; }

    /* ── Badges: a card's one-word state, in the head ────────────────── */
    .badge {
      font-size: 0.7rem;
      font-weight: 500;
      padding: 0.3rem 0.7rem;
      border-radius: 4px;
      letter-spacing: 0.05em;
      white-space: nowrap;
      flex-shrink: 0;
    }
    .badge-green { background: rgba(74,222,128,0.12); color: var(--green); border: 1px solid rgba(74,222,128,0.2); }
    .badge-red   { background: rgba(248,113,113,0.12); color: var(--red);  border: 1px solid rgba(248,113,113,0.2); }
    .badge-dim   { background: rgba(255,255,255,0.04); color: var(--muted); border: 1px solid var(--border); }
    .badge-warn  { background: rgba(251,191,36,0.12); color: var(--amber); border: 1px solid rgba(251,191,36,0.4); }

    /* ── Buttons ─────────────────────────────────────────────────────────
       Every button reads the same way: available is Servette green, hover
       brightens it, unavailable is dim and says so by being unclickable —
       never by vanishing. The variants below change only what a button
       means, never that rule. */
    button.action {
      font-family: inherit;
      font-size: 0.75rem;
      color: var(--text);
      border: 1px solid rgba(90,132,102,0.6);
      background: rgba(90,132,102,0.15);
      border-radius: 4px;
      padding: 0.5rem 0.9rem;
      cursor: pointer;
      letter-spacing: 0.03em;
    }
    button.action:hover:not(:disabled) { background: rgba(90,132,102,0.28); }
    button.action:disabled {
      color: var(--muted);
      border-color: rgba(90,132,102,0.25);
      background: rgba(90,132,102,0.05);
      cursor: not-allowed;
    }

    /* Sits on a fact row rather than in a button row. */
    button.action.tiny { padding: 0.2rem 0.55rem; font-size: 0.68rem; }

    /* Red deletes, amber pauses, neutral cancels — the warning ladder the
       remove panel and the stop panel both use. */
    button.action.danger {
      color: var(--red);
      border-color: rgba(248,113,113,0.5);
      background: rgba(248,113,113,0.08);
    }
    button.action.danger:hover:not(:disabled) { background: rgba(248,113,113,0.18); }
    button.action.pause {
      color: var(--amber);
      border-color: rgba(251,191,36,0.5);
      background: rgba(251,191,36,0.08);
    }
    button.action.pause:hover:not(:disabled) { background: rgba(251,191,36,0.18); }

    /* Due: something is waiting on this button. Amber until it is pressed,
       green under the pointer, so attention is said in colour and the
       button still reads as available. */
    button.action.due {
      color: var(--amber);
      border-color: rgba(251,191,36,0.5);
      background: rgba(251,191,36,0.08);
    }
    button.action.due:hover:not(:disabled) {
      color: var(--text);
      border-color: rgba(90,132,102,0.6);
      background: rgba(90,132,102,0.15);
    }

    /* An icon button is still a button: the icon replaces the label, not
       the border. */
    button.action.tiny svg { display: block; }
    button.action.tiny:has(svg) { padding: 0.3rem 0.4rem; }

    .btn-row { display: flex; gap: 0.6rem; flex-wrap: wrap; }
    .add-zone { display: flex; justify-content: center; margin-bottom: 1.5rem; }

    button:focus-visible {
      outline: 1px solid rgba(90,132,102,0.8);
      outline-offset: 1px;
    }

    /* ── Fact rows: label left, value right, the shell's status in HTML ─ */
    .rows { font-size: 0.72rem; line-height: 1.9; color: var(--text); }
    .rows > div { padding: 0.18rem 0; }
    /* padding-right, not just min-width: a key longer than the column (a
       long request path) would otherwise butt straight against its value
       with nothing between them. border-box keeps the value column at 8rem
       for every key short enough to fit. */
    .rows .k {
      color: var(--muted);
      display: inline-block;
      min-width: 8rem;
      padding-right: 0.75rem;
    }
    .rows a { color: var(--brand); text-decoration: none; }
    .rows a:hover { text-decoration: underline; }
    /* A ledger's total sits under a rule, at the foot of what it sums. */
    .rows .ledger {
      margin-top: 0.35rem;
      padding-top: 0.35rem;
      border-top: 1px solid var(--border);
    }
    .rows b { color: var(--text); font-weight: 500; }
    .rows .ok { color: var(--brand); }
    /* Not scoped to .rows: the running dot moved onto the status switch-row
       when the service controls joined it, and a `.rows .dot` rule stopped
       matching — the dot was still in the markup and simply invisible. */
    .dot {
      display: inline-block;
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--brand);
      margin-right: 0.45rem;
      vertical-align: middle;
      position: relative;
      top: -1px;
      animation: pulse 2s ease infinite;
    }

    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

    /* ── Prose: hints under a control, errors, the attention band ─────── */
    .hint  { font-size: 0.72rem; color: var(--muted); line-height: 1.7; margin-top: 0.75rem; }
    .hint b { color: var(--text); font-weight: 500; }
    .warn  { color: var(--amber); }
    .fault { color: var(--red); }
    /* Not a fault at all — a change typed and not yet saved. It used to
       borrow .warn, which made an unsaved intention look like something
       broken. */
    .pending { color: var(--muted); font-style: italic; }
    .error { font-size: 0.72rem; color: var(--red); line-height: 1.6; margin-top: 0.75rem; }

    /* What needs review, said in words and pointed at its fix. */
    .attention {
      border: 1px solid rgba(251,191,36,0.35);
      background: rgba(251,191,36,0.07);
      border-radius: 8px;
      padding: 0.7rem 1rem;
      margin-bottom: 1.25rem;
      font-size: 0.72rem;
      line-height: 1.8;
      color: var(--amber);
    }
    .attention b { color: var(--text); font-weight: 500; }
    .attention a { color: var(--amber); text-decoration: underline; }

    .note {
      font-size: 0.7rem;
      color: var(--muted);
      line-height: 1.7;
    }
    .note b { color: var(--text); font-weight: 500; }
    /* The one link that leaves this page, so it opens in its own tab: the
       operator is mid-task here, and navigating away would lose it. */
    .note a { color: var(--brand); text-decoration: none; }
    .note a:hover { text-decoration: underline; }

    /* ── Forms ───────────────────────────────────────────────────────────
       Label left, field right, the hint under the field. Narrow screens
       stack them again, at the foot of this sheet. */
    .cfg-field {
      margin-top: 0.9rem;
      display: grid;
      grid-template-columns: 8rem 1fr;
      align-items: center;
    }
    .cfg-field label {
      font-size: 0.7rem;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .cfg-field .cfg-hint { grid-column: 2; }
    .cfg-hint {
      font-size: 0.68rem;
      color: var(--muted);
      line-height: 1.6;
      margin-top: 0.3rem;
    }

    input[type="text"], input[type="password"], select {
      font-family: inherit;
      font-size: 0.75rem;
      color: var(--text);
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.4rem 0.7rem;
      width: 100%;
    }
    select { width: auto; }

    /* The browser's default focus halo clashes with the theme; replaced —
       never just removed — so keyboard focus stays visible. */
    input[type="text"]:focus, input[type="password"]:focus, select:focus {
      outline: none;
      border-color: rgba(90,132,102,0.8);
      box-shadow: 0 0 0 2px rgba(90,132,102,0.25);
    }

    /* A fact row that carries a control: the same 8rem key column the
       plain rows use, so a value with a button beside it still lines up
       with the values above and below it. */
    .switch-row {
      display: grid;
      grid-template-columns: 8rem 1fr;
      align-items: center;
      font-size: 0.72rem;
      line-height: 1.9;
      padding: 0.3rem 0;
    }
    .switch-row .k { color: var(--muted); }
    .switch-row label.k { cursor: pointer; }
    .switch-row .switch-value {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      color: var(--text);
    }
    .switch-act { display: flex; align-items: center; gap: 0.5rem; }
    /* A value that needs two lines gets them, and the row keeps centring
       its label and buttons against the pair. */
    .ver-state span { display: block; }
    .switch-act label { color: var(--muted); cursor: pointer; }

    /* The public/private switch — a literal toggle: the knob's position
       and a green tint say private (on). */
    input.switch {
      appearance: none;
      -webkit-appearance: none;
      margin: 0;
      position: relative;
      flex-shrink: 0;
      width: 38px;
      height: 20px;
      border-radius: 99px;
      background: var(--bg);
      border: 1px solid var(--border);
      cursor: pointer;
      transition: background 0.15s, border-color 0.15s;
    }
    input.switch::after {
      content: '';
      position: absolute;
      top: 50%;
      left: 2px;
      width: 14px;
      height: 14px;
      border-radius: 50%;
      background: var(--muted);
      transform: translateY(-50%);
      transition: left 0.15s, right 0.15s, background 0.15s;
    }
    input.switch:checked {
      background: rgba(90,132,102,0.15);
      border-color: rgba(90,132,102,0.6);
    }
    input.switch:checked::after { left: auto; right: 2px; background: var(--brand); }
    input.switch:focus-visible { outline: 1px solid rgba(90,132,102,0.8); outline-offset: 1px; }

    /* ── Site cards ──────────────────────────────────────────────────── */

    /* The primary action on a site card, sized like one: a target you can
       drop a folder onto without aiming. The whole strip is clickable, so
       the picker is reachable without hitting the link exactly. */
    .dropstrip {
      min-height: 116px;
      padding: 1.5rem 1rem;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 0.35rem;
      border: 1px dashed var(--border);
      border-radius: 6px;
      text-align: center;
      font-size: 0.72rem;
      color: var(--muted);
      letter-spacing: 0.04em;
      cursor: pointer;
    }
    .dropstrip:hover { border-color: rgba(90,132,102,0.5); }
    .dropstrip .drop-lead { font-size: 0.8rem; color: var(--text); }
    .dropstrip a { color: var(--brand); text-decoration: none; }
    .dropstrip a:hover { text-decoration: underline; }

    /* A folder is over the card: the whole card answers, not just the
       strip, because the whole card accepts the drop. */
    .site-card.drag {
      border-color: rgba(90,132,102,0.7);
      background: rgba(90,132,102,0.08);
    }
    .site-card.drag .dropstrip { border-color: rgba(90,132,102,0.7); color: var(--text); }

    /* Reordering, the notebook's grammar: grab the header, a ghost follows
       the cursor, the source dims to a dashed placeholder, and neighbours
       swap in place as the ghost crosses them. */
    .site-card .card-head { cursor: grab; user-select: none; }
    .site-card.drag-placeholder { opacity: 0.35; border-style: dashed; }
    .card-ghost { box-shadow: 0 8px 32px rgba(0,0,0,0.5); }
    .head-left, .head-right { display: flex; align-items: center; gap: 0.5rem; min-width: 0; }
    .head-left .card-title { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .handle { color: var(--muted); font-size: 0.8rem; }

    /* A deactivated site keeps its card and dims its name. */
    .site-card.inactive .card-title { opacity: 0.55; }

    /* Folded: the head stays, so the card still says which site it is and
       whether it needs attention. Only the body goes. */
    .site-card.folded .card-body { display: none; }
    /* The pill is the folded card's Status line, not a second copy of it.
       Open, the Status row inside the card carries the count; folded, that
       row is hidden and the pill takes over. Never both. */
    .site-card:not(.folded) .badge.needs { display: none; }
    .site-card.folded .card-head { border-bottom: none; }

    /* The remove panel is a popover under the button that opens it, not a
       block at the far end of the card — a question asked three hundred
       pixels from the thing you clicked is a question you have to go and
       find. Drawn by the page, never by the browser: the rule against
       borrowed voices is about alert() and confirm(), not about panels. */
    .card-head { position: relative; }
    .site-card .confirm {
      position: absolute;
      top: calc(100% + 0.4rem);
      right: 0.75rem;
      z-index: 20;
      width: min(24rem, calc(100% - 1.5rem));
      padding: 0.25rem 1rem 1rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.55);
      cursor: default;
      user-select: text;      /* the head sets none, for dragging */
    }
    /* The panel hangs below the head, so the card must not clip it. */
    .site-card { overflow: visible; }

    /* The staged draft, in a frame that cannot reach back. The sandbox
       attribute deliberately withholds allow-same-origin: the draft runs on
       an opaque origin, so a script in someone's own content cannot read
       this page or call its endpoints. */
    .preview-frame {
      width: 100%;
      height: 420px;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: #fff;
      margin-top: 0.5rem;
    }

    /* ── Charts: inline SVG, no library — the page loads no third-party
       code. The y-axis is part of the chart: a line without a scale is a
       shape, not a measurement. ─────────────────────────────────────── */
    .chart { width: 100%; height: 60px; display: block; }
    .chart-wrap { display: flex; gap: 0.5rem; margin-top: 0.8rem; }
    .chart-body { flex: 1; min-width: 0; }
    .chart-y {
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      align-items: flex-end;
      height: 60px;
      font-size: 0.62rem;
      color: var(--muted);
      white-space: nowrap;
    }
    .chart-labels {
      display: flex;
      justify-content: space-between;
      font-size: 0.62rem;
      color: var(--muted);
      margin-top: 0.2rem;
    }

    /* ── Utility and narrow screens ──────────────────────────────────── */
    .hidden { display: none !important; }

    @media (max-width: 560px) {
      .cfg-field { grid-template-columns: 1fr; row-gap: 0.25rem; }
      .cfg-field .cfg-hint { grid-column: 1; }
      .switch-row { grid-template-columns: 1fr auto; }
    }
  </style>
</head>
<body>

<div class="container">

  <div class="header">
    <div class="servette-logo">Serv<span class="ette">ette</span><span class="cursor">_</span></div>
    <div class="tagline">Admin</div>
  </div>

  <!-- Shown instead of the app when the browser lacks the pipeline. -->
  <div class="card hidden" id="unsupported">
    <div class="card-head">
      <span class="card-title">Browser not supported</span>
      <span class="badge badge-red">✕ missing gzip</span>
    </div>
    <div class="card-body">
      <p class="hint">This page builds content bundles with the browser's own
      <b>CompressionStream</b>, and this browser does not provide it. Recent
      versions of Chrome, Firefox (113+), and Safari (16.4+) do. Nothing is
      downloaded to work around it — this page loads no third-party code.</p>
    </div>
  </div>

  <div id="app" class="hidden">

  <!-- What needs review, said in words and pointed at its fix — a marker
       that only signals something is wrong, without saying what or where,
       is a puzzle rather than a notice. -->
  <div class="attention hidden" id="attention"></div>

  <!-- role="tab" without aria-selected announces a tab strip and then
       never says which tab is current; showTab keeps both in step. -->
  <nav class="tabs" role="tablist">
    <button class="tab active" id="tab-sites" type="button" role="tab"
            aria-controls="panel-sites" aria-selected="true">Sites</button>
    <button class="tab" id="tab-server" type="button" role="tab"
            aria-controls="panel-server" aria-selected="false">Server</button>
    <button class="tab" id="tab-stats" type="button" role="tab"
            aria-controls="panel-stats" aria-selected="false">Statistics</button>
  </nav>

  <!-- ══ Sites — one card per site, carrying everything about it. Cards
       can be added, removed, and reordered by dragging the header, because
       the cards ARE the site list: their order is config — the first
       domainless site answers unmatched Hosts. ══ -->
  <div id="panel-sites" role="tabpanel" class="hidden">
    <div id="site-cards"></div>
    <div class="add-zone">
      <button class="action" id="btn-add-site" type="button">+ Add a site</button>
    </div>
    <p class="error hidden" id="sites-error"></p>
  </div>

  <div id="panel-server" role="tabpanel" class="hidden">

    <div class="card">
      <div class="card-head">
        <span class="card-title">Status</span>
      </div>
      <div class="card-body">
        <div class="switch-row">
          <span class="k">Status</span>
          <span class="switch-value"><span id="status-state"></span>
            <span class="switch-act">
            <button class="action tiny" id="btn-restart" type="button">Restart</button>
            <button class="action tiny" id="btn-power" type="button">Stop</button>
            </span>
          </span>
        </div>
        <div class="rows" id="host-rows"></div>
        <div class="confirm hidden" id="stop-confirm">
          <div class="split"></div>
          <p class="hint">Stopping takes <b>every site on this server</b>
          offline until it is started again. This page keeps working — it is
          served by the terminal command, not by the server.</p>
          <div class="btn-row" style="margin-top:0.75rem">
            <button class="action danger" id="btn-stop-yes" type="button">Stop the server</button>
            <button class="action" id="btn-stop-no" type="button">Cancel</button>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title">Settings</span>
        <span class="badge badge-dim hidden" id="cfg-host-badge"></span>
      </div>
      <div class="card-body">
        <div id="cfg-host-fields"></div>
        <div class="btn-row" style="margin-top:0.9rem">
          <button class="action" id="btn-save-host" type="button">Save</button>
        </div>
        <p class="error hidden" id="cfg-host-error"></p>
      </div>
    </div>

  </div>

  <div id="panel-stats" role="tabpanel" class="hidden">

    <div class="card">
      <div class="card-head">
        <span class="card-title">Site traffic</span>
        <select id="traffic-window">
          <option value="1">last 24 hours</option>
          <option value="2">last 48 hours</option>
          <option value="7" selected>last 7 days</option>
          <option value="30">last 30 days</option>
          <option value="90">last 90 days</option>
        </select>
      </div>
      <div class="card-body">
        <div id="traffic-chart"></div>
        <p class="hint">Every request this server answered, split by what
        happened to it. Counted across every site the server answers for,
        not one site alone; visitor IP addresses stay in the server log,
        readable in the terminal.</p>
        <div class="rows" id="traffic-rows" style="margin-top:1.1rem"></div>
        <div class="btn-row" style="margin-top:1.1rem">
          <button class="action" id="btn-traffic-refresh" type="button">Refresh</button>
        </div>
        <p class="error hidden" id="traffic-error"></p>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <span class="card-title">Server load</span>
      </div>
      <div class="card-body">
        <div class="rows" id="load-rows"></div>
        <div id="load-chart"></div>
        <p class="hint">Averages since the server started; the line is live
        while this tab is open and is kept nowhere. High CPU on a static
        server usually means a bot, not popularity.</p>
        <p class="error hidden" id="load-error"></p>
      </div>
    </div>
  </div>

  </div><!-- /app -->

  <div class="note">
    This page is served on <b>127.0.0.1</b> through your SSH tunnel. It does
    not exist on the public internet. No signature or password is required
    because <b>only your SSH key can open the tunnel</b>.
    More information is available at
    <a href="https://servette.org" target="_blank" rel="noopener">servette.org</a>.
  </div>

</div>

<script>
  'use strict';

  /* ═══════════════════════════════════════════════════════════════════════
     One script, in the order a reader meets the page:

       1. Shared vocabulary — constants, formatting, and the page's state
       2. The loopback server — one door for every request
       3. Tabs
       4. The Sites tab — cards, reordering, publishing
       5. The Server tab — status, service controls, settings
       6. The Statistics tab — traffic, load, charts, the live meter
       7. Feature gate and startup

     Every render reads `statusData` and `cfgData` and nothing else, so the
     three tabs cannot disagree about what the server is doing.
     ═══════════════════════════════════════════════════════════════════════ */

  /* ══ 1. Shared vocabulary ═══════════════════════════════════════════ */

  const $ = (id) => document.getElementById(id);

  const MAX_BUNDLE_BYTES = 500 * 1024 * 1024;  // mirrors _MAX_BUNDLE_BYTES server-side

  // This run's passcode, carried by every request. Reaching the tunnel is
  // the authentication; the passcode only proves this is that run's page.
  const CODE = new URLSearchParams(location.search).get('t') || '';

  // A fetch that dies with no HTTP response at all surfaces as a TypeError
  // ('Failed to fetch') — the wire itself is gone, not the server saying
  // no. On this page the wire is the SSH tunnel, so say that instead of
  // echoing the browser's bare message (learned the hard way: issue #114).
  const TUNNEL_DOWN = 'Could not reach the server — the SSH tunnel is ' +
    'probably down. Check the terminal: if the ssh session or the admin ' +
    'command has ended, reconnect, run servette admin again, and open the ' +
    'fresh link it prints.';

  // What to tell the operator about a failure, decided once: a dead wire
  // reads as the tunnel, and anything else already carries the server's own
  // sentence — the same one the terminal would have printed. `about` names
  // what was being attempted, and is worth saying only for the second kind:
  // the tunnel sentence is about the tunnel, not about the request.
  const reason = (e, about) => (e instanceof TypeError) ? TUNNEL_DOWN
    : (about ? about + ': ' : '') + e.message;

  /* ── Text and markup. Everything the server sends is escaped before it
     reaches innerHTML; page-authored markup is interpolated as written. ── */

  const escapeHtml = (s) => String(s == null ? '' : s)
    .replace(/[&<>"']/g, (c) => '&#' + c.charCodeAt(0) + ';');

  // A label/value line. Both halves are interpolated raw, so a caller
  // passing server text escapes it first — factRow, just below, is the
  // wrapper that always does.
  const row = (k, v, cls) =>
    `<div class="${cls || ''}"><span class="k">${k}</span>${v}</div>`;

  // A fact is not a victory: rows read like the shell's status — label and
  // value, plainly — and only a row that needs attention wears a mark.
  // Two marks, because two things are true at once and one colour cannot
  // say both: red where visitors cannot use the site as configured (nothing
  // to serve, everyone locked out, the server stopped, an untrusted
  // certificate on a site that advertises a name), amber where it serves
  // and something still wants doing.
  const faultClass = (c) => c.blocking ? 'fault' : 'warn';
  const factRow = (c) => row(escapeHtml(c.label),
    c.ok ? escapeHtml(c.detail)
         : `<span class="${faultClass(c)}">${escapeHtml(c.detail)}</span>`);

  // One labelled input. The hint is page-authored markup (several carry
  // <b>), never server text; the value is escaped because it is.
  const field = (key, label, value, opts) => {
    const o = opts || {};
    return `<div class="cfg-field">` +
      `<label for="cfg-${key}">${label}</label>` +
      `<input id="cfg-${key}" type="${o.type || 'text'}"` +
      ` value="${escapeHtml(value)}">` +
      (o.hint ? `<div class="cfg-hint">${o.hint}</div>` : '') +
      `</div>`;
  };

  const fmtSize = (n) =>
    n < 1024 ? n + ' B'
    : n < 1024 * 1024 ? (n / 1024).toFixed(1) + ' KB'
    : (n / (1024 * 1024)).toFixed(1) + ' MB';

  // dd Mmm yy, then the time. Day-first and a two-digit year keep every
  // stamp the same width, so a column of them lines up.
  const when = (epoch) => {
    const d = new Date(epoch * 1000);
    return String(d.getDate()).padStart(2, '0') + ' ' +
           d.toLocaleString(undefined, { month: 'short' }) + ' ' +
           String(d.getFullYear()).slice(-2) + ', ' +
           d.toLocaleString(undefined, { hour: '2-digit', minute: '2-digit' });
  };

  /* ── Badges and error lines: the two ways this page reports on itself. ── */

  // Only the colour variant is swapped. A badge may carry a marker class
  // that says which badge it is (a site card has two), and replacing the
  // whole class list would quietly take that with it.
  const BADGE_VARIANTS = ['badge-green', 'badge-red', 'badge-dim', 'badge-warn'];
  function setBadge(el, cls, text) {
    el.classList.remove(...BADGE_VARIANTS);
    el.classList.add('badge', cls);
    el.textContent = text;
    el.classList.remove('hidden');
  }
  function showError(el, msg) { el.textContent = msg; el.classList.remove('hidden'); }
  function clearError(el) { el.classList.add('hidden'); }

  /* ── The page's state: one read of the server, rendered into every tab. ── */

  let statusData = null;      // GET /status  — what the box is doing
  let cfgData = null;         // GET /config  — what it is set to
  let latestVersion = null;   // GET /update  — asked once, by the operator

  /* ══ 2. The loopback server ═════════════════════════════════════════
     Every request goes through these. The passcode is attached in one
     place, and every POST is judged one way: the body is read before the
     status is believed, because the server answers a refusal with the
     sentence the terminal would have printed. ══ */

  const api = (path, params) =>
    path + '?' + new URLSearchParams(Object.assign({ t: CODE }, params || {}));

  async function getJSON(path, params) {
    const r = await fetch(api(path, params));
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }

  // `want` is the value of `result` that means this op succeeded: 'ok' from
  // the site, service, and swap doors, 'saved' from a settings write.
  async function post(path, body, want) {
    const r = await fetch(api(path), { method: 'POST', body: JSON.stringify(body) });
    let data = {};
    try { data = await r.json(); } catch (e) { data = {}; }
    if (!r.ok || data.result !== want)
      throw new Error(data.error || 'HTTP ' + r.status);
    return data;
  }

  // The one read every tab renders from. Both documents are fetched
  // together, so no tab can show status from one moment beside config
  // from another.
  async function refresh() {
    clearError($('cfg-host-error'));
    try {
      const [status, cfg] = await Promise.all([getJSON('/status'), getJSON('/config')]);
      statusData = status;
      cfgData = cfg;
      renderServer();
      renderSiteCards();
      clearError($('sites-error'));
    } catch (e) {
      setBadge($('cfg-host-badge'), 'badge-red', '✕ unreachable');
      const msg = (e instanceof TypeError) ? TUNNEL_DOWN
        : 'Could not read the server: ' + e.message +
          ' — if the terminal command was closed, re-run it and open the fresh link.';
      showError($('cfg-host-error'), msg);
      showError($('sites-error'), msg);
    }
  }

  // Asked once when the page opens, and never on a timer: Servette does not
  // phone home on its own schedule, and this is the operator asking.
  async function checkUpgrade() {
    try {
      latestVersion = (await getJSON('/update')).latest || null;
      if (latestVersion) renderServer();
    } catch (e) { /* offline, or PyPI unreachable — the row simply omits it */ }
  }

  /* ══ 3. Tabs — fragment-addressable, so a terminal command can
     deep-link. ══ */

  const PANELS = { sites: 'panel-sites', server: 'panel-server',
                   stats: 'panel-stats' };

  function showTab(name) {
    // Old bookmarks still land somewhere sensible.
    if (['status', 'config', 'settings'].includes(name)) name = 'server';
    if (['analytics', 'traffic'].includes(name)) name = 'stats';
    if (name === 'publish') name = 'sites';
    if (!PANELS[name]) name = 'sites';
    for (const key of Object.keys(PANELS)) {
      $(PANELS[key]).classList.toggle('hidden', key !== name);
      $('tab-' + key).classList.toggle('active', key === name);
      $('tab-' + key).setAttribute('aria-selected', String(key === name));
    }
    refresh();  // every tab renders from the same /status + /config truth
    if (name === 'stats') { loadTraffic(); startMeter(); } else stopMeter();
    if (location.hash !== '#' + name)
      history.replaceState(null, '', '#' + name + location.search);
  }

  $('tab-sites').addEventListener('click', () => showTab('sites'));
  $('tab-server').addEventListener('click', () => showTab('server'));
  $('tab-stats').addEventListener('click', () => showTab('stats'));

  /* ══ 4. The Sites tab ═══════════════════════════════════════════════
     One card per site, carrying everything about it. The cards ARE the
     site list: their order is config — the first domainless site answers
     unmatched Hosts — so reordering them is a config write. ══ */

  // What a site's unhealthy row is called on its card — the fault named,
  // rather than an exclamation mark standing in for the name.
  const NEEDS_WORD = {
    cert:     'Needs certificate',
    password: 'Needs password',
    dir:      'Folder missing',
  };

  // A card's index is its position in the DOM, read at the moment it is
  // needed: adding, removing, or dragging a card renumbers its neighbours,
  // and a stale index would act on the wrong site.
  // Which cards are folded shut. Kept here rather than on the card,
  // because every op re-renders the list and a card that sprang open on
  // each save would be worse than no fold at all. Keyed by domain where
  // there is one, since dragging renumbers indexes.
  const folded = new Set();
  const foldKey = (siteData, idx) => siteData.domain || '#' + idx;

  const cardIndex = (el) =>
    [...document.querySelectorAll('#site-cards .site-card')].indexOf(el);

  // One op door for add, remove, move, name, and certificate: the server
  // runs the same cores the terminal's add-site / remove-site / move-site /
  // set domain / certificate run, then the cards re-render from fresh
  // /config truth.
  async function siteOp(body, errEl) {
    clearError($('sites-error'));
    if (errEl) clearError(errEl);
    try {
      await post('/sites', body, 'ok');
      await refresh();
      return true;
    } catch (e) {
      showError(errEl || $('sites-error'), reason(e));
      if (body.op === 'move')
        renderSiteCards();  // snap the dragged DOM back to the loaded truth
      return false;
    }
  }

  $('btn-add-site').addEventListener('click', () => siteOp({ op: 'add' }));

  function renderSiteCards() {
    const wrap = $('site-cards');
    wrap.innerHTML = '';
    const sites = (cfgData && cfgData.sites) || [];
    // One site is a site; the plural is earned.
    $('tab-sites').textContent = sites.length === 1 ? 'Site' : 'Sites';
    sites.forEach((s, idx) => wrap.appendChild(buildSiteCard(s, idx)));
  }

  /* ── Reordering, in the notebook's grammar: grab the header, a ghost
     follows the cursor, the source dims to a placeholder, neighbours swap
     in place as the ghost crosses them — and the drop is a single move
     op, so the config write happens once, at the end. ── */

  function attachCardDrag(head, el) {
    head.addEventListener('mousedown', (e) => {
      if (e.button !== 0 || e.target.closest('button') || e.target.closest('a')
          || e.target.closest('.confirm')) return;   // the panel is not a handle
      const startX = e.clientX, startY = e.clientY;
      const rect = el.getBoundingClientRect();
      const offY = e.clientY - rect.top;
      const startIdx = cardIndex(el);
      let started = false, ghost = null;
      const move = (ev) => {
        // A drag begins only after 5px of travel, so a click on the header
        // is still a click.
        if (!started) {
          if (Math.abs(ev.clientX - startX) < 5 && Math.abs(ev.clientY - startY) < 5) return;
          started = true;
          ghost = el.cloneNode(true);
          ghost.classList.add('card-ghost');
          ghost.style.cssText = 'position:fixed;left:' + rect.left + 'px;top:' + rect.top +
            'px;width:' + rect.width + 'px;margin:0;pointer-events:none;z-index:1000;opacity:0.93;';
          document.body.appendChild(ghost);
          el.classList.add('drag-placeholder');
          document.body.style.userSelect = 'none';
        }
        ghost.style.top = (ev.clientY - offY) + 'px';
        const cards = [...document.querySelectorAll('#site-cards .site-card')];
        const i = cards.indexOf(el);
        const gr = ghost.getBoundingClientRect();
        if (i > 0 && gr.top < cards[i - 1].getBoundingClientRect().top)
          el.parentNode.insertBefore(el, cards[i - 1]);
        else if (i < cards.length - 1 && gr.bottom > cards[i + 1].getBoundingClientRect().bottom)
          el.parentNode.insertBefore(cards[i + 1], el);
      };
      const up = () => {
        document.removeEventListener('mousemove', move);
        document.removeEventListener('mouseup', up);
        if (!started) return;
        ghost.remove();
        el.classList.remove('drag-placeholder');
        document.body.style.userSelect = '';
        const endIdx = cardIndex(el);
        if (endIdx !== startIdx) siteOp({ op: 'move', from: startIdx, to: endIdx });
      };
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', up);
    });
  }

  /* ── The bundle builder: the pub tool's, with the signing removed. The
     server's contract (_extract_bundle / _land_bundle) is a tar.gz of
     plain files and directories, paths relative to the site root, no entry
     escaping it, under 500 MB uncompressed — POSTed to /upload with this
     run's passcode. Hand-rolled ustar, because the browser has no tar and
     this page loads no third-party code. ── */

  // The same hidden-path rule the server enforces: any '.'-segment except
  // .well-known is never served, so it is not bundled either — a .git or
  // .env under the site folder must not end up on the server.
  const isHiddenPath = (path) =>
    path.split('/').some((seg) => seg.startsWith('.') && seg !== '.well-known');

  // ustar splits a long path across two header fields; find a split point
  // that fits both, or refuse rather than emit a truncated name.
  function splitTarName(path) {
    const len = (s) => new TextEncoder().encode(s).length;
    if (len(path) <= 100) return ['', path];
    const parts = path.split('/');
    for (let i = 1; i < parts.length; i++) {
      const prefix = parts.slice(0, i).join('/');
      const name   = parts.slice(i).join('/');
      if (len(prefix) <= 155 && len(name) <= 100) return [prefix, name];
    }
    throw new Error(`path too long for a tar header: ${path}`);
  }

  function tarHeader(path, size, isDir, mtime) {
    const block = new Uint8Array(512);
    const enc = new TextEncoder();
    const putStr   = (off, s) => block.set(enc.encode(s), off);
    const putOctal = (off, width, n) => putStr(off, n.toString(8).padStart(width - 1, '0'));

    const [prefix, name] = splitTarName(isDir ? path + '/' : path);
    putStr(0, name);
    putOctal(100, 8, isDir ? 0o755 : 0o644);                // mode
    putOctal(108, 8, 0);                                    // uid
    putOctal(116, 8, 0);                                    // gid
    putOctal(124, 12, isDir ? 0 : size);                    // size
    putOctal(136, 12, mtime);                               // mtime
    block.set(enc.encode('        '), 148);                 // chksum: spaces while summing
    block[156] = isDir ? 0x35 : 0x30;                       // typeflag: '5' dir, '0' file
    putStr(257, 'ustar');                                   // magic (NUL-terminated)
    putStr(263, '00');                                      // version
    putOctal(329, 8, 0);                                    // devmajor
    putOctal(337, 8, 0);                                    // devminor
    putStr(345, prefix);

    let sum = 0;
    for (const b of block) sum += b;
    putOctal(148, 7, sum);                                  // 6 digits + NUL, then the space stays
    return block;
  }

  // entries: [{ path, bytes }] with '/'-separated site-root-relative paths.
  function buildTar(entries) {
    const mtime = Math.floor(Date.now() / 1000);
    // Every ancestor directory gets its own entry, so the archive is
    // complete rather than relying on the extractor to invent them.
    const dirs = new Set();
    for (const e of entries)
      for (let i = e.path.indexOf('/'); i !== -1; i = e.path.indexOf('/', i + 1))
        dirs.add(e.path.slice(0, i));

    const blocks = [];
    for (const d of [...dirs].sort())
      blocks.push(tarHeader(d, 0, true, mtime));
    for (const e of [...entries].sort((a, b) => a.path < b.path ? -1 : 1)) {
      blocks.push(tarHeader(e.path, e.bytes.length, false, mtime));
      blocks.push(e.bytes);
      const pad = (512 - (e.bytes.length % 512)) % 512;
      if (pad) blocks.push(new Uint8Array(pad));
    }
    blocks.push(new Uint8Array(1024));                      // end-of-archive

    const total = blocks.reduce((n, b) => n + b.length, 0);
    const tar = new Uint8Array(total);
    let off = 0;
    for (const b of blocks) { tar.set(b, off); off += b.length; }
    return tar;
  }

  async function gzipBytes(u8) {
    const stream = new Blob([u8]).stream().pipeThrough(new CompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  /* ── The drop door. A dropped folder walks the same intake as the
     picker: a single dropped directory is the site folder (its name
     stripped, exactly like the picker does), and several dropped items
     land as the site root's own entries. ── */

  // Read one directory to the end. The reader hands back a batch at a time
  // and signals the end with an empty one, so this cannot be a single call.
  async function readChildren(dirEntry, prefix, out) {
    const reader = dirEntry.createReader();
    for (;;) {
      const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
      if (!batch.length) break;
      for (const child of batch) await readDropped(child, prefix, out);
    }
  }

  async function readDropped(entry, prefix, out) {
    if (entry.isFile) {
      const file = await new Promise((res, rej) => entry.file(res, rej));
      out.push({ path: prefix + entry.name, file });
    } else if (entry.isDirectory) {
      await readChildren(entry, prefix + entry.name + '/', out);
    }
  }

  /* ── One card. Everything about a site lives inside it — publish, facts,
     domain, certificate, access, the outside test — so nothing on the card
     needs to say which site it means. ── */

  function buildSiteCard(siteData, idx) {
    const label = siteData.domain || 'site ' + idx;
    const inactive = siteData.active === false;
    const siteNeeds = (((statusData || {}).checks) || [])
      .filter((c) => c.site === idx && !c.ok);
    const card = document.createElement('div');
    card.className = 'card site-card' + (inactive ? ' inactive' : '');

    // The remove panel behind ✕: red deletes, amber pauses, neutral
    // cancels — one bullet says exactly what each choice means. A card
    // that is already deactivated offers only the delete.
    const confirmHtml =
      `<div class="confirm hidden">` +
      `<p class="hint"><b>Delete</b> removes this server's copies — the ` +
      `published files and their backup. Your originals in local storage ` +
      `are untouched; publishing again rebuilds the site.</p>` +
      (inactive ? '' :
        `<p class="hint"><b>Deactivate</b> keeps everything on the server ` +
        `and stops serving this site until you reactivate it.</p>`) +
      `<div class="btn-row" style="margin-top:0.75rem">` +
      `<button class="action danger do-delete" type="button">Delete</button>` +
      (inactive ? '' :
        `<button class="action pause do-deactivate" type="button">Deactivate</button>`) +
      `<button class="action do-cancel" type="button">Cancel</button>` +
      `</div></div>`;

    const bodyHtml = inactive
      ? (`<p class="hint">Not being served — its files and settings are kept, ` +
         `and visitors get the plain not-found answer until it is reactivated.</p>` +
         `<div class="btn-row" style="margin-top:0.75rem">` +
         `<button class="action do-reactivate" type="button">Reactivate</button></div>`)

      // ── What this site IS, at the top: its state, the address it
      // answers at, and the three things that decide both. What you DO to
      // it — publish, preview, download, redirect — follows underneath.
      : (`<div class="rows info"></div>` +

         `<div class="switch-row"><span class="k">Domain</span>` +
         `<span class="switch-value"><input class="dom-input" type="text" ` +
         `placeholder="example.com" value="${escapeHtml(siteData.domain)}">` +
         `<span class="switch-act"><button class="action tiny dom" type="button">` +
         `Set</button></span></span></div>` +
         `<div class="switch-row"><span class="k">Certificate</span>` +
         `<span class="switch-value"><span class="cert-state"></span>` +
         `<span class="switch-act"><button class="action tiny cert" type="button">` +
         `Get certificate</button></span></span></div>` +
         // The explanation belongs under the button it explains, not three
         // controls further down where it read as a note about access.
         `<p class="cfg-hint">A certificate is issued only for a name that ` +
         `already points here — check that the domain's DNS has an A record ` +
         `to this server's IP before requesting one.</p>` +

         `<div class="switch-row">` +
         `<label class="k auth-label">Access</label>` +
         `<span class="switch-value"><span class="auth-state"></span>` +
         `<span class="switch-act"><label class="auth-action"></label>` +
         `<input class="switch auth-switch" type="checkbox"></span></span></div>` +
         `<div class="auth-fields"></div>` +
         `<div class="btn-row auth-save hidden" style="margin-top:0.9rem">` +
         `<button class="action save-site" type="button">Save</button></div>` +
         `<p class="hint auth-hint"></p>` +

         // ── Publishing: drop a folder, look at it, ship it.
         `<div class="split"></div>` +
         `<div class="dropstrip"><span class="drop-lead">Drop this site's folder here</span>` +
         `<span>or <a href="#">browse for it</a></span></div>` +
         `<input type="file" webkitdirectory multiple class="hidden">` +
         `<p class="hint summary">The folder to drop is the one holding the ` +
         `site's <b>index.html</b>.</p>` +
         // Both of these act on the folder you chose, so both are dim until
         // you have chosen one. Download is not here: it acts on what is
         // live, and sits on the line that reports it.
         `<div class="btn-row" style="margin-top:0.75rem">` +
           `<button class="action pub" type="button" disabled ` +
           `title="Choose a folder first">Publish</button>` +
           // Look before you ship. Content only — the real domain, its
           // certificate, and its headers are not in scope here.
           `<button class="action prev" type="button" disabled ` +
           `title="Choose a folder first — this shows what you are about to ` +
           `publish, not the live site">Preview</button>` +
         `</div>` +
         `<div class="preview hidden">` +
           `<p class="hint">This is the folder you chose, served over the ` +
           `tunnel and not published. Links inside it work; the site's real ` +
           `domain, certificate, and headers are not part of what you are ` +
           `seeing.</p>` +
           `<iframe class="preview-frame" sandbox="allow-scripts allow-forms" ` +
           `title="Preview of the chosen folder"></iframe>` +
         `</div>` +
         `<div class="done hidden">` +
           `<p class="hint note-done" style="margin-top:0.75rem"></p>` +
         `</div>` +

         // ── What this site has served, newest first. Present always, not
         // only after a publish: "put yesterday's back" is a thing you
         // want on the day you did not publish anything.
         `<div class="split"></div>` +
         `<div class="switch-row"><span class="k">Published</span>` +
         `<span class="switch-value"><span class="ver-state">reading…</span>` +
         `<span class="switch-act">` +
         // The reverse of Publish, on the line that says what is live: the
         // live tree as the same tar.gz the publish door accepts, so what
         // comes down can go back up.
         `<button class="action tiny dl" type="button" ` +
         `title="Download the live content as a tar.gz">Download</button>` +
         `<button class="action tiny ver-refresh" type="button" ` +
         `title="Re-read this list. The page updates it after a publish or ` +
         `restore of its own — this is for one done in the terminal.">` +
         `Refresh</button>` +
         `</span></span></div>` +
         `<div class="rows versions"></div>` +

         // ── Redirects: one path on this site sends visitors to another
         // place. A setting, so it lives with the site's other settings
         // rather than as a file in the content.
         `<div class="split"></div>` +
         `<div class="switch-row"><span class="k">Redirects</span>` +
         `<span class="switch-value"><span class="redir-state"></span>` +
         `<span class="switch-act"><button class="action tiny redir-add" ` +
         `type="button">Add</button></span></span></div>` +
         `<div class="rows redirects"></div>` +
         `<div class="redir-form hidden">` +
           `<div class="cfg-field"><label>Path</label>` +
           `<input class="redir-from" type="text" placeholder="/talk"></div>` +
           `<div class="cfg-field"><label>Sends visitors to</label>` +
           `<input class="redir-to" type="text" placeholder="/2026/keynote"></div>` +
           `<p class="cfg-hint">Any path on this site: one that moved, a short ` +
           `link worth remembering, a name you want to keep working. It can ` +
           `point at another path here or at a full https:// address. Visitors ` +
           `are sent on with a <b>permanent</b> redirect, which browsers ` +
           `remember — so a wrong one outlives fixing it here.</p>` +
           `<div class="btn-row" style="margin-top:0.75rem">` +
           `<button class="action redir-save" type="button">Add redirect</button>` +
           `<button class="action redir-cancel" type="button">Cancel</button>` +
           `</div>` +
         `</div>` +

         // ── The one view a page on the tunnel cannot compute for itself.
         `<div class="split"></div>` +
         `<div class="btn-row">` +
         `<button class="action outside" type="button" disabled>Test connection</button>` +
         `</div>`)

    const q = (sel) => card.querySelector(sel);

    card.innerHTML =
      `<div class="card-head">` +
        `<span class="head-left"><span class="handle" title="Drag to reorder">⠿</span>` +
        `<span class="card-title">${escapeHtml(label)}</span></span>` +
        `<span class="head-right">` +
          // The fault badge names the fault and stays put. The state badge
          // beside it is the one publishing writes into, which is why they
          // are separate elements: overwriting the first would erase a
          // standing fault the moment a folder was read.
          (siteNeeds.length
            ? `<span class="badge ${siteNeeds.some((c) => c.blocking)
                 ? 'badge-red' : 'badge-warn'} needs" title="${escapeHtml(
                 siteNeeds.map((c) => c.detail).join(' · '))}">${
                 siteNeeds.length === 1
                   ? escapeHtml(NEEDS_WORD[siteNeeds[0].key] || 'Needs attention')
                   : siteNeeds.length + ' to review'}</span>`
            : '') +
          `<span class="badge state badge-dim${inactive ? '' : ' hidden'}">${
             inactive ? 'deactivated' : ''}</span>` +
          // Collapse, for a box serving more sites than fit on a screen.
          // Chevrons toward each other close; away, open.
          `<button class="action tiny fold" type="button" ` +
            `title="Collapse this card"><svg viewBox="0 0 16 16" width="12" ` +
            `height="12" fill="none" stroke="currentColor" stroke-width="1.6" ` +
            `stroke-linecap="round"><path class="fold-a" d="M4 2.5l4 3.5 4-3.5"></path>` +
            `<path class="fold-b" d="M4 13.5l4-3.5 4 3.5"></path></svg></button>` +
          // Removing a site is destructive, so it wears the destructive
          // colour all the time rather than only under the pointer — the
          // same rule the stop button follows.
          `<button class="action tiny danger del" type="button" ` +
            `title="Remove or deactivate">` +
            `<svg viewBox="0 0 16 16" width="12" height="12" fill="none" ` +
            `stroke="currentColor" stroke-width="1.3"><path d="M3 4h10M6.5 4V2.5h3V4` +
            `M5 4l0.6 9.5h4.8L11 4"></path></svg></button>` +
        `</span>` +
      `</div>` +
      `<div class="card-body">` + bodyHtml +
        `<p class="error hidden"></p>` +
      `</div>`;
    // Anchored to the head, so the panel opens where the trash button is
    // rather than at the far end of a long card. Appended after innerHTML
    // because it belongs to the head, not to the body's flow.
    q('.card-head').insertAdjacentHTML('beforeend', confirmHtml);

    const badge = q('.badge.state'), errEl = q('.error');
    // One error element, moved to whichever control refused. A message
    // about the login field is no use at the foot of the card, below Test
    // connection — the reason to fix something and the thing that fixes it
    // belong within a glance of each other.
    const errAt = (anchor, msg) => {
      if (anchor) anchor.insertAdjacentElement('afterend', errEl);
      showError(errEl, msg);
    };
    let files = null, folderName = '';
    const mark = (cls, text) => setBadge(badge, cls, text);

    /* ── Lifecycle: deactivate, reactivate, delete ── */

    // Deactivation rides the same settings write as everything else — it is
    // a setting ('set n active=no' is the terminal spelling).
    async function setActive(on) {
      clearError(errEl);
      try {
        await post('/config', { site: cardIndex(card),
                                values: { active: on ? 'yes' : 'no' } }, 'saved');
        await refresh();
      } catch (e) {
        showError(errEl, reason(e));
      }
    }

    q('.del').addEventListener('click', () => {
      clearError(errEl);
      q('.confirm').classList.toggle('hidden');
    });
    q('.do-cancel').addEventListener('click', () =>
      q('.confirm').classList.add('hidden'));
    q('.do-delete').addEventListener('click', () => {
      if (document.querySelectorAll('#site-cards .site-card').length === 1) {
        q('.confirm').classList.add('hidden');
        showError(errEl, "Can't remove the only site — a box needs at least one.");
        return;
      }
      siteOp({ op: 'remove', site: cardIndex(card) }, errEl);
    });
    const deact = q('.do-deactivate');
    if (deact) deact.addEventListener('click', () => setActive(false));
    const react = q('.do-reactivate');
    if (react) react.addEventListener('click', () => setActive(true));

    // ── Fold. The head keeps its title, its badges, and its controls, so
    // a folded card still says which site it is and whether it needs
    // attention — the reason to fold is length, not secrecy.
    const key = foldKey(siteData, idx);
    const applyFold = () => {
      const shut = folded.has(key);
      card.classList.toggle('folded', shut);
      q('.fold').title = shut ? 'Expand this card' : 'Collapse this card';
      // Shallow chevrons at the edges, with a clear gap between them.
      // Drawn tall and meeting in the middle they read as an X, which sits
      // beside a delete button and means the wrong thing entirely.
      // A caret needs its angle: rise about equal to half its width. The
      // gap between the two is what stops them reading as an X, so the
      // pair sit at the edges — apexes 4px apart in a 16px box.
      q('.fold-a').setAttribute('d', shut ? 'M4 6l4-3.5 4 3.5' : 'M4 2.5l4 3.5 4-3.5');
      q('.fold-b').setAttribute('d', shut ? 'M4 10l4 3.5 4-3.5' : 'M4 13.5l4-3.5 4 3.5');
    };
    q('.fold').addEventListener('click', () => {
      if (folded.has(key)) folded.delete(key); else folded.add(key);
      applyFold();
    });
    applyFold();

    attachCardDrag(q('.card-head'), card);

    // Everything below is the publish machinery only an active card carries.
    if (inactive) return card;
    const input = q('input[type="file"]'), pubBtn = q('.pub');
    const prevBtn = q('.prev');
    const summary = q('.summary'), done = q('.done');

    /* ── Reading a folder: one intake for both doors, the picker and the
       drop, so they cannot drift on the hidden-path rule or the summary. ── */

    function useFolder(items, name) {
      const kept = items.filter((en) => !isHiddenPath(en.path));
      const hidden = items.length - kept.length;
      if (!kept.length) {
        showError(errEl, 'That folder has no publishable files' +
          (hidden ? ` (${hidden} hidden entries were excluded).` : '.'));
        return;
      }
      files = kept;
      folderName = name;
      const totalBytes = kept.reduce((n, en) => n + en.file.size, 0);
      const hasIndex = kept.some((en) => en.path === 'index.html');
      summary.innerHTML =
        `<b>${escapeHtml(name)}/</b> — ${kept.length} file${kept.length === 1 ? '' : 's'}, ` +
        `${fmtSize(totalBytes)}` +
        (hidden ? ` · ${hidden} hidden entr${hidden === 1 ? 'y' : 'ies'} excluded ` +
                  `(paths starting with '.' are never served)` : '') +
        (hasIndex ? '' : ` · <span class="warn">no index.html at the top level — ` +
                         `the site root would show a directory miss</span>`);
      done.classList.add('hidden');
      q('.preview').classList.add('hidden');
      pubBtn.disabled = false;
      pubBtn.title = 'Publish this folder as the live site';
      prevBtn.disabled = false;
      prevBtn.title = 'Look at this folder before publishing it';
      mark('badge-green', '✓ folder read');
    }

    // The whole strip opens the picker, not just the link inside it — a
    // drop target that only accepts a click on two exact words is a
    // smaller target than it looks.
    q('.dropstrip').addEventListener('click', (e) => { e.preventDefault(); input.click(); });
    input.addEventListener('change', () => {
      clearError(errEl);
      const all = [...input.files];
      if (!all.length) return;
      // webkitRelativePath is '<picked folder>/rest…' — the folder name is
      // stripped so index.html sits at the bundle root, where the site wants it.
      useFolder(all.map((f) => ({
        path: f.webkitRelativePath.split('/').slice(1).join('/'), file: f,
      })).filter((en) => en.path), all[0].webkitRelativePath.split('/')[0]);
    });

    // dragenter/dragleave fire for every child element the pointer crosses,
    // so the highlight is counted rather than toggled — otherwise a large
    // drop zone flickers as the pointer moves over the text inside it.
    let dragDepth = 0;
    card.addEventListener('dragenter', (e) => {
      e.preventDefault();
      if (dragDepth++ === 0) card.classList.add('drag');
    });
    card.addEventListener('dragover', (e) => e.preventDefault());
    card.addEventListener('dragleave', () => {
      if (--dragDepth <= 0) { dragDepth = 0; card.classList.remove('drag'); }
    });
    card.addEventListener('drop', async (e) => {
      e.preventDefault();
      dragDepth = 0;
      card.classList.remove('drag');
      clearError(errEl);
      const entries = [...e.dataTransfer.items]
        .map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry())
        .filter(Boolean);
      if (!entries.length) return;
      try {
        const items = [];
        let name;
        if (entries.length === 1 && entries[0].isDirectory) {
          name = entries[0].name;
          await readChildren(entries[0], '', items);   // the folder's name is stripped
        } else {
          name = 'dropped files';
          for (const entry of entries) await readDropped(entry, '', items);
        }
        useFolder(items, name);
      } catch (err) {
        showError(errEl, 'Could not read the dropped folder: ' + err.message);
      }
    });

    /* ── Publishing: build the bundle in the browser, POST it whole. ── */

    pubBtn.addEventListener('click', async () => {
      clearError(errEl);
      pubBtn.disabled = true;
      mark('badge-dim', 'building…');
      try {
        const { entries, gz } = await buildBundle();

        // Not through post(): the body is the gzipped bundle itself rather
        // than JSON, and a refused passcode earns its own sentence.
        mark('badge-dim', 'publishing…');
        const resp = await fetch(api('/upload', { site: cardIndex(card) }),
                                 { method: 'POST', body: gz });
        let result = '';
        try { result = (await resp.json()).result; } catch (e) { result = ''; }

        if (resp.ok && result === 'published') {
          q('.note-done').innerHTML = `<b>${escapeHtml(folderName)}/</b> is live — ` +
            `${entries.length} file${entries.length === 1 ? '' : 's'}, ` +
            `${fmtSize(gz.length)} sent, swapped in atomically with the previous ` +
            `content kept as the one-step backup.`;
          done.classList.remove('hidden');
          mark('badge-green', '✓ published');
          loadVersions();          // the tree just replaced is now restorable
        } else if (resp.status === 403) {
          throw new Error('The server refused the passcode — close this page, ' +
                          'and open the fresh link the terminal prints for this run.');
        } else {
          throw new Error('The server rejected the bundle' +
                          (result ? ` (${result})` : ` (HTTP ${resp.status})`) +
                          ' — nothing was changed. The terminal log has the detail.');
        }
      } catch (e) {
        // Not reason(): a dropped tunnel mid-upload cannot half-publish (the
        // server swaps content in only after a complete, valid bundle has
        // landed), and the refusals thrown just above already end by saying
        // nothing was changed.
        showError(errEl, (e instanceof TypeError)
          ? TUNNEL_DOWN + ' Nothing was published.' : e.message);
        mark('badge-red', '✕ failed');
      }
      pubBtn.disabled = !files;
    });

    /* ── Preview: the same bundle, staged where only this page can reach
       it. Content only — HTTPS, the real domain, and the site's headers are
       not part of what a preview shows, and the note beside it says so. ── */

    // Building the bundle is the publish path's own work, so it is one
    // function and both buttons call it.
    async function buildBundle() {
      const entries = [];
      let totalBytes = 0;
      for (const { path, file } of files) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        totalBytes += bytes.length;
        if (totalBytes > MAX_BUNDLE_BYTES)
          throw new Error(`bundle exceeds ${fmtSize(MAX_BUNDLE_BYTES)} uncompressed — ` +
                          `the server would reject it`);
        entries.push({ path, bytes });
      }
      return { entries, gz: await gzipBytes(buildTar(entries)) };
    }

    prevBtn.addEventListener('click', async () => {
      clearError(errEl);
      prevBtn.disabled = true;
      mark('badge-dim', 'staging…');
      try {
        const { gz } = await buildBundle();
        const resp = await fetch(api('/preview', { site: siteIndex() }),
                                 { method: 'POST', body: gz });
        let data = {};
        try { data = await resp.json(); } catch (e) { data = {}; }
        if (!resp.ok || data.result !== 'staged')
          throw new Error('The server would not stage this folder' +
                          (data.result ? ` (${data.result})` : '') +
                          ' — the same check a publish would fail.');
        // The token is a path segment, not a query parameter: a draft's own
        // relative links resolve against the path and drop the query, so a
        // token in the query would load the page and 403 every stylesheet
        // it asks for. And it is the PREVIEW token, never the run's
        // passcode — a draft can read its own address, and must not learn
        // the credential that publishes.
        q('.preview-frame').src = '/preview/' + encodeURIComponent(data.token) +
          '/' + encodeURIComponent(siteIndex()) + '/';
        q('.preview').classList.remove('hidden');
        mark('badge-green', '✓ staged');
      } catch (e) {
        showError(errEl, reason(e));
        mark('badge-red', '✕ not staged');
      }
      prevBtn.disabled = !files;
    });

    /* ── The version ring: what this site has served, and one click back
       to any of it. The list is its own fetch because answering it walks
       every kept tree on disk, and /status is polled every few seconds. ── */

    // Every other control on this card reads its index at click time,
    // because dragging renumbers the neighbours. The version list is the
    // one that also runs while the card is still being built and is not in
    // the DOM yet — where cardIndex answers -1. It falls back to the index
    // the card was built for, which is right until the first drag.
    const siteIndex = () => {
      const i = cardIndex(card);
      return i < 0 ? idx : i;
    };

    async function loadVersions() {
        const state = q('.ver-state'), list = q('.versions');
        try {
          const v = await getJSON('/versions', { site: siteIndex() });
          const rows = v.versions || [];
          const live = rows.find((r) => r.live);
          // The live version's own size is the answer to "did the right
          // folder land" — a file count off by an order of magnitude is
          // the wrong folder, however right the site looks.
          // Two lines: what is there, then when it landed. One line ran to
          // the buttons and wrapped mid-date; the switch-row still centres
          // the label and the buttons against the pair.
          // A missing folder is marked here, because publishing is what
          // fixes it — the same rule every other fault follows. It has no
          // row of its own and used to sit in the facts block, which is
          // nowhere near anything that would put it right.
          const gone = checksFor.find((c) => c.key === 'dir');
          state.innerHTML = gone
            ? `<span class="${faultClass(gone)}">${escapeHtml(gone.detail)}</span>`
            : live
              ? `<span>${live.files} file${live.files === 1 ? '' : 's'}, ` +
                `${fmtSize(live.bytes)}</span>` +
                `<span>${escapeHtml(when(live.published))}</span>`
              : 'nothing published yet';
          // Nothing published is nothing to download, and offering it
          // anyway made the card contradict itself in two adjacent words.
          const dl = q('.dl');
          dl.disabled = !live || !live.files;
          dl.title = dl.disabled
            ? 'Nothing published yet — there is nothing to download'
            : 'Download the live content as a tar.gz';
          list.innerHTML = rows.length < 2 ? '' :
            rows.map((r) => row(escapeHtml(when(r.published)),
              `${r.files} file${r.files === 1 ? '' : 's'}, ${fmtSize(r.bytes)}` +
              (r.live ? ' <span class="ok">· live</span>'
                      : ` <button class="action tiny restore" type="button" ` +
                        `data-v="${escapeHtml(r.name)}">Restore</button>`))).join('') +
            `<p class="hint">The ${v.keep} most recent are kept. Restoring does ` +
            `not consume one — you can restore back.</p>`;
          for (const b of list.querySelectorAll('.restore'))
            b.addEventListener('click', async () => {
              b.disabled = true;
              b.textContent = 'restoring…';
              const ok = await siteOp({ op: 'restore', site: siteIndex(),
                                        version: b.dataset.v }, errEl);
              if (!ok) { b.disabled = false; b.textContent = 'Restore'; }
            });
        } catch (e) {
          state.textContent = '';
          showError(errEl, reason(e, 'Could not read the kept versions'));
        }
      }

    q('.ver-refresh').addEventListener('click', loadVersions);
    loadVersions();

    // The response carries Content-Disposition, so the browser saves it
    // rather than navigating: the operator stays on the page they were
    // working in.
    q('.dl').addEventListener('click', () => {
      clearError(errEl);
      location.assign(api('/download', { site: siteIndex() }));
    });

    /* ── Redirects. Both halves of the pair reach _set_site_value through
       the same settings write, so a rule the terminal refuses the page
       refuses with the same sentence. ── */

    const renderRedirects = () => {
      const table = siteData.redirects || {};
      const keys = Object.keys(table).sort();
      q('.redir-state').textContent = keys.length
        ? keys.length + (keys.length === 1 ? ' rule' : ' rules') : 'none';
      q('.redirects').innerHTML = keys.map((k) =>
        row(escapeHtml(k),
            `→ ${escapeHtml(table[k])} <button class="action tiny redir-del" ` +
            `type="button" data-k="${escapeHtml(k)}">Remove</button>`)).join('');
      for (const b of q('.redirects').querySelectorAll('.redir-del'))
        b.addEventListener('click', () => {
          b.disabled = true;
          // Nothing after the comma is the removal, the same spelling the
          // terminal takes.
          saveSettings({ redirect: b.dataset.k + ',' }, siteIndex(), badge, errEl);
        });
    };
    renderRedirects();

    q('.redir-add').addEventListener('click', () =>
      q('.redir-form').classList.toggle('hidden'));
    q('.redir-cancel').addEventListener('click', () =>
      q('.redir-form').classList.add('hidden'));
    q('.redir-save').addEventListener('click', () => {
      const from = q('.redir-from').value.trim();
      const to   = q('.redir-to').value.trim();
      clearError(errEl);
      if (!from || !to)
        return errAt(q('.redir-form'),
                     'Both the path and where it sends visitors are needed.');
      // The pair travels as one value, so the comma is the separator on both
      // surfaces — which leaves it out of reach as a character in the old
      // path. Rare, and said plainly rather than mangled quietly.
      if (from.includes(','))
        return errAt(q('.redir-form'), 'A path containing a comma has to be set by ' +
                     'editing servette.toml — the comma separates the pair here.');
      saveSettings({ redirect: from + ',' + to }, siteIndex(), badge, errEl);
    });

    /* ── The site's facts and the controls that change them. ── */

    const info = q('.info');
    const checksFor = (((statusData || {}).checks) || []).filter((c) => c.site === idx);
    const certRow = checksFor.find((c) => c.key === 'cert');
    const authRow = checksFor.find((c) => c.key === 'password');

    // What the operator has asked for but not yet saved. null means the
    // switch is still showing what the server says.
    let authDesired = null;
    const authOn = () => (authDesired === null) ? !!siteData.username : authDesired;

    /* ── What this card wants dealt with ───────────────────────────────
       ONE list, and everything about attention reads it: the count on the
       Status line, and the mark on the row that fixes each item. Two
       appearances per item, never three, and never a third register (a red
       paragraph somewhere else) for the same fact.

       It holds the server's stored faults AND an edit begun on this card
       and not finished. An unfinished edit is not a defect of the site —
       nothing is saved — but it is something to deal with, and a card that
       said "healthy" beside a form it was refusing to accept was lying
       about one of the two. */

    // The switch says private; what the login still needs, in the words of
    // the thing that is actually missing. Read live from the fields, so the
    // count follows the typing. null means nothing is missing.
    const authGap = () => {
      if (!authOn()) return null;
      const u = q('#cfg-username-' + idx), pw = q('#cfg-password-' + idx);
      if (!u) return null;                    // the fields are not rendered yet
      if (!u.value.trim()) return 'a username is needed';
      if (!siteData.has_password && !pw.value) return 'a password is needed';
      return null;
    };
    const authIncomplete = () => authGap() !== null;

    const reviewList = () => {
      const out = checksFor.filter((c) => !c.ok && c.key !== 'password');
      const gap = authGap();
      // The stored half-authenticated state and an edit in progress are the
      // same row's business, so only one of them is ever listed. The stored
      // one BLOCKS — a username saved with no password locks every visitor
      // out — while an edit half-typed has changed nothing yet.
      if (gap)
        out.push({ key: 'password',
                   blocking: !!siteData.username && !siteData.has_password,
                   detail: gap });
      else if (authRow && !authRow.ok)
        out.push(authRow);
      return out;
    };

    /* Two renders, because they run at different rates. renderInfo rebuilds
       the card's controls — including the login fields — and runs when the
       card's shape changes. renderAttention only re-states what needs
       dealing with, and runs on every keystroke, because whether the login
       is complete changes as you type. Rebuilding the fields on a keystroke
       would wipe what was being typed into them; that is exactly what the
       first version of this did. */

    const renderAttention = () => {
      const on = authOn();
      const pending = authDesired !== null && authDesired !== !!siteData.username;
      const needs = reviewList();
      const blocking = needs.some((c) => c.blocking);

      // The head pill is the Status line for a folded card, so it reads the
      // same list rather than a snapshot taken when the card was built.
      const pill = q('.badge.needs');
      if (pill) {
        pill.textContent = needs.length === 1
          ? (NEEDS_WORD[needs[0].key] || 'Needs attention')
          : needs.length + ' to review';
        pill.classList.toggle('badge-red', blocking);
        pill.classList.toggle('badge-warn', !blocking);
        pill.classList.toggle('hidden', !needs.length);
      }

      info.innerHTML =
        // The count, and the all-clear. It does not name its members: each
        // is named on the row that fixes it, and four names here would be a
        // sentence nobody reads. This is also the only place the card can
        // say the site is WELL — every other row speaks for its own subject.
        row('Status', needs.length
          ? `<span class="${blocking ? 'fault' : 'warn'}">` +
            `${needs.length} to review</span>`
          : '<span class="ok">✓</span> healthy') +
        // The site itself, one click away and in its own tab: the fastest
        // answer to "did that publish land" is looking at it.
        row('Serving', siteData.domain
          ? `<a href="${escapeHtml('https://' + siteData.domain)}" target="_blank" ` +
            `rel="noopener">${escapeHtml('https://' + siteData.domain)}</a>`
          : "this server's IP address (no domain set)");

      // One marker per row, taken from the same list the count read, so a
      // row and the count can never disagree about what is wrong.
      q('.cert-state').innerHTML = !certRow ? ''
        : certRow.ok ? escapeHtml(certRow.detail)
        : `<span class="${faultClass(certRow)}">${escapeHtml(certRow.detail)}</span>`;

      const mine = needs.find((c) => c.key === 'password');
      q('.auth-state').innerHTML = mine
        ? `<span class="${faultClass(mine)}">${escapeHtml(mine.detail)}</span>`
        // Going public needs nothing filled in, so it is a note, not a
        // thing to review.
        : (pending && !on)
          ? '<span class="pending">not saved yet — becoming public</span>'
          : (on ? 'private' : 'public');

      // Dim rather than a refusal to print: what is missing is already on
      // the access row and in the count, and a red paragraph saying it a
      // third time is what made one problem look like three.
      const saveBtn = q('.save-site');
      saveBtn.disabled = authIncomplete();
      saveBtn.title = saveBtn.disabled
        ? 'Fill in the username and password above, or make the site public'
        : 'Save the access settings for this site';
    };

    const renderInfo = () => {
      const on = authOn();
      const pending = authDesired !== null && authDesired !== !!siteData.username;

      // Naming and certifying are two acts on one card: the name saves
      // instantly, the certificate is asked for when you ask for it —
      // and the button says so while the site has no trusted one.
      const certBtn = q('.cert');
      certBtn.disabled = !siteData.domain;
      certBtn.classList.toggle('due', !!siteData.domain && !!certRow && !certRow.ok);
      certBtn.textContent = (certRow && certRow.ok) ? 'Renew' : 'Get certificate';
      certBtn.title = siteData.domain
        ? 'Request a certificate for ' + siteData.domain
        : 'Set a domain first — a certificate is issued for a name';

      q('.auth-switch').checked = on;
      q('.auth-action').textContent = on ? 'Make public' : 'Make private';
      q('.auth-fields').innerHTML = !on ? '' :
        field('username-' + idx, 'Username', siteData.username,
              { hint: 'Case-sensitive. Any characters except a colon.' }) +
        field('password-' + idx,
              siteData.has_password ? 'New password (blank = keep the current one)' : 'Password',
              '', { type: 'password',
                    hint: 'Case-sensitive. Any characters, spaces included. No length limit.' });
      q('.auth-save').classList.toggle('hidden', !(on || pending));
      q('.auth-hint').textContent = on ? ''
        : (siteData.username
           ? 'Saving makes the site public: the login is removed and the stored password deleted.'
           : '');

      // Typing changes whether the login is complete, so the count follows
      // the keystroke — but only the attention half re-renders, or the
      // fields would be rebuilt under the cursor.
      for (const el of q('.auth-fields').querySelectorAll('input'))
        el.addEventListener('input', () => { clearError(errEl); renderAttention(); });

      const outside = q('.outside');
      outside.disabled = !siteData.domain;
      outside.title = siteData.domain
        ? 'Opens the connection test on ' + siteData.domain
        : 'Needs a domain — a site without one has no public name to test';

      // Last, because it reads the fields the block above just created.
      renderAttention();
    };
    renderInfo();

    q('.auth-switch').addEventListener('change', (e) => {
      // A refusal describes the form as it stood when Save was pressed.
      // Move the switch and it is about a form that no longer exists, so it
      // goes with the state that produced it — it used to sit there in red
      // through every subsequent flip.
      clearError(errEl);
      authDesired = e.target.checked;
      renderInfo();
    });

    // The public internet's vantage is the one view a page on the tunnel
    // cannot compute: cross-origin responses are opaque by the browser's
    // rules, so the site's own reserved page is opened instead.
    q('.outside').addEventListener('click', () => {
      if (siteData.domain)
        window.open('https://' + siteData.domain + '/.well-known/servette-check',
                    '_blank', 'noopener');
    });

    // Setting the name is a config write and nothing more — instant, and
    // it cannot fail on someone else's DNS.
    q('.dom').addEventListener('click', async () => {
      const domain = q('.dom-input').value.trim().toLowerCase();
      clearError(errEl);
      if (!domain) return errAt(q('.dom-input').closest('.switch-row'),
                                'Type the domain first.');
      await siteOp({ op: 'name', site: cardIndex(card), domain }, errEl);
    });

    // Asking for the certificate is the slow, network-dependent act, so
    // it waits itself out and reports its own failure.
    q('.cert').addEventListener('click', async () => {
      const b = q('.cert');
      const old = b.textContent;
      b.disabled = true;
      b.textContent = 'requesting…';
      const ok = await siteOp({ op: 'certificate', site: cardIndex(card) }, errEl);
      if (!ok) { b.disabled = false; b.textContent = old; }
    });

    q('.save-site').addEventListener('click', () => {
      clearError(errEl);
      if (!authOn())
        return saveSettings({ username: '' }, cardIndex(card), badge, errEl);
      // No refusal to print: Save is dim until the login is complete, and
      // what is missing is already said on the access row and counted on
      // the status line. A red paragraph here was a third register for a
      // fact the card states twice.
      const username = q('#cfg-username-' + idx).value.trim();
      const pw = q('#cfg-password-' + idx).value;
      saveSettings(Object.assign({ username }, pw ? { password: pw } : {}),
                   cardIndex(card), badge, errEl);
    });

    return card;
  }

  /* ══ 5. The Server tab ══════════════════════════════════════════════
     What the box is doing, and how it is set. The settings forms run over
     the same validators the `set` command runs, so a value the terminal
     refuses the page refuses with the same sentence. Deliberately absent
     (the terminal keeps them): port and trusted proxy (behind-a-balancer
     deployments) and every lifecycle verb. The domain is not a form either
     — naming a site belongs on that site's card. ══ */

  const HOST_FIELDS = [
    ['email', 'Email',
     'Registers this server with the certificate authority — one account for ' +
     'every site here, not one per domain. Where renewal and expiry notices go.'],
    ['rate_limit', 'Rate limit',
     'Requests one visitor may make per minute. Over it, they are refused until their last minute falls back under the limit.'],
    ['auth_rate_limit', 'Auth rate limit',
     'Wrong-password attempts one visitor may make per minute, counted the same rolling way.'],
    ['cache_size_mb', 'File cache size (MB)',
     'Memory set aside to serve frequently requested files without re-reading the disk.'],
  ];

  function renderServer() {
    const d = statusData || {};
    const hostChecks = ((d.checks) || []).filter((c) => c.site === null);

    // What has no card of its own says its piece here; a site's trouble is
    // worn by that site's card on the Sites tab.
    const needs = hostChecks.filter((c) => !c.ok);
    $('attention').classList.toggle('hidden', !needs.length);
    $('attention').innerHTML = needs.map((c) =>
      `<b>This server</b> · ${escapeHtml(c.label)} — ${escapeHtml(c.detail)} ` +
      `<a href="#server">open Server →</a>`).join('<br>');
    for (const a of $('attention').querySelectorAll('a'))
      a.addEventListener('click', (e) => { e.preventDefault(); showTab('server'); });

    $('status-state').innerHTML = d.running
      ? '<span class="dot"></span>running'
      : '<span class="warn">stopped</span>';
    // Two controls, not three: restart is meaningless on a stopped server,
    // and the second is whichever of stop/start the state calls for. Both
    // are always present, dim when unavailable — the rule every button on
    // this page follows.
    $('btn-restart').disabled = !d.running;
    $('btn-restart').title = d.running
      ? 'Stop and start the service — applies a port change, or clears a wedged process'
      : 'Nothing to restart — the server is stopped';
    $('btn-power').textContent = d.running ? 'Stop' : 'Start';
    $('btn-power').classList.toggle('danger', !!d.running);
    $('btn-power').title = d.running
      ? 'Take every site on this server offline until it is started again'
      : 'Start the installed system service';

    // The upgrade row tells; it never installs. Upgrading is a terminal
    // act, so the row names the two commands and stops there.
    $('host-rows').innerHTML =
      row('Version', 'v' + (d.version || '?') +
        (latestVersion
          ? ` <span class="warn">v${escapeHtml(latestVersion)} available</span>` +
            ` — <b>pipx upgrade servette</b> in the terminal, then <b>enable</b>`
          : '')) +
      hostChecks.map(factRow).join('');

    renderHostFields();
    renderLoad();
  }

  function renderHostFields() {
    // Swap is a size the operator types — the terminal has always asked for
    // it that way — so it is a field among fields, saved by the same button.
    const sw = (statusData || {}).swap || {};
    // Allocated, not active: the kernel reports usable space, a page short
    // of the file, so a field showing 1099 for an 1100 MB file would make
    // typing the recommended number look like a resize that did not take.
    const swapField = (sw.allocated_mb == null && sw.recommended_mb == null) ? '' :
      field('swap_mb', 'Swap file (MB)',
            sw.allocated_mb != null ? sw.allocated_mb : '',
            { hint: 'Disk that absorbs a memory spike, so a burst past free RAM ' +
                    'cannot take the host down.' +
                    (sw.recommended_mb
                      ? ' Recommended for this host: <b>' + sw.recommended_mb + ' MB</b>.'
                      : '') });
    // Re-rendering the form under a cursor would discard what is being
    // typed, and the meter refreshes this tab every few seconds.
    if (document.activeElement && document.activeElement.id === 'cfg-swap_mb') return;
    $('cfg-host-fields').innerHTML =
      HOST_FIELDS.map(([k, l, h]) => field(k, l, ((cfgData || {}).host || {})[k], { hint: h }))
        .join('') + swapField;
  }

  /* ── The service's lifecycle: start, restart, stop. The page runs the
     lifecycle of an installed service; it never installs one. ── */

  async function serviceOp(b, op) {
    b.disabled = true;
    clearError($('cfg-host-error'));
    try {
      await post('/service', { op }, 'ok');
      await refresh();
    } catch (e) {
      showError($('cfg-host-error'), reason(e));
    }
    b.disabled = false;
  }

  $('btn-restart').addEventListener('click', () => serviceOp($('btn-restart'), 'restart'));
  // One control for the two states: starting needs no ceremony, stopping
  // takes every site offline and asks first — in the page's own voice, the
  // way a site card asks before deleting.
  $('btn-power').addEventListener('click', () => {
    if ((statusData || {}).running) $('stop-confirm').classList.toggle('hidden');
    else serviceOp($('btn-power'), 'start');
  });
  $('btn-stop-no').addEventListener('click', () =>
    $('stop-confirm').classList.add('hidden'));
  $('btn-stop-yes').addEventListener('click', async () => {
    $('stop-confirm').classList.add('hidden');
    await serviceOp($('btn-power'), 'stop');
  });

  /* ── Saving settings. One Save covers every field on a form. ── */

  async function saveSettings(values, siteIdx, badge, errEl) {
    clearError(errEl);
    setBadge(badge, 'badge-dim', 'saving…');
    try {
      await post('/config', { site: siteIdx, values }, 'saved');
      setBadge(badge, 'badge-green', '✓ saved');
      refresh();
    } catch (e) {
      setBadge(badge, 'badge-red', '✕ not saved');
      showError(errEl, reason(e) + ' Nothing was changed.');
    }
  }

  $('btn-save-host').addEventListener('click', async () => {
    const badge = $('cfg-host-badge'), errEl = $('cfg-host-error');
    clearError(errEl);
    const values = {};
    for (const [k] of HOST_FIELDS) values[k] = $('cfg-' + k).value.trim();

    // The swapfile is the one setting whose save does filesystem work, so it
    // runs only when its number actually changed — pressing Save on an
    // untouched field must never swapoff anything.
    const swapEl = $('cfg-swap_mb');
    const want = swapEl ? parseInt(swapEl.value.trim(), 10) : NaN;
    const allocated = ((statusData || {}).swap || {}).allocated_mb;
    const resize = swapEl && want > 0 && want !== allocated;
    if (swapEl && swapEl.value.trim() && !(want > 0))
      return showError(errEl, 'Swap file size must be a number of megabytes.');

    setBadge(badge, 'badge-dim', 'saving…');
    try {
      await post('/config', { site: 0, values }, 'saved');
      if (resize) {
        setBadge(badge, 'badge-dim', 'resizing the swapfile…');
        await post('/swap', { mb: want }, 'ok');
      }
      setBadge(badge, 'badge-green', '✓ saved');
      refresh();
    } catch (e) {
      setBadge(badge, 'badge-red', '✕ not saved');
      showError(errEl, reason(e));
    }
  });

  /* ══ 6. The Statistics tab ══════════════════════════════════════════
     Counted traffic across every site, and the box's own load. ══ */

  async function loadTraffic() {
    clearError($('traffic-error'));
    try {
      const t = await getJSON('/traffic', { days: $('traffic-window').value });
      const total = t.total || 0;
      // Status codes are the server's vocabulary, not the reader's: each
      // count is named for what actually happened.
      const NAMED = [['Files sent', ['200', '206']],
                     ['Already cached', ['304']],
                     ['Nothing there', ['404']],
                     ['Refused', ['403', '405']],
                     ['Sign-in needed', ['401']],
                     ['Rate limited', ['429']]];
      const named = NAMED
        .map(([name, codes]) => [name, codes.reduce(
          (n, c) => n + ((t.statuses || {})[c] || 0), 0)])
        .filter(([, n]) => n > 0);
      $('traffic-chart').innerHTML = total
        ? chart(lineSVG(t.days.map((d) => d[1])),
                t.days.length ? t.days[0][0] : '',
                t.days.length ? t.days[t.days.length - 1][0] : '',
                Math.max(...t.days.map((d) => d[1])))
        : '';
      $('traffic-rows').innerHTML = !total
        ? row('Requests', 'none in this window — or no readable journal on this host')
        : named.map(([name, n]) => row(name, String(n))).join('') +
          row('Total requests', `<b>${total}</b>`, 'ledger');

    } catch (e) {
      showError($('traffic-error'), reason(e, 'Could not read traffic'));
    }
  }

  $('btn-traffic-refresh').addEventListener('click', loadTraffic);
  $('traffic-window').addEventListener('change', loadTraffic);

  function renderLoad() {
    const l = ((statusData || {}).load) || {};
    $('load-rows').innerHTML =
      row('CPU', l.cpu_percent == null ? '(not available on this host)'
                 : l.cpu_percent.toFixed(1) + '% average' +
                   (l.started_at ? ' since ' + escapeHtml(when(l.started_at)) : '')) +
      row('Memory', l.memory_mb == null ? '(not available on this host)'
                    : l.memory_mb.toFixed(1) + ' MB');
    $('load-chart').innerHTML = cpuSeries.length < 2
      ? '<p class="hint">Live CPU — the line starts when you open this tab.</p>'
      : chart(lineSVG(cpuSeries),
              (cpuSeries.length - 1) * METER_SECONDS + 's ago',
              cpuSeries[cpuSeries.length - 1].toFixed(1) + '% now',
              Math.max(1, ...cpuSeries).toFixed(0), '%');
  }

  /* ── Charts: inline SVG, sized by viewBox, no library. Every chart is
     drawn with its scale — a line without a y-axis is a shape, not a
     measurement. ── */

  function lineSVG(values) {
    const w = 300, h = 60, max = Math.max(1, ...values);
    // A single reading has no slope to draw, so it is drawn as the flat
    // line it is, corner to corner.
    const pts = values.length === 1
      ? [`0,${(h - (values[0] / max) * h).toFixed(1)}`,
         `${w},${(h - (values[0] / max) * h).toFixed(1)}`]
      : values.map((v, i) =>
          `${(i / (values.length - 1) * w).toFixed(1)},${(h - (v / max) * h).toFixed(1)}`);
    return `<svg viewBox="0 0 ${w} ${h}" class="chart" preserveAspectRatio="none">` +
      `<polyline points="${pts.join(' ')}" fill="none" stroke="#5A8466" ` +
      `stroke-width="1.5" vector-effect="non-scaling-stroke"></polyline></svg>`;
  }

  // A chart, its y-axis (top of scale and zero), and its x labels.
  const chart = (svg, xFrom, xTo, yMax, unit) =>
    `<div class="chart-wrap"><div class="chart-y">` +
    `<span>${escapeHtml(String(yMax))}${unit || ''}</span><span>0</span></div>` +
    `<div class="chart-body">${svg}` +
    `<div class="chart-labels"><span>${escapeHtml(xFrom)}</span>` +
    `<span>${escapeHtml(xTo)}</span></div></div></div>`;

  /* ── The live meter: successive readings of the server's own cumulative
     CPU counter, differenced here. Nothing is sampled or stored on the
     server — the line exists only while this tab is open. ── */

  const METER_SECONDS = 3;
  let meterTimer = null, lastSample = null, cpuSeries = [];

  async function sampleLoad() {
    try {
      const d = await getJSON('/status');
      const l = d.load || {};
      if (l.cpu_ns != null && lastSample) {
        const dt = l.sampled_at - lastSample.at;
        if (dt > 0) {
          cpuSeries.push(Math.max(0,
            (l.cpu_ns - lastSample.ns) / 1_000_000_000 / dt * 100));
          if (cpuSeries.length > 60) cpuSeries.shift();
        }
      }
      if (l.cpu_ns != null) lastSample = { ns: l.cpu_ns, at: l.sampled_at };
      statusData = d;
      renderLoad();
      clearError($('load-error'));
    } catch (e) {
      // Nothing is listening any more — the admin command ended, or the
      // tunnel closed. Keep polling and every attempt prints another
      // 'channel N: open failed' in the operator's terminal.
      stopMeter();
      showError($('load-error'), reason(e));
    }
  }

  function startMeter() {
    if (meterTimer) return;
    meterTimer = setInterval(sampleLoad, METER_SECONDS * 1000);
    sampleLoad();
  }

  function stopMeter() {
    clearInterval(meterTimer);
    meterTimer = null;
  }

  // A backgrounded tab has nobody reading it, and a closing one is gone:
  // either way the polling stops, so an abandoned page cannot keep dialing
  // a tunnel whose command has ended.
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stopMeter();
    else if (!$('panel-stats').classList.contains('hidden')) startMeter();
  });
  window.addEventListener('pagehide', stopMeter);

  /* ══ 7. Feature gate and startup ════════════════════════════════════ */

  const supported = typeof CompressionStream === 'function';
  $(supported ? 'app' : 'unsupported').classList.remove('hidden');
  if (supported) {
    showTab((location.hash || '').replace('#', ''));
    checkUpgrade();
  }
</script>

</body>
</html>
"""


# The loopback handler
class _UIHandler(http.server.BaseHTTPRequestHandler):
    """The loopback server's one handler. GET / is the page (login page
    until the code is presented); POST /upload lands a content bundle. After
    _UI_MAX_BAD_CODES wrong guesses the run stops authenticating anyone,
    including the right code — re-run the command for a fresh one."""

    def log_message(self, fmt, *args):
        log.info("ui: " + fmt % args)  # the default writes to stderr, past the log

    def _respond(self, status, body, ctype="text/html; charset=utf-8", extra=()):
        # `body` is text for every JSON and message answer, and bytes for the
        # two that hand back a file: the site download and a preview asset.
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _serve_preview(self, path):
        """Serve one file out of a staged preview: /preview/TOKEN/SITE/rest.

        The token rides in the PATH, not the query, and that is the whole
        reason a preview is staged server-side at all. A draft's own
        `<link href="s.css">` resolves against the path and drops any query
        string, so a token in the query would authenticate the page and then
        403 every stylesheet and image it asks for — a preview showing
        unstyled text. With the token as a path segment, every relative
        reference inside the draft resolves and works, which is exactly what
        an operator is previewing for. (Found in a browser: the page loaded,
        the stylesheet did not.)

        Everything the draft could reach is bounded here. The token is not
        the run's passcode — a previewed page can read its own URL, and a
        script in someone's own content must not learn the credential that
        publishes. The tree is the staging directory, never the live one.
        Resolution is the server's own _resolve_request_path, so traversal
        and hidden paths are refused by the code that refuses them on the
        public side. And the response says twice that this is untrusted
        content: nosniff, and a CSP sandbox so the draft has an opaque
        origin even if it is opened outside the page's own frame."""
        rest = path[len("/preview"):]
        parts = rest[1:].split("/", 2) if rest.startswith("/") else []
        if len(parts) < 2:
            return self._respond(404, "Not a live preview.")
        token = getattr(self.server, "preview_code", "")
        if not token or not hmac.compare_digest(parts[0], token):
            return self._respond(403, "Not a live preview.")
        try:
            idx = int(parts[1])
        except ValueError:
            return self._respond(400, "site must be a whole number.")
        if not (0 <= idx < len(config.sites)):
            return self._respond(404, "No such site.")
        staged = _preview_dir(config.sites[idx])
        if not os.path.isdir(staged):
            return self._respond(404, "Nothing staged for this site.")
        file_path, status = _resolve_request_path("/" + (parts[2] if len(parts) > 2 else ""),
                                                  staged)
        if status != 200 or file_path is None:
            return self._respond(status, "Not in this preview."
                                 if status == 404 else "Refused.")
        try:
            with open(file_path, "rb") as f:
                body = f.read(_MAX_BUNDLE_BYTES)
        except OSError:
            return self._respond(404, "Not in this preview.")
        return self._respond(200, body, _mime_type(file_path), [
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "sandbox allow-scripts allow-forms"),
        ])

    def _auth(self):
        """"ok", "locked", "bad", or "none". A wrong code is a guess and is
        counted; a missing one is not. Compared as bytes so any input gets
        the constant-time path rather than a TypeError."""
        qs   = parse_qs(urlsplit(self.path).query)
        code = (qs.get("t") or [""])[0] or self.headers.get("X-Servette-Code", "")
        if self.server.bad_codes >= _UI_MAX_BAD_CODES:
            return "locked"
        if not code:
            return "none"
        if hmac.compare_digest(code.encode(), self.server.code.encode()):
            return "ok"
        self.server.bad_codes += 1
        return "bad"

    def do_GET(self):
        path = urlsplit(self.path).path

        # Preview content, on its own token. NOT the run's passcode: a
        # previewed page can read its own URL, and a draft with a script in
        # it must not be able to lift the credential that publishes. The
        # preview token buys exactly one thing — reading the staged tree —
        # and it is minted fresh by each staging.
        if path == "/preview" or path.startswith("/preview/"):
            return self._serve_preview(path)

        if path not in ("/", "/status", "/config", "/traffic", "/update",
                        "/versions", "/download"):
            return self._respond(404, "Not found.")
        auth = self._auth()
        if auth == "locked":
            return self._respond(403, "Too many wrong passcodes. Close this page and re-run the command.")
        if path == "/status":
            # The inside view, for the page's Status tab: exactly what
            # `status --json` prints, because it is the same function.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            return self._respond(200, json.dumps(_status_data()), "application/json")
        if path == "/config":
            # The Config tab's read half: exactly the vocabulary `set`
            # accepts, plus current values to fill the forms — and
            # has_password, a boolean only, so the page can show whether
            # protection is on without the hash ever crossing the wire.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            return self._respond(200, json.dumps({
                "host":  {k: getattr(config, k) for k in _SET_HOST_KEYS},
                "sites": [{"index": i, "domain": s.domain, "dir": s.serve_dir,
                           "active": s.active,
                           "username": s.username,
                           "redirects": s.redirects,
                           "has_password": bool(s.password_hash)}
                          for i, s in enumerate(config.sites)],
            }), "application/json")
        if path == "/update":
            # Asked, never volunteered: the page requests this when the
            # operator opens it, and the answer is cached for six hours.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            return self._respond(200, json.dumps({"latest": _upgrade_available()}),
                                 "application/json")

        if path == "/download":
            # Content leaves the box the way it arrived: the same tar.gz the
            # publish door takes, so what comes down can go back up. A site
            # too large to hold in memory says so rather than half-sending.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            try:
                idx = int(parse_qs(urlsplit(self.path).query).get("site", ["0"])[0])
            except ValueError:
                return self._respond(400, "site must be a whole number.")
            if not (0 <= idx < len(config.sites)):
                return self._respond(404, "No such site.")
            target = config.sites[idx]
            blob = _tar_live_site(target)
            if blob is None:
                return self._respond(413, json.dumps(
                    {"error": f"this site is larger than {_MAX_BUNDLE_BYTES // (1024 * 1024)} MB "
                              "— copy it with scp instead"}), "application/json")
            # The filename is built from the site's own name, never from
            # anything a request supplied.
            stem = re.sub(r"[^a-z0-9.-]", "-", (target.domain or f"site-{idx}").lower())
            return self._respond(200, blob, "application/gzip",
                                 [("Content-Disposition",
                                   f'attachment; filename="{stem}.tar.gz"')])

        if path == "/versions":
            # One site's kept trees. Its own endpoint rather than a field on
            # /status because answering it walks every tree on disk, and
            # /status is polled every few seconds while the page is open.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            try:
                idx = int(parse_qs(urlsplit(self.path).query).get("site", ["0"])[0])
            except ValueError:
                return self._respond(400, "site must be a whole number.")
            if not (0 <= idx < len(config.sites)):
                return self._respond(404, "No such site.")
            return self._respond(200, json.dumps(
                {"versions": _site_versions(config.sites[idx]),
                 "keep": _KEEP_VERSIONS}), "application/json")

        if path == "/traffic":
            # The Analytics tab's feed: the journal re-read as counts, and
            # never carrying a visitor's IP. The window is the reader's
            # choice, bounded — a request for a year would read a year of
            # journal to draw a chart nobody asked for.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            try:
                days = int(parse_qs(urlsplit(self.path).query).get("days", ["7"])[0])
            except ValueError:
                days = 7
            return self._respond(200, json.dumps(_traffic_summary(max(1, min(days, 90)))),
                                 "application/json")
        if auth == "ok":
            return self._respond(200, self.server.page)
        return self._respond(200, _UI_LOGIN_PAGE)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/upload", "/preview", "/config", "/sites", "/service",
                        "/swap"):
            return self._respond(404, "Not found.")
        if self._auth() != "ok":
            return self._respond(403, "Not logged in.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self._respond(400, "Empty upload.")

        if path == "/service":
            # The page runs the service's lifecycle but never its
            # installation: start, restart, stop. Stopping was withheld while
            # the fear was that a misclick could darken a box with no way
            # back — it cannot, because this page is served by the admin
            # command's own process, not the server's, so Start survives a
            # stopped server. `disable` stays terminal-only: removing the
            # unit is installation, and it would take this page's own way
            # back with it.
            if length > 512:
                return self._respond(413, "Body too large.")
            try:
                body_op = json.loads(self.rfile.read(length)).get("op", "start")
            except (ValueError, TypeError):
                body_op = "start"
            if not _service_file_exists():
                return self._respond(422, json.dumps(
                    {"error": "no system service installed — run 'enable' in the terminal"}),
                    "application/json")
            verb = str(body_op) if str(body_op) in ("start", "restart", "stop") else "start"
            try:
                subprocess.run(["systemctl", verb, "servette"],
                               check=True, capture_output=True)
            except (OSError, subprocess.CalledProcessError) as e:
                return self._respond(500, json.dumps(
                    {"error": f"could not {verb} the service ({e})"}), "application/json")
            return self._respond(200, json.dumps({"result": "ok"}), "application/json")

        if path == "/swap":
            # The size the terminal asks for at setup, asked for here
            # instead — the same _apply_swapfile underneath, so the two
            # surfaces cannot drift on disk checks, fstab, or the
            # restore-the-old-size path when a resize fails.
            if length > 512:
                return self._respond(413, "Body too large.")
            try:
                mb = int(json.loads(self.rfile.read(length)).get("mb"))
            except (ValueError, TypeError):
                return self._respond(422, json.dumps(
                    {"error": "a size in MB is needed"}), "application/json")
            if not (64 <= mb <= 65536):
                return self._respond(422, json.dumps(
                    {"error": "swap size must be 64-65536 MB"}), "application/json")
            err = _apply_swapfile(mb)
            return self._respond(200 if not err else 422,
                                 json.dumps({"result": "ok"} if not err
                                            else {"error": err}),
                                 "application/json")

        if path == "/sites":
            # The page's card row: add, remove, move — the same cores the
            # terminal's add-site / remove-site / move-site run. Add invents
            # the folder itself (a Servette-assigned name under the data
            # directory): the folder is where publishes land, not a question
            # an operator should have to answer.
            if length > 4096:
                return self._respond(413, "Body too large.")
            try:
                body = json.loads(self.rfile.read(length))
                op   = str(body.get("op") or "")
            except (ValueError, TypeError):
                return self._respond(400, "Malformed body.")
            try:
                if op == "add":
                    _append_site(_invent_site_dir())
                    err = ""
                    if _server_running() or _service_is_active():
                        _reload_server()
                elif op in ("remove", "move"):
                    try:
                        err = (_remove_site(int(body.get("site")))
                               if op == "remove"
                               else _move_site(int(body.get("from")),
                                               int(body.get("to"))))
                    except (TypeError, ValueError):
                        err = "site indexes must be whole numbers"
                elif op in ("name", "certificate"):
                    # Naming and certifying are two acts, and the page shows
                    # them as two. `name` is a config write: instant, and it
                    # cannot fail on someone else's DNS. `certificate` is the
                    # slow, network-dependent one — the same
                    # _obtain_trusted_cert the terminal runs, which persists
                    # and reloads on success. Between them a site can sit
                    # named but self-signed; that state is honest and loud on
                    # the card rather than hidden inside one button.
                    try:
                        idx = int(body.get("site"))
                    except (TypeError, ValueError):
                        idx = -1
                    if not (0 <= idx < len(config.sites)):
                        err = f"no site {idx}"
                    elif op == "name":
                        domain = str(body.get("domain") or "").strip().lower()
                        if not domain:
                            err = "a domain is needed"
                        elif _domain_in_use(domain, excluding=config.sites[idx]):
                            err = f"{domain} is already used by another site on this box"
                        else:
                            config.sites[idx].domain = domain
                            config.save()
                            err = ""
                            if _server_running() or _service_is_active():
                                _reload_server()
                    else:
                        target = config.sites[idx]
                        if not target.domain:
                            err = "set a domain first — a certificate is issued for a name"
                        else:
                            outcome = _obtain_trusted_cert(target.domain, target)
                            err = ("" if outcome is None else
                                   "the authority refused — is the domain's DNS "
                                   "pointing at this server? The terminal has the "
                                   "detail" if outcome == "refused" else
                                   "could not reach the certificate authority — "
                                   "try again in a moment")
                elif op == "restore":
                    # The same _restore_site the terminal's numbered list
                    # runs. The version arrives as a name over the wire and
                    # is matched against the ring inside the core, never
                    # taken as a path.
                    try:
                        idx = int(body.get("site"))
                    except (TypeError, ValueError):
                        idx = -1
                    if not (0 <= idx < len(config.sites)):
                        err = f"no site {idx}"
                    else:
                        want = body.get("version")
                        err = _restore_site(config.sites[idx],
                                            str(want) if want else None)
                else:
                    err = "unknown op"
            except PermissionError:
                return self._respond(500, json.dumps(
                    {"error": "writing the config needs root — re-run 'admin' elevated"}),
                    "application/json")
            return self._respond(200 if not err else 422,
                                 json.dumps({"result": "ok"} if not err
                                            else {"error": err}),
                                 "application/json")

        if path == "/config":
            # The Config tab's write half: the same validate-then-apply path
            # `set` runs, so a value the terminal refuses the page refuses
            # with the same sentence. The password travels only here — never
            # on argv, which is why `set` excludes it — and mirrors the
            # terminal prompt's rules: a username must exist, and blank
            # means unchanged, never cleared.
            if length > 65536:
                return self._respond(413, "Settings body too large.")
            try:
                body = json.loads(self.rfile.read(length))
                idx  = int(body.get("site") or 0)
                values = {str(k).strip().lower(): str(v)
                          for k, v in dict(body.get("values") or {}).items()}
            except (ValueError, TypeError):
                return self._respond(400, "Malformed settings body.")
            password = values.pop("password", "")
            pairs = list(values.items())
            if not pairs and not password:
                return self._respond(400, "No settings given.")
            if not (0 <= idx < len(config.sites)):
                return self._respond(422, json.dumps({"error": f"no site {idx}"}),
                                     "application/json")
            site = config.sites[idx]
            # Judged before anything applies: a password riding with an empty
            # (or emptied) username would otherwise half-write — the pairs
            # land and save before the password check could object.
            if password and not values.get("username", site.username):
                return self._respond(422, json.dumps(
                    {"error": "password: set a username first"}),
                    "application/json")
            try:
                err = _apply_settings(site, pairs) if pairs else ""
                if not err and password:
                    site.password_hash, site.password_salt = _hash_password(password)
                    config.save()
            except PermissionError:
                return self._respond(500, json.dumps(
                    {"error": "writing the config needs root — re-run 'admin' elevated"}),
                    "application/json")
            return self._respond(200 if not err else 422,
                                 json.dumps({"result": "saved"} if not err
                                            else {"error": err}),
                                 "application/json")

        if length > _MAX_BUNDLE_BYTES:
            return self._respond(413, "Bundle too large.")
        # The page names the site each card publishes; without the parameter
        # (older callers, the tests' bare posts) the command's own site stands.
        site = self.server.site
        picked = parse_qs(urlsplit(self.path).query).get("site")
        if picked:
            try:
                idx = int(picked[0])
            except ValueError:
                idx = -1
            if not (0 <= idx < len(config.sites)):
                return self._respond(422, json.dumps({"result": "rejected"}),
                                     "application/json")
            site = config.sites[idx]

        if path == "/preview":
            # The same bundle, staged where only this page can see it. A
            # fresh token per staging, so a preview's reach ends when the
            # next one is staged or the command exits.
            result = _stage_preview(site, self.rfile.read(length))
            if result != "staged":
                return self._respond(422, json.dumps({"result": result}),
                                     "application/json")
            self.server.preview_code = os.urandom(8).hex()
            return self._respond(200, json.dumps(
                {"result": "staged", "token": self.server.preview_code}),
                "application/json")

        result = _land_bundle(site, self.rfile.read(length), "browser upload")
        if result == "published" and getattr(self.server, "on_publish", None):
            self.server.on_publish(site)  # the terminal narrates what the browser did
        self._respond(200 if result == "published" else 422,
                      json.dumps({"result": result}), "application/json")


# Starting and stopping
def _start_ui(site, page, port=_UI_PORT):
    """Start the loopback page server for one command's lifetime: bound to
    127.0.0.1 only, one fresh code per run. Returns (httpd, code); the caller
    prints the URL and later hands httpd back to _stop_ui. A port already in
    use raises OSError for the caller to report."""
    httpd = http.server.ThreadingHTTPServer((_UI_HOST, port), _UIHandler)
    httpd.site, httpd.page = site, page
    httpd.code, httpd.bad_codes = os.urandom(3).hex(), 0
    httpd.preview_code = ""      # minted by the first staging, not before
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.code


def _stop_ui(httpd):
    """The page dies with the command: stop accepting, close the socket, and
    drop any staged preview — a draft nobody published has no business
    outliving the session that made it."""
    httpd.shutdown()
    httpd.server_close()
    _clear_previews()


# admin
def cmd_admin():
    site = config.sites[0]  # the fallback when an upload names no site
    try:
        httpd, code = _start_ui(site, _UI_ADMIN_PAGE)
    except OSError as e:
        print(f"  Could not open the page (port {_UI_PORT}: {e.strerror or e}).")
        return
    httpd.on_publish = lambda s: print(
        f"\n  Published from browser to {s.domain or s.serve_dir}: "
        "content swapped in — restore-site undoes it.")

    try:
        # Two labelled lines and nothing above them. The address is stable
        # and worth a bookmark, the passcode is this run's, and the login
        # page marries the two — printing them apart keeps a bookmark free
        # of the secret. Each label says what its line IS, which is why no
        # header announces the page: it could only repeat the label.
        print(f"  admin page  http://localhost:{_UI_PORT}/")
        print(f"  passcode    {code}")
        print()
        while True:
            try:
                # The prompt is where a reader looks when wondering what to
                # type, so the two things they might want are named there
                # rather than on lines of their own above. 'close the page'
                # names what 'back' actually ends — the page server this
                # command started — and matches the line printed on the way
                # out; the browser tab is the operator's to close.
                raw = input("  type 'help' if the page will not load, "
                            "'back' to close the page: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if raw in ("help", "?"):
                print("  A page that won't load means this SSH connection isn't carrying")
                print("  the tunnel. Add this line once to ~/.ssh/config on the computer")
                print("  you ssh FROM, inside this server's entry, then reconnect:")
                print(f"      LocalForward {_UI_PORT} 127.0.0.1:{_UI_PORT}")
                print(f"  The address is worth a bookmark — the login page it")
                print(f"  opens asks for this run's passcode: {code}")
                continue
            if raw in ("back", "done", "exit", "quit", "q"):
                break
    finally:
        _stop_ui(httpd)
        # An abandoned tab keeps asking for a port nothing answers on any
        # more, and the operator's own terminal is where SSH prints the
        # refusals ('channel N: open failed'). Cheaper to say than to
        # diagnose later.
        print("  Page closed — close the browser tab too, or your terminal")
        print("  will collect 'channel N: open failed' notices from it.")


# Formatting uptime
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


# Production issues
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
        # A public site is deliberately not listed: public is a choice, not
        # a defect — most sites are public. The half-state IS a defect: a
        # username with nothing stored to check locks every visitor out.
        if site.username and not site.password_hash:
            issues.append(f"a username with no stored password{tag} — visitors are locked out; run 'config' to set one")
    mem_kb, avail_kb, committed_kb = _meminfo()
    rec     = _swap_recommendation(mem_kb, committed_kb,
                                   _cache_headroom_mb(config.cache_size_mb))
    ours_mb, foreign_mb = _swap_sizes()
    offer   = _swap_offer(rec // (1024 * 1024) if rec else None,
                          os.path.exists(_SWAP_PATH), ours_mb, foreign_mb)
    if offer is not None:
        if ours_mb:
            # ours_mb, not SwapTotal: with a swap partition alongside, the
            # total printed a size the swapfile does not have.
            issues.append(f"swapfile {ours_mb} MB but {rec // (1024 * 1024)} MB "
                          "recommended — run 'enable' to resize")
        else:
            issues.append(f"no swap ({mem_kb // 1024} MB RAM) — run 'enable' to add a swapfile")
    # Both surfaces say the same thing about disk: the page reads the health
    # row, the terminal reads this list, and neither may know something the
    # other does not.
    disk = _disk_snapshot()
    if _disk_is_low(disk):
        issues.append(f"only {disk['free_mb']:,.0f} MB free where content lands — "
                      "a publish may fail; remove what the box no longer needs")
    return issues


# Cache warnings
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


# Runtime stats
def _runtime_stats(service_active):
    """Runtime stats for the running server as (label, value) rows — uptime, memory,
    PID — omitting any that aren't available. Service mode reads from systemd;
    session mode reads from /proc and the in-process start time."""
    rows = []
    if service_active:
        try:
            result = subprocess.run(
                ["systemctl", "show", "servette",
                 "--property=ActiveEnterTimestampMonotonic,MemoryCurrent,"
                 "CPUUsageNSec,MainPID"],
                capture_output=True, text=True
            )
            props = dict(
                line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line
            )
        except Exception:
            return rows
        elapsed = None
        mono = props.get("ActiveEnterTimestampMonotonic", "")
        if mono and mono != "0":
            try:
                with open("/proc/uptime") as f:
                    boot_elapsed = float(f.read().split()[0])
                elapsed = boot_elapsed - int(mono) / 1_000_000
                if elapsed >= 0:
                    rows.append(("Uptime", _format_uptime(elapsed)))
                else:
                    elapsed = None
            except Exception:
                elapsed = None
        mem = props.get("MemoryCurrent", "")
        if mem and mem.isdigit() and int(mem) > 0:
            rows.append(("Memory", f"{int(mem) / (1024 * 1024):.1f} MB"))
        # Average CPU for this run: systemd's cumulative CPU time over the
        # uptime just computed. Free — the same systemctl call already
        # answers it — and the honest reading on a static server, where
        # sustained CPU means something is wrong rather than popular. It is
        # an average, not a live meter: a spike that has passed is diluted
        # by every quiet second since.
        cpu = props.get("CPUUsageNSec", "")
        if elapsed and cpu.isdigit() and elapsed > 0:
            pct = (int(cpu) / 1_000_000_000) / elapsed * 100
            rows.append(("CPU", f"{pct:.1f}% average this run"))
        pid = props.get("MainPID", "")
        if pid and pid != "0":
            rows.append(("PID", pid))
    else:
        if _server_start_time is not None:
            rows.append(("Uptime", _format_uptime(time.monotonic() - _server_start_time)))
        try:
            if _IS_MACOS:
                out = subprocess.run(["ps", "-o", "rss=", "-p", str(os.getpid())],
                                     capture_output=True, text=True).stdout.strip()
                rows.append(("Memory", f"{int(out) / 1024:.1f} MB"))
            else:
                with open("/proc/self/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            rows.append(("Memory", f"{int(line.split()[1]) / 1024:.1f} MB"))
                            break
        except Exception:
            pass
        rows.append(("PID", str(os.getpid())))
    return rows


# The site rows
def _site_rows():
    """The per-site rows machine consumers read — shared by _status_data and
    `sites --json`, which deliberately pays only for this list: no systemctl
    round-trip, no cache-warning walk over every site's tree."""
    return [{
        "index":     i,
        "domain":    site.domain,
        "active":    site.active,
        "serve_dir": site.serve_dir,
        "auth":      bool(site.username),
        "cert_days": _cert_days_remaining(_resolve(site.cert_file)),
    } for i, site in enumerate(config.sites)]


def _health_checks():
    """Every health fact as a row, green included — the admin page's Health
    checks card. The same ground _production_issues walks, saying what passes
    as plainly as what needs attention: ok True is healthy, False needs it.
    `key` is stable for consumers; `site` carries the index where the row is
    site-scoped, None where it is host-wide — the admin page splits its
    Settings cards (This site / This server) on exactly that."""
    rows = []
    service_active = _service_is_active()
    running        = service_active or _server_running()
    # Labeled Mode, because that is what its three answers describe — and
    # the page prints no second Mode row beside it.
    rows.append({"key": "service", "site": None, "ok": running,
                 "blocking": not running, "label": "Mode",
                 "detail": "system service (survives reboots)" if service_active
                 else ("session only (stops when this terminal closes)" if running
                       else "stopped — 'start' brings it up")})
    if not _IS_MACOS:
        armed = os.path.exists(NETWATCH_PATH + ".timer")
        rows.append({"key": "netwatch", "site": None, "ok": armed,
                     "blocking": False, "label": "Network watchdog",
                     "detail": "armed (checks once per minute)" if armed
                     else "not installed — 'enable' provisions it"})
        mem_kb, _avail_kb, committed_kb = _meminfo()
        rec = _swap_recommendation(mem_kb, committed_kb,
                                   _cache_headroom_mb(config.cache_size_mb))
        ours_mb, foreign_mb = _swap_sizes()
        rec_mb = (rec // (1024 * 1024)) if rec else None
        offer  = _swap_offer(rec_mb, os.path.exists(_SWAP_PATH), ours_mb, foreign_mb)
        have   = (ours_mb or 0) + foreign_mb
        # The recommendation is named by the field that sets it, so this row
        # states the size and speaks up only when it falls short. `offer` is
        # a (description, hint) pair for the terminal's prompt — never a
        # number, which is what it used to be interpolated as here.
        if offer is None:
            detail = f"{have} MB active" if have else "not needed at this host's memory"
        elif have:
            detail = (f"{have} MB active, below the {rec_mb} MB recommendation"
                      if rec_mb else f"{have} MB active")
        else:
            detail = f"none — {rec_mb} MB recommended" if rec_mb else "none"
        rows.append({"key": "swap", "site": None, "ok": offer is None,
                     "blocking": False, "label": "Swap file", "detail": detail})
    # Disk is host-wide and platform-independent: a full disk is the outage
    # every other row assumes is not happening. A publish that cannot write
    # its tree fails in staging and leaves the live site alone, so this is a
    # warning rather than a fault — but an unread number prevents nothing,
    # which is why it is a row and not only a figure.
    disk = _disk_snapshot()
    if disk["free_mb"] is not None:
        low = _disk_is_low(disk)
        rows.append({"key": "disk", "site": None, "ok": not low,
                     "blocking": False, "label": "Disk",
                     "detail": f"{disk['free_mb']:,.0f} MB free of "
                               f"{disk['total_mb']:,.0f} MB"
                               + (" — publishing may fail" if low else "")})

    labeled = len(config.sites) > 1
    for i, site in enumerate(config.sites):
        tag = f"Site {i} · " if labeled else ""
        # The folder reports only when it is missing. Where content lives is
        # Servette's business, not the operator's (the folder-retirement
        # ruling) — but a serve directory that has vanished is a defect the
        # operator must hear about.
        dir_ok = bool(site.serve_dir) and os.path.exists(_resolve(site.serve_dir))
        if not dir_ok:
            rows.append({"key": "dir", "site": i, "ok": False, "blocking": True,
                         "label": tag + "Folder",
                         "detail": "missing — publish to recreate it"})
        days = _cert_days_remaining(_resolve(site.cert_file)) if site.cert_file else None
        covers = _domain_from_cert(_resolve(site.cert_file)) if site.cert_file else None
        mismatched = bool(site.domain) and bool(covers) and covers != site.domain
        cert_ok = days is not None and days > 0 and bool(site.domain) and not mismatched
        # Severity turns on whether the site claims a public name. With a
        # domain set, an untrusted certificate is a full-page browser
        # interstitial for everyone who visits it — the site is unusable at
        # the name it advertises. Without one, self-signed is simply where
        # every site starts, and reporting it in the same red as a locked-out
        # site would cry wolf on the normal case.
        rows.append({"key": "cert", "site": i, "ok": cert_ok,
                     "blocking": bool(site.domain) and not cert_ok,
                     "label": tag + "Certificate",
                     "days": days,
                     "detail": (f"{days} days remaining (auto-renew enabled)" if cert_ok
                                else f"issued for {covers} — get one for this name" if mismatched
                                else "expired" if (days is not None and days <= 0)
                                else "self-signed" if days is not None
                                else "not configured")})
        # A public site is a choice, not a defect: no password is healthy.
        # What IS broken is the half-state — a username with nothing stored
        # to check against, which locks every visitor out.
        half_auth = bool(site.username) and not site.password_hash
        rows.append({"key": "password", "site": i, "ok": not half_auth,
                     "blocking": half_auth, "label": tag + "Access",
                     "detail": ("private — visitors sign in" if site.username and site.password_hash
                                else "a username with no stored password — set one below, or make the site public"
                                if half_auth
                                else "public — anyone can view it (the form below makes it private)")})
    return rows


def _load_snapshot():
    """Average CPU for this run and current memory, as numbers — the same
    facts _status_rows prints for the terminal, in the form the page
    renders. An average, not a live meter: cumulative CPU time over the
    time the server has been up, so a spike that has passed is diluted by
    every quiet second since. None for any figure that cannot be read."""
    out = {"cpu_percent": None, "memory_mb": None, "uptime_s": None,
           "started_at": None, "cpu_ns": None, "sampled_at": time.time()}
    if _service_is_active():
        try:
            result = subprocess.run(
                ["systemctl", "show", "servette",
                 "--property=ActiveEnterTimestampMonotonic,MemoryCurrent,CPUUsageNSec"],
                capture_output=True, text=True)
            props = dict(line.split("=", 1) for line in result.stdout.strip().splitlines()
                         if "=" in line)
            mono = props.get("ActiveEnterTimestampMonotonic", "")
            if mono.isdigit() and mono != "0":
                with open("/proc/uptime") as f:
                    elapsed = float(f.read().split()[0]) - int(mono) / 1_000_000
                if elapsed > 0:
                    out["uptime_s"] = elapsed
                    out["started_at"] = out["sampled_at"] - elapsed
                    cpu = props.get("CPUUsageNSec", "")
                    if cpu.isdigit():
                        # The raw counter travels too: successive readings
                        # are what let the page draw a live meter without
                        # anything being sampled or stored server-side.
                        out["cpu_ns"] = int(cpu)
                        out["cpu_percent"] = (int(cpu) / 1_000_000_000) / elapsed * 100
            mem = props.get("MemoryCurrent", "")
            if mem.isdigit() and int(mem) > 0:
                out["memory_mb"] = int(mem) / (1024 * 1024)
        except Exception:
            pass
    elif _server_running() and _server_start_time is not None:
        # Session mode: the server IS this process, so its own CPU clock
        # answers — no systemd to ask.
        elapsed = time.monotonic() - _server_start_time
        if elapsed > 0:
            times = os.times()
            out["uptime_s"] = elapsed
            out["started_at"] = out["sampled_at"] - elapsed
            out["cpu_ns"] = int((times[0] + times[1]) * 1_000_000_000)
            out["cpu_percent"] = (times[0] + times[1]) / elapsed * 100
    return out


_LATEST_CACHE = {"at": None, "version": None}


def _latest_release(ttl=21600):
    """The newest Servette on PyPI, or None when the question cannot be
    answered. Servette makes no outbound call on its own schedule: this one
    happens when the operator opens the admin page and asks, is cached for
    six hours, and fails silently — a box with no route out, or a PyPI
    having a bad day, must cost the page nothing but this row."""
    now = time.monotonic()
    if _LATEST_CACHE["at"] is not None and now - _LATEST_CACHE["at"] < ttl:
        return _LATEST_CACHE["version"]
    version = None
    try:
        with urllib.request.urlopen(
                "https://pypi.org/pypi/servette/json", timeout=4) as response:
            version = json.loads(response.read().decode("utf-8"))["info"]["version"]
    except Exception:
        version = None
    _LATEST_CACHE["at"], _LATEST_CACHE["version"] = now, version
    return version


def _version_parts(text):
    """A version as comparable integers, ignoring anything that is not one —
    Servette's own scheme is 0.<yy>.<doy>, and a suffix should never make a
    release look older than it is."""
    parts = []
    for chunk in str(text).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _upgrade_available():
    """The newer version's string when PyPI has one, else None. Telling is
    all Servette does here: installing is the package manager's job, and
    stays in the terminal (DECISIONS, 'pip install is the only installation
    path')."""
    latest = _latest_release()
    if latest and _version_parts(latest) > _version_parts(__version__):
        return latest
    return None


def _swap_snapshot():
    """Servette's own swapfile as numbers — what is allocated, what the
    kernel reports active, and what the sizing recommends. None on a host
    with no swap to speak of (macOS manages its own).

    The two sizes differ by design and the difference matters. /proc/swaps
    reports USABLE space, which is the file minus one page of header, so a
    1100 MB swapfile reads as 1099 MB active. A field showing the active
    number would invite an operator to type the recommended 1100, save, and
    watch it come back 1099 — a resize that looks broken while working
    perfectly. The field shows what was allocated; the status row keeps
    reporting what is active, which is the honest thing for a status row."""
    if _IS_MACOS:
        return {"allocated_mb": None, "active_mb": None, "recommended_mb": None}
    mem_kb, _avail_kb, committed_kb = _meminfo()
    rec = _swap_recommendation(mem_kb, committed_kb,
                               _cache_headroom_mb(config.cache_size_mb))
    ours_mb, _foreign = _swap_sizes()
    allocated = None
    try:
        allocated = os.path.getsize(_SWAP_PATH) // (1024 * 1024)
    except OSError:
        pass                      # no swapfile of ours on this host
    return {"allocated_mb": allocated, "active_mb": ours_mb,
            "recommended_mb": (rec // (1024 * 1024)) if rec else None}


def _disk_snapshot():
    """Free and total disk on the filesystem holding the data directory —
    where site content, the versions kept behind it, and the config live.
    That filesystem rather than '/' because it is the one a publish can
    fill. None for a figure the host will not answer."""
    try:
        total, _used, free = shutil.disk_usage(BASE_DIR)
    except OSError:
        return {"free_mb": None, "total_mb": None}
    return {"free_mb": free / (1024 * 1024), "total_mb": total / (1024 * 1024)}


def _disk_is_low(disk):
    """Whether free disk is low enough to say so. Two thresholds, because
    one does not fit both a 4 GB Pi card and a 200 GB VPS: an absolute
    floor that a publish plus its kept versions can exhaust, and a
    fraction that catches a large disk filling steadily."""
    if disk["free_mb"] is None:
        return False
    return (disk["free_mb"] < _DISK_LOW_MB
            or disk["free_mb"] < disk["total_mb"] * _DISK_LOW_FRACTION)


def _status_data():
    """The status snapshot as data — the shape `status --json` prints, for
    external tooling. cert_days is None when no certificate is readable;
    `checks` is the health-row form of the same facts, `load` the
    utilization figures, and `disk` the space left where content lands."""
    service_active = _service_is_active()
    running        = service_active or _server_running()
    return {
        "version":  __version__,
        "running":  running,
        "mode":     "service" if service_active else ("session" if running else None),
        "sites":    _site_rows(),
        "issues":   _production_issues(),
        "warnings": _cache_warnings(),
        "checks":   _health_checks(),
        "load":     _load_snapshot(),
        "swap":     _swap_snapshot(),
        "disk":     _disk_snapshot(),
    }


# status
def cmd_status(json_mode=False):
    if json_mode:
        print(json.dumps(_status_data(), indent=2))
        return
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


# setup
def cmd_setup():
    with _spinner("Detecting public IP..."):
        try:
            public_ip = urllib.request.urlopen("https://api.ipify.org", timeout=5).read().decode()
        except Exception:
            public_ip = "your.server.ip"

    _banner("Getting Started")

    site = config.sites[0]  # the site setup provisions; 'add-site' handles the rest

    # Step 1 — the folder. Setup must never finish with nothing to serve (#37),
    # and no longer needs to write a file to keep that promise: it creates the
    # folder if missing, and a folder with no index.html answers its domain
    # with the embedded error page, which reports what the connection is
    # actually sending.
    print()
    print("  Step 1 — Site folder")
    serve_path = _resolve(site.serve_dir)
    if not os.path.isdir(serve_path):
        if _is_within_base_dir(serve_path):
            try:
                os.makedirs(serve_path, exist_ok=True)
                _chown_operator(serve_path)  # root created it; the operator owns it
                print(f"  Created {serve_path}.")
            except OSError as e:
                print(f"  Could not create {serve_path}: {e}")
        else:
            # Unreachable from any command: every folder Servette assigns is
            # under BASE_DIR. It takes a hand-edited servette.toml to get
            # here, so the sentence names the file rather than a command
            # that no longer exists.
            print(f"  serve_dir {serve_path} is outside {BASE_DIR}, where the publish")
            print(f"  swap and the service sandbox both need it — fix it in {Config.CONFIG_FILE}.")
    if os.path.isdir(serve_path):
        if os.path.exists(os.path.join(serve_path, "index.html")):
            print(f"  Serving {serve_path}.")
        else:
            print(f"  {serve_path} has no index.html yet — until you publish one, the")
            print("  site answers with Servette's error page: it reports that the")
            print("  server is up and what the connection is actually sending.")

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

    # The one-time client-side line for the browser admin page — said here
    # because setup is the moment the operator is already reading.
    print()
    print("  Optional, once, on the computer you ssh FROM: add this line to")
    print("  ~/.ssh/config inside this server's entry, and 'admin' opens a")
    print("  browser page over this same SSH connection:")
    print(f"      LocalForward {_UI_PORT} 127.0.0.1:{_UI_PORT}")


# `set [n] key=value ...` is the write half of the tooling surface (`status
# --json` and `sites --json` are the read half): external tools drive it over
# SSH, which is the authentication — no network admin API exists, by design.
# Host pairs
def _set_host_value(target, key, value):
    """Validate one host-level pair and apply it to target (config, or a
    scratch object during the validation pass). Returns an error string,
    empty on success."""
    if key == "port":
        if not (value.isdigit() and 0 < int(value) < 65536):
            return "port must be 1-65535"
        target.port = int(value)
    elif key == "email":
        target.email = value
    elif key in ("rate_limit", "auth_rate_limit"):
        if not (value.isdigit() and int(value) > 0):
            return f"{key} must be a positive integer"
        setattr(target, key, int(value))
    elif key == "cache_size_mb":
        if not (value.isdigit() and int(value) > 0):
            return "cache_size_mb must be a positive integer"
        target.cache_size_mb = int(value)
    elif key == "trusted_proxy":
        if value:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                return "trusted_proxy must be an IP address (or empty to clear)"
        target.trusted_proxy = value
    return ""


# Site pairs
def _set_site_value(target, key, value):
    """Validate one per-site pair and apply it to target (the chosen site, or
    a scratch Site during the validation pass). Returns an error string,
    empty on success."""
    if key == "username":
        # Auth is one switch, not two half-states: a cleared username takes
        # the stored password with it, on every surface that writes settings
        # (`set` and the page alike, since both land here) — the same rule
        # the interactive prompt has always kept.
        target.username = value
        if not value:
            target.password_hash = ""
            target.password_salt = ""
    elif key == "redirect":
        # One pair per token: 'redirect=/path,/target' adds or replaces,
        # 'redirect=/path,' removes. The table is a mapping and `set` speaks
        # in scalars, so the comma is where the two grammars meet.
        # Validation is _clean_redirects — the same function the config load
        # runs, so a redirect the file would refuse the command refuses too.
        src, comma, dst = value.partition(",")
        if not comma:
            return ("a redirect is a pair: redirect=/path,/where-it-goes "
                    "(or /path, to remove)")
        src, dst = src.strip(), dst.strip()
        table = dict(target.redirects)
        if not dst:
            if not table.pop(src.rstrip("/") or "/", None):
                return f"no redirect from {src}"
        else:
            checked = _clean_redirects({src: dst})
            if not checked:
                return ("a redirect goes from a site path to a site path or an "
                        "http(s) URL, and may not point at itself")
            table.update(checked)
        target.redirects = table
    elif key == "active":
        # The pause between serving and deleting: a deactivated site keeps
        # its config and files but is invisible to request routing.
        v = value.strip().lower()
        if v not in ("yes", "no"):
            return "active must be yes or no"
        target.active = (v == "yes")
    return ""


# The set vocabulary
_SET_HOST_KEYS = ("port", "email", "rate_limit", "auth_rate_limit",
                  "cache_size_mb", "trusted_proxy")
_SET_SITE_KEYS = ("username", "active", "redirect")


def _set_usage():
    print("  Usage: set [n] key=value ...")
    print(f"  Host keys: {', '.join(_SET_HOST_KEYS)}")
    print(f"  Site keys: {', '.join(_SET_SITE_KEYS)} (site index first, default 0)")
    print("  A redirect is a pair: redirect=/path,/where-it-goes — and")
    print("  redirect=/path, (nothing after the comma) removes it.")


# set
def _apply_settings(site, pairs):
    """Validate `pairs` ([(key, value)]) against scratch objects, then apply
    them to config/`site` and save — the one settings write path, shared by
    `set` and the admin page's Config tab so the two surfaces cannot drift.
    Returns an error string, empty on success; every pair is checked before
    any is applied, so a bad pair never leaves the config half-written.
    PermissionError from the save propagates — each caller words its own
    hint."""
    class _ScratchHost:
        pass
    scratch_host, scratch_site = _ScratchHost(), Site()
    # The scratch site starts blank for every scalar — each is simply
    # overwritten — but the redirect table is edited rather than replaced,
    # so validating a removal against an empty table would refuse a
    # redirect that is really there.
    scratch_site.redirects = dict(site.redirects)
    for key, value in pairs:
        if key not in _SET_HOST_KEYS + _SET_SITE_KEYS:
            return f"unknown setting: {key}"
        err = (_set_host_value(scratch_host, key, value) if key in _SET_HOST_KEYS
               else _set_site_value(scratch_site, key, value))
        if err:
            return f"{key}: {err}"
    for key, value in pairs:
        if key in _SET_HOST_KEYS:
            _set_host_value(config, key, value)
        else:
            _set_site_value(site, key, value)
    config.save()
    return ""


def cmd_set(args):
    """`set [n] key=value ...` — non-interactive configuration for tooling.
    The optional leading index picks the site for site keys (default 0).
    Deliberately absent: password (a secret on argv leaks into shell history
    and the process table — set it interactively), and domain (bound up with
    certificate issuance — run 'config cert')."""
    site = config.sites[0]
    if args and args[0].isdigit():
        idx = int(args[0])
        if idx >= len(config.sites):
            print(f"  No site {idx} — 'sites' lists {len(config.sites)}.")
            return
        site, args = config.sites[idx], args[1:]
    pairs = []
    for token in args:
        key, eq, value = token.partition("=")
        key = key.strip().lower()
        if not eq or key not in _SET_HOST_KEYS + _SET_SITE_KEYS:
            print(f"  Unknown or malformed: {token!r}")
            _set_usage()
            return
        pairs.append((key, value))
    if not pairs:
        _set_usage()
        return
    try:
        err = _apply_settings(site, pairs)
    except PermissionError:
        print("  Error: writing the config needs root, and sudo is unavailable — re-run as root.")
        return
    if err:
        print(f"  {err}")
        return
    print(f"  Saved {len(pairs)} setting{'s' if len(pairs) != 1 else ''}.")


# The startup refresh
def _startup_refresh():
    """What 'update' once did after swapping versions, done at every shell
    launch instead: code now arrives through the package manager, which cannot
    refresh a stale systemd unit — so the shell notices on its next run.
    Prints nothing when nothing is stale, and fails soft: a refresh that needs
    root just says so.

    Auto-refresh is gated on the environment matching: a stale unit whose
    data directory or interpreter differs from this shell's is reported and
    left alone — rewriting it would repoint a live service at this shell's
    environment, which only an explicit 'enable' may do."""
    if _stale_units():
        drift = _service_env_drift()
        if drift:
            print("  The enabled service was set up from a different environment:")
            for d in drift:
                print(f"    - {d}")
            print("  Leaving it untouched — run 'enable' to re-provision from this shell.")
        else:
            try:
                _write_unit_files()
                if _service_is_active():
                    _reload_server()
                print(f"  Service refreshed to v{__version__}.")
            except (PermissionError, FileNotFoundError, subprocess.CalledProcessError):
                # Option A of the refresh decision (#99): notice and tell. The
                # shell runs unprivileged, and a password prompt nobody asked
                # for at launch is the one place self-elevation would stop
                # feeling like Servette asking — so the refresh names the one
                # command that finishes the upgrade, and 'enable' does its own
                # asking when run.
                print("  Service unit is stale for this version — run 'enable' to refresh it.")
            except ValueError:
                # The writer refuses a path systemd cannot carry safely, and has
                # already printed why. A refusal must not take the launch down
                # with it: _startup_refresh runs on every interactive start, so
                # an un-writable unit has to leave a usable shell behind.
                print("  Leaving the existing service untouched.")


# Elevating to root
# The commands that never do their work as an ordinary user: they write the
# config the service reads, the unit files, or a site folder the service user
# owns. Read-only ones (status, sites, log) are absent deliberately — they must
# keep working without a password prompt.
_ROOT_COMMANDS = ("setup", "config", "enable", "disable", "set", "admin",
                  "publish", "restore-site")

# What sudo made of the last elevated command. The one-shot `servette <command>`
# form exits with it, so tooling driving Servette over SSH sees a refused
# password as a failure rather than a silent success; the interactive shell
# ignores it and keeps its prompt.
_elevated_status = 0


def _needs_root(cmd):
    """Whether this command, run right now, has work only root can do.

    An unreadable servette.toml makes that true of everything, including the
    read-only commands: without the file this process is holding defaults, and
    reporting those as the operator's settings would be a lie. One password
    prompt beats a confident wrong answer.

    start and stop are the conditional pair. They drive systemd when a unit is
    installed — root — but otherwise act on a session server living in this
    process, which an elevated child could neither keep alive after it exits
    nor reach in its parent. On that path they stay here and a privileged port
    reports its own bind failure, which is the truthful answer."""
    if config.unreadable:
        return True
    # Session mode owns nothing root does: the data directory is the operator's
    # own (~/.servette on macOS) and there is no systemd to drive, so no command
    # has work only root can do. A privileged port bind reports its own failure,
    # exactly like the Linux session-server path. The unreadable check stays
    # above this one deliberately — a config left root-owned by the retired
    # `sudo servette` era still needs one elevation to read.
    if _IS_MACOS:
        return False
    if cmd in _ROOT_COMMANDS:
        return True
    if cmd == "start":
        return _service_file_exists()
    if cmd == "stop":
        return _service_is_active() and not _server_running()
    return False


def _elevate(cmd, args):
    """Re-run one command under sudo, from a non-root invocation. Always
    returns True: the command has been handled, whatever sudo made of it.

    sys.executable is an absolute path, so sudo resolves the interpreter
    without consulting PATH — which is the whole point. Nothing has to be
    installed into a directory on sudo's secure_path for this to work, so an
    install needs no symlink and the operator never types sudo themselves.

    SERVETTE_HOME is passed through explicitly because sudo resets the
    environment: losing it would silently point the elevated run at a
    different data directory than the one the operator is working in, which is
    a far worse failure than not elevating at all.

    A child process rather than an exec, so the interactive shell survives the
    privileged command and returns to its prompt instead of vanishing.

    The one notice goes to stderr: the child owns stdout, and `status --json`
    has to stay parseable through an elevation."""
    global _elevated_status
    if not shutil.which("sudo"):
        print(f"  '{cmd}' needs root, and sudo is not installed — re-run as root.",
              file=sys.stderr)
        _elevated_status = 1
        return True
    # Nothing is printed on the way in. sudo announces itself when it wants
    # a password, and says nothing when it does not — which is the right
    # amount either way. A line of ours ahead of it told an operator who
    # just typed an admin command something they already knew.
    argv = ["sudo"]
    if "SERVETTE_HOME" in os.environ:
        argv.append("--preserve-env=SERVETTE_HOME")
    argv += [sys.executable, "-m", "servette", cmd, *args]
    try:
        _elevated_status = subprocess.run(argv).returncode
    except KeyboardInterrupt:
        print(file=sys.stderr)   # the operator declined the password prompt
        _elevated_status = 130
    # The child may have changed the config this process is holding — a shell
    # that kept showing the pre-elevation values would be reporting settings
    # that no longer exist.
    config.reload_if_changed()
    return True


# The dispatcher
def run_command(cmd, args):
    """Dispatch one command by name; False for a name it doesn't know. Shared
    verbatim by the interactive loop and the one-shot `servette <command>`
    argv form — one dispatcher, so the two surfaces can never drift. quit and
    help stay in the interactive loop: they are about the loop itself."""
    if os.geteuid() != 0 and _needs_root(cmd):
        return _elevate(cmd, args)

    # A root shell never elevates, so nothing else re-reads the file for it —
    # and a long-lived root session would otherwise act on hours-old state,
    # silently reverting anything written since (by tooling over SSH, or a
    # service-side migration) with its next save. Unprivileged shells get the
    # same freshness through _elevate's child, which loads from disk.
    if os.geteuid() == 0:
        config.reload_if_changed()

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
        cmd_status(json_mode="--json" in args)
    elif cmd == "sites":
        if "--json" in args:
            print(json.dumps(_site_rows(), indent=2))
        else:
            _config_sites()
    elif cmd == "set":
        cmd_set(args)
    elif cmd == "log":
        try:
            cmd_log(int(args[0]) if args else 20)
        except ValueError:
            print("  Usage: log [number]")
    elif cmd == "traffic":
        cmd_traffic()
    elif cmd == "admin":
        cmd_admin()
    elif cmd == "publish":
        cmd_publish()
    elif cmd == "restore-site":
        site = _config_site_arg(args)
        if site is not None:
            cmd_restore_site(site)
    else:
        return False
    return True


# The shell
def shell():
    _banner("Servette — The Simple Secure Server")
    print(HELP)
    _startup_refresh()

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

        if cmd in ("help", "?"):
            print(HELP)
        elif cmd in ("quit", "exit"):
            stop_server()
            print("  Goodbye.")
            break
        elif not run_command(cmd, args):
            print(f"  Unknown command: {cmd}. Type 'help' for a list of commands.")


# Config is a module-level singleton, instantiated here (not at its class
# definition, near the top) because migrating a pre-multi-site flat config
# calls _domain_from_cert() to backfill the migrated site's domain, and that
# function is defined much later, in Certificate management. Dependency
# injection (passing config into every function) is the textbook alternative,
# but the stdlib request handlers have fixed signatures and cannot accept
# extra arguments. In a single-file server that is always run as a process,
# the global is the right call.

# The data directory must exist before the singleton loads from it. Unwritable
# (not root on a fresh host) is not fatal: config falls back to defaults and
# read-only commands still work — the first privileged command creates it.
try:
    os.makedirs(BASE_DIR, exist_ok=True)
except OSError:
    pass

# The config singleton
config = Config()

# The entry point
def main():
    try:
        # The inner finally flushes INSIDE the guarded region. stdout on a pipe
        # is block-buffered, and output smaller than the buffer reaches the
        # pipe only at interpreter shutdown — after this function has returned,
        # where the EPIPE becomes an "Exception ignored" message and a wrong
        # exit status instead of the handled case below. Flushing here makes
        # the broken pipe surface where it can be caught, on every Python
        # version and output size.
        try:
            _main()
        finally:
            sys.stdout.flush()
    except BrokenPipeError:
        # A consumer closed stdout mid-print — `servette status | head` is the
        # canonical case. That is the consumer's normal behavior, not a fault
        # here, so no traceback. stdout is re-pointed at devnull before exit so
        # the interpreter's shutdown flush cannot raise the same error again,
        # and the exit status is 141 (128+SIGPIPE): what the shell reports for
        # any tool that dies on a closed pipe, so pipelines see the convention
        # they already handle.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(141)


def _main():
    if sys.argv[1:2] == ["--serve"]:
        # Fail closed. Defaults standing in for an unreadable config is the
        # SHELL's affordance — it elevates and reads again as root. A service
        # has no second try, and the defaults carry no password: serving them
        # would open a protected site to the world because a file's ownership
        # broke. Exiting nonzero puts the truth in the journal instead.
        if config.unreadable:
            log.error("servette.toml exists but cannot be read — refusing to "
                      "serve defaults in its place. Run 'enable' to restore "
                      "its ownership (servette, operator-group-readable, 0640): %s",
                      config.CONFIG_FILE)
            sys.exit(1)
        start_server()
        try:
            _watch_server()
        except KeyboardInterrupt:
            stop_server()
        else:
            if _reload_requested:
                log.info("Exiting to reload — systemd restarts the service")
            else:
                log.error("HTTPS server stopped unexpectedly — exiting so systemd restarts the service")
            sys.exit(1)
    elif len(sys.argv) > 1:
        cmd, args = sys.argv[1].lower(), sys.argv[2:]
        if not run_command(cmd, args):
            print(f"Unknown command: {cmd}. Run 'servette' for the interactive shell and its command list.")
            sys.exit(2)
        # The work may have happened in an elevated child. Exit with what sudo
        # made of it, so a refused password reads as a failure to whatever is
        # driving this over SSH instead of a silent success.
        if _elevated_status:
            sys.exit(_elevated_status)
    else:
        shell()


if __name__ == "__main__":
    main()
