# SERVER

*Every incoming request: config, rate limiting, the file cache, site selection, the request handler, and the threaded HTTP servers.*

*Authored here. `servette.py` is built from the Markdown sources in `src/` by [`build.py`](build.py) — edit the Markdown, not the generated file.*

## Config

```python
# ── Config ────────────────────────────────────────────────────────────────────


def _resolve(path):
    """Return path as-is if absolute, otherwise anchor it to BASE_DIR."""
    return path if os.path.isabs(path) else os.path.join(BASE_DIR, path)


```

> scrypt cost parameters — OWASP baseline (N=2**14, r=8, p=1 ≈ 16 MB per hash).
> scrypt is memory-hard: each guess must hold that much RAM, denying an attacker
> who steals the hash the cheap GPU parallelism that PBKDF2 (CPU-hard) allows.
> ~16 MB and ~30 ms per check stays comfortable even on a Raspberry Pi.
>
> That same memory-hardness is a lever pointed back at the server: the per-IP
> auth-fail limit bounds one address, but many distinct IPs each get a first
> hash before their own limiter engages, and concurrent requests are otherwise
> bounded only by `MAX_CONNECTIONS` — up to ~128 × 16 MB ≈ 2 GB transient, an
> OOM on the 512 MB-class hosts Servette targets. `_SCRYPT_SLOTS` bounds the
> spike: at most 4 verification hashes run at once (≤ 64 MB); requests past
> that *block* rather than fail. The worst case is arithmetic, not luck — ~40
> hashes/s drain against at most `MAX_CONNECTIONS` waiters is a ~3 s ceiling —
> so an attack degrades login to slow, never to unavailable (a shed-with-503
> design would hand attackers a deterministic denial of every legitimate login).

```python
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
```

> Leave domain blank for a self-signed certificate (browsers will warn visitors)

```python
domain = {s(site.domain)}
serve_dir = {s(site.serve_dir)}
cert_file = {s(site.cert_file)}
key_file = {s(site.key_file)}

```

> Leave username blank to disable password protection

```python
username = {s(site.username)}

```

> Site publish channel: where signed content bundles are pulled from, and the
> public key (distinct from Servette's own release-signing key) that verifies
> them. Leave blank to disable — no polling happens without both set.

```python
publish_url = {s(site.publish_url)}
publish_key = {s(site.publish_key)}

```

> Machine-generated — do not edit by hand

```python
password_hash = {s(site.password_hash)}
password_salt = {s(site.password_salt)}
""" for site in self.sites)

        content = f"""\
```

> Servette configuration — https://github.com/andy-emerson/servette
>
> Host-level settings below apply to every site on this box. Each [[site]]
> block below is one hosted domain — its own folder, certificate, auth, and
> publish channel.

```python

port = {self.port}

```

> Rate limiting (requests per minute per IP, shared across all sites)

```python
rate_limit = {self.rate_limit}
auth_rate_limit = {self.auth_rate_limit}

```

> Browser cache policy: no-store, no-cache, or max-age

```python
cache_policy = {s(self.cache_policy)}
cache_max_age = {self.cache_max_age}
```

> In-memory file cache limit in MB — reduce on constrained hardware

```python
cache_size_mb = {self.cache_size_mb}

```

> Let's Encrypt registration email and optional reverse proxy IP

```python
email = {s(self.email)}
trusted_proxy = {s(self.trusted_proxy)}

```

> TLS settings

```python
tls_min_version = {s(self.tls_min_version)}
ciphers = {s(self.ciphers)}

```

> Security headers — use config shell to adjust

```python
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
        # the servette service user, which would kill the running service's
        # per-request config reload and crash-loop the next restart. Restore
        # the ownership enable establishes; a no-op where the user doesn't
        # exist (session mode, tests, macOS). Late import shape as with
        # _domain_from_cert: _chown_servette is defined in System.
        _chown_servette(self.CONFIG_FILE)
        try:
            self._mtime = os.path.getmtime(self.CONFIG_FILE)
        except OSError:
            pass


```

## Logging

```python
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


```

## Rate limiter

```python
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


```

## File cache

```python
# ── File cache ────────────────────────────────────────────────────────────────

_file_cache       = collections.OrderedDict()
_file_cache_lock  = threading.Lock()
_file_cache_bytes = 0

```

> Text-like types worth gzipping. Already-compressed formats (images, woff/woff2,
> pdf, video, archives) gain nothing, so they're served and stored uncompressed.

```python
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


```

## HTTP server

```python
# ── HTTP server ───────────────────────────────────────────────────────────────

_WELL_KNOWN_VERSION_PATH = "/.well-known/servette"

# The reserved self-test page (DECISIONS.md: "The self-test is server-
# delivered, client-executed"): shipped beside this module as package data,
# read once at import, served at /selftest/ wherever the operator's content
# doesn't shadow it. A missing file (an unusual install) degrades to the
# normal 404 rather than an error.
_SELFTEST_PATHS = ("/selftest", "/selftest/", "/selftest/index.html")
try:
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "selftest.html"), "rb") as _f:
        _SELFTEST_PAGE = _f.read()
    _SELFTEST_ETAG = '"' + hashlib.sha256(_SELFTEST_PAGE).hexdigest()[:16] + '"'
except OSError:
    _SELFTEST_PAGE = None
    _SELFTEST_ETAG = None


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

    # Version discovery: what this box is running — the embedded self-test
    # page reads this to show the served version. Deliberately
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
        # The reserved self-test path, as a 404 fallback: the embedded page
        # answers /selftest/ only when resolution above came up empty AND no
        # entry named selftest (file or directory) exists in the site root —
        # so operator content wins by simply existing, in either shape. The
        # response mirrors the file path's caching contract (ETag,
        # Cache-Control, 304) because the page's own checks probe the URL it
        # was served from; the page checks, in the visitor's browser, the
        # connection it arrived over, behind the site's own auth.
        if (_SELFTEST_PAGE is not None
                and url_path.split("?", 1)[0] in _SELFTEST_PATHS
                and not os.path.exists(os.path.join(_resolve(site.serve_dir), "selftest"))):
            if headers.get("If-None-Match", "") == _SELFTEST_ETAG:
                log.info("304 Not Modified %s to %s", log_path, ip)
                return resp(304, [(b"etag", _SELFTEST_ETAG.encode()),
                                  (b"cache-control", _cache_control_header(site.username).encode())])
            log.info("200 %s (embedded self-test) to %s", log_path, ip)
            return resp(200, [
                (b"content-type",   b"text/html; charset=utf-8"),
                (b"content-length", str(len(_SELFTEST_PAGE)).encode()),
                (b"etag",           _SELFTEST_ETAG.encode()),
                (b"cache-control",  _cache_control_header(site.username).encode()),
            ], _SELFTEST_PAGE)

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


```

> Ceilings on concurrent connections — one global, one per source IP. Each connection
> holds one worker thread for its lifetime (up to the 30s idle timeout on keep-alive),
> so the global cap bounds thread/memory use under a connection flood — light enough
> for a Raspberry Pi, ample for a static site. The per-IP cap stops one source from
> holding every slot: monopolizing the pool takes cooperating addresses, not one client.

```python
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


```
