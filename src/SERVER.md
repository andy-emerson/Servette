# SERVER

*Every incoming request: config, rate limiting, the file cache, site selection, the request handler, and the threaded HTTP servers.*

*Authored here. `servette.py` is generated from the Markdown sources in `src/` — by the package build itself ([`_literate_backend.py`](_literate_backend.py)), or by hand with [`build.py`](build.py). Edit the Markdown, never the module; the committed copy exists to be read, and `--check` holds it equal to the sources.*

## Config

Relative paths in the config are anchored to the data directory, never to wherever the process happens to run.

```python
# Resolving data paths
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


```

Everything that varies per hosted domain lives on a `Site`; everything host-level lives once on `Config`. No field exists at both levels, so there is no fallback lookup to reason about.

```python
# A site
class Site:
    """One `[[site]]` block: everything that varies per hosted domain — the domain
    itself, its folder, its own certificate, its visitor auth, its publish channel.
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
        self.publish_url    = data.get("publish_url",    "")
        self.publish_key    = data.get("publish_key",    "")
        self._cert_mtime    = None  # populated by Config._load(); externally-rotated-cert detection


```

The signal for a config that must not take effect. Where it is raised decides what happens: fatal at startup, ignored (last good config stays live) on the per-request reload.

```python
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


```

The `Config` class is the whole settings lifecycle: load (with validation before any live field mutates, and the flat-config migration), the per-request reload that survives a bad edit, and the atomic save that writes `servette.toml` — the TOML template with its operator-facing comments is the string literal inside `save()`.

```python
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


```

## Logging

In service mode, logs go to the systemd journal (`StandardOutput=journal`); interactively, warnings and errors go to the terminal.

```python
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


```

Color for interactive output only; pipes and the journal get plain text.

```python
# Terminal color
def _c(text, color):
    """Wrap text in an ANSI color for interactive (TTY) output; plain text otherwise."""
    codes = {"green": "32", "red": "31", "yellow": "33"}
    if color not in codes or not sys.stdout.isatty():
        return text
    return f"\033[{codes[color]}m{text}\033[0m"


```

## Rate limiter

Sliding-window counters per IP, guarded by a plain `threading.Lock` — the critical section is in-memory deque manipulation, not I/O, so it is held only briefly and stays barely contended even when many connection threads hit it at once.

```python
# Rate state
RATE_WINDOW  = 60      # seconds
_RATE_IP_CAP = 10_000  # max IPs tracked per dict; bounds memory under IP-flood attacks

_request_times   = {}
_auth_fail_times = {}
_rate_lock       = threading.Lock()


```

Both spellings of a mapped IPv4 address must share one bucket — and an IPv6 client's whole /64 must too, or the buckets aren't limits at all. Two functions, because the two jobs diverge: the log wants the address, the limiter wants the subscriber.

```python
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


```

A background sweep keeps the trackers bounded no matter what traffic does.

```python
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


```

The check itself, with its two modes: count-and-decide, or peek without counting so an expensive operation can be gated on the limit before it spends anything.

```python
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


```

## File cache

An LRU byte-cache of served files, bounded by `cache_size_mb`.

```python
# Cache state
_file_cache       = collections.OrderedDict()
_file_cache_lock  = threading.Lock()
_file_cache_bytes = 0

```

> Text-like types worth gzipping. Already-compressed formats (images, woff/woff2,
> pdf, video, archives) gain nothing, so they're served and stored uncompressed.

```python
# Compressible types
_COMPRESSIBLE_EXTS = {
    ".html", ".css", ".js", ".json", ".svg", ".txt", ".xml", ".webmanifest", ".ttf",
}


```

An entry's cost counts both representations it may hold.

```python
# An entry's cost
def _entry_bytes(entry):
    return len(entry["raw"]) + (len(entry["compressed"]) if entry["compressed"] else 0)


```

The read-through path: mtime-validated hits, one gzip per file change, and two protections for the bound — a file too large for the cache is served but never stored (so it can't purge everything else), and eviction is oldest-first.

```python
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


```

## Path resolution

Extension-to-MIME is a fixed table; anything unknown is served as opaque bytes.

```python
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


```

Two predicates: containment for config-time checks, and the dotfile refusal. The request path deliberately does not use `_within` — its containment guard is written out inline below, where a scanner and a reader can both verify it at the security boundary itself.

```python
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


```

URL to file, confined to the matched site's `serve_dir`. The hidden-name rule runs twice — once on the requested segments, once on the resolved target — so a dotfile is refused by whatever name it was reached, including through a symlink.

```python
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


```

## Response headers

Cache-Control scope follows the site's auth: a password-protected site's responses are `private`, so a shared cache never holds what only some visitors may see.

```python
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


```

Single byte ranges only — enough for media seeking; multi-range requests fall back to the full body.

```python
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


```

Security headers ride every HTTPS response, success or error; HSTS only where a real certificate backs the pin.

```python
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


```

## The request core

Three things precede the handler: version discovery at `/.well-known/servette`, the connection test at its reserved sibling path, and the default 404 body — the pages inlined into the module by the build so there is no file to lose.

```python
# Reserved paths
_WELL_KNOWN_VERSION_PATH = "/.well-known/servette"
_CHECK_PATH              = "/.well-known/servette-check"

# The default 404 body (DECISIONS.md: "The error page is server-delivered,
# client-executed"): authored as src/404.html and inlined by build.py, so it is
# part of the module rather than a file beside it. That is deliberate — a page
# shipped as package data can be deleted on the box, and deleting it would
# silently take the default 404 body with it. There is no read at import and no
# missing-file case to degrade through.
_NOT_FOUND_PAGE = """@@NOT_FOUND_HTML@@""".encode()
_NOT_FOUND_ETAG = '"' + hashlib.sha256(_NOT_FOUND_PAGE).hexdigest()[:16] + '"'

# The connection test (src/check.html), served at _CHECK_PATH on every site —
# a reserved path under /.well-known/, the one namespace the hidden-path rule
# already sets apart, so an operator's content never shadows the outside
# vantage the way a custom 404.html takes over the miss body.
_CHECK_PAGE = """@@CHECK_HTML@@""".encode()
_CHECK_ETAG = '"' + hashlib.sha256(_CHECK_PAGE).hexdigest()[:16] + '"'


```

Anything a request writes into the logs is escaped first — a crafted path must never drive an operator's terminal.

```python
# Log escaping
def _loggable(s):
    """Escape control characters in a string bound for the logs. A request path
    reaches the journal and, from there, an operator's terminal — an unescaped
    ANSI/control sequence could move the cursor, clear the screen, or hide text.
    Printable characters (including non-ASCII) pass through unchanged."""
    return "".join(c if c >= " " and c != "\x7f" else f"\\x{ord(c):02x}" for c in s)


```

The request core is one function, transport-agnostic and ordered deliberately: reload, site selection (bound before the limiter so a matched host's 429 carries HSTS like every other response), rate limit (still ahead of the closed-system miss, so unmatched Hosts throttle too), the undifferentiated 404 for an unmatched Host (deliberately ahead of the method check, so no 405 leaks that something is here), method check, per-site auth with the scrypt gate, the reserved paths, then file resolution and the caching/range/gzip protocol. Every inline comment below marks one of those decisions where it takes effect.

```python
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
    if url_path.split("?", 1)[0] == _CHECK_PATH:
        cache = _cache_control_header(site.username)
        if "max-age" in cache:
            cache = ("private" if site.username else "public") + ", no-cache"
        if headers.get("If-None-Match", "") == _CHECK_ETAG:
            log.info("304 Not Modified %s to %s", log_path, ip)
            return resp(304, [(b"etag", _CHECK_ETAG.encode()),
                              (b"cache-control", cache.encode())])
        log.info("200 %s (connection test) to %s", log_path, ip)
        return resp(200, [
            (b"content-type",   b"text/html; charset=utf-8"),
            (b"content-length", str(len(_CHECK_PAGE)).encode()),
            (b"etag",           _CHECK_ETAG.encode()),
            (b"cache-control",  cache.encode()),
        ], _CHECK_PAGE)

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


```

## Site selection and TLS

Host to site, uniform regardless of site count: exact domain first, then the www pairing (mirroring what `_obtain_trusted_cert` issues), then the first domainless site as catch-all.

```python
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


```

Two sites must never share a domain — TLS and routing would silently disagree about which is served.

```python
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


```

One certificate, one TLS context — minimum version enforced, ALPN pinned to HTTP/1.1, unreadable material raising so startup fails closed.

```python
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


```

The certificate presented when SNI matches nothing and no domainless site exists to be the natural default — tied to no site's identity.

```python
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


```

The SNI table: one context per site, the www names answered with their bare domain's certificate, and the default context carrying the callback so the per-site contexts live only inside its closure.

```python
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


```

## The servers

The HTTPS handler is a thin adapter: it hands `_handle_request` what `http.server` parsed and writes back what it returns.

```python
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


```

The port-80 handler serves ACME challenge tokens during issuance and 301-redirects everything else to HTTPS.

```python
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


```

> Ceilings on concurrent connections — one global, one per source IP. Each connection
> holds one worker thread for its lifetime (up to the 30s idle timeout on keep-alive),
> so the global cap bounds thread/memory use under a connection flood — light enough
> for a Raspberry Pi, ample for a static site. The per-IP cap stops one source from
> holding every slot: monopolizing the pool takes cooperating addresses, not one client.

```python
# Connection ceilings
MAX_CONNECTIONS        = 128
MAX_CONNECTIONS_PER_IP = 32


```

The capped server enforces both ceilings at accept time — before any bytes are read, which is what catches connections that never send a request.

```python
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


```

TLS on top, with the handshake deferred to the worker thread so a slow handshake can't stall the accept loop.

```python
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


```
