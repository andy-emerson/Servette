# SYSTEM

*The environment: server lifecycle, certificates and the ACME client, systemd and host provisioning.*

*Authored here. `servette.py` is generated from the Markdown sources in `src/` — by the package build itself ([`_literate_backend.py`](_literate_backend.py)), or by hand with [`build.py`](build.py). Edit the Markdown, never the module; the committed copy exists to be read, and `--check` holds it equal to the sources.*

## Server lifecycle

Each server is a `ThreadingHTTPServer` run by `serve_forever()` in a daemon thread; `stop_server()` calls `shutdown()` on it from the shell thread to stop gracefully. The module state is that machinery: the two servers, their threads, and the background threads that watch them. Renewal attempts are tracked per domain so one site's failure-triggered backoff can't delay another's renewal.

```python
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


```

The liveness test the lifecycle, the watchdog, and the status command all share.

```python
# The liveness test
def _server_running():
    """True when the HTTPS server is actually serving — the thread must be alive,
    not merely the server object constructed, so a crashed serve loop reads as
    stopped instead of running."""
    return _https_thread is not None and _https_thread.is_alive()


```

One pass of the certificate watchdog: renew expiring Let's Encrypt certificates, reload when an externally managed certificate rotates on disk.

```python
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


```

The thread that runs the pass once a minute for the life of the server.

```python
# The watchdog thread
def _cert_watchdog():
    """Auto-renew Let's Encrypt certs before expiry; detect externally-rotated certs."""
    while _server_running():
        time.sleep(60)
        if not _server_running():
            break
        _cert_watchdog_tick()


```

Starting validates every site's configuration first, then builds the HTTPS server **failing closed** — a socket that can't bind or a certificate that can't load must surface here, synchronously (the bind happens in the constructor, the certs in `_build_site_ssl_contexts`), rather than leave a live process serving nothing. The port-80 redirect is best-effort: it needs privilege and a free port, and the site works without it. Startup ends by printing what is being served, plus any expiry, production, or cache warnings.

```python
# Starting
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

    # fail closed: a bad bind or an unreadable cert surfaces here, synchronously
    try:
        https = _TLSThreadingHTTPServer(("0.0.0.0", config.port), _Handler, _build_site_ssl_contexts())
    except Exception as e:
        log.error("Server failed to start on port %d: %s", config.port, e)
        print(f"Server failed to start on port {config.port}: {e}")
        if "--serve" in sys.argv:
            sys.exit(1)
        return

    # the port-80 redirect is best-effort (needs privilege and a free port)
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


```

Stopping closes both servers and joins their threads, then stops the rate-limit sweep.

```python
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
    print("Session server stopped.")


```

What `--serve` blocks on: the watch that turns a dead server thread into a dead process, so systemd can resurrect it.

```python
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


```

## Service management

Three probes for the state of the installed service, each answering one question.

```python
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


```

Files the service process must read — config, certificates, the ACME account — are owned by the `servette` user. The config is the one that also grants a group: it is the operator's file about the operator's box, so their own group reads it and their read-only commands never ask for a password.

```python
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


```

Site content is different: it belongs to the operator, with the service user granted read-only group access. The plan is computed separately from the run so the decision is testable without root.

```python
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


```

The systemd unit is the service's sandbox definition; its docstring carries the reasoning line by line — the write confinement, the read-only module pin, the conditional `PYTHONPATH`, and the version stamp that makes upgrades read as stale units.

```python
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


```

A headless host that loses its default route stays dark until someone notices. The watchdog timer checks every five minutes and pokes whichever network manager is actually running.

```python
# The network watchdog units
def _netwatch_units():
    """The (service, timer) unit pair for the network watchdog.

    Every 5 minutes: if the host has no route out, ask the network manager to
    start over. Recovers the observed failure where a netlink timeout leaves the
    link permanently 'Failed' — networkd never retries on its own, so the host
    stays dark until reboot. try-restart only touches a unit that is actually
    running, so of the three known managers (systemd-networkd on Ubuntu,
    NetworkManager on Raspberry Pi OS, dhcpcd on older Pi OS) exactly one acts;
    the whole check is a no-op while the route is healthy."""
    service = f"""# generated by servette {__version__}
[Unit]
Description=Servette network watchdog — recover a dropped default route

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'ip route get 1.1.1.1 >/dev/null 2>&1 && exit 0; for u in systemd-networkd NetworkManager dhcpcd; do systemctl try-restart "$u.service" 2>/dev/null || true; done'
"""
    timer = f"""# generated by servette {__version__}
[Unit]
Description=Run the Servette network watchdog every 5 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
"""
    return service, timer


```

## The swapfile

A small host that runs out of memory drops offline; a swapfile absorbs the spike to disk. Servette measures rather than guesses: supply and current demand come from `/proc/meminfo`.

```python
# Reading /proc/meminfo
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


```

> The unpredictable part of demand: an allowance for the single-process spike
> nobody plans for, sized to the largest one observed in production (fwupd
> ballooning to ~656 MB virtual on a 414 MB host, hourly, for weeks).

```python
# The swap bounds
_SPIKE_ALLOWANCE_KB = 700 * 1024
_SWAP_MIN_MB        = 512
_SWAP_MAX_MB        = 2048
_SWAP_SLACK_MB      = 8


```

`_SWAP_SLACK_MB` is how far under the recommendation still counts as meeting it. A host that accepted a 1400 MB offer reports `SwapTotal` of 1399 MB, because `mkswap` spends the first page on a header and the arithmetic floors what is left; compared exactly, that host is told forever to resize to a size it already has, and resizing produces the same shortfall again. The recommendation is rounded to two significant digits, so it carries less precision than the slack it now forgives.

Integer division that rounds up instead of down, spelled out once — the swap sizing and the JWK encoding both need it, and Python has no built-in operator for it.

```python
# Ceiling division
def _ceil_div(a, b):
    """Integer division of a by b, rounding up instead of down."""
    quotient, remainder = divmod(a, b)
    return quotient + 1 if remainder else quotient


```

The recommendation is an estimate, and its rounding says so.

```python
# Rounding an estimate
def _round_up_2sig(n):
    """Round a positive integer up to two significant digits (1148 → 1200).

    The swap default is an estimate; a round number says so, where an
    exact-looking one would overstate its precision."""
    mag = 10 ** max(len(str(int(n))) - 2, 0)
    return _ceil_div(int(n), mag) * mag


```

How much swap this host should have, from measured supply and demand — and whether an offer is even due, which depends on whose swap is already active.

```python
# The recommendation
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


```

On SD-card hosts the offer carries one extra fact the operator should weigh.

```python
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


```

The interactive offer itself: present the measurement, take a size or a decline, then create (or grow) the swapfile — sized only after checking the disk can afford it, activated only after `mkswap` succeeds, and rolled back if any step fails.

```python
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
    mem_kb, avail_kb, _ = _meminfo()
    rec       = _swap_recommendation(mem_kb, avail_kb, config.cache_size_mb)
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
    if ours and abs(mb - active_mb) <= _SWAP_SLACK_MB:
        return  # the size asked for is the size already active — nothing to do
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
        _make_swapfile(size)
        with open("/etc/fstab") as f:
            fstab = f.read()
        if _SWAP_PATH not in fstab.split():
            with open("/etc/fstab", "a") as f:
                f.write(f"{_SWAP_PATH} none swap sw 0 0\n")
        print(f"  Swapfile active ({mb} MB), persistent across reboots.")
        log.info("Swapfile active: %d MB at %s", mb, _SWAP_PATH)
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"  Could not set up swapfile: {e}")
        # A failed RESIZE has already truncated the old file, so try to give
        # the host back the swap it walked in with — a memory-tight host that
        # accepted a grow offer must not end up worse than it started. Swap
        # content is scratch (it was swapoff'd above), so rebuilding at the
        # old size restores the prior state in full.
        if ours and active_mb > 0:
            try:
                _make_swapfile(active_mb * 1024 * 1024)
                print(f"  Restored the previous {active_mb} MB swapfile.")
                return
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


```

## The service's runtime

The shell runs as the operator; the service runs as `servette`, an unprivileged system user. Where the program is installed decides whether that user can reach it at all — and a per-user install (`pip install --user`, `pipx`) puts it under a home directory that Debian and Ubuntu create mode `0750`, which the service user cannot traverse. Nothing about that is visible at install time: the unit writes, `systemctl enable` succeeds, and the failure arrives at the next boot as `ModuleNotFoundError` on a restart loop.

So `enable` measures reachability rather than assuming it, and when the program is out of reach it puts a copy where the service can read it. That copy also makes the service independent of the operator's account: it keeps serving if the home directory is unmounted, re-permissioned, or the account is removed.

```python
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


```

What the units should say is computed in exactly one place and compared against what disk says, so the startup refresh, the staleness check, and `enable` can never disagree with each other. A writer that recomputed the texts independently of the checker could drift from it and rewrite units on every shell launch.

```python
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


```

> A systemd directive value splits on whitespace, so a path carrying any would
> silently become two wrong grants — and a newline would inject an arbitrary
> directive into the sandbox definition. Servette refuses to write units for
> such a path rather than encode it wrongly.

```python
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


```

The single source of truth for unit content, and the staleness check built on it.

```python
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


```

Text drift alone is safe to adopt silently; environment drift is not. The distinction gates the startup refresh.

```python
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


```

The one writer. It contains no prompts, so it is safe to call silently — shared by `cmd_enable` (interactive) and the post-update path, so a release that changes what the units should contain reaches an already-enabled host without a separate manual `enable`. Alongside the unit texts it settles everything they depend on: the service user, file ownership, and the ACME webroot.

```python
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
    # startup refresh in a checkout the operator owns) used to get exactly as
    # far as its permissions allowed: on such a host that meant swapping the
    # runtime copy, then failing at the unit write — a version-skewed,
    # operator-owned runtime behind a unit that still described the old one.
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
        print("Created system user 'servette'.")

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


```

## Enable and disable

`enable` writes the units, offers the swapfile, and — when refreshing an already-active service or upgrading a session server — restarts onto the new definition. Every failure mode gets a plain-language message naming what to do instead.

```python
# enable
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

    except ValueError:
        pass  # the writer already printed the path refusal
    except PermissionError:
        print("Error: enable needs root, and sudo is unavailable — re-run as root.")
    except FileNotFoundError:
        print("Error: enable requires a Linux server with systemd.")
    except subprocess.CalledProcessError as e:
        print(f"Error during enable: {e}")


```

`disable` unwinds exactly what enable created: stop, disable, remove the unit files, reload systemd.

```python
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
        print("Servette service disabled.")
        log.info("Systemd service disabled")
    except PermissionError:
        print("Error: disable needs root, and sudo is unavailable — re-run as root.")
    except FileNotFoundError:
        print("Error: disable requires a Linux server with systemd.")
    except subprocess.CalledProcessError as e:
        print(f"Error during disable: {e}")


```

## Certificate management

Long operations get a spinner — on a TTY only, so service renewals and piped runs stay clean in the journal.

```python
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


```

Every private key Servette writes goes through one function, and the mode exists before the content does.

```python
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


```

The fallback for sites without a domain: a ten-year self-signed certificate for localhost, the loopback address, and the host's own IP when it can be discovered.

```python
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


```

A restart needs the old process's port back before the new one can bind it.

```python
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


```

Reloading picks the mechanism the environment allows: inside the sandboxed service the process can only stop itself and let systemd restart it; outside, `systemctl restart` or a stop/start of the session server.

```python
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


```

## The ACME client

Certificate issuance runs on Servette's own minimal ACME (RFC 8555) client — stdlib `urllib` plus `cryptography`, replacing the certbot `acme` + `josepy` libraries. First, the encoding JOSE uses everywhere.

```python
# base64url
def _b64url(data):
    """base64url without padding — the encoding JOSE/ACME uses everywhere."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_int(n):
    """A non-negative integer as a base64url big-endian byte string (for JWK n/e)."""
    length = max(_ceil_div(n.bit_length(), 8), 1)   # zero still encodes as one byte
    return _b64url(n.to_bytes(length, "big"))


```

Two small carriers: a uniform response holder, and the error that names which DNS names failed validation so the caller can decide about fallback.

```python
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


```

The client itself, deliberately narrow: HTTP-01 issuance with a single account key, nothing else. Requests are RS256-signed JWS; the replay nonce rides each response's header; the directory is fetched lazily so construction touches no network and stays unit-testable.

```python
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


```

The full issuance flow around the client: account key handling, a temporary port-80 listener when the server isn't running, retries with backoff, and the www fallback — when `www.<domain>` alone fails DNS validation, the certificate is reissued for the bare domain rather than failing the site.

```python
# Issuance
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
    # — writing files, saving config, reloading — used to sit inside it, and a
    # local failure (the sandboxed service cannot write the data directory)
    # was then retried as if Let's Encrypt had refused: each "retry" a full
    # fresh issuance, three duplicate certificates burned per pass against the
    # 5-per-week duplicate limit, and the reload never reached — the renewed
    # certificate sat on disk while the server served the old one to expiry.
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
        log.error("ACME failed for %s after %d attempts: %s", domain, ACME_RETRIES, last_error)
        return

    _persist_issued_cert(domain, site, CERTS_DIR, issued[0], issued[1],
                         f"{domain} and {www_domain}" if include_www else domain)


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


```

## Certificate inspection

Reading what a certificate on disk actually says, without trusting the config to agree with it.

```python
# Loading a certificate
def _load_cert(cert_path):
    """Return a cryptography X.509 certificate object, or None on failure."""
    try:
        from cryptography import x509 as _x509
        with open(cert_path, "rb") as f:
            return _x509.load_pem_x509_certificate(f.read())
    except Exception:
        return None


```

The domain a certificate names — SAN first, Common Name as fallback — filtered through what counts as a real domain (not `localhost`, not the self-signed placeholder, not an IP).

```python
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


```

Days to expiry, the number the watchdog and the startup warnings key on.

```python
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


```
