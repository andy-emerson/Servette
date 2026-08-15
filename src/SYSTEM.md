# SYSTEM

*The environment: bootstrap into the managed venv, server lifecycle, certificates and the ACME client, systemd and host provisioning.*

*Authored here. `servette.py` is built from the Markdown sources in `src/` by [`build.py`](build.py) — edit the Markdown, not the generated file.*

## Bootstrap

```python
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
            except (Exception, SystemExit) as e:
                # SystemExit is caught deliberately: Debian and Ubuntu patch
                # their venv module to print apt instructions and *exit*
                # rather than raise, and SystemExit is not an Exception —
                # without this, the recovery below is dead code on the two
                # platforms it exists for.
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
                if _IS_MACOS:
                    print("  This Python lacks venv/pip support. Install Python 3.11+ from")
                    print("  python.org or Homebrew and run Servette with that python3.")
                else:
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


```

## Server lifecycle

```python
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


```

## Service management

```python
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
    The service's own code (servette.py) and the managed venv are
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
ReadOnlyPaths={servette_path} -{_VENV_DIR}
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


```

> The unpredictable part of demand: an allowance for the single-process spike
> nobody plans for, sized to the largest one observed in production (fwupd
> ballooning to ~656 MB virtual on a 414 MB host, hourly, for weeks).

```python
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
    if _IS_MACOS:
        return  # macOS manages its own swap; mkswap/swapon/fallocate do not exist there
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


def _unit_python_path():
    """The interpreter the unit's ExecStart names. Shared by the writer and
    the drift check below — two computations of this path could disagree and
    manufacture phantom drift."""
    return _VENV_PY if os.path.exists(_VENV_PY) else subprocess.run(
        ["which", "python3"], capture_output=True, text=True
    ).stdout.strip()


def _desired_units():
    """What every unit file should contain, as {path: text}, computed from
    this version of the code."""
    netwatch_service, netwatch_timer = _netwatch_units()
    return {
        SERVICE_PATH:               _systemd_unit(_unit_python_path(), os.path.abspath(__file__)),
        NETWATCH_PATH + ".service": netwatch_service,
        NETWATCH_PATH + ".timer":   netwatch_timer,
    }


def _stale_units():
    """Unit files that differ from what this version would write — including
    ones missing entirely, so a release that adds a unit flags as stale on
    hosts enabled before it existed. Empty when the service isn't installed
    at all: nothing to refresh on a session-only host."""
    if not _service_file_exists():
        return []
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
    python_path   = _unit_python_path()

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


```

## Certificate management

```python
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


```
