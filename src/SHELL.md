# SHELL

*The interactive terminal interface.*

*Authored here. `servette.py` is built from the Markdown sources in `src/` by [`build.py`](build.py) — edit the Markdown, not the generated file.*

> Menus are generated so the right-hand column always begins at the same place
> (2-space indent + a 22-wide label) as the status and config displays.

```python
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


```

> Ordered like systemctl's own manual: runtime control (start/stop) before
> persistence (enable/disable) — Servette wraps systemd, and its audience
> already has that convention's intuition. Onboarding, then runtime control,
> then persistence, then observability, then maintenance, then meta.

```python
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

```

> Ordered: sites first (list/add/remove — the multi-site entry points), then
> what a site serves and how it's reached (dir/port/cert/email — email is the
> ACME registration address, grouped with the certificate it belongs to), then
> access control, then traffic shaping, then advanced/rarely-touched security
> tuning, then meta. dir/cert/publish/username/password take an optional site
> index (default 0) — same [n] convention as the top-level 'log [n]'.

```python
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


```

## Config sub-shell

```python
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
            if _IS_MACOS:
                print("Service install is Linux-only; keep this session alive (tmux/screen) to stay up.")
            elif _prompt("Install as a permanent service?"):
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
        if _IS_MACOS:
            print("No journal on macOS — in session mode the log is this terminal's own output.")
        else:
            print("journalctl not found. Is this a systemd system?")


RELEASES_API_URL    = "https://api.github.com/repos/andy-emerson/servette/releases/latest"
_SIGNING_PUBLIC_KEY = "abb8854be0b82df813f3b052296a26573063fc6314ea2701d54354605e6f15db"
_VERSION_RE         = re.compile(rb"""^__version__\s*=\s*['"]([^'"]+)['"]""", re.M)
```

> Ceiling on a downloaded release asset — servette.py or the demo page. Both are
> orders of magnitude under this; the cap exists so a hostile or broken response
> is bounded before the signature check, not to constrain growth.

```python
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


```

## Site content publishing

```python
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
    so a bad bundle leaves no partial extraction behind. Where the interpreter
    has it (3.11.4+), filter='data' is passed to extractall() too: defense in
    depth, not the only guard — it independently enforces the same containment
    and rejects the same entry types at the library level."""
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
        # The PEP 706 feature probe: data_filter exists exactly when
        # extractall() accepts filter=. Debian 12's 3.11.2 predates the
        # backport — there the checks above are the (sufficient) guard.
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest_dir, members=members, filter="data")
        else:
            tf.extractall(dest_dir, members=members)


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


```

## Setup wizard

```python
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


```

## Main shell loop

```python
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


```
