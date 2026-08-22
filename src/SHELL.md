# SHELL

*The interactive terminal interface.*

*Authored here. `servette.py` is generated from the Markdown sources in `src/` — by the package build itself ([`_literate_backend.py`](_literate_backend.py)), or by hand with [`build.py`](build.py). Edit the Markdown, never the module; the committed copy exists to be read, and `--check` holds it equal to the sources.*

## Menus and prompts

Menus are generated so the right-hand column always begins at the same place (2-space indent + a 22-wide label) as the status and config displays. The full-width banner is reserved for the two moments a user enters a new mode: the shell launching, the setup wizard.

```python
# Menu metrics
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

The command list is ordered like systemctl's own manual: runtime control (start/stop) before persistence (enable/disable) — Servette wraps systemd, and its audience already has that convention's intuition. Onboarding, then runtime control, then persistence, then observability, then maintenance, then meta.

```python
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
    ("admin",            "open the browser admin page over your SSH tunnel"),
    ("publish",          "one guided flow for site content: pull, roll back, channel"),
    ("pull [n]",         "check a site's publish channel and pull new content now"),
    ("restore-site [n]", "roll back a site's content (undoes its last pull)"),
    ("help",             "show this message"),
    ("quit",             "exit"),
]
HELP = _section_text("Commands") + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _COMMANDS)

```

The config sub-shell's commands, ordered: sites first (list/add/remove/move — the multi-site entry points), then what a site serves and how it's reached (dir/port/cert/email — email is the ACME registration address, grouped with the certificate it belongs to), then access control, then traffic shaping, then advanced security tuning, then meta. `dir`/`cert`/`publish`/`username`/`password` take an optional site index (default 0) — the same `[n]` convention as the top-level `log [n]`.

```python
# The config commands
_CONFIG_COMMANDS = [
    ("sites",           "list configured sites"),
    ("add-site",        "add a new site (folder, domain, password, publish channel)"),
    ("remove-site <n>", "remove a site"),
    ("move-site <n> <to>", "reorder sites (the first domainless one answers unmatched Hosts)"),
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


```

The publish sub-shell gathers the content channel's scattered verbs — pull, roll back, and the channel's settings — into one guided place, shaped like `config`: day-to-day verbs first, then settings, then meta.

```python
# The publish commands
_PUBLISH_COMMANDS = [
    ("pull [n]",         "fetch and swap in new content from the site's channel"),
    ("restore-site [n]", "roll back a site's content (undoes its last pull)"),
    ("channel [n]",      "view or edit the publish channel (watch URL and key)"),
    ("show",             "show each site's channel and backup"),
    ("back",             "return to main shell"),
]
PUBLISH_HELP = _section_text("Commands") + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _PUBLISH_COMMANDS)


```

Input that can't kill the shell: Ctrl-D and Ctrl-C answer the default instead of letting the exception traceback out of a command.

```python
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


```

## Config sub-shell

The settings display: host-level rows once, then each site's own block.

```python
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


```

The two predicates every serve_dir edit runs through: it must sit inside the data directory (the publish swap and the systemd sandbox both depend on that), and it must not be a folder that holds Servette's own secrets.

```python
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


```

Adding a site asks the same questions setup asks for the first one, plus the folder question — and its inline comments carry the two traps this function is shaped around: certificate names that must not collide across remove/add sequences, and a fallback pair that must exist on disk before ACME is even attempted.

```python
# add-site
def _invent_site_dir():
    """Create and own an empty folder for a page-added site. Servette names
    it: the folder is where publishes land, not a question an operator
    should have to answer (the add-card ruling — and the folder concept is
    on its way out of the vocabulary entirely)."""
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
    # Nothing is written and nothing is offered: a site with no index.html
    # answers its own domain with the embedded error page, which says the
    # server is up and that nothing is published yet. Setup still never leaves
    # a site with nothing to serve (#37) — it just no longer needs to put a
    # file in the operator's folder to keep that promise.
    if not os.path.exists(os.path.join(_resolve(folder), "index.html")):
        print("  No index.html yet — the site will answer with Servette's error page until you publish one.")

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


```

Removal discards config only — files on disk are never touched — and the last site can't be removed. The core is shared with the page's delete-card, which does its confirming in the browser.

```python
# remove-site
def _remove_site(idx):
    """Drop site `idx` from config — files on disk are never touched, and
    the last site can't be removed. Returns an error sentence, empty on
    success. Shared by the terminal's remove-site and the page's cards."""
    if not (0 <= idx < len(config.sites)):
        return f"no site {idx}"
    if len(config.sites) == 1:
        return "can't remove the only site — a box needs at least one"
    del config.sites[idx]
    config.save()
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
    if not _prompt(f"Remove site {idx} ({label})? Its config is discarded; its files on disk are not touched."):
        print("  Cancelled.")
        return

    err = _remove_site(idx)
    print(f"  {err}" if err else f"  → site {idx} removed.")


```

Order is config too: `_select_site` hands unmatched Hosts to the *first* domainless site, so where a site sits in the list is visible truth, moved and saved like any other setting.

```python
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


```

Changing a site's directory runs the same containment and secrets checks as add-site.

```python
# dir
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


```

One generic prompt-validate-save for the simple host-level settings; the settings with more shape get their own functions below.

```python
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


```

The certificate prompt: a domain means ACME issuance; blank means a fresh self-signed pair.

```python
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


```

Clearing the username clears the password with it — auth is one switch, not two half-states. The password never echoes and is stored only as its scrypt hash.

```python
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


```

The traffic and caching prompts.

```python
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


```

The reverse-proxy setting explains its own default: blank means X-Forwarded-For is ignored, which is correct when Servette faces the internet directly.

```python
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


```

The publish channel's two halves: the watch URL (https only) and the Ed25519 public key that verifies what it serves.

```python
# publish
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


```

TLS floor and optional cipher override; both take effect on the next server start.

```python
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


```

The `[n]` site-index convention, resolved in one place.

```python
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


```

The sub-shell loop itself: show the settings, then dispatch until `back`.

```python
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


```

## Runtime commands

`start` prefers the installed service; without one it starts a session server and offers to make it permanent.

```python
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
                print("Error: start needs root, and sudo is unavailable — re-run as root.")
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


```

`stop` stops whichever is running — service, session server, or both.

```python
# stop
def cmd_stop():
    stopped = False

    if _service_is_active():
        try:
            subprocess.run(["systemctl", "stop", "servette"], check=True, capture_output=True)
            print("Service stopped.")
            log.info("Service stopped")
            stopped = True
        except PermissionError:
            print("Error: stop needs root, and sudo is unavailable — re-run as root.")
        except FileNotFoundError:
            print("Error: stop requires a Linux server with systemd.")
        except subprocess.CalledProcessError as e:
            print(f"Error stopping service: {e}")

    if _server_running():
        stop_server()
        stopped = True

    if not stopped:
        cmd_status()


```

`log` reads the service's journal; session mode's log is the terminal itself.

```python
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
            print("No journal on macOS — in session mode the log is this terminal's own output.")
        else:
            print("journalctl not found. Is this a systemd system?")


```

## Site content publishing

> The update channel for a site's *content*: a signed tar.gz bundle, pulled
> from publish_url, verified against publish_key, and swapped into serve_dir
> with a single-shot .bak — 'restore-site' rolls back to it, and a successful
> restore consumes it. Pull-only — this box never accepts an inbound push of
> content, only fetches from a URL it already trusts. (Servette's own code
> updates travel through the package manager, not through Servette.)

```python
# The bundle ceiling
_MAX_BUNDLE_BYTES = 500 * 1024 * 1024  # generous for a static site; bounds a decompression-bomb bundle


```

Extraction validates everything before writing anything: containment, entry types, and the uncompressed total.

```python
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
        # abort at the ceiling. (Only a signed bundle gets here at all, so
        # this bounds a compromised or buggy publisher, not the anonymous
        # internet.)
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


```

The content lives in two sibling slots behind a symlink, so the swap is one atomic link flip. `serve_dir.bak` marks the single-shot backup — a symlink to the previous tree, or a real directory left by the pre-flip design, and both eras answer `os.path.isdir` the same way.

```python
# The content slots
def _content_slots(serve_dir):
    """The two sibling trees the serve_dir symlink flips between."""
    base = _resolve(serve_dir).rstrip(os.sep)
    return base + ".a", base + ".b"


def _drop_backup(bak):
    """Remove the single-shot backup marker, whichever era made it: a symlink
    from the flip design (the tree it names is handled by the caller), or a
    real directory from before it."""
    if os.path.islink(bak):
        os.remove(bak)
    elif os.path.isdir(bak):
        shutil.rmtree(bak, ignore_errors=True)


```

The swap itself. A converted site never shows a missing directory: the flip is one `os.replace` of a symlink, and a crash leaves old or new content live — never neither. The pre-flip design was two renames back to back, and between them the live directory did not exist: a microseconds 404 window on every publish, and a crash there left the site with no content at all. That window now survives only in one place, paid once — the first swap on a legacy real directory, which converts it.

```python
# The content swap
def _swap_site_content(new_dir, serve_dir):
    """Make new_dir the live content behind serve_dir, keeping the previous
    tree as the single-shot backup that restore-site consumes.

    serve_dir is a symlink into one of two sibling slots (.a/.b): new_dir's
    tree moves into the idle slot and one atomic os.replace flips the link —
    no window, crash-safe. `serve_dir.bak` then points at the previous slot.
    A legacy real directory at serve_dir is converted on its first swap: the
    old content becomes the .bak directory and the link lands — the one swap
    that still carries the old rename gap, once per site ever, with the same
    rollback the old design had (a failed conversion must never leave NO live
    directory — every request a 404 — while the caller reports merely
    'rejected')."""
    if not os.path.isdir(new_dir):
        # A dangling symlink would "succeed" — the old rename raised here,
        # and the flip must fail just as loudly rather than serve nothing.
        raise FileNotFoundError(f"new content tree missing: {new_dir}")
    live = _resolve(serve_dir).rstrip(os.sep)
    bak  = live + ".bak"
    a, b = _content_slots(serve_dir)

    if os.path.islink(live):
        old_target = os.path.realpath(live)
        dest = b if old_target == os.path.realpath(a) else a
        if os.path.realpath(new_dir) != os.path.realpath(dest):
            _drop_backup(bak)                    # single-shot: newest wins
            shutil.rmtree(dest, ignore_errors=True)
            os.rename(new_dir, dest)
        flip = live + ".flip"
        if os.path.lexists(flip):
            os.remove(flip)                      # a crash's leftover, harmless
        os.symlink(dest, flip)
        os.replace(flip, live)                   # the swap: one atomic syscall
        _drop_backup(bak)
        if os.path.isdir(old_target) and old_target != os.path.realpath(live):
            os.symlink(old_target, bak)
        return

    # Legacy: a real directory (or nothing yet) at serve_dir — convert.
    had_live = os.path.isdir(live)
    if os.path.realpath(new_dir) != os.path.realpath(a):
        shutil.rmtree(a, ignore_errors=True)
        os.rename(new_dir, a)
    if had_live:
        _drop_backup(bak)
        os.rename(live, bak)
    try:
        os.symlink(a, live)
    except OSError:
        if had_live:
            os.rename(bak, live)
        raise


_publish_lock = threading.Lock()  # serializes site-content mutation across every
                                   # site: 'pull' and 'restore-site' can run from
                                   # two shell sessions at once, and the swap is
                                   # multiple unguarded filesystem ops, not one.


```

The landing every content channel shares — validated extraction into staging, atomic swap, ownership repair, under the publish lock. Pull hands it a bundle fetched and signature-checked from the shelf; the loopback page hands it one the operator uploaded over their SSH tunnel, which carries no signature: the transport already proved the identity (the DECISIONS record "Tunnel uploads are authenticated by SSH").

```python
# Landing a bundle
def _land_bundle(site, bundle, source):
    """Extract `bundle` into staging and swap it live for `site`, with the
    single-shot backup and ownership repair — the shared tail of every content
    channel. `source` is only for the log line. Returns "rejected" or
    "published"."""
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


```

The `.sig` companion is appended to the URL's path, not the whole URL, so a query string survives.

```python
# The .sig companion
def _publish_sig_url(url):
    """url's own '.sig' companion, with '.sig' appended to the path rather than
    the whole URL — naive string concatenation breaks for a publish_url that
    carries a query string (e.g. a pre-signed download link), landing '.sig'
    after the query instead of after the file extension."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path + ".sig",
                       parts.query, parts.fragment))


```

The pull pipeline: capped fetch and signature check, then the landing every channel shares — each failure mapped to a status string the command turns into one printed line.

```python
# Checking the channel
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

    return _land_bundle(site, bundle, site.publish_url)


```

The two commands over that pipeline: pull now, and roll back to the single-shot backup.

```python
# pull
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
    """Roll back to the content saved by the last successful publish. The
    backup is single-shot: one is kept, and a successful restore consumes it.
    On a converted site the restore is the same atomic flip as the publish —
    instant, no window; the tree being rolled away is then removed. A legacy
    real-directory backup restores the old way (its window rides along, once)."""
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
        if os.path.islink(live_dir) and os.path.islink(bak_dir):
            bad    = os.path.realpath(live_dir)
            target = os.path.realpath(bak_dir)
            flip   = live_dir + ".flip"
            if os.path.lexists(flip):
                os.remove(flip)
            os.symlink(target, flip)
            os.replace(flip, live_dir)          # the restore: one atomic flip
            os.remove(bak_dir)                  # consumed
            if os.path.isdir(bad) and bad != target:
                shutil.rmtree(bad, ignore_errors=True)
        else:
            # A legacy real-directory backup — possibly behind a converted
            # site, so the link (or old directory) is cleared first.
            if os.path.islink(live_dir):
                bad = os.path.realpath(live_dir)
                os.remove(live_dir)
                shutil.rmtree(bad, ignore_errors=True)
            elif os.path.isdir(live_dir):
                shutil.rmtree(live_dir)
            os.rename(bak_dir, live_dir)
        # The restored tree may date from a pre-flip pull that extracted as
        # root — the same ownership repair as a publish, for the same reason.
        _chown_operator(os.path.realpath(live_dir), strip_world=True)
    print("  Site content restored from backup.")

```

## Publish sub-shell

One guided place for site content, shaped like `config`: show each site's channel and backup, then dispatch until `back`. Every verb delegates to the command it gathers — `channel` reuses the config sub-shell's own prompt — so the two surfaces cannot drift.

```python
# The publish display
def _publish_show():
    _section("Publish")
    for i, site in enumerate(config.sites):
        backup = os.path.isdir(_resolve(site.serve_dir).rstrip(os.sep) + ".bak")
        print(f"  [{i}] {site.domain or site.serve_dir}")
        print(f"      channel: {site.publish_url if site.publish_url and site.publish_key else '(not set)'}")
        print(f"      backup:  {'present — restore-site undoes the last pull' if backup else 'none'}")
    print()


```

The loop itself: show the state, then dispatch until `back`. Pure terminal — the browser door is the `admin` command's job, and one hint line points there.

```python
# publish
def cmd_publish():
    _publish_show()
    print("  Prefer a browser? 'admin' opens the publish page over your SSH tunnel.")
    print(PUBLISH_HELP)

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
        elif cmd == "pull":
            site = _config_site_arg(args)
            if site is not None:
                cmd_pull(site)
        elif cmd == "restore-site":
            site = _config_site_arg(args)
            if site is not None:
                cmd_restore_site(site)
        elif cmd == "channel":
            site = _config_site_arg(args)
            if site is not None:
                _config_publish(site)
        elif cmd in ("back", "done", "exit", "quit"):
            break
        elif cmd in ("help", "?"):
            print(PUBLISH_HELP)
        else:
            print(f"  Unknown command: {cmd}")
            print(PUBLISH_HELP)


```

## Loopback page server

The browser half of a paired command. It binds 127.0.0.1 only and lives only while the operator's command runs, reached through the operator's SSH tunnel — the shell wearing a friendlier skin, not a third surface (the DECISIONS record "Multi-step features pair a shell flow with a loopback browser page"). One six-character code per run is the pairing: the printed URL carries it, the bare URL asks for it, and five wrong guesses end authentication for the run.

```python
# The loopback server's shape
_UI_HOST          = "127.0.0.1"
_UI_PORT          = 8377  # the LocalForward line in the operator's ssh config names it
_UI_MAX_BAD_CODES = 5     # then the run stops authenticating anyone: a six-character
                          # code holds against five guesses, not against a local
                          # process free to try millions over loopback


```

The pairing page is what the bare, bookmarkable URL answers with: a form that asks for the code the terminal printed and submits it as the same `t` the printed URL carries.

```python
# The pairing page
_UI_PAIR_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Servette</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 26rem; margin: 4rem auto;">
<h1>Servette</h1>
<p>Enter the code printed in your terminal:</p>
<form method="get" action="/"><input name="t" autofocus autocomplete="off">
<button>Open</button></form>
</body></html>
"""


```

The admin page is inlined by the build exactly as the 404 page is — authored as `src/admin.html`, counted apart from the Python figures. One page, tabs per feature (Status, Publish; Config when it earns its forms), so every feature shares one scaffold, one bookmark, one code. The publish tab is the pub tool's bundle builder with every trace of key custody removed: on this page, being here is the authentication.

```python
# The admin page
_UI_ADMIN_PAGE = """@@ADMIN_HTML@@"""


```

One page, one upload endpoint, one code. Requests without the run's code get the pairing page or a refusal — never content, and never a write. The code is compared in constant time; the upload is capped before it is read and lands through the same `_land_bundle` as every other channel.

```python
# The loopback handler
class _UIHandler(http.server.BaseHTTPRequestHandler):
    """The loopback server's one handler. GET / is the page (pairing page
    until the code is presented); POST /upload lands a content bundle. After
    _UI_MAX_BAD_CODES wrong guesses the run stops authenticating anyone,
    including the right code — re-run the command for a fresh one."""

    def log_message(self, fmt, *args):
        log.info("ui: " + fmt % args)  # the default writes to stderr, past the log

    def _respond(self, status, body, ctype="text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

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
        if path not in ("/", "/status", "/config"):
            return self._respond(404, "Not found.")
        auth = self._auth()
        if auth == "locked":
            return self._respond(403, "Too many wrong codes. Close this page and re-run the command.")
        if path == "/status":
            # The inside view, for the page's Status tab: exactly what
            # `status --json` prints, because it is the same function.
            if auth != "ok":
                return self._respond(403, "Not paired.")
            return self._respond(200, json.dumps(_status_data()), "application/json")
        if path == "/config":
            # The Config tab's read half: exactly the vocabulary `set`
            # accepts, plus current values to fill the forms — and
            # has_password, a boolean only, so the page can show whether
            # protection is on without the hash ever crossing the wire.
            if auth != "ok":
                return self._respond(403, "Not paired.")
            return self._respond(200, json.dumps({
                "host":  {k: getattr(config, k) for k in _SET_HOST_KEYS},
                "sites": [{"index": i, "domain": s.domain, "dir": s.serve_dir,
                           "username": s.username, "publish_url": s.publish_url,
                           "publish_key": s.publish_key,
                           "has_password": bool(s.password_hash)}
                          for i, s in enumerate(config.sites)],
            }), "application/json")
        if auth == "ok":
            return self._respond(200, self.server.page)
        return self._respond(200, _UI_PAIR_PAGE)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/upload", "/config", "/sites"):
            return self._respond(404, "Not found.")
        if self._auth() != "ok":
            return self._respond(403, "Not paired.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self._respond(400, "Empty upload.")

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
        result = _land_bundle(site, self.rfile.read(length), "browser upload")
        if result == "published" and getattr(self.server, "on_publish", None):
            self.server.on_publish(site)  # the terminal narrates what the browser did
        self._respond(200 if result == "published" else 422,
                      json.dumps({"result": result}), "application/json")


```

Starting and stopping bracket one command's run: a fresh code each start, and the socket closed at stop — the page cannot outlive the operator's session.

```python
# Starting and stopping
def _start_ui(site, page, port=_UI_PORT):
    """Start the loopback page server for one command's lifetime: bound to
    127.0.0.1 only, one fresh code per run. Returns (httpd, code); the caller
    prints the URL and later hands httpd back to _stop_ui. A port already in
    use raises OSError for the caller to report."""
    httpd = http.server.ThreadingHTTPServer((_UI_HOST, port), _UIHandler)
    httpd.site, httpd.page = site, page
    httpd.code, httpd.bad_codes = os.urandom(3).hex(), 0
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.code


def _stop_ui(httpd):
    """The page dies with the command: stop accepting, close the socket."""
    httpd.shutdown()
    httpd.server_close()


```

`admin` is the door: it runs the page server for exactly its own lifetime, prints the two ways in, narrates what the browser does, and closes the page on the way out. Its terminal side is deliberately thin — every capability the page exposes already has its own shell command.

```python
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
        # The happy path pays one line; the troubleshooting lives behind
        # 'help', summoned exactly when the page fails to load.
        print("  The admin page is up:")
        print(f"    open  http://localhost:{_UI_PORT}/?t={code}")
        print("    (page won't load? type 'help')")
        print()
        while True:
            try:
                raw = input("  admin — 'back' closes the page: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if raw in ("help", "?"):
                print("  A page that won't load means this SSH connection isn't carrying")
                print("  the tunnel. Add this line once to ~/.ssh/config on the computer")
                print("  you ssh FROM, inside this server's entry, then reconnect:")
                print(f"      LocalForward {_UI_PORT} 127.0.0.1:{_UI_PORT}")
                print(f"  You can also bookmark http://localhost:{_UI_PORT}/ — the bare page")
                print(f"  asks for this run's code: {code}")
                continue
            if raw in ("back", "done", "exit", "quit", "q"):
                break
    finally:
        _stop_ui(httpd)
        print("  Page closed.")


```

## Status

Uptime as humans read it.

```python
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


```

`_production_issues` is the project's model for understatement: it lists what is wrong rather than implying everything is fine — per site, plus the host-level swap check.

```python
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
        if not site.username:
            issues.append(f"no password protection{tag} — run 'config' to set credentials")
        if bool(site.publish_url) != bool(site.publish_key):
            issues.append(f"publish channel partially configured{tag} — run 'config publish' to finish setup")
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
    return issues


```

The cache warnings walk every site's tree, so they run only where a human is reading the answer.

```python
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


```

Runtime stats come from systemd in service mode, from `/proc` and the in-process start time in session mode.

```python
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


```

The machine-readable half: per-site rows shared by `status --json` and `sites --json` — the latter deliberately pays only for this list — and the full status snapshot.

```python
# The site rows
def _site_rows():
    """The per-site rows machine consumers read — shared by _status_data and
    `sites --json`, which deliberately pays only for this list: no systemctl
    round-trip, no cache-warning walk over every site's tree."""
    return [{
        "index":     i,
        "domain":    site.domain,
        "serve_dir": site.serve_dir,
        "auth":      bool(site.username),
        "cert_days": _cert_days_remaining(_resolve(site.cert_file)),
        "publish":   bool(site.publish_url and site.publish_key),
    } for i, site in enumerate(config.sites)]


def _health_checks():
    """Every health fact as a row, green included — the admin page's Health
    checks card. The same ground _production_issues walks, saying what passes
    as plainly as what needs attention: ok True is healthy, False needs it.
    `key` is stable for consumers (the page routes password and channel rows
    to its Config tab); `site` carries the index where the row is
    site-scoped, None where it is host-wide."""
    rows = []
    service_active = _service_is_active()
    running        = service_active or _server_running()
    rows.append({"key": "service", "site": None, "ok": running, "label": "Service",
                 "detail": "running as a system service — survives reboots" if service_active
                 else ("running in this session only — 'enable' outlives the terminal" if running
                       else "stopped — 'start' brings it up")})
    if not _IS_MACOS:
        armed = os.path.exists(NETWATCH_PATH + ".timer")
        rows.append({"key": "netwatch", "site": None, "ok": armed, "label": "Network watchdog",
                     "detail": "armed — a dropped default route recovers within a minute" if armed
                     else "not installed — 'enable' provisions it"})
        mem_kb, _avail_kb, committed_kb = _meminfo()
        rec = _swap_recommendation(mem_kb, committed_kb,
                                   _cache_headroom_mb(config.cache_size_mb))
        ours_mb, foreign_mb = _swap_sizes()
        offer = _swap_offer(rec // (1024 * 1024) if rec else None,
                            os.path.exists(_SWAP_PATH), ours_mb, foreign_mb)
        have = (ours_mb or 0) + foreign_mb
        rows.append({"key": "swap", "site": None, "ok": offer is None, "label": "Swap",
                     "detail": ((f"{have} MB active" if have else "not needed at this host's memory")
                                if offer is None else
                                (f"{have} MB active, below the {offer} MB recommendation — setup offers a resize"
                                 if have else f"none — setup offers a {offer} MB swapfile"))})
    labeled = len(config.sites) > 1
    for i, site in enumerate(config.sites):
        tag = f"Site {i} · " if labeled else ""
        dir_ok = bool(site.serve_dir) and os.path.exists(_resolve(site.serve_dir))
        rows.append({"key": "dir", "site": i, "ok": dir_ok, "label": tag + "Folder",
                     "detail": site.serve_dir if dir_ok else "not configured"})
        days = _cert_days_remaining(_resolve(site.cert_file)) if site.cert_file else None
        cert_ok = days is not None and days > 0 and bool(site.domain)
        rows.append({"key": "cert", "site": i, "ok": cert_ok, "label": tag + "Certificate",
                     "detail": (f"trusted, {days} days remaining — renews itself" if cert_ok
                                else "expired" if (days is not None and days <= 0)
                                else "self-signed — a domain earns a trusted one" if days is not None
                                else "not configured")})
        rows.append({"key": "password", "site": i, "ok": bool(site.username),
                     "label": tag + "Password",
                     "detail": "enabled" if site.username
                     else "none — optional; the Config tab sets one"})
        half = bool(site.publish_url) != bool(site.publish_key)
        rows.append({"key": "channel", "site": i, "ok": not half,
                     "label": tag + "Publish channel",
                     "detail": ("partially configured — finish or clear it on the Config tab" if half
                                else ("configured — 'pull' fetches from it" if site.publish_url
                                      else "none — the admin page publishes directly"))})
    return rows


def _status_data():
    """The status snapshot as data — the shape `status --json` prints, for
    external tooling. cert_days is None when no certificate is readable;
    `checks` is the health-row form of the same facts."""
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
    }


```

The human-facing status display over the same data.

```python
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


```

## Setup wizard

Three steps — folder, certificate, password — reusing the config sub-shell's own prompts, and ending with the offer to enable and start. Setup must never finish with nothing to serve.

```python
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
            print(f"  serve_dir {serve_path} is outside {BASE_DIR} — fix it with 'config' > 'dir' first.")
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


```

## Non-interactive configuration

> `set [n] key=value ...` is the write half of the tooling surface (`status
> --json` and `sites --json` are the read half): external tools drive it over
> SSH, which is the authentication — no network admin API exists, by design.

Validation mirrors the interactive sub-shell's rules; every pair is validated against scratch objects before any is applied, so a bad pair never leaves the config half-written.

```python
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


```

```python
# Site pairs
def _set_site_value(target, key, value):
    """Validate one per-site pair and apply it to target (the chosen site, or
    a scratch Site during the validation pass). Returns an error string,
    empty on success."""
    if key == "dir":
        # The same inline-barrier discipline as _resolve_request_path, for
        # the same reason: this value can arrive over HTTP (the admin page's
        # Config tab — loopback and paired, but HTTP all the same), so the
        # containment check is written out where an analyzer can see it
        # dominate every probe below — a guard folded into a helper is, to
        # it and strictly speaking, not a guard. Containment first, the
        # filesystem probe last.
        resolved = os.path.realpath(_resolve(value))
        if not resolved.startswith(os.path.realpath(BASE_DIR) + os.sep):
            return f"dir must live under {BASE_DIR} (the publish swap and the service sandbox depend on it)"
        if _serve_dir_exposes_secrets(resolved):
            return "dir would serve Servette's own config and keys — refused"
        if not os.path.isdir(resolved):
            return f"directory not found: {resolved}"
        target.serve_dir = value
    elif key == "username":
        # Auth is one switch, not two half-states: a cleared username takes
        # the stored password with it, on every surface that writes settings
        # (`set` and the page alike, since both land here) — the same rule
        # the interactive prompt has always kept.
        target.username = value
        if not value:
            target.password_hash = ""
            target.password_salt = ""
    elif key == "publish_url":
        if value and not value.startswith("https://"):
            return "publish_url must be https:// (or empty to clear)"
        target.publish_url = value
    elif key == "publish_key":
        v = value.strip().lower()
        if v and not (len(v) == 64 and all(c in "0123456789abcdef" for c in v)):
            return "publish_key must be 64 hex characters (a 32-byte Ed25519 public key)"
        target.publish_key = v
    return ""


```

The vocabulary `set` accepts, and its usage line.

```python
# The set vocabulary
_SET_HOST_KEYS = ("port", "email", "rate_limit", "auth_rate_limit",
                  "cache_size_mb", "trusted_proxy")
_SET_SITE_KEYS = ("dir", "username", "publish_url", "publish_key")


def _set_usage():
    print("  Usage: set [n] key=value ...")
    print(f"  Host keys: {', '.join(_SET_HOST_KEYS)}")
    print(f"  Site keys: {', '.join(_SET_SITE_KEYS)} (site index first, default 0)")


```

The command itself. Two keys are deliberately absent: password (a secret on argv leaks into shell history and the process table) and domain (bound up with certificate issuance).

```python
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


```

## Main shell loop

What `update` once did after swapping versions now happens at every shell launch: the package manager cannot refresh a stale systemd unit, so the shell notices on its next run.

```python
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


```

Servette needs root for a handful of things — the systemd unit, the service user, the config the service reads, the site folders it serves. It asks for that itself rather than requiring `sudo` in front of every invocation: prefixing the command forces the console script onto `sudo`'s `secure_path`, which forces an install to put it there — two extra install steps serving nothing.

```python
# Elevating to root
# The commands that never do their work as an ordinary user: they write the
# config the service reads, the unit files, or a site folder the service user
# owns. Read-only ones (status, sites, log) are absent deliberately — they must
# keep working without a password prompt.
_ROOT_COMMANDS = ("setup", "config", "enable", "disable", "set", "admin",
                  "publish", "pull", "restore-site")

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

    The notices go to stderr: the child owns stdout, and `status --json` has to
    stay parseable through an elevation."""
    global _elevated_status
    if not shutil.which("sudo"):
        print(f"  '{cmd}' needs root, and sudo is not installed — re-run as root.",
              file=sys.stderr)
        _elevated_status = 1
        return True
    print(f"  '{cmd}' needs root; asking sudo.", file=sys.stderr)
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


```

One dispatcher, shared verbatim by the interactive loop and the one-shot `servette <command>` argv form, so the two surfaces can never drift.

```python
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
            print("Usage: log [number]")
    elif cmd == "admin":
        cmd_admin()
    elif cmd == "publish":
        cmd_publish()
    elif cmd == "pull":
        site = _config_site_arg(args)
        if site is not None:
            cmd_pull(site)
    elif cmd == "restore-site":
        site = _config_site_arg(args)
        if site is not None:
            cmd_restore_site(site)
    else:
        return False
    return True


```

The interactive loop: banner, help, then the startup refresh — in that order deliberately, so an actionable notice ("run 'enable'") is the last thing printed before the prompt rather than the first thing the sixteen-line command list scrolls away.

```python
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
            print("Goodbye.")
            break
        elif not run_command(cmd, args):
            print(f"Unknown command: {cmd}. Type 'help' for a list of commands.")


```
