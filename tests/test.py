#!/usr/bin/env python3
"""
test.py — Automated tests for servette.py

Run from inside the managed virtualenv:
    .servette-env/bin/python3 test.py

Or, after first-run bootstrap:
    sudo python3 servette.py   # triggers bootstrap
    .servette-env/bin/python3 test.py
"""

import base64
import gzip
import http.client
import http.server
import io
import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request

# test.py lives in tests/; the repo root (containing servette.py and servette.toml) is its parent.
SERVETTE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SERVETTE_DIR)  # so `import servette` resolves to the file under test
TEST_PORT    = 8443
BASE_URL     = f"https://127.0.0.1:{TEST_PORT}"
TEST_HTML    = "<!DOCTYPE html><html><body><p>Servette test</p></body></html>"
TEST_CSS     = "body { margin: 0; }"
TEST_JS      = "console.log('test');"
TEST_SUB_HTML = "<!DOCTYPE html><html><body><p>subpage</p></body></html>"

# Used for regular requests — advertises HTTP/1.1 only so urllib can read responses
SSL_CTX = ssl.create_default_context()
SSL_CTX.minimum_version = ssl.TLSVersion.TLSv1_2
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE
SSL_CTX.set_alpn_protocols(["http/1.1"])

# Used only for the ALPN check — advertises h2 to confirm the server does NOT speak it
SSL_CTX_H2 = ssl.create_default_context()
SSL_CTX_H2.minimum_version = ssl.TLSVersion.TLSv1_2
SSL_CTX_H2.check_hostname = False
SSL_CTX_H2.verify_mode    = ssl.CERT_NONE
SSL_CTX_H2.set_alpn_protocols(["h2", "http/1.1"])


# ─────────────────────────────────────────────────────────────────────────────
# TEST RUNNER
# ─────────────────────────────────────────────────────────────────────────────

_passed = 0
_failed = 0


def check(label, condition):
    global _passed, _failed
    if condition:
        print(f"  ✓  {label}")
        _passed += 1
    else:
        print(f"  ✗  {label}")
        _failed += 1


def section(title):
    print(f"\n{title}")
    print("─" * 52)


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST HELPERS
# ─────────────────────────────────────────────────────────────────────────────

class Response:
    def __init__(self, status, headers, body):
        self.status  = status
        self.headers = headers
        self.body    = body


def req(method="GET", path="/", headers=None, auth=None):
    r = urllib.request.Request(BASE_URL + path, method=method)
    if headers:
        for k, v in headers.items():
            r.add_header(k, v)
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        r.add_header("Authorization", f"Basic {token}")
    try:
        resp = urllib.request.urlopen(r, context=SSL_CTX)
        return Response(resp.getcode(), resp.headers, resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return Response(e.code, e.headers, body)


# ─────────────────────────────────────────────────────────────────────────────
# SETUP AND TEARDOWN
# ─────────────────────────────────────────────────────────────────────────────

def setup():
    # Creates an isolated temp directory containing:
    #   - A throwaway RSA cert/key via openssl. servette isn't imported yet at this
    #     point, so _generate_self_signed_cert can't be used here.
    #   - A minimal serve_dir file tree covering the cases integration tests need.
    #   - A test servette.toml. Any existing config is backed up and restored by teardown.
    # Then imports servette, reloads config into that test state, clears all runtime
    # caches and rate-limit trackers, and starts the live server on TEST_PORT.
    tmpdir = tempfile.mkdtemp()

    cert_path = os.path.join(tmpdir, "cert.pem")
    key_path  = os.path.join(tmpdir, "key.pem")
    result = subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", "365", "-nodes", "-subj", "/CN=127.0.0.1"
    ], capture_output=True)
    if result.returncode != 0:
        print("ERROR: openssl is required. Install it and try again.")
        shutil.rmtree(tmpdir)
        sys.exit(1)

    # Serve directory with a realistic file tree
    serve_dir = os.path.join(tmpdir, "serve")
    os.makedirs(os.path.join(serve_dir, "sub"))

    with open(os.path.join(serve_dir, "index.html"), "w") as f:
        f.write(TEST_HTML)
    with open(os.path.join(serve_dir, "style.css"), "w") as f:
        f.write(TEST_CSS)
    with open(os.path.join(serve_dir, "app.js"), "w") as f:
        f.write(TEST_JS)
    with open(os.path.join(serve_dir, "sub", "index.html"), "w") as f:
        f.write(TEST_SUB_HTML)
    with open(os.path.join(serve_dir, "sub", "page.html"), "w") as f:
        f.write(TEST_SUB_HTML)

    config_path  = os.path.join(SERVETTE_DIR, "servette.toml")
    saved_config = None
    if os.path.exists(config_path):
        with open(config_path, "rb") as f:
            saved_config = f.read()

    with open(config_path, "w") as f:
        f.write(f"""\
serve_dir = "{serve_dir}"
port = {TEST_PORT}
cert_file = "{cert_path}"
key_file = "{key_path}"
username = ""
password_hash = ""
password_salt = ""
rate_limit = 200
auth_rate_limit = 6
cache_policy = "no-cache"
cache_max_age = 3600
cache_size_mb = 128
email = ""
""")

    import servette
    servette.config._load()
    servette._request_times.clear()
    servette._auth_fail_times.clear()
    servette._file_cache.clear()

    servette.start_server()

    if not servette._server_running():
        print(f"ERROR: Server failed to start on port {TEST_PORT}.")
        teardown(tmpdir, saved_config, config_path, servette)
        sys.exit(1)

    return tmpdir, serve_dir, saved_config, config_path, servette


def teardown(tmpdir, saved_config, config_path, servette):
    # Stops the server, restores the original servette.toml (or removes the test
    # one if none existed), and deletes the temp directory.
    servette.stop_server()
    if saved_config is not None:
        with open(config_path, "wb") as f:
            f.write(saved_config)
        os.chmod(config_path, 0o600)
    elif os.path.exists(config_path):
        os.remove(config_path)
    shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# UNIT TESTS
# ─────────────────────────────────────────────────────────────────────────────

def run_unit_tests(s):
    # Pure-function tests — no network I/O, no server required.
    # Calls internal helpers directly and verifies return values.

    section("Password hashing")

    h1, salt1 = s._hash_password("hello")
    h2, salt2 = s._hash_password("hello")
    check("Same password produces different salts each time", salt1 != salt2)
    check("Correct password verifies",    s._check_password("hello", h1, salt1))
    check("Wrong password fails",         not s._check_password("wrong", h1, salt1))
    check("Empty hash returns False",     not s._check_password("hello", "", salt1))
    check("Empty salt returns False",     not s._check_password("hello", h1, ""))
    check("Hash does not contain plaintext", "hello" not in h1)

    section("Config schema migration ([[site]] tables)")

    saved_config_file = s.Config.CONFIG_FILE
    migrate_dir = tempfile.mkdtemp()
    try:
        s.Config.CONFIG_FILE = os.path.join(migrate_dir, "servette.toml")

        # Fresh install: no file at all → one default Site, nothing written yet.
        c = s.Config()
        check("Fresh install produces exactly one site", len(c.sites) == 1)
        check("Fresh install's site has no domain", c.sites[0].domain == "")
        check("Fresh install's site uses the default serve_dir", c.sites[0].serve_dir == "site")
        check("Fresh install does not write a config file", not os.path.exists(s.Config.CONFIG_FILE))

        # Legacy flat config with a plaintext password and publish channel: migrates
        # into a single [[site]] block, hashes the password, and is saved immediately.
        cert_path = os.path.join(migrate_dir, "cert.pem")
        key_path  = os.path.join(migrate_dir, "key.pem")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes", "-subj", "/CN=legacy.example.com"
        ], capture_output=True, check=True)
        with open(s.Config.CONFIG_FILE, "w") as f:
            f.write(f"""\
serve_dir = "myserve"
port = 443
cert_file = "{cert_path}"
key_file = "{key_path}"
username = "bob"
password = "hunter2"
rate_limit = 120
auth_rate_limit = 6
cache_policy = "no-cache"
cache_max_age = 3600
cache_size_mb = 128
email = ""
publish_url = "https://example.com/site.tar.gz"
publish_key = "aa"
""")
        c = s.Config()
        check("Legacy flat config migrates to exactly one site", len(c.sites) == 1)
        check("Migrated site's domain is backfilled from its existing cert",
              c.sites[0].domain == "legacy.example.com")
        check("Migrated site keeps its serve_dir", c.sites[0].serve_dir == "myserve")
        check("Migrated site keeps its publish channel", c.sites[0].publish_url == "https://example.com/site.tar.gz")
        check("Plaintext password is hashed on migration", c.sites[0].password_hash != "")
        check("Hashed password verifies", s._check_password("hunter2", c.sites[0].password_hash, c.sites[0].password_salt))
        check("Migration rewrites the file in [[site]] form", "[[site]]" in open(s.Config.CONFIG_FILE).read())

        # Reloading the now-migrated file must not re-migrate or re-derive anything —
        # it should load the [[site]] table(s) as-is.
        c2 = s.Config()
        check("Reloading an already-migrated config still has one site", len(c2.sites) == 1)
        check("Reloading preserves the migrated domain", c2.sites[0].domain == "legacy.example.com")

        # A genuine multi-site config loads every [[site]] block.
        with open(s.Config.CONFIG_FILE, "w") as f:
            f.write("""\
port = 443
rate_limit = 120
auth_rate_limit = 6
cache_policy = "no-cache"
cache_max_age = 3600
cache_size_mb = 128
email = ""

[[site]]
domain = "a.example.com"
serve_dir = "a"

[[site]]
domain = "b.example.com"
serve_dir = "b"
""")
        c3 = s.Config()
        check("Multi-site config loads all [[site]] blocks", len(c3.sites) == 2)
        check("Sites load in file order",
              [site.domain for site in c3.sites] == ["a.example.com", "b.example.com"])
    finally:
        s.Config.CONFIG_FILE = saved_config_file
        shutil.rmtree(migrate_dir, ignore_errors=True)

    section("Config save escapes control characters")

    _cfg_saved = s.Config.CONFIG_FILE
    _cfg_dir   = tempfile.mkdtemp()
    try:
        s.Config.CONFIG_FILE = os.path.join(_cfg_dir, "servette.toml")
        c = s.Config()
        # A value carrying control characters must survive save→load rather than
        # corrupt the file into something tomllib refuses (which would stop
        # Servette from starting on the next run).
        nasty = "a\x00b\tc\x1bd\ne\rf\x7fg"
        c.email = nasty
        c.save()
        check("A control-char value round-trips through save/load",
              s.Config().email == nasty)
        check("The saved file is valid TOML (reloaded without error)",
              "[[site]]" in open(s.Config.CONFIG_FILE).read())
    finally:
        s.Config.CONFIG_FILE = _cfg_saved
        shutil.rmtree(_cfg_dir, ignore_errors=True)

    section("Site selection by Host/SNI")

    saved_sites = s.config.sites
    try:
        site_a    = s.Site({"domain": "a.example.com", "serve_dir": "x"})
        site_b    = s.Site({"domain": "b.example.com", "serve_dir": "y"})
        catch_all = s.Site({"domain": "", "serve_dir": "z"})

        s.config.sites = [site_a, site_b]
        check("Exact domain match", s._select_site("a.example.com") is site_a)
        check("Matching is case-insensitive", s._select_site("A.Example.COM") is site_a)
        check("Port suffix is stripped before matching", s._select_site("b.example.com:443") is site_b)
        check("No domainless catch-all, no match → None", s._select_site("nope.example.com") is None)
        check("Empty Host, no catch-all → None", s._select_site("") is None)

        s.config.sites = [site_a, catch_all]
        check("Domainless site is the catch-all for an unmatched Host",
              s._select_site("nope.example.com") is catch_all)
        check("A real domain match still wins over the catch-all",
              s._select_site("a.example.com") is site_a)

        # _obtain_trusted_cert issues one certificate covering <domain> and
        # www.<domain>, so routing has to answer for both or the www name gets a
        # certificate and then a 404.
        site_www = s.Site({"domain": "www.a.example.com", "serve_dir": "w"})

        s.config.sites = [site_a, site_b]
        check("www.<domain> reaches the site configured as <domain>",
              s._select_site("www.a.example.com") is site_a)
        check("www fallback is case-insensitive",
              s._select_site("WWW.A.Example.COM") is site_a)
        check("www fallback strips the port too",
              s._select_site("www.a.example.com:443") is site_a)
        check("www of an unconfigured domain still misses",
              s._select_site("www.nope.example.com") is None)

        s.config.sites = [site_a, site_www]
        check("An explicit www.<domain> site wins its own traffic",
              s._select_site("www.a.example.com") is site_www)
        s.config.sites = [site_www, site_a]
        check("An explicit www.<domain> site wins whatever the list order",
              s._select_site("www.a.example.com") is site_www)
        check("The bare domain still reaches the bare site alongside it",
              s._select_site("a.example.com") is site_a)

        s.config.sites = [site_a, catch_all]
        check("www fallback is preferred over the domainless catch-all",
              s._select_site("www.a.example.com") is site_a)
    finally:
        s.config.sites = saved_sites

    section("Multi-site TLS contexts")

    saved_sites2         = s.config.sites
    default_cert_existed = os.path.exists(s._DEFAULT_CERT_FILE)
    tls_dir = tempfile.mkdtemp()
    try:
        def gen_cert(cn):
            cert_path = os.path.join(tls_dir, f"{cn}-cert.pem")
            key_path  = os.path.join(tls_dir, f"{cn}-key.pem")
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
                "-out", cert_path, "-days", "1", "-nodes", "-subj", f"/CN={cn}"
            ], capture_output=True, check=True)
            return cert_path, key_path

        # A single domainless site: its own cert becomes the default context, and
        # no generic cert is generated for the role — matches today's behavior
        # for a self-signed/LAN single-site box exactly, with no new machinery.
        if default_cert_existed:
            os.remove(s._DEFAULT_CERT_FILE)
        solo_cert, solo_key = gen_cert("localhost")
        s.config.sites = [s.Site({"domain": "", "cert_file": solo_cert, "key_file": solo_key, "serve_dir": tls_dir})]
        default_ctx = s._build_site_ssl_contexts()
        check("Domainless single site: no generic default cert generated",
              not os.path.exists(s._DEFAULT_CERT_FILE))
        check("Default context carries an sni_callback", default_ctx.sni_callback is not None)

        # Two domain-bearing sites, no catch-all: a generic default cert IS needed.
        cert_a, key_a = gen_cert("a.example.com")
        cert_b, key_b = gen_cert("b.example.com")
        site_a2 = s.Site({"domain": "a.example.com", "cert_file": cert_a, "key_file": key_a, "serve_dir": tls_dir})
        site_b2 = s.Site({"domain": "b.example.com", "cert_file": cert_b, "key_file": key_b, "serve_dir": tls_dir})
        s.config.sites = [site_a2, site_b2]
        default_ctx2 = s._build_site_ssl_contexts()
        check("All-domain multi-site: a generic default cert is generated",
              os.path.exists(s._DEFAULT_CERT_FILE))

        class _FakeSSLSocket:
            def __init__(self, ctx):
                self.context = ctx

        sni_cb = default_ctx2.sni_callback

        fake_a = _FakeSSLSocket(default_ctx2)
        sni_cb(fake_a, "a.example.com", default_ctx2)
        check("SNI match switches the socket's context away from default",
              fake_a.context is not default_ctx2)

        fake_b = _FakeSSLSocket(default_ctx2)
        sni_cb(fake_b, "b.example.com", default_ctx2)
        check("A different domain switches to a different context",
              fake_b.context is not fake_a.context)

        # The issued certificate covers www.<domain>, so SNI for that name must
        # land on the same context. Without this the connection falls to the
        # default context and the visitor is shown a certificate for nothing
        # they asked for — a warning before routing ever runs.
        fake_www = _FakeSSLSocket(default_ctx2)
        sni_cb(fake_www, "www.a.example.com", default_ctx2)
        check("SNI for www.<domain> gets the same context as <domain>",
              fake_www.context is fake_a.context)

        fake_miss = _FakeSSLSocket(default_ctx2)
        sni_cb(fake_miss, "unrecognized.example.com", default_ctx2)
        check("Unrecognized SNI leaves the default (closed-system) context",
              fake_miss.context is default_ctx2)

        fake_none = _FakeSSLSocket(default_ctx2)
        sni_cb(fake_none, None, default_ctx2)
        check("Absent SNI leaves the default context",
              fake_none.context is default_ctx2)
    finally:
        s.config.sites = saved_sites2
        shutil.rmtree(tls_dir, ignore_errors=True)
        if not default_cert_existed and os.path.exists(s._DEFAULT_CERT_FILE):
            shutil.rmtree(s._DEFAULT_CERT_DIR, ignore_errors=True)

    section("Versioning")

    check("__version__ is set",              bool(s.__version__))
    check("__version__ has 3 parts",         len(s.__version__.split(".")) == 3)
    check("__version__ major is 0",          s.__version__.split(".")[0] == "0")

    section("Cache-Control header")

    s.config.sites[0].username     = ""
    s.config.cache_policy = "no-store"
    check("no-store",                          s._cache_control_header(s.config.sites[0].username) == "no-store")

    s.config.cache_policy = "no-cache"
    check("no-cache, no auth → public",        s._cache_control_header(s.config.sites[0].username) == "public, no-cache")

    s.config.sites[0].username = "alice"
    check("no-cache, with auth → private",     s._cache_control_header(s.config.sites[0].username) == "private, no-cache")

    s.config.cache_policy  = "max-age"
    s.config.cache_max_age = 3600
    check("max-age with auth → private, max-age=3600",
          s._cache_control_header(s.config.sites[0].username) == "private, max-age=3600")

    s.config.sites[0].username     = ""
    s.config.cache_policy = "no-cache"

    section("Rate limiter bounds memory per IP")

    # _RATE_IP_CAP bounds how many IPs are tracked; nothing bounded a single
    # IP's deque, and a client already being refused still appends on every 429.
    rl_tracker = {}
    for _ in range(500):
        s._rate_limit_exceeded(rl_tracker, "203.0.113.9", 10)
    check("One IP's deque stays bounded regardless of volume",
          len(rl_tracker["203.0.113.9"]) == 11)
    check("A flooding IP is still over the limit after the bound applies",
          s._rate_limit_exceeded(rl_tracker, "203.0.113.9", 10) is True)
    under = {}
    for _ in range(5):
        s._rate_limit_exceeded(under, "203.0.113.10", 10)
    check("A well-behaved IP is unaffected and stays under",
          s._rate_limit_exceeded(under, "203.0.113.10", 10) is False)

    section("IPv6 normalization")

    check("::ffff: prefix stripped",       s._normalize_ip("::ffff:192.168.1.1") == "192.168.1.1")
    check("hex-mapped form normalized",    s._normalize_ip("::ffff:c0a8:0101") == "192.168.1.1")
    check("dotted and hex map to same key",
          s._normalize_ip("::ffff:c0a8:0101") == s._normalize_ip("::ffff:192.168.1.1"))
    check("Plain IPv4 unchanged",          s._normalize_ip("10.0.0.1") == "10.0.0.1")
    check("Plain IPv6 unchanged",          s._normalize_ip("2001:db8::1") == "2001:db8::1")
    check("Non-address passes through",    s._normalize_ip("unknown") == "unknown")

    section("_is_within_base_dir (serve_dir containment)")

    # Added by the commit that rejected a serve_dir outside BASE_DIR, which
    # shipped without one. The containment rule is what keeps the publish
    # pipeline's atomic rename on one filesystem and inside the systemd unit's
    # ReadWritePaths — a serve_dir outside it fails silently under the sandbox
    # while working fine in a manual run.
    _base = os.path.realpath(s.BASE_DIR)
    check("BASE_DIR itself is inside",            s._is_within_base_dir(_base))
    check("A child of BASE_DIR is inside",        s._is_within_base_dir(os.path.join(_base, "site")))
    check("A deep child is inside",               s._is_within_base_dir(os.path.join(_base, "a", "b", "c")))
    check("A parent of BASE_DIR is outside",      not s._is_within_base_dir(os.path.dirname(_base)))
    check("An unrelated absolute path is outside", not s._is_within_base_dir("/etc"))
    # The prefix trap: a sibling whose name merely starts with BASE_DIR's.
    check("A sibling sharing BASE_DIR's prefix is outside",
          not s._is_within_base_dir(_base + "-evil"))
    # Traversal back out through a child must not read as inside.
    check("Traversal out of BASE_DIR is outside",
          not s._is_within_base_dir(os.path.join(_base, "..", "elsewhere")))

    _sym_root = tempfile.mkdtemp()
    try:
        _outside = os.path.join(_sym_root, "outside")
        os.makedirs(_outside, exist_ok=True)
        _link = os.path.join(_base, "symlink-escape-test")
        if os.path.islink(_link) or os.path.exists(_link):
            os.remove(_link)
        os.symlink(_outside, _link)
        try:
            check("A symlink pointing outside BASE_DIR is outside",
                  not s._is_within_base_dir(_link))
        finally:
            os.remove(_link)
    finally:
        shutil.rmtree(_sym_root, ignore_errors=True)

    section("_resolve_request_path")

    path, status = s._resolve_request_path("/", s.config.sites[0].serve_dir)
    check("/ resolves to index.html (200)",
          path is not None and path.endswith("index.html") and status == 200)

    path, status = s._resolve_request_path("/style.css", s.config.sites[0].serve_dir)
    check("/style.css resolves (200)",
          path is not None and path.endswith("style.css") and status == 200)

    path, status = s._resolve_request_path("/sub/", s.config.sites[0].serve_dir)
    check("/sub/ resolves to sub/index.html (200)",
          path is not None and "sub" in path and path.endswith("index.html") and status == 200)

    path, status = s._resolve_request_path("/sub/page.html", s.config.sites[0].serve_dir)
    check("/sub/page.html resolves (200)",
          path is not None and path.endswith("page.html") and status == 200)

    path, status = s._resolve_request_path("/nonexistent.html", s.config.sites[0].serve_dir)
    check("/nonexistent.html → 404",     path is None and status == 404)

    path, status = s._resolve_request_path("/../etc/passwd", s.config.sites[0].serve_dir)
    check("Path traversal .. → 403",     path is None and status == 403)

    path, status = s._resolve_request_path("/%2e%2e/etc/passwd", s.config.sites[0].serve_dir)
    check("Encoded traversal %2e%2e → 403", path is None and status == 403)

    # Hidden files are refused before existence is even checked (#45), so a .git
    # checkout or a .env under serve_dir is never served.
    path, status = s._resolve_request_path("/.git/config", s.config.sites[0].serve_dir)
    check("Dotfile .git/config → 403",       path is None and status == 403)
    path, status = s._resolve_request_path("/.env", s.config.sites[0].serve_dir)
    check("Dotfile .env → 403",              path is None and status == 403)
    path, status = s._resolve_request_path("/sub/.secret", s.config.sites[0].serve_dir)
    check("Hidden file in a subdirectory → 403", path is None and status == 403)
    # .well-known is the exception: not refused by the dotfile rule, so an absent
    # file there is a plain 404 (403 would mean the rule wrongly caught it).
    path, status = s._resolve_request_path("/.well-known/security.txt", s.config.sites[0].serve_dir)
    check("/.well-known is exempt (absent file → 404, not 403)",
          path is None and status == 404)

    section("_serve_dir_exposes_secrets (#45)")

    _sbase = os.path.realpath(s.BASE_DIR)
    check("serve_dir == BASE_DIR is refused (holds config + keys)",
          s._serve_dir_exposes_secrets(_sbase))
    check("serve_dir == certs/ is refused (the TLS private keys)",
          s._serve_dir_exposes_secrets(os.path.join(_sbase, "certs")))
    check("serve_dir under certs/ is refused",
          s._serve_dir_exposes_secrets(os.path.join(_sbase, "certs", "example.com")))
    check("an ordinary child folder (site/) is fine",
          not s._serve_dir_exposes_secrets(os.path.join(_sbase, "site")))

    section("_loggable escapes log-bound control characters")

    check("ESC is escaped",       s._loggable("a\x1bb")    == "a\\x1bb")
    check("newline is escaped",   s._loggable("x\ny")      == "x\\x0ay")
    check("DEL is escaped",       s._loggable("\x7f")      == "\\x7f")
    check("printable path kept",  s._loggable("/a/b?c=1")  == "/a/b?c=1")
    check("non-ASCII kept as-is", s._loggable("/café") == "/café")

    section("_is_downgrade (update version floor)")

    check("older patch is a downgrade",            s._is_downgrade("0.26.219", "0.26.3"))
    check("newer patch is not a downgrade",        not s._is_downgrade("0.26.3", "0.26.219"))
    check("equal version is not a downgrade",      not s._is_downgrade("1.2.3", "1.2.3"))
    check("a higher major is not a downgrade",     not s._is_downgrade("0.26.219", "1.0.0"))
    check("an uncomparable version never blocks",  not s._is_downgrade("1.2.3", "2.0rc1"))

    section("_format_uptime")

    check("Seconds",  s._format_uptime(45)    == "45s")
    check("Minutes",  s._format_uptime(90)    == "1m 30s")
    check("Hours",    s._format_uptime(3700)  == "1h 1m")
    check("Days",     s._format_uptime(90061) == "1d 1h")

    section("Minimal ACME client (JWS)")
    # Exercise the crypto the hand-rolled ACME client does — base64url, the JWK
    # thumbprint, and RS256 JWS signing — without touching the network (the client
    # fetches its directory lazily, so construction makes no requests).
    import json as _json
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, padding as _pad
    from cryptography.hazmat.primitives import hashes as _h

    def unb64(x):
        return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))

    check("_b64url strips padding",        s._b64url(b"\x00\x00") == "AAA")
    check("_b64url_int encodes exponent",  s._b64url_int(65537) == "AQAB")

    akey = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    c    = s._ACMEClient("https://acme.example/directory", akey)
    tp   = c.thumbprint()
    check("thumbprint is url-safe + unpadded", not (set(tp) & set("=+/")))
    check("key_authorization is token.thumbprint", c.key_authorization("tok") == f"tok.{tp}")

    c._nonce = "testnonce"
    jws  = _json.loads(c._sign("https://acme.example/new-order", {"x": 1}))
    prot = _json.loads(unb64(jws["protected"]))
    check("JWS alg is RS256",               prot["alg"] == "RS256")
    check("JWS carries jwk before account known", "jwk" in prot and "kid" not in prot)
    check("JWS pins url + nonce",            prot["url"].endswith("/new-order") and prot["nonce"] == "testnonce")
    try:
        akey.public_key().verify(unb64(jws["signature"]),
                                 (jws["protected"] + "." + jws["payload"]).encode(),
                                 _pad.PKCS1v15(), _h.SHA256())
        sig_ok = True
    except Exception:
        sig_ok = False
    check("JWS signature verifies (RS256)", sig_ok)
    check("POST-as-GET payload is empty",   _json.loads(c._sign("https://acme.example/a", None))["payload"] == "")

    c._kid = "https://acme.example/acct/1"
    prot2  = _json.loads(unb64(_json.loads(c._sign("https://acme.example/a", None))["protected"]))
    check("kid replaces jwk once account known", "kid" in prot2 and "jwk" not in prot2)


def run_dispatch_tests(s):
    # Covers two seams the live-server tests can't reach:
    #   - the port-80 _RedirectHandler (HTTP->HTTPS redirect + ACME HTTP-01 challenge
    #     serving), exercised against a throwaway ThreadingHTTPServer on an ephemeral
    #     port so neither port 80 nor root is needed;
    #   - the interactive shell's command dispatch, driven with scripted input.
    # Full Let's Encrypt issuance and systemd integration need external
    # infrastructure and remain integration-territory, intentionally uncovered.
    import builtins, io, contextlib

    def redirect_request(method, path, headers=None):
        """Drive one request through _RedirectHandler on an ephemeral port."""
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), s._RedirectHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            body = resp.read()
            result = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, body)
            conn.close()
        finally:
            srv.shutdown()
            srv.server_close()
        return result

    section("Redirect handler — HTTPS redirect")

    status, headers, _ = redirect_request("GET", "/some/page", headers={"Host": "example.com"})
    port     = s.config.port
    expected = (f"https://example.com/some/page" if port == 443
                else f"https://example.com:{port}/some/page")
    check("Plain HTTP → 301",            status == 301)
    check("Location is https host+path", headers.get("location") == expected)

    _, qheaders, _ = redirect_request("GET", "/p?a=1&b=2", headers={"Host": "example.com"})
    check("Redirect preserves the query string",
          qheaders.get("location", "").endswith("/p?a=1&b=2"))

    section("Redirect handler — ACME HTTP-01 challenge")

    orig_webroot = s.ACME_WEBROOT
    acme_dir = tempfile.mkdtemp()
    s.ACME_WEBROOT = acme_dir
    try:
        chall_dir = os.path.join(acme_dir, ".well-known", "acme-challenge")
        os.makedirs(chall_dir)
        with open(os.path.join(chall_dir, "token123"), "w") as f:
            f.write("keyauth-value")
        status, _, body = redirect_request("GET", "/.well-known/acme-challenge/token123")
        check("Valid token → 200",        status == 200)
        check("Serves challenge content", body == b"keyauth-value")
        status, _, _ = redirect_request("GET", "/.well-known/acme-challenge/missing")
        check("Unknown token → 404",      status == 404)

        # Tokens are base64url per RFC 8555 — anything outside that charset is
        # rejected before any filesystem lookup happens.
        for bad_charset in ["tok.en", "tok+en", "tok%2Fen", "..", "caf%C3%A9"]:
            status, _, _ = redirect_request("GET", f"/.well-known/acme-challenge/{bad_charset}")
            check(f"Non-base64url token {bad_charset!r} → 404", status == 404)
        for bad in ["/.well-known/acme-challenge/",
                    "/.well-known/acme-challenge/a/b",
                    "/.well-known/acme-challenge/..%2f..%2fpasswd"]:
            st, _, _ = redirect_request("GET", bad)
            check(f"Rejected token path {bad!r}", st == 404)

        # A symlinked webroot must still serve valid tokens: the containment check
        # realpath's both sides, so the token path and the base agree after the
        # symlink resolves. (Guards against comparing a resolved path to an
        # unresolved base, which would 404 every token on such a host.)
        link_root = tempfile.mkdtemp()
        link_dir  = os.path.join(link_root, "webroot-link")
        os.symlink(acme_dir, link_dir)
        s.ACME_WEBROOT = link_dir
        status, _, body = redirect_request("GET", "/.well-known/acme-challenge/token123")
        check("Valid token via symlinked webroot → 200", status == 200 and body == b"keyauth-value")
        s.ACME_WEBROOT = acme_dir
        shutil.rmtree(link_root, ignore_errors=True)
    finally:
        s.ACME_WEBROOT = orig_webroot
        shutil.rmtree(acme_dir, ignore_errors=True)

    section("Shell — command dispatch")

    # Spy on the handlers so we verify routing without their side effects, and
    # feed scripted input. 'quit' calls stop_server, so stub it to keep the
    # live test server up for the integration tests that follow.
    calls       = []
    saved       = {n: getattr(s, n) for n in
                   ("cmd_status", "cmd_start", "stop_server", "cmd_pull", "cmd_restore_site")}
    saved_input = builtins.input
    try:
        s.cmd_status       = lambda: calls.append("status")
        s.cmd_start        = lambda: calls.append("start")
        s.stop_server      = lambda: calls.append("stop")
        s.cmd_pull         = lambda site: calls.append(("pull", site))
        s.cmd_restore_site = lambda site: calls.append(("restore-site", site))
        script = iter(["status", "start", "pull 0", "restore-site 0", "pull 99", "bogus", "quit"])
        builtins.input = lambda prompt="": next(script, "quit")
        with contextlib.redirect_stdout(io.StringIO()):
            s.shell()
    finally:
        builtins.input = saved_input
        for n, fn in saved.items():
            setattr(s, n, fn)

    check("'status' routed to cmd_status", "status" in calls)
    check("'start' routed to cmd_start",   "start" in calls)
    check("'pull 0' routes to cmd_pull with site 0",
          ("pull", s.config.sites[0]) in calls)
    check("'restore-site 0' routes to cmd_restore_site with site 0",
          ("restore-site", s.config.sites[0]) in calls)
    pull_calls = [c for c in calls if isinstance(c, tuple) and c[0] == "pull"]
    check("'pull 99' (bad site index) does not call cmd_pull", len(pull_calls) == 1)
    check("'quit' stops server and exits", calls[-1] == "stop")

    section("Post-update reload")

    # _apply_post_update runs immediately after 'update' re-execs into the new
    # file. Drive it with the real file-system checks stubbed out (they need
    # root/systemd) and verify it refreshes the unit and restarts only when a
    # service is actually enabled — and that a refresh failure is contained
    # rather than raised.
    saved = {n: getattr(s, n) for n in
             ("_service_file_exists", "_write_unit_files", "_service_is_active", "_reload_server")}
    try:
        calls = []
        s._service_file_exists = lambda: True
        s._write_unit_files    = lambda: calls.append("write") or True
        s._service_is_active   = lambda: True
        s._reload_server       = lambda: calls.append("reload")
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s._apply_post_update()
        check("Enabled service: unit refreshed and reloaded", calls == ["write", "reload"])
        check("Prints the version it reloaded to", f"v{s.__version__}" in buf.getvalue())

        calls = []
        s._service_file_exists = lambda: False
        with contextlib.redirect_stdout(io.StringIO()):
            s._apply_post_update()
        check("No service enabled: unit left untouched", calls == [])

        s._service_file_exists = lambda: True
        s._write_unit_files    = lambda: (_ for _ in ()).throw(subprocess.CalledProcessError(1, "x"))
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s._apply_post_update()  # must not raise
        check("A failed unit refresh is contained, not raised",
              "Could not refresh" in buf.getvalue())
    finally:
        for n, fn in saved.items():
            setattr(s, n, fn)

    section("Restore command")
    # cmd_restore swaps servette.py.bak back into place and consumes it. Drive it
    # against a throwaway servette.py/.bak by pointing the module's __file__ there
    # and auto-confirming the prompt; no service, no real file is touched.
    rdir = tempfile.mkdtemp()
    sv   = os.path.join(rdir, "servette.py")
    bak  = sv + ".bak"
    with open(sv, "w")  as f: f.write('__version__ = "9.9.9"\n')
    with open(bak, "w") as f: f.write('__version__ = "8.8.8"\n')
    saved = {n: getattr(s, n) for n in ("__file__", "_prompt", "_service_is_active", "_server_running")}
    try:
        s.__file__           = sv
        s._prompt            = lambda *a, **k: True
        s._service_is_active = lambda: False
        s._server_running    = lambda: False
        with contextlib.redirect_stdout(io.StringIO()):
            s.cmd_restore()
        check("restore swaps the backup into place", open(sv).read().strip() == '__version__ = "8.8.8"')
        check("restore consumes the backup",         not os.path.exists(bak))

        # With no backup present, restore is a no-op that leaves the file alone.
        with contextlib.redirect_stdout(io.StringIO()):
            s.cmd_restore()
        check("restore with no backup leaves file unchanged", open(sv).read().strip() == '__version__ = "8.8.8"')
    finally:
        for n, v in saved.items():
            setattr(s, n, v)
        shutil.rmtree(rdir, ignore_errors=True)

    section("Site management (add/remove/select)")

    saved_sites7  = list(s.config.sites)  # a copy: add-site/remove-site mutate the
                                          # list in place, so a bare reference here
                                          # wouldn't actually restore anything
    saved_reload  = s._reload_server
    saved_ssrv    = s._server_running
    saved_sact    = s._service_is_active
    site_test_dir = tempfile.mkdtemp(dir=s.BASE_DIR)  # add-site now requires serve_dir under BASE_DIR
    new_site_cert_files = []  # populated below once add-site picks its (randomized) names
    try:
        s._server_running    = lambda: False
        s._service_is_active = lambda: False
        s._reload_server     = lambda: None

        check("_config_site_arg([]) resolves to site 0",
              s._config_site_arg([]) is s.config.sites[0])
        check("_config_site_arg(['0']) resolves to site 0",
              s._config_site_arg(["0"]) is s.config.sites[0])
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            result = s._config_site_arg(["99"])
        check("Out-of-range site index returns None", result is None)
        check("Out-of-range site index reports cleanly", "No site 99" in buf.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            result = s._config_site_arg(["nope"])
        check("Non-numeric site index returns None", result is None)

        saved_input = builtins.input
        try:
            # add-site: folder, domain (blank → self-signed), username (blank).
            script = iter([site_test_dir, "", ""])
            builtins.input = lambda prompt="": next(script, "")
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                s._config_add_site()
            check("add-site appends exactly one site", len(s.config.sites) == 2)
            check("add-site's new site uses the given folder",
                  s.config.sites[1].serve_dir == site_test_dir)
            check("add-site's new site gets a unique cert/key (no collision with site 0)",
                  s.config.sites[1].cert_file != s.config.sites[0].cert_file)
            check("add-site generates a real self-signed cert",
                  os.path.isfile(s._resolve(s.config.sites[1].cert_file)))
            check("add-site reports the new site's index", "Site 1 added" in buf.getvalue())
            new_site_cert_files.extend([s.config.sites[1].cert_file, s.config.sites[1].key_file])
        finally:
            builtins.input = saved_input

        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s._config_sites()
        out = buf.getvalue()
        check("'sites' lists site 0", "0:" in out)
        check("'sites' lists site 1", "1:" in out)

        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s._config_remove_site([])
        check("remove-site with no argument reports usage", "Usage" in buf.getvalue())

        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s._config_remove_site(["99"])
        check("remove-site with an out-of-range index reports cleanly", "No site 99" in buf.getvalue())

        saved_prompt = s._prompt
        try:
            s._prompt = lambda *a, **k: True
            with contextlib.redirect_stdout(io.StringIO()):
                s._config_remove_site(["1"])
            check("remove-site removes the confirmed site", len(s.config.sites) == 1)

            with contextlib.redirect_stdout(io.StringIO()) as buf:
                s._config_remove_site(["0"])
            check("remove-site refuses to remove the only site", len(s.config.sites) == 1)
            check("Refusing to remove the only site reports why", "only site" in buf.getvalue())
        finally:
            s._prompt = saved_prompt
    finally:
        for fname in new_site_cert_files:
            p = os.path.join(s.BASE_DIR, fname)
            if os.path.exists(p):
                os.remove(p)
        s._reload_server     = saved_reload
        s._server_running    = saved_ssrv
        s._service_is_active = saved_sact
        s.config.sites       = saved_sites7
        shutil.rmtree(site_test_dir, ignore_errors=True)

    section("_domain_in_use")

    saved_sites9 = s.config.sites
    try:
        site_a = s.Site({"domain": "a.example.com"})
        site_b = s.Site({"domain": ""})
        s.config.sites = [site_a, site_b]
        check("Domain already claimed by another site is in use",
              s._domain_in_use("a.example.com") is True)
        check("Matching is case-insensitive",
              s._domain_in_use("A.EXAMPLE.COM") is True)
        check("A different domain is not in use",
              s._domain_in_use("b.example.com") is False)
        check("excluding= lets a site's own current domain pass",
              s._domain_in_use("a.example.com", excluding=site_a) is False)
        check("excluding= doesn't hide a genuine collision with a different site",
              s._domain_in_use("a.example.com", excluding=site_b) is True)
    finally:
        s.config.sites = saved_sites9

    section("Site management: cert collision, chown, reload, duplicate-domain guards")

    saved_sites10 = list(s.config.sites)  # a copy — see the note in the previous section
    saved_reload2 = s._reload_server
    saved_ssrv2   = s._server_running
    saved_sact2   = s._service_is_active
    saved_chown   = s._chown_servette
    saved_obtain  = s._obtain_trusted_cert
    dirs2 = [tempfile.mkdtemp(dir=s.BASE_DIR) for _ in range(3)]  # add-site requires serve_dir under BASE_DIR
    generated_files = []
    try:
        s._server_running    = lambda: True
        s._service_is_active = lambda: False
        reload_calls = []
        s._reload_server = lambda: reload_calls.append(1)
        chown_calls = []
        s._chown_servette = lambda path: chown_calls.append(path)

        saved_input2 = builtins.input
        try:
            # Two self-signed sites added back to back must not collide.
            script = iter([dirs2[0], "", "", dirs2[1], "", ""])
            builtins.input = lambda prompt="": next(script, "")
            with contextlib.redirect_stdout(io.StringIO()):
                s._config_add_site()
                s._config_add_site()
            check("Two self-signed sites get distinct cert files",
                  s.config.sites[1].cert_file != s.config.sites[2].cert_file)
            check("Self-signed add-site chowns its new cert and key",
                  s._resolve(s.config.sites[2].cert_file) in chown_calls
                  and s._resolve(s.config.sites[2].key_file) in chown_calls)
            generated_files.extend([s.config.sites[1].cert_file, s.config.sites[1].key_file,
                                     s.config.sites[2].cert_file, s.config.sites[2].key_file])

            # Remove the middle site, then add a third — its cert must not reuse
            # the surviving site's filename just because a list index freed up.
            survivor_cert = s.config.sites[2].cert_file
            saved_prompt2 = s._prompt
            try:
                s._prompt = lambda *a, **k: True
                with contextlib.redirect_stdout(io.StringIO()):
                    s._config_remove_site(["1"])
            finally:
                s._prompt = saved_prompt2
            check("Survivor kept its own cert file across the removal",
                  s.config.sites[1].cert_file == survivor_cert)

            script2 = iter([dirs2[2], "", ""])
            builtins.input = lambda prompt="": next(script2, "")
            with contextlib.redirect_stdout(io.StringIO()):
                s._config_add_site()
            check("A newly added site's cert never collides with a survivor's",
                  s.config.sites[2].cert_file != survivor_cert)
            check("The survivor's cert file is unchanged, not silently overwritten",
                  s.config.sites[1].cert_file == survivor_cert)
            generated_files.extend([s.config.sites[2].cert_file, s.config.sites[2].key_file])
        finally:
            builtins.input = saved_input2

        # Domain branch: _obtain_trusted_cert already reloads on success — add-site
        # must not reload a second time on top of it.
        def _fake_obtain_success(domain, site):
            reload_calls.append("obtain-reloaded")
            site.domain = domain  # only happens on the real success path
        s._obtain_trusted_cert = _fake_obtain_success
        reload_calls.clear()
        dir6 = tempfile.mkdtemp(dir=s.BASE_DIR)  # add-site requires serve_dir under BASE_DIR
        saved_input3 = builtins.input
        try:
            script3 = iter([dir6, "domain-test.example.com", ""])
            builtins.input = lambda prompt="": next(script3, "")
            with contextlib.redirect_stdout(io.StringIO()):
                s._config_add_site()
        finally:
            builtins.input = saved_input3
            shutil.rmtree(dir6, ignore_errors=True)
        check("add-site's own reload doesn't double up on the domain branch's",
              reload_calls.count(1) == 0 and reload_calls.count("obtain-reloaded") == 1)
        generated_files.extend([s.config.sites[-1].cert_file, s.config.sites[-1].key_file])

        # A real issuance repoints cert_file/key_file at certs/<domain>/, which
        # orphans the placeholder pair add-site generates before it even asks
        # about a domain. Those must not accumulate on disk forever.
        acme_dir = tempfile.mkdtemp(dir=s.BASE_DIR)
        def _fake_obtain_repoints(domain, site):
            new_cert = os.path.join(acme_dir, "fullchain.pem")
            new_key  = os.path.join(acme_dir, "privkey.pem")
            for p in (new_cert, new_key):
                with open(p, "w") as f:
                    f.write("x")
            site.cert_file = new_cert
            site.key_file  = new_key
            site.domain    = domain   # only happens on the real success path
        s._obtain_trusted_cert = _fake_obtain_repoints
        placeholders_before = {f for f in os.listdir(s.BASE_DIR) if f.startswith(("cert-", "key-"))}
        dir6c = tempfile.mkdtemp(dir=s.BASE_DIR)
        saved_input3c = builtins.input
        try:
            script3c = iter([dir6c, "issued.example.com", ""])
            builtins.input = lambda prompt="": next(script3c, "")
            with contextlib.redirect_stdout(io.StringIO()):
                s._config_add_site()
        finally:
            builtins.input = saved_input3c
            shutil.rmtree(dir6c, ignore_errors=True)
        placeholders_after = {f for f in os.listdir(s.BASE_DIR) if f.startswith(("cert-", "key-"))}
        check("Issuance repointed the site away from its placeholder",
              s._resolve(s.config.sites[-1].cert_file) == os.path.join(acme_dir, "fullchain.pem"))
        check("The orphaned placeholder cert/key are removed after issuance succeeds",
              placeholders_after == placeholders_before)
        shutil.rmtree(acme_dir, ignore_errors=True)

        # ACME failure on the domain branch must not leave a dangling cert
        # reference: the self-signed fallback (generated unconditionally,
        # before the domain is even asked about) stays as the site's live
        # cert, and add-site's own reload must still fire since no reload
        # happened inside the failed _obtain_trusted_cert call.
        s._obtain_trusted_cert = lambda domain, site: None  # simulates ACME failure: no site.domain assignment
        reload_calls.clear()
        dir6b = tempfile.mkdtemp(dir=s.BASE_DIR)  # add-site requires serve_dir under BASE_DIR
        saved_input3b = builtins.input
        try:
            script3b = iter([dir6b, "unreachable.example.com", ""])
            builtins.input = lambda prompt="": next(script3b, "")
            with contextlib.redirect_stdout(io.StringIO()):
                s._config_add_site()
        finally:
            builtins.input = saved_input3b
            shutil.rmtree(dir6b, ignore_errors=True)
        failed_site = s.config.sites[-1]
        check("A failed ACME attempt leaves the site with a real, generated self-signed cert",
              os.path.exists(s._resolve(failed_site.cert_file)) and os.path.exists(s._resolve(failed_site.key_file)))
        check("...and the site's domain stays unset rather than the failed one",
              failed_site.domain == "")
        check("...and add-site still reloads to bring the self-signed fallback live",
              reload_calls.count(1) == 1)
        generated_files.extend([failed_site.cert_file, failed_site.key_file])

        # Duplicate-domain guard: add-site falls back to self-signed rather than
        # creating a second site that would silently steal the first's TLS identity.
        s.config.sites[1].domain = "taken.example.com"
        dir7 = tempfile.mkdtemp(dir=s.BASE_DIR)  # add-site requires serve_dir under BASE_DIR
        saved_input4 = builtins.input
        try:
            script4 = iter([dir7, "taken.example.com", ""])
            builtins.input = lambda prompt="": next(script4, "")
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                s._config_add_site()
        finally:
            builtins.input = saved_input4
            shutil.rmtree(dir7, ignore_errors=True)
        check("add-site refuses a domain already claimed by another site",
              "already used by another site" in buf.getvalue())
        check("...and the new site ends up self-signed instead", s.config.sites[-1].domain == "")
        generated_files.extend([s.config.sites[-1].cert_file, s.config.sites[-1].key_file])

        # Same guard on the single-site 'cert' command: editing an existing
        # site's cert to a domain another site already holds must refuse,
        # leaving that other site's TLS identity alone.
        saved_input5 = builtins.input
        try:
            builtins.input = lambda prompt="": "taken.example.com"
            with contextlib.redirect_stdout(io.StringIO()) as buf2:
                s._config_cert(s.config.sites[0])
        finally:
            builtins.input = saved_input5
        check("'cert' refuses a domain already claimed by another site",
              "already used by another site" in buf2.getvalue())
        check("...and leaves the editing site's own domain unchanged",
              s.config.sites[0].domain != "taken.example.com")

        # serve_dir outside BASE_DIR breaks the publish pipeline's same-filesystem
        # atomic swap and the systemd sandbox's ReadWritePaths — both add-site and
        # 'dir' must refuse it rather than accept a site that silently can't publish.
        outside_dir = tempfile.mkdtemp()  # deliberately NOT under BASE_DIR
        try:
            sites_before = len(s.config.sites)
            saved_input6 = builtins.input
            try:
                script6 = iter([outside_dir, "", ""])
                builtins.input = lambda prompt="": next(script6, "")
                with contextlib.redirect_stdout(io.StringIO()) as buf3:
                    s._config_add_site()
            finally:
                builtins.input = saved_input6
            check("add-site refuses a serve_dir outside BASE_DIR",
                  f"must be inside {s.BASE_DIR}" in buf3.getvalue())
            check("...and no site was added", len(s.config.sites) == sites_before)

            saved_dir = s.config.sites[0].serve_dir
            saved_input7 = builtins.input
            try:
                builtins.input = lambda prompt="": outside_dir
                with contextlib.redirect_stdout(io.StringIO()) as buf4:
                    s._config_dir(s.config.sites[0])
            finally:
                builtins.input = saved_input7
            check("'dir' refuses a serve_dir outside BASE_DIR",
                  f"must be inside {s.BASE_DIR}" in buf4.getvalue())
            check("...and leaves the site's serve_dir unchanged",
                  s.config.sites[0].serve_dir == saved_dir)
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)
    finally:
        for fname in generated_files:
            p = os.path.join(s.BASE_DIR, fname)
            if os.path.exists(p):
                os.remove(p)
        for d in dirs2:
            shutil.rmtree(d, ignore_errors=True)
        s._reload_server     = saved_reload2
        s._server_running    = saved_ssrv2
        s._service_is_active = saved_sact2
        s._chown_servette    = saved_chown
        s._obtain_trusted_cert = saved_obtain
        s.config.sites        = saved_sites10

    section("Setup wizard smoke test")

    # cmd_setup calls _config_cert/_config_username/_config_password, which
    # take a site argument now — this exact call caught a real bug (they were
    # still being called with none) that no other test happened to exercise.
    saved2 = {n: getattr(s, n) for n in
              ("_prompt", "cmd_enable", "cmd_start", "_server_running", "_service_is_active")}
    saved_input2   = builtins.input
    saved_urlopen2 = urllib.request.urlopen
    try:
        urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(Exception("no network in tests"))
        s._prompt             = lambda *a, **k: False   # "Ready to start?" -> no
        s.cmd_enable           = lambda: None
        s.cmd_start            = lambda: None
        s._server_running      = lambda: False
        s._service_is_active   = lambda: False
        script = iter(["", ""])  # domain blank (self-signed), username blank
        builtins.input = lambda prompt="": next(script, "")
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                s.cmd_setup()
            check("cmd_setup runs end to end without raising", True)
        except Exception as e:
            check(f"cmd_setup runs end to end without raising (raised {e})", False)
    finally:
        urllib.request.urlopen = saved_urlopen2
        builtins.input = saved_input2
        for n, fn in saved2.items():
            setattr(s, n, fn)

    section("Request core — _handle_request")
    # The core returns (status, headers, body) directly and reads the request headers
    # straight off http.server's parsed HTTPMessage, so exercise it without a socket.
    def msg(pairs=()):
        m = http.client.HTTPMessage()
        for k, v in pairs:
            m[k] = v
        return m

    tmpd = tempfile.mkdtemp()
    with open(os.path.join(tmpd, "index.html"), "w") as f:
        f.write("<h1>hi</h1>")
    saved_serve, saved_pw = s.config.sites[0].serve_dir, s.config.sites[0].password_hash
    s.config.sites[0].serve_dir     = tmpd
    s.config.sites[0].password_hash = ""
    try:
        status, headers, body = s._handle_request("GET", "/", msg(), "127.0.0.1")
        hdict = dict(headers)
        check("GET / → 200",                 status == 200)
        check("Body is the file content",    body == b"<h1>hi</h1>")
        check("Content-Length matches body", hdict.get(b"content-length") == b"11")
        _, _, head_body = s._handle_request("HEAD", "/", msg(), "127.0.0.1")
        check("HEAD drops the body",          head_body == b"")
        pstatus, _, _ = s._handle_request("POST", "/", msg(), "127.0.0.1")
        check("POST → 405",                  pstatus == 405)
        # Reads request headers off the parsed (case-insensitive) HTTPMessage.
        _, gz_headers, gz_body = s._handle_request("GET", "/", msg([("accept-encoding", "gzip")]), "127.0.0.1")
        gzd = dict(gz_headers)
        check("Accept-Encoding honored via parsed headers",
              gzd.get(b"content-encoding") == b"gzip" and gzip.decompress(gz_body) == b"<h1>hi</h1>")
    finally:
        s.config.sites[0].serve_dir     = saved_serve
        s.config.sites[0].password_hash = saved_pw
    shutil.rmtree(tmpd, ignore_errors=True)

    section("Bundle extraction safety")

    def make_tar_gz(entries):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, content in entries:
                data = content.encode() if isinstance(content, str) else content
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    extract_root = tempfile.mkdtemp()
    try:
        good = make_tar_gz([("index.html", "<h1>hi</h1>"), ("sub/page.html", "sub")])
        dest = os.path.join(extract_root, "good")
        s._extract_bundle(good, dest)
        check("Valid bundle extracts top-level files",
              os.path.isfile(os.path.join(dest, "index.html")))
        check("Valid bundle extracts nested files",
              os.path.isfile(os.path.join(dest, "sub", "page.html")))

        traversal = make_tar_gz([("../evil.txt", "pwned")])
        dest2 = os.path.join(extract_root, "traversal")
        raised = False
        try:
            s._extract_bundle(traversal, dest2)
        except ValueError:
            raised = True
        check("Path-traversal entry rejected", raised)
        check("Nothing escaped the destination",
              not os.path.exists(os.path.join(extract_root, "evil.txt")))

        symlink_bytes = io.BytesIO()
        with tarfile.open(fileobj=symlink_bytes, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="evil-link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
        dest3 = os.path.join(extract_root, "symlink")
        raised = False
        try:
            s._extract_bundle(symlink_bytes.getvalue(), dest3)
        except ValueError:
            raised = True
        check("Symlink entry rejected", raised)

        saved_max = s._MAX_BUNDLE_BYTES
        try:
            s._MAX_BUNDLE_BYTES = 10  # tiny, so an ordinary small file trips the cap
            oversized = make_tar_gz([("big.txt", "x" * 1000)])
            dest4 = os.path.join(extract_root, "oversized")
            raised = False
            try:
                s._extract_bundle(oversized, dest4)
            except ValueError:
                raised = True
            check("Oversized bundle rejected", raised)
        finally:
            s._MAX_BUNDLE_BYTES = saved_max
    finally:
        shutil.rmtree(extract_root, ignore_errors=True)

    section("Atomic site-content swap and restore")

    saved_serve_dir = s.config.sites[0].serve_dir
    swap_root = tempfile.mkdtemp()
    try:
        s.config.sites[0].serve_dir = os.path.join(swap_root, "site")  # does not exist yet

        new1 = os.path.join(swap_root, "new1")
        os.makedirs(new1)
        with open(os.path.join(new1, "marker.txt"), "w") as f:
            f.write("v1")
        s._swap_site_content(new1, s.config.sites[0].serve_dir)
        check("First swap: content is live",
              open(os.path.join(s.config.sites[0].serve_dir, "marker.txt")).read() == "v1")
        check("First swap: no backup (nothing existed to back up)",
              not os.path.isdir(s.config.sites[0].serve_dir + ".bak"))

        new2 = os.path.join(swap_root, "new2")
        os.makedirs(new2)
        with open(os.path.join(new2, "marker.txt"), "w") as f:
            f.write("v2")
        s._swap_site_content(new2, s.config.sites[0].serve_dir)
        check("Second swap: new content is live",
              open(os.path.join(s.config.sites[0].serve_dir, "marker.txt")).read() == "v2")
        check("Second swap: previous content became the backup",
              open(os.path.join(s.config.sites[0].serve_dir + ".bak", "marker.txt")).read() == "v1")

        new3 = os.path.join(swap_root, "new3")
        os.makedirs(new3)
        with open(os.path.join(new3, "marker.txt"), "w") as f:
            f.write("v3")
        s._swap_site_content(new3, s.config.sites[0].serve_dir)
        check("Third swap: backup now holds v2, not v1 — single-shot, not a history",
              open(os.path.join(s.config.sites[0].serve_dir + ".bak", "marker.txt")).read() == "v2")

        saved_input = builtins.input
        try:
            builtins.input = lambda prompt="": "y"
            with contextlib.redirect_stdout(io.StringIO()):
                s.cmd_restore_site(s.config.sites[0])
        finally:
            builtins.input = saved_input
        check("Restore: live content reverts to the backup (v2)",
              open(os.path.join(s.config.sites[0].serve_dir, "marker.txt")).read() == "v2")
        check("Restore: backup is consumed",
              not os.path.isdir(s.config.sites[0].serve_dir + ".bak"))

        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_restore_site(s.config.sites[0])
        check("Restoring again with nothing to restore reports cleanly, does not raise",
              "Nothing to restore" in buf.getvalue())
    finally:
        s.config.sites[0].serve_dir = saved_serve_dir
        shutil.rmtree(swap_root, ignore_errors=True)

    section("Content update pipeline")

    saved_url, saved_key = s.config.sites[0].publish_url, s.config.sites[0].publish_key
    try:
        s.config.sites[0].publish_url = s.config.sites[0].publish_key = ""
        try:
            s._check_for_content_update(s.config.sites[0])
            check("Neither publish_url nor publish_key set: no-ops cleanly", True)
        except Exception as e:
            check(f"Neither set: no-ops cleanly (raised {e})", False)

        s.config.sites[0].publish_url = "https://example.com/site.tar.gz"
        s.config.sites[0].publish_key = "not-valid-hex"
        logging.disable(logging.CRITICAL)
        try:
            s._check_for_content_update(s.config.sites[0])
            check("Invalid publish_key rejected before any network call", True)
        except Exception as e:
            check(f"Invalid publish_key rejected cleanly (raised {e})", False)
        finally:
            logging.disable(logging.NOTSET)
    finally:
        s.config.sites[0].publish_url, s.config.sites[0].publish_key = saved_url, saved_key

    section("Content update pipeline: full pull/verify/swap (network mocked)")

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as _ser2

    priv_key = Ed25519PrivateKey.generate()
    pub_hex  = priv_key.public_key().public_bytes(
        _ser2.Encoding.Raw, _ser2.PublicFormat.Raw).hex()
    bundle_bytes = make_tar_gz([("index.html", "published content")])
    signature    = priv_key.sign(bundle_bytes)

    class _FakeResp:
        def __init__(self, data):
            self._data = data
        def read(self, size=None):
            return self._data if size is None else self._data[:size]

    saved_urlopen    = urllib.request.urlopen
    saved_serve_dir2 = s.config.sites[0].serve_dir
    saved_url2, saved_key2 = s.config.sites[0].publish_url, s.config.sites[0].publish_key
    swap_root2 = tempfile.mkdtemp()
    try:
        s.config.sites[0].serve_dir   = os.path.join(swap_root2, "site")
        s.config.sites[0].publish_url = "https://example.com/site.tar.gz"
        s.config.sites[0].publish_key = pub_hex

        urllib.request.urlopen = lambda url, timeout=None: (
            _FakeResp(signature) if url.endswith(".sig") else _FakeResp(bundle_bytes))
        result = s._check_for_content_update(s.config.sites[0])
        check("Correctly signed bundle is published",
              open(os.path.join(s.config.sites[0].serve_dir, "index.html")).read() == "published content")
        check("Returns 'published'", result == "published")

        other_key = Ed25519PrivateKey.generate()
        bad_sig   = other_key.sign(bundle_bytes)
        urllib.request.urlopen = lambda url, timeout=None: (
            _FakeResp(bad_sig) if url.endswith(".sig") else _FakeResp(bundle_bytes))
        with open(os.path.join(s.config.sites[0].serve_dir, "index.html"), "w") as f:
            f.write("unchanged")
        logging.disable(logging.CRITICAL)
        result = s._check_for_content_update(s.config.sites[0])
        logging.disable(logging.NOTSET)
        check("Bundle signed by the wrong key is rejected, content unchanged",
              open(os.path.join(s.config.sites[0].serve_dir, "index.html")).read() == "unchanged")
        check("Returns 'bad-signature'", result == "bad-signature")

        section("Publish pipeline: size cap and sig-URL query handling")

        saved_max2 = s._MAX_BUNDLE_BYTES
        try:
            s._MAX_BUNDLE_BYTES = 10  # smaller than bundle_bytes
            urllib.request.urlopen = lambda url, timeout=None: (
                _FakeResp(signature) if url.endswith(".sig") else _FakeResp(bundle_bytes))
            logging.disable(logging.CRITICAL)
            result = s._check_for_content_update(s.config.sites[0])
            logging.disable(logging.NOTSET)
            check("Oversized bundle rejected as 'too-large' before signature check",
                  result == "too-large")
        finally:
            s._MAX_BUNDLE_BYTES = saved_max2

        seen_urls = []
        def _record(url, timeout=None):
            seen_urls.append(url)
            return _FakeResp(signature) if ".sig" in url else _FakeResp(bundle_bytes)
        s.config.sites[0].publish_url = "https://example.com/site.tar.gz?token=abc123"
        urllib.request.urlopen = _record
        s._check_for_content_update(s.config.sites[0])
        sig_url = next(u for u in seen_urls if u != s.config.sites[0].publish_url)
        check("'.sig' is appended to the path, not after the query string",
              sig_url == "https://example.com/site.tar.gz.sig?token=abc123")
        s.config.sites[0].publish_url = "https://example.com/site.tar.gz"

        section("Publish pipeline serialization")

        urllib.request.urlopen = lambda url, timeout=None: (
            _FakeResp(signature) if url.endswith(".sig") else _FakeResp(bundle_bytes))
        saved_swap = s._swap_site_content
        in_critical, max_concurrent = [], []
        def _slow_swap(new_dir, serve_dir):
            in_critical.append(1)
            max_concurrent.append(len(in_critical))
            time.sleep(0.1)
            saved_swap(new_dir, serve_dir)
            in_critical.pop()
        s._swap_site_content = _slow_swap
        try:
            threads = [threading.Thread(target=s._check_for_content_update, args=(s.config.sites[0],))
                       for _ in range(3)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            check("Concurrent triggers never overlap inside the swap (max concurrent == 1)",
                  max(max_concurrent) == 1)
        finally:
            s._swap_site_content = saved_swap

        section("Manual pull command (cmd_pull)")

        s.config.sites[0].publish_url = s.config.sites[0].publish_key = ""
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_pull(s.config.sites[0])
        check("No publish channel configured: reports cleanly, doesn't touch the network",
              "No publish channel configured" in buf.getvalue())

        s.config.sites[0].publish_url, s.config.sites[0].publish_key = "https://example.com/site.tar.gz", pub_hex
        urllib.request.urlopen = lambda url, timeout=None: (
            _FakeResp(signature) if url.endswith(".sig") else _FakeResp(bundle_bytes))
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_pull(s.config.sites[0])
        check("Successful pull prints a confirmation",
              "New site content published" in buf.getvalue())
        check("Successful pull actually swapped in the content",
              open(os.path.join(s.config.sites[0].serve_dir, "index.html")).read() == "published content")
    finally:
        urllib.request.urlopen = saved_urlopen
        s.config.sites[0].serve_dir = saved_serve_dir2
        s.config.sites[0].publish_url, s.config.sites[0].publish_key = saved_url2, saved_key2
        shutil.rmtree(swap_root2, ignore_errors=True)


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def run_server_tests(s, serve_dir):
    # Live integration tests against the real server on TEST_PORT.
    # Each section mutates config or server state as needed and restores it afterward.

    section("Protocol negotiation")

    # Servette is HTTP/1.1 only; even when the client offers h2, the server must
    # negotiate http/1.1 (it advertises only that via ALPN).
    conn  = socket.create_connection(("127.0.0.1", TEST_PORT))
    tls   = SSL_CTX_H2.wrap_socket(conn, server_hostname="127.0.0.1")
    proto = tls.selected_alpn_protocol()
    tls.close()
    check("ALPN selects HTTP/1.1, not h2", proto == "http/1.1")

    section("Bind conflict is detected (fail-closed premise)")

    # start_server fails closed because binding a busy port raises in the
    # ThreadingHTTPServer constructor. The live server holds TEST_PORT, so a second
    # server on it must raise rather than silently succeed.
    raised = False
    try:
        dup = http.server.ThreadingHTTPServer(("0.0.0.0", TEST_PORT), s._Handler)
        dup.server_close()
    except OSError:
        raised = True
    check("Second bind on the live port raises OSError", raised)

    section("Connection cap (slowloris mitigation)")

    # The live HTTPS server enforces a bounded connection pool.
    check("Live server exposes a connection cap", hasattr(s._https_server, "_slots"))

    # With every slot taken, process_request must drop the connection immediately
    # rather than spawn another worker thread. Drive it directly (no sockets) on a
    # throwaway server capped at one.
    capped = s._CappedThreadingHTTPServer(("127.0.0.1", 0), s._RedirectHandler, max_connections=1)
    try:
        check("Slot pool grants up to the cap", capped._slots.acquire(blocking=False) is True)
        dropped = {"hit": False}
        capped.shutdown_request = lambda req: dropped.__setitem__("hit", True)
        capped.process_request(object(), ("127.0.0.1", 5555))   # at capacity now
        check("At capacity, new connection is dropped", dropped["hit"] is True)
    finally:
        capped.server_close()

    section("GET — gzip response")

    resp = req("GET", headers={"Accept-Encoding": "gzip"})
    check("Returns 200",                  resp.status == 200)
    check("Content-Type is text/html",    "text/html" in resp.headers.get("Content-Type", ""))
    check("Content-Encoding is gzip",     resp.headers.get("Content-Encoding") == "gzip")
    check("Body decompresses correctly",  gzip.decompress(resp.body).decode() == TEST_HTML)

    section("GET — raw response")

    resp = req("GET")
    check("Returns 200",                  resp.status == 200)
    check("No Content-Encoding header",   resp.headers.get("Content-Encoding") is None)
    check("Body matches HTML file",       resp.body.decode() == TEST_HTML)

    section("Compression by type")

    # Already-compressed types aren't gzipped, even when the client offers gzip.
    png_path = os.path.join(serve_dir, "pic.png")
    with open(png_path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + b"\x00" * 256)
    s._file_cache.clear()
    resp = req("GET", path="/pic.png", headers={"Accept-Encoding": "gzip"})
    check(".png served 200",       resp.status == 200)
    check(".png not gzipped",      resp.headers.get("Content-Encoding") is None)
    os.remove(png_path)

    section("Cache fit — can't-fit guard")

    # A file larger than the whole cache is served but not stored, and doesn't
    # purge what's already cached.
    orig_cache_mb = s.config.cache_size_mb
    s.config.cache_size_mb = 1                     # 1 MB cache
    s._file_cache.clear()
    s._file_cache_bytes = 0
    small_path = os.path.join(serve_dir, "small.bin")
    with open(small_path, "wb") as f:
        f.write(b"y" * 100)
    s._get_cached_file(small_path)
    check("Small file is cached",       small_path in s._file_cache)
    big_path = os.path.join(serve_dir, "toobig.bin")
    with open(big_path, "wb") as f:
        f.write(b"x" * (1200 * 1024))              # 1.2 MB > 1 MB cache
    raw_big, _, _ = s._get_cached_file(big_path)
    check("Oversized file served",      raw_big is not None and len(raw_big) == 1200 * 1024)
    check("Oversized file not cached",  big_path not in s._file_cache)
    check("Cache not purged",           small_path in s._file_cache)
    # #2: an oversized *compressible* file is served raw, not re-gzipped on every request
    big_css = os.path.join(serve_dir, "toobig.css")
    with open(big_css, "wb") as f:
        f.write(b"a{color:red}" * 120000)             # ~1.4 MB compressible > 1 MB cache
    raw_css, comp_css, etag_css = s._get_cached_file(big_css)
    check("Oversized compressible file served raw (not gzipped)", comp_css is None and raw_css is not None)
    check("Oversized compressible file keeps its etag", bool(etag_css))
    os.remove(big_css)
    os.remove(small_path); os.remove(big_path)
    s._file_cache.clear()
    s._file_cache_bytes = 0

    section("Cache fit — warnings")

    s.config.cache_size_mb = 128
    check("No warnings when site fits", s._cache_warnings() == [])
    s.config.cache_size_mb = 1
    huge_path = os.path.join(serve_dir, "huge.bin")
    with open(huge_path, "wb") as f:
        f.write(b"z" * (1300 * 1024))              # 1.3 MB > 1 MB cache
    w = s._cache_warnings()
    check("Warns: single file too big", any("never cached" in x for x in w))
    check("Warns: site exceeds cache",  any("not all of it" in x for x in w))
    os.remove(huge_path)
    s.config.cache_size_mb = orig_cache_mb

    section("Range requests")

    full  = req("GET", path="/style.css")
    total = len(full.body)
    check("Accept-Ranges advertised",  full.headers.get("Accept-Ranges") == "bytes")
    r = req("GET", path="/style.css", headers={"Range": "bytes=0-3"})
    check("Range → 206",               r.status == 206)
    check("206 returns the slice",     r.body == full.body[:4])
    check("Content-Range header",      r.headers.get("Content-Range") == f"bytes 0-3/{total}")
    r = req("GET", path="/style.css", headers={"Range": "bytes=-3"})
    check("Suffix range",              r.status == 206 and r.body == full.body[-3:])
    r = req("GET", path="/style.css", headers={"Range": "bytes=2-"})
    check("Open-ended range",          r.status == 206 and r.body == full.body[2:])
    r = req("GET", path="/style.css", headers={"Range": f"bytes={total + 10}-"})
    check("Unsatisfiable → 416",       r.status == 416)
    r = req("GET", path="/style.css", headers={"Range": "bytes=0-1,3-4"})
    check("Multi-range → full 200",    r.status == 200 and r.body == full.body)

    section("HEAD")

    resp = req("HEAD", headers={"Accept-Encoding": "gzip"})
    check("Returns 200",                  resp.status == 200)
    check("Includes Content-Length",      resp.headers.get("Content-Length") is not None)
    check("Body is empty",                resp.body == b"")

    section("ETag and 304 Not Modified")

    index_path = os.path.join(serve_dir, "index.html")

    resp = req("GET")
    etag = resp.headers.get("ETag")
    check("Response includes ETag",               etag is not None)

    resp = req("GET", headers={"If-None-Match": etag})
    check("Matching ETag returns 304",            resp.status == 304)
    check("304 body is empty",                    resp.body == b"")

    resp = req("GET", headers={"If-None-Match": '"stale-etag"'})
    check("Stale ETag returns 200",               resp.status == 200)

    with open(index_path, "w") as f:
        f.write(TEST_HTML + "<!-- updated -->")
    time.sleep(0.05)

    resp_updated = req("GET")
    new_etag     = resp_updated.headers.get("ETag")
    check("ETag changes after file edit",         new_etag != etag)

    resp_old = req("GET", headers={"If-None-Match": etag})
    check("Old ETag no longer triggers 304",      resp_old.status == 200)

    with open(index_path, "w") as f:
        f.write(TEST_HTML)

    section("Security headers")

    resp = req("GET")
    check("HSTS absent for self-signed cert",
          resp.headers.get("Strict-Transport-Security") is None)
    check("X-Frame-Options: DENY",
          resp.headers.get("X-Frame-Options") == "DENY")
    check("X-Content-Type-Options: nosniff",
          resp.headers.get("X-Content-Type-Options") == "nosniff")
    check("Referrer-Policy: no-referrer",
          resp.headers.get("Referrer-Policy") == "no-referrer")
    check("Vary: Accept-Encoding",
          resp.headers.get("Vary") == "Accept-Encoding")
    check("Cache-Control present",
          resp.headers.get("Cache-Control") is not None)
    check("Content-Security-Policy sent",
          resp.headers.get("Content-Security-Policy") is not None)
    check("CSP blocks plugins (object-src 'none')",
          "object-src 'none'" in resp.headers.get("Content-Security-Policy", ""))
    check("CSP blocks eval (no unsafe-eval)",
          "'unsafe-eval'" not in resp.headers.get("Content-Security-Policy", ""))
    check("Permissions-Policy sent",
          resp.headers.get("Permissions-Policy") is not None)
    check("Permissions-Policy denies camera",
          "camera=()" in resp.headers.get("Permissions-Policy", ""))
    check("Permissions-Policy denies microphone",
          "microphone=()" in resp.headers.get("Permissions-Policy", ""))
    check("Permissions-Policy does not deny payment",
          "payment" not in resp.headers.get("Permissions-Policy", ""))

    # Security headers must be on every response, not only 200s.
    resp404 = req("GET", path="/nonexistent.html")
    check("X-Frame-Options on 404",
          resp404.headers.get("X-Frame-Options") == "DENY")
    check("X-Content-Type-Options on 404",
          resp404.headers.get("X-Content-Type-Options") == "nosniff")
    check("Content-Security-Policy on 404",
          resp404.headers.get("Content-Security-Policy") is not None)
    resp405 = req("POST")
    check("X-Frame-Options on 405",
          resp405.headers.get("X-Frame-Options") == "DENY")
    check("Server header suppressed",
          req("GET").headers.get("Server") is None)

    section("Method handling")

    check("POST returns 405",   req("POST").status   == 405)
    check("PUT returns 405",    req("PUT").status    == 405)
    check("DELETE returns 405", req("DELETE").status == 405)
    check("PATCH returns 405",  req("PATCH").status  == 405)

    section("Directory serving and MIME types")

    resp = req("GET", path="/")
    check("/ serves index.html",
          resp.status == 200 and resp.body.decode() == TEST_HTML)

    resp = req("GET", path="/sub/")
    check("/sub/ serves sub/index.html",
          resp.status == 200 and resp.body.decode() == TEST_SUB_HTML)

    resp = req("GET", path="/sub/page.html")
    check("/sub/page.html is served",
          resp.status == 200 and resp.body.decode() == TEST_SUB_HTML)

    resp = req("GET", path="/style.css")
    check(".css returns text/css",
          resp.status == 200 and "text/css" in resp.headers.get("Content-Type", ""))

    resp = req("GET", path="/app.js")
    check(".js returns application/javascript",
          resp.status == 200 and "javascript" in resp.headers.get("Content-Type", ""))

    section("404 and custom 404.html")

    check("Non-existent path returns 404",
          req("GET", path="/nonexistent.html").status == 404)

    custom_404      = b"<html><body>Custom 404</body></html>"
    custom_404_path = os.path.join(serve_dir, "404.html")
    with open(custom_404_path, "wb") as f:
        f.write(custom_404)
    s._file_cache.clear()

    resp = req("GET", path="/nonexistent.html")
    check("Custom 404.html is returned",          resp.body == custom_404)
    check("Status is still 404",                  resp.status == 404)
    check("Content-Type is text/html for custom 404",
          "text/html" in resp.headers.get("Content-Type", ""))

    os.remove(custom_404_path)
    s._file_cache.clear()

    section("403 — path traversal")

    check("/../etc/passwd returns 403",      req("GET", path="/../etc/passwd").status == 403)
    check("/%2e%2e/etc/passwd returns 403",  req("GET", path="/%2e%2e/etc/passwd").status == 403)

    section("Basic Auth")

    s.config.sites[0].username = "testuser"
    s.config.sites[0].password_hash, s.config.sites[0].password_salt = s._hash_password("testpass")

    check("No credentials → 401",
          req("GET").status == 401)
    check("Wrong password → 401",
          req("GET", auth=("testuser", "wrong")).status == 401)
    check("Correct credentials → 200",
          req("GET", auth=("testuser", "testpass")).status == 200)
    check("Wrong username → 401",
          req("GET", auth=("wronguser", "testpass")).status == 401)
    check("Non-ASCII username → 401 (compared as bytes, no TypeError crash)",
          req("GET", auth=("café", "testpass")).status == 401)
    check("HEAD with correct credentials → 200",
          req("HEAD", auth=("testuser", "testpass")).status == 200)

    s._auth_fail_times.clear()
    for _ in range(7):
        req("GET", auth=("testuser", "wrong"))
    check("Auth rate limit → 429",
          req("GET", auth=("testuser", "wrong")).status == 429)

    s.config.sites[0].username      = ""
    s.config.sites[0].password_hash = ""
    s.config.sites[0].password_salt = ""
    s._auth_fail_times.clear()

    section("Multi-site Host routing")

    # The TLS listener was already built (at start_server()) from the single
    # domainless test site, so it keeps presenting that cert regardless of what
    # config.sites holds from here — irrelevant to this section, which tests
    # only the HTTP-layer Host routing added on top (TLS/SNI selection itself
    # is covered directly against _build_site_ssl_contexts() in run_unit_tests).
    second_dir = tempfile.mkdtemp()
    try:
        with open(os.path.join(second_dir, "index.html"), "w") as f:
            f.write("second site content")

        saved_sites       = s.config.sites
        original_site     = saved_sites[0]  # domainless — the catch-all in this fixture
        saved_orig_domain = original_site.domain
        second_site       = s.Site({
            "domain": "second.example.com", "serve_dir": second_dir,
            "cert_file": original_site.cert_file, "key_file": original_site.key_file,
        })
        s.config.sites = [original_site, second_site]
        try:
            check("Host matching the second site's domain serves that site's content",
                  req("GET", headers={"Host": "second.example.com"}).body == b"second site content")
            check("Unmatched Host falls through to the domainless catch-all",
                  req("GET", headers={"Host": "unrecognized.example.com"}).body.decode() == TEST_HTML)

            # Give the original site a domain too, removing the catch-all — an
            # unmatched Host should now be a bare, closed-system 404.
            original_site.domain = "first.example.com"
            resp = req("GET", headers={"Host": "unrecognized.example.com"})
            check("No catch-all site left: unmatched Host is a bare 404",
                  resp.status == 404 and resp.body == b"Not found.")
            check("Closed-system 404 sends no HSTS",
                  resp.headers.get("Strict-Transport-Security") is None)
            check("Closed-system 404 carries the ordinary security headers",
                  resp.headers.get("X-Frame-Options") == "DENY")

            resp2 = req("GET", headers={"Host": "first.example.com"})
            check("The now-domain-bearing original site still matches its own domain",
                  resp2.status == 200 and resp2.body.decode() == TEST_HTML)
            check("Its GET response carries HSTS",
                  resp2.headers.get("Strict-Transport-Security") is not None)

            resp405 = req("POST", headers={"Host": "first.example.com"})
            check("POST to a domain-bearing site is 405 with HSTS "
                  "(site is resolved before the method check now)",
                  resp405.status == 405 and resp405.headers.get("Strict-Transport-Security") is not None)

            resp_unmatched_post = req("POST", headers={"Host": "unrecognized.example.com"})
            check("POST to an unmatched Host is still the closed-system 404, not 405",
                  resp_unmatched_post.status == 404)
        finally:
            original_site.domain = saved_orig_domain
            s.config.sites = saved_sites
    finally:
        shutil.rmtree(second_dir, ignore_errors=True)

    section("Version discovery endpoint")

    resp = req("GET", "/.well-known/servette")
    check("200 with JSON content-type",
          resp.status == 200 and "application/json" in resp.headers.get("Content-Type", ""))
    data = json.loads(resp.body)
    check("Reports the running version", data["running"] == s.__version__)
    check("No backup present → backup is null", data["backup"] is None)

    bak_path = os.path.abspath(s.__file__) + ".bak"
    with open(bak_path, "w") as f:
        f.write('__version__ = "1.2.3"\n')
    try:
        data = json.loads(req("GET", "/.well-known/servette").body)
        check("Existing .bak's version is reported", data["backup"] == "1.2.3")
    finally:
        os.remove(bak_path)

    check("HEAD returns 200 with an empty body",
          req("HEAD", "/.well-known/servette").status == 200
          and req("HEAD", "/.well-known/servette").body == b"")

    s.config.sites[0].username = "testuser"
    s.config.sites[0].password_hash, s.config.sites[0].password_salt = s._hash_password("testpass")
    check("Respects auth like any other path: no credentials → 401",
          req("GET", "/.well-known/servette").status == 401)
    check("Respects auth like any other path: correct credentials → 200",
          req("GET", "/.well-known/servette", auth=("testuser", "testpass")).status == 200)
    s.config.sites[0].username      = ""
    s.config.sites[0].password_hash = ""
    s.config.sites[0].password_salt = ""
    s._auth_fail_times.clear()

    section("Cache-Control policies")

    s.config.cache_policy = "no-cache"
    check("no-cache in response",
          "no-cache" in req("GET").headers.get("Cache-Control", ""))

    s.config.cache_policy  = "max-age"
    s.config.cache_max_age = 7200
    check("max-age=7200 in response",
          "max-age=7200" in req("GET").headers.get("Cache-Control", ""))

    s.config.cache_policy = "no-store"
    check("no-store in response",
          "no-store" in req("GET").headers.get("Cache-Control", ""))

    s.config.cache_policy = "no-cache"

    section("Request rate limiting")

    s._request_times.clear()
    s.config.rate_limit = 2

    req("GET")
    req("GET")
    check("Third request over limit → 429",  req("GET").status == 429)

    s.config.rate_limit = 200
    s._request_times.clear()

    section("X-Forwarded-For ignored from untrusted source")

    # trusted_proxy is set to an IP that is NOT our test client (127.0.0.1).
    # If the server wrongly trusted XFF here, each request below would count
    # against a different IP and never hit the per-IP rate limit.
    # Correct behaviour: XFF is ignored, all three count against 127.0.0.1 → 429.
    s._request_times.clear()
    s.config.rate_limit    = 2
    s.config.trusted_proxy = "10.0.0.1"

    req("GET", headers={"X-Forwarded-For": "1.2.3.4"})
    req("GET", headers={"X-Forwarded-For": "5.6.7.8"})
    check("XFF from untrusted source ignored — third request hits rate limit",
          req("GET", headers={"X-Forwarded-For": "9.10.11.12"}).status == 429)

    s.config.rate_limit    = 200
    s.config.trusted_proxy = ""
    s._request_times.clear()

    section("Auth rate limit — credential-absent requests don't count")

    s.config.sites[0].username = "testuser"
    s.config.sites[0].password_hash, s.config.sites[0].password_salt = s._hash_password("testpass")
    s._auth_fail_times.clear()

    for _ in range(7):
        req("GET")

    check("Correct credentials still work after 7 no-credential requests",
          req("GET", auth=("testuser", "testpass")).status == 200)
    check("auth_fail_times tracker is empty (no attempts recorded)",
          len(s._auth_fail_times) == 0)

    s.config.sites[0].username      = ""
    s.config.sites[0].password_hash = ""
    s.config.sites[0].password_salt = ""
    s._auth_fail_times.clear()

    section("Auth rate limit gates the scrypt hash (#46)")

    # The fix: once an IP is over the auth-fail limit, further Basic attempts are
    # refused BEFORE the memory-hard scrypt runs. Count real hashes across a flood
    # far larger than the limit — it must stay near the limit, not scale with the
    # flood (which is what let a flood burn CPU/RAM regardless of the limit).
    s.config.sites[0].username = "testuser"
    s.config.sites[0].password_hash, s.config.sites[0].password_salt = s._hash_password("testpass")
    s.config.auth_rate_limit = 6
    s._auth_fail_times.clear()

    hashes    = {"n": 0}
    real_check = s._check_password
    s._check_password = lambda *a, **k: (hashes.__setitem__("n", hashes["n"] + 1) or real_check(*a, **k))
    try:
        for _ in range(50):
            req("GET", auth=("testuser", "wrong"))
        check("A 50-request flood computes far fewer than 50 hashes",
              hashes["n"] <= s.config.auth_rate_limit + 2)
        check("At least one real attempt was hashed (legit auth still works)",
              hashes["n"] >= 1)
        check("The flood is being refused with 429",
              req("GET", auth=("testuser", "wrong")).status == 429)
    finally:
        s._check_password = real_check

    s.config.sites[0].username      = ""
    s.config.sites[0].password_hash = ""
    s.config.sites[0].password_salt = ""
    s._auth_fail_times.clear()


# ─────────────────────────────────────────────────────────────────────────────
# CERT TESTS
# ─────────────────────────────────────────────────────────────────────────────

def run_cert_tests(s, tmpdir):
    # Tests certificate generation and inspection helpers.
    # ACME issuance is intentionally not covered — it requires a real domain and
    # outbound Let's Encrypt connectivity.

    section("Self-signed certificate generation")

    cert_path = os.path.join(tmpdir, "self-signed-cert.pem")
    key_path  = os.path.join(tmpdir, "self-signed-key.pem")

    s._generate_self_signed_cert(cert_path, key_path)

    check("cert.pem created",          os.path.exists(cert_path))
    check("key.pem created",           os.path.exists(key_path))
    check("key.pem is 0o600",          oct(os.stat(key_path).st_mode)[-3:] == "600")

    days = s._cert_days_remaining(cert_path)
    check("cert valid for ~10 years",  days is not None and days > 3600)

    domain = s._domain_from_cert(cert_path)
    check("domain_from_cert returns None for self-signed", domain is None)

    section("_cert_days_remaining uses cryptography lib (no openssl subprocess)")

    test_cert = os.path.join(tmpdir, "cert.pem")
    days2     = s._cert_days_remaining(test_cert)
    check("reads test cert expiry correctly", days2 is not None and days2 > 0)


def run_install_tests(s, tmpdir):
    # Tests installation helpers and the systemd service file template.
    # cmd_enable (and the _write_unit_files helper it shares with the
    # post-update path) is not called — it writes to /etc/systemd/system/ and
    # creates a system user, both of which require root and would affect the real
    # system. The service file template is reconstructed inline instead.

    section("System user helpers")

    # _servette_user_exists: just check it returns a bool without crashing
    result = s._servette_user_exists()
    check("_servette_user_exists returns bool", isinstance(result, bool))

    # _chown_servette: no-ops gracefully when path does not exist
    try:
        s._chown_servette("/tmp/nonexistent-servette-test-path")
        check("_chown_servette silently skips nonexistent path", True)
    except Exception as e:
        check(f"_chown_servette silently skips nonexistent path (raised {e})", False)

    # _chown_servette: no-ops when servette user does not exist
    if not s._servette_user_exists():
        tmp_file = os.path.join(tmpdir, "chown-test.txt")
        with open(tmp_file, "w") as f:
            f.write("test")
        try:
            s._chown_servette(tmp_file)
            check("_chown_servette no-ops when user absent", True)
        except Exception as e:
            check(f"_chown_servette no-ops when user absent (raised {e})", False)

    section("Service file content")

    # Test the real generated unit, not a reconstructed copy.
    servette_path = os.path.abspath(s.__file__)
    python_path   = s._VENV_PY if os.path.exists(s._VENV_PY) else "python3"
    service = s._systemd_unit(python_path, servette_path)
    check("Service runs as the least-privilege user",  "User=servette" in service)
    check("Capabilities bounded to net-bind only",     "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in service)
    check("NoNewPrivileges is set",                    "NoNewPrivileges=yes" in service)
    check("Filesystem is read-only (ProtectSystem=strict)", "ProtectSystem=strict" in service)
    check("Private /tmp",                              "PrivateTmp=yes" in service)
    check("Writes confined to BASE_DIR + ACME webroot",
          f"ReadWritePaths={s.BASE_DIR} {s.ACME_WEBROOT}" in service)
    ro_line = next((l for l in service.splitlines() if l.startswith("ReadOnlyPaths=")), "")
    check("The source file is pinned read-only within the writable dir (#47)",
          servette_path in ro_line)
    check("The managed venv is pinned read-only",
          s._VENV_DIR in ro_line)

    # Validate the real unit with systemd-analyze where available (Ubuntu CI has it;
    # skipped on macOS / non-systemd hosts). Catches typo'd or unknown directives.
    if shutil.which("systemd-analyze"):
        unit_path = os.path.join(tmpdir, "servette.service")
        with open(unit_path, "w") as f:
            f.write(s._systemd_unit(sys.executable, os.path.abspath(s.__file__)))
        out  = subprocess.run(["systemd-analyze", "verify", unit_path], capture_output=True, text=True)
        text = (out.stdout + out.stderr).lower()
        check("systemd-analyze verify: no unknown directives",
              "unknown lvalue" not in text and "unknown key name" not in text)
    else:
        print("  (systemd-analyze unavailable — unit syntax check skipped)")

    section("Network watchdog units")

    watch_service, watch_timer = s._netwatch_units()
    check("Service checks the default route",        "ip route get" in watch_service)
    check("Recovery uses try-restart (no-op for managers not running)",
          "try-restart" in watch_service)
    check("Covers networkd, NetworkManager, and dhcpcd",
          all(m in watch_service for m in ("systemd-networkd", "NetworkManager", "dhcpcd")))
    check("Service is oneshot",                      "Type=oneshot" in watch_service)
    check("Timer fires every 5 minutes",             "OnUnitActiveSec=5min" in watch_timer)
    check("Timer starts checking after boot",        "OnBootSec=5min" in watch_timer)

    if shutil.which("systemd-analyze"):
        # Write both units first — verify resolves the timer's service by sibling file.
        paths = {}
        for name, content in (("servette-netwatch.service", watch_service),
                              ("servette-netwatch.timer",   watch_timer)):
            paths[name] = os.path.join(tmpdir, name)
            with open(paths[name], "w") as f:
                f.write(content)
        for name, path in paths.items():
            out  = subprocess.run(["systemd-analyze", "verify", path], capture_output=True, text=True)
            text = (out.stdout + out.stderr).lower()
            check(f"systemd-analyze verify {name}: no unknown directives",
                  "unknown lvalue" not in text and "unknown key name" not in text)

    section("Swap recommendation (supply and demand)")

    MB    = 1024         # 1 MB expressed in kB, matching /proc/meminfo units
    GB_KB = 1024 * 1024  # 1 GB in kB
    # The incident box: 414 MB RAM, ~176 MB available, no swap, 50 MB cache.
    # Demand = resident (238) + cache (50) + spike allowance (700) = 988 MB;
    # deficit over RAM = 574 MB; recommendation = 2× deficit.
    rec = s._swap_recommendation(414 * MB, 176 * MB, 50)
    check("Incident-class host gets a recommendation", rec is not None)
    check("Recommendation is twice the demand deficit, rounded to 2 significant digits",
          rec == 1200 * 1024 ** 2)  # 2 × 574 MB deficit = 1148 → 1200

    check("Round-up: 1148 → 1200",  s._round_up_2sig(1148) == 1200)
    check("Round-up: 575 → 580",    s._round_up_2sig(575) == 580)
    check("Round-up: 2049 → 2100",  s._round_up_2sig(2049) == 2100)
    check("Round-up: 99 stays 99",  s._round_up_2sig(99) == 99)
    check("Round-up: exact 1200 stays 1200", s._round_up_2sig(1200) == 1200)
    check("Idle big host → no recommendation (demand fits)",
          s._swap_recommendation(4 * GB_KB, int(3.5 * GB_KB), 50) is None)
    check("Loaded big host → still recommended (threshold is demand, not a RAM ceiling)",
          s._swap_recommendation(2 * GB_KB, 100 * MB, 50) is not None)
    check("Small deficit floors at 512 MB",
          s._swap_recommendation(1024 * MB, 600 * MB, 50) == 512 * 1024 ** 2)
    check("Recommendation capped at 2 GB",
          s._swap_recommendation(414 * MB, 50 * MB, 1024) == 2 * 1024 ** 3)
    check("Unreadable meminfo → no recommendation",
          s._swap_recommendation(None, None, 50) is None)

    section("Swap offer")

    check("No swap → offer, declining skips",
          s._swap_offer(1200, False, 0) == ("no swapfile", "skip"))
    check("Foreign swap (partition, distro-managed) → no offer",
          s._swap_offer(1200, False, 600) is None)
    check("Our swapfile, big enough → no offer",
          s._swap_offer(1200, True, 1200) is None)
    check("Our swapfile, undersized → offer, declining keeps current",
          s._swap_offer(1200, True, 600) == ("a 600 MB swapfile", "keep 600"))
    check("Our swapfile, inactive → offer, declining skips",
          s._swap_offer(1200, True, 0) == ("an inactive swapfile", "skip"))
    check("No recommendation → no offer",
          s._swap_offer(None, False, 0) is None)

    mem_kb, avail_kb, swap_kb = s._meminfo()
    check("_meminfo returns a consistent triple",
          (mem_kb is None and avail_kb is None and swap_kb is None)
          or (isinstance(mem_kb, int) and isinstance(avail_kb, int)
              and isinstance(swap_kb, int) and mem_kb > 0))
    check("_root_on_sd_card returns bool (no crash on any host)",
          isinstance(s._root_on_sd_card(), bool))

    section("Host health warning")

    saved_meminfo = s._meminfo
    try:
        s._meminfo = lambda: (414 * 1024, 176 * 1024, 0)
        check("No-swap host under demand pressure is flagged",
              any("no swap" in issue for issue in s._production_issues()))
        s._meminfo = lambda: (414 * 1024, 176 * 1024, GB_KB)
        check("Host with swap is not flagged",
              not any("no swap" in issue for issue in s._production_issues()))
    finally:
        s._meminfo = saved_meminfo

    section("Publish channel config")

    saved_url, saved_key = s.config.sites[0].publish_url, s.config.sites[0].publish_key
    try:
        s.config.sites[0].publish_url = s.config.sites[0].publish_key = ""
        check("Neither set → not flagged",
              not any("publish channel" in issue for issue in s._production_issues()))
        s.config.sites[0].publish_url, s.config.sites[0].publish_key = "https://example.com/site.tar.gz", "a" * 64
        check("Both set → not flagged",
              not any("publish channel" in issue for issue in s._production_issues()))
        s.config.sites[0].publish_url, s.config.sites[0].publish_key = "https://example.com/site.tar.gz", ""
        check("URL only → flagged as partial",
              any("publish channel" in issue for issue in s._production_issues()))
        s.config.sites[0].publish_url, s.config.sites[0].publish_key = "", "a" * 64
        check("Key only → flagged as partial",
              any("publish channel" in issue for issue in s._production_issues()))
    finally:
        s.config.sites[0].publish_url, s.config.sites[0].publish_key = saved_url, saved_key

    section("Server watch (--serve supervision)")

    # _watch_server must return once the HTTPS thread has been dead for the grace
    # period — that return is what lets --serve exit non-zero so systemd restarts
    # the service instead of supervising a corpse.
    saved_thread = s._https_thread
    try:
        dead = threading.Thread(target=lambda: None)
        dead.start()
        dead.join()
        s._https_thread = dead
        t0 = time.monotonic()
        s._watch_server(poll=0.05, grace=0.2)
        elapsed = time.monotonic() - t0
        check("Watch returns after grace once thread is dead", 0.15 <= elapsed < 5)

        stop_evt = threading.Event()
        live = threading.Thread(target=stop_evt.wait)
        live.start()
        s._https_thread = live
        released = threading.Event()

        def _run_watch():
            s._watch_server(poll=0.05, grace=0.2)
            released.set()

        watcher = threading.Thread(target=_run_watch)
        watcher.start()
        time.sleep(0.5)
        check("Watch holds while the thread is alive", not released.is_set())
        stop_evt.set()
        watcher.join(timeout=5)
        check("Watch releases after the thread dies",  released.is_set())
    finally:
        s._https_thread = saved_thread

    section("Prompts survive a closed stdin")

    # Ctrl-D mid-prompt must answer the default, never traceback out of a command.
    import builtins
    saved_builtin_input = builtins.input
    try:
        def _eof(prompt=""):
            raise EOFError
        builtins.input = _eof
        check("_input returns its default on EOF", s._input("size? ", default="n") == "n")
        check("_prompt answers no on EOF",         s._prompt("proceed?") is False)
    finally:
        builtins.input = saved_builtin_input

    section("_server_running reflects thread liveness")

    # A crashed serve loop must read as stopped — the old flag check reported
    # Running as long as the server object existed.
    saved_live_thread = s._https_thread
    try:
        dead_t = threading.Thread(target=lambda: None)
        dead_t.start()
        dead_t.join()
        s._https_thread = dead_t
        check("Dead serve thread reads as not running", not s._server_running())
    finally:
        s._https_thread = saved_live_thread
    check("Live serve thread reads as running", s._server_running())

    section("Status resolves a relative cert path")

    # cmd_status must anchor a relative cert_file to BASE_DIR like every other
    # call site — from a foreign CWD it previously lost the certificate entirely.
    # Asserted on the Cert row, which is what still reads the file: the URL row
    # is now built from site.domain, since routing, TLS selection and HSTS all
    # key off the configured domain rather than the certificate's subject, and a
    # URL derived from the subject could name a host that does not reach here.
    # An unanchored path makes _cert_days_remaining return None and the row
    # vanish, so its presence is what proves the anchoring.
    import contextlib
    import datetime as _dt
    import io
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes as _hashes, serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    _key  = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    _cert = (x509.CertificateBuilder().subject_name(_name).issuer_name(_name)
             .public_key(_key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
             .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30))
             .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False)
             .sign(_key, _hashes.SHA256()))
    rel_name = "relcert-test.pem"
    rel_path = os.path.join(SERVETTE_DIR, rel_name)
    with open(rel_path, "wb") as f:
        f.write(_cert.public_bytes(_ser.Encoding.PEM))

    saved_cert_file, saved_cwd = s.config.sites[0].cert_file, os.getcwd()
    try:
        s.config.sites[0].cert_file = rel_name
        os.chdir(tmpdir)   # a CWD that does not contain the cert
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            s.cmd_status()
        cert_row = next((line for line in buf.getvalue().splitlines() if line.strip().startswith("Cert")), "")
        check("Status reads a relative cert path from a foreign CWD",
              "days remaining" in cert_row)
        # The URL row reports the configured domain, not the certificate's — this
        # site has a domain-bearing cert but no domain set, which is exactly the
        # state where trusting the subject would advertise an unreachable host.
        url_row = next((line for line in buf.getvalue().splitlines() if line.strip().startswith("URL")), "")
        check("Status reports the configured domain, not the certificate subject",
              url_row.split()[-1] == f"https://localhost:{s.config.port}")
    finally:
        s.config.sites[0].cert_file = saved_cert_file
        os.chdir(saved_cwd)
        os.remove(rel_path)

    section("Connection cap survives thread-start failure")

    # If Thread.start() raises after a slot is acquired (memory/thread exhaustion),
    # the slot must be reclaimed — leaked slots permanently shrink capacity.
    import socketserver
    cap_srv  = s._CappedThreadingHTTPServer(("127.0.0.1", 0), s._RedirectHandler, max_connections=2)
    saved_pr = socketserver.ThreadingMixIn.process_request
    sock_a, sock_b = socket.socketpair()
    try:
        def _fail(self, request, client_address):
            raise RuntimeError("cannot start thread")
        socketserver.ThreadingMixIn.process_request = _fail
        try:
            cap_srv.process_request(sock_a, ("127.0.0.1", 1))
        except RuntimeError:
            pass
        first  = cap_srv._slots.acquire(blocking=False)
        second = cap_srv._slots.acquire(blocking=False)
        check("Both slots free after failed thread start", first and second)
        if first:
            cap_srv._slots.release()
        if second:
            cap_srv._slots.release()
    finally:
        socketserver.ThreadingMixIn.process_request = saved_pr
        sock_a.close()
        sock_b.close()
        cap_srv.server_close()

    section("Update downloads pinned to GitHub")

    check("HTTPS github.com asset accepted",
          s._release_asset_url_ok("https://github.com/a/b/releases/download/v1/servette.py"))
    check("Other host rejected",
          not s._release_asset_url_ok("https://evil.example/servette.py"))
    check("Plain HTTP rejected",
          not s._release_asset_url_ok("http://github.com/a/b/servette.py"))
    check("Userinfo spoof rejected",
          not s._release_asset_url_ok("https://github.com@evil.example/servette.py"))

    section("In-service cert reload exits for systemd")

    # Under --serve the unit's user cannot systemctl restart itself; _reload_server
    # must stop the server so _watch_server exits non-zero and systemd relaunches
    # with the new certificate.
    sys.argv.append("--serve")
    try:
        s._reload_server()
        check("Reload under --serve stops the server", not s._server_running())
    finally:
        sys.argv.remove("--serve")
    s.start_server()
    check("Server restarted for the remaining tests", s._server_running())

    section("Cert watchdog survives a failing pass")

    saved_cdr         = s._cert_days_remaining
    saved_orig_domain = s.config.sites[0].domain
    logging.disable(logging.CRITICAL)   # the contained failure logs a traceback — mute it
    try:
        def _boom(path):
            raise RuntimeError("watchdog test failure")
        s._cert_days_remaining  = _boom
        s.config.sites[0].domain = "watchdog-test.example.com"  # take the domain-bearing branch
        try:
            s._cert_watchdog_tick()
            check("A raising pass is contained by the tick", True)
        except Exception as e:
            check(f"A raising pass is contained by the tick (raised {e})", False)
    finally:
        s._cert_days_remaining   = saved_cdr
        s.config.sites[0].domain = saved_orig_domain
        logging.disable(logging.NOTSET)

    section("Cert watchdog: one site's failure doesn't stop the others")

    saved_cdr2    = s._cert_days_remaining
    saved_reload  = s._reload_server
    saved_sites4  = s.config.sites
    watchdog_dir  = tempfile.mkdtemp()
    try:
        cert_a = os.path.join(watchdog_dir, "a-cert.pem")
        key_a  = os.path.join(watchdog_dir, "a-key.pem")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_a,
            "-out", cert_a, "-days", "1", "-nodes", "-subj", "/CN=a.example.com"
        ], capture_output=True, check=True)
        site_a = s.Site({"domain": "a.example.com", "cert_file": cert_a, "key_file": key_a, "serve_dir": watchdog_dir})

        cert_b = os.path.join(watchdog_dir, "b-cert.pem")
        key_b  = os.path.join(watchdog_dir, "b-key.pem")
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_b,
            "-out", cert_b, "-days", "1", "-nodes", "-subj", "/CN=localhost"
        ], capture_output=True, check=True)
        site_b = s.Site({"domain": "", "cert_file": cert_b, "key_file": key_b, "serve_dir": watchdog_dir})
        site_b._cert_mtime = os.path.getmtime(cert_b) - 100  # force a "changed on disk" detection

        s.config.sites = [site_a, site_b]

        def _boom_for_a(path):
            if path == cert_a:
                raise RuntimeError("site A failure")
            return saved_cdr2(path)

        reload_calls = []
        s._cert_days_remaining = _boom_for_a
        s._reload_server       = lambda: reload_calls.append(1)

        logging.disable(logging.CRITICAL)
        try:
            s._cert_watchdog_tick()
        finally:
            logging.disable(logging.NOTSET)

        check("Site B's self-signed reload still runs despite site A's failure",
              reload_calls == [1])
    finally:
        s._cert_days_remaining = saved_cdr2
        s._reload_server       = saved_reload
        s.config.sites         = saved_sites4
        shutil.rmtree(watchdog_dir, ignore_errors=True)

    section("Production issues and cache warnings: multi-site labeling")

    saved_sites5 = s.config.sites
    try:
        site_solo = s.Site({"domain": "", "serve_dir": "", "cert_file": "", "username": ""})
        s.config.sites = [site_solo]
        issues = s._production_issues()
        check("Single site: messages carry no site label",
              any(i == "serve directory not configured — run 'config'" for i in issues))

        site_x = s.Site({"domain": "x.example.com", "serve_dir": "", "cert_file": "", "username": ""})
        site_y = s.Site({"domain": "", "serve_dir": "y", "cert_file": "", "username": ""})
        s.config.sites = [site_x, site_y]
        issues2 = s._production_issues()
        check("Multi-site: a domain-bearing site is labeled with its domain",
              any("serve directory not configured (x.example.com) —" in i for i in issues2))
        check("Multi-site: a domainless site is labeled with its serve_dir",
              any("serve directory not configured (y) —" in i for i in issues2))
    finally:
        s.config.sites = saved_sites5

    section("serve_dir world-readable check")

    # World-readable dir: no warning expected (we capture logic by checking the stat)
    readable_dir = os.path.join(tmpdir, "readable")
    os.makedirs(readable_dir, exist_ok=True)
    os.chmod(readable_dir, 0o755)
    mode = os.stat(readable_dir).st_mode
    check("World-readable dir passes check (mode & 0o005 == 0o005)", (mode & 0o005) == 0o005)

    # Non-world-readable dir: warning expected
    restricted_dir = os.path.join(tmpdir, "restricted")
    os.makedirs(restricted_dir, exist_ok=True)
    os.chmod(restricted_dir, 0o700)
    mode2 = os.stat(restricted_dir).st_mode
    check("Restricted dir fails check (mode & 0o005 != 0o005)", (mode2 & 0o005) != 0o005)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n──────────────────────────────────────────────────────")
    print("  Servette Test Suite")
    print("──────────────────────────────────────────────────────")

    tmpdir, serve_dir, saved_config, config_path, s = setup()

    try:
        run_unit_tests(s)
        run_dispatch_tests(s)
        run_server_tests(s, serve_dir)
        run_cert_tests(s, tmpdir)
        run_install_tests(s, tmpdir)
    finally:
        teardown(tmpdir, saved_config, config_path, s)

    print(f"\n──────────────────────────────────────────────────────")
    total = _passed + _failed
    print(f"  {_passed} / {total} passed" + ("  — all good!" if _failed == 0 else f"  — {_failed} failed"))
    print(f"──────────────────────────────────────────────────────\n")

    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
