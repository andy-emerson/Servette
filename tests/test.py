#!/usr/bin/env python3
"""
test.py — Automated tests for the servette package

Run with any Python 3.11+ that has the one dependency:
    python3 -m venv .venv && .venv/bin/pip install cryptography
    .venv/bin/python3 tests/test.py
"""

import base64
import contextlib
import datetime
import gzip
import http.client
import http.server
import inspect
import io
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import html.parser
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# test.py lives in tests/; the repo root is its parent. servette.py is
# generated, not committed, so the suite builds it first — the same transform
# the package backend runs, so what is tested is what ships.
SERVETTE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
subprocess.run([sys.executable, os.path.join(SERVETTE_DIR, "src", "build.py"),
                "--output", os.path.join(SERVETTE_DIR, "servette.py")], check=True)
sys.path.insert(0, SERVETTE_DIR)  # so `import servette` resolves to the module under test
os.environ["SERVETTE_HOME"] = SERVETTE_DIR  # data dir = the repo, as a dev checkout runs
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

class _PageBits(html.parser.HTMLParser):
    """Read a page the way a browser does, instead of with a regex.

    The suite needs two things out of the admin page: where its links point,
    and what its script says. A regex over tags gets both wrong in ways that
    pass silently rather than fail — `<SCRIPT>` or `<script type="module">`
    matches nothing, and every check reading the extraction then succeeds
    without having seen a line of the page. This suite shipped exactly that
    defect, and CodeQL found it before a person did.

    A parser also removes the shape those alerts were about: nothing here
    searches a URL for a substring, so a host is compared as a host."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self._script, self._in_script = [], [], False

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links += [v for k, v in attrs if k == "href" and v]
        elif tag == "script":
            self._in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._script.append(data)

    @property
    def script(self):
        return "\n".join(self._script)


def page_bits(page):
    """(links, script text) for one HTML page."""
    parser = _PageBits()
    parser.feed(page)
    parser.close()
    return parser.links, parser.script


def _free_port():
    """A port the OS says is free right now — the browser check runs a
    loopback server and must not collide with a developer's own."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


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
    # Sites added through the page's /sites door get a Servette-named folder
    # under SERVETTE_HOME, which the suite points at the repository. Those
    # folders were empty and so invisible to git; once publishing began
    # keeping versions beside them they held files, and turned up in a
    # commit. The suite cleans up what it caused, both the folder and any
    # version trees the ring left next to it.
    for name in os.listdir(SERVETTE_DIR):
        if re.fullmatch(r"site-[0-9a-f]{6}(\.v\d+(\.\d+)?)?", name):
            path = os.path.join(SERVETTE_DIR, name)
            if os.path.islink(path):
                os.remove(path)
            else:
                shutil.rmtree(path, ignore_errors=True)


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
        # The retired pull-channel keys are in the fixture on purpose: an
        # operator upgrading has them in their file. They must be ignored
        # rather than carried onto the Site or written back out.
        check("The retired channel keys are dropped, not migrated",
              not hasattr(c.sites[0], "publish_url")
              and not hasattr(c.sites[0], "publish_key"))
        check("Plaintext password is hashed on migration", c.sites[0].password_hash != "")
        check("Hashed password verifies", s._check_password("hunter2", c.sites[0].password_hash, c.sites[0].password_salt))
        migrated_text = open(s.Config.CONFIG_FILE).read()
        check("Migration rewrites the file in [[site]] form", "[[site]]" in migrated_text)
        check("...and the rewrite does not carry the retired channel keys forward",
              "publish_url" not in migrated_text and "publish_key" not in migrated_text)

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

        # A hand-edit that breaks the file must not kill the reload: this runs
        # on request threads, so the loaded config keeps serving and the miss
        # is logged, not raised.
        good_sites = [site.domain for site in c3.sites]
        with open(s.Config.CONFIG_FILE, "w") as f:
            f.write("port = [broken\n")
        c3._mtime = None
        c3.reload_if_changed()   # must neither raise nor exit
        check("Invalid TOML on reload keeps the previous configuration",
              [site.domain for site in c3.sites] == good_sites)
        check("Bad reload stamps the mtime so it isn't re-parsed per request",
              c3._mtime == os.path.getmtime(s.Config.CONFIG_FILE))

        # Same keep-last-good when a reload would serve Servette's own secrets.
        with open(s.Config.CONFIG_FILE, "w") as f:
            f.write('[[site]]\nserve_dir = "."\n')
        c3._mtime = None
        c3.reload_if_changed()
        check("Secret-exposing serve_dir on reload keeps the previous configuration",
              [site.domain for site in c3.sites] == good_sites)

        # The load-door principle: a scalar the write doors would refuse
        # refuses the file — last good config on the live reload, and no
        # attribute of the live config half-changes on the way to the raise.
        with open(s.Config.CONFIG_FILE, "w") as f:
            f.write('port = "abc"\nrate_limit = 200\n')
        good_port, good_rl = c3.port, c3.rate_limit
        c3._mtime = None
        c3.reload_if_changed()
        check("An invalid scalar on reload keeps the previous configuration whole",
              [site.domain for site in c3.sites] == good_sites
              and c3.port == good_port and c3.rate_limit == good_rl)
        with open(s.Config.CONFIG_FILE, "w") as f:
            f.write("rate_limit = 0\n")
        c3._mtime = None
        c3.reload_if_changed()
        check("...a zero rate limit is refused the same way, never adopted",
              c3.rate_limit == good_rl)
        # And the raise carries the write door's own sentence, naming the key.
        _load_err = ""
        try:
            with open(s.Config.CONFIG_FILE, "w") as f:
                f.write('tls_min_version = "1.1"\n')
            c3._mtime = None
            c3._load()
        except s._ConfigInvalid as e:
            _load_err = str(e)
        check("...and the refusal names the key with set's own sentence",
              "tls_min_version" in _load_err and "1.2 or 1.3" in _load_err)
        # Two doors a hand-edit could push a BARE TypeError/ValueError
        # through — outside the family the last-good handling keys on. Both
        # now refuse inside it: a scalar `site` (valid TOML), and a NUL in a
        # path field (valid in a TOML string, refused by realpath with a
        # bare ValueError downstream).
        _load_err = ""
        try:
            with open(s.Config.CONFIG_FILE, "w") as f:
                f.write("site = 1\n")
            c3._mtime = None
            c3._load()
        except s._ConfigInvalid as e:
            _load_err = str(e)
        check("A scalar `site` refuses inside the family, not as a bare TypeError",
              "site must be" in _load_err)
        _load_err = ""
        try:
            with open(s.Config.CONFIG_FILE, "w") as f:
                f.write('[[site]]\nserve_dir = "site\\u0000x"\n')
            c3._mtime = None
            c3._load()
        except s._ConfigInvalid as e:
            _load_err = str(e)
        check("...and a NUL in a path field is named, not crashed on",
              "control characters" in _load_err)
        # And the reload's catch is deliberately broad: even a failure from
        # outside the family degrades to last-good, never to request threads
        # dying over a hand-edit.
        saved_load_fn = s.Config._load
        try:
            def _boom(self, tolerate_unreadable=False):
                raise RuntimeError("boom")
            s.Config._load = _boom
            c3._mtime = None
            c3.reload_if_changed()
            check("An off-family failure on reload keeps last-good and stamps",
                  [site.domain for site in c3.sites] == good_sites
                  and c3._mtime == os.path.getmtime(s.Config.CONFIG_FILE))
        finally:
            s.Config._load = saved_load_fn
        with open(s.Config.CONFIG_FILE, "w") as f:
            f.write('[[site]]\nserve_dir = "x"\n'
                    '[site.redirects]\n"/a" = "/b"\n"/b" = "/a"\n')
        c3._mtime = None
        c3.reload_if_changed()
        check("A redirect ring in a hand-edited file keeps the previous "
              "configuration — refused whole, not loaded minus the ring",
              [site.domain for site in c3.sites] == good_sites)

        # At startup the same conditions are fatal — fail closed, matching the
        # shell's edit-time refusal of these exact values.
        raised = False
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                s.Config()
        except SystemExit:
            raised = True
        check("Secret-exposing serve_dir at startup exits", raised)
        with open(s.Config.CONFIG_FILE, "w") as f:
            f.write("port = [broken\n")
        raised = False
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                s.Config()
        except SystemExit:
            raised = True
        check("Invalid TOML at startup exits", raised)

        # Migration under a Python without cryptography must defer rather than
        # persist an empty domain (which would demote the site to the
        # domainless catch-all: no HSTS, no renewal). A later load with
        # cryptography available completes it — under a pip install the
        # dependency is always present, so this is defense in depth.
        with open(s.Config.CONFIG_FILE, "w") as f:
            f.write(f'serve_dir = "myserve"\ncert_file = "{cert_path}"\nkey_file = "{key_path}"\n')
        saved_crypto = sys.modules.get("cryptography")
        sys.modules["cryptography"] = None   # makes `import cryptography` raise
        try:
            c4 = s.Config()
        finally:
            if saved_crypto is not None:
                sys.modules["cryptography"] = saved_crypto
            else:
                del sys.modules["cryptography"]
        check("Migration without cryptography defers (file not rewritten)",
              "[[site]]" not in open(s.Config.CONFIG_FILE).read())
        check("Deferred migration still loads the legacy site in memory",
              c4.sites[0].serve_dir == "myserve")
        c5 = s.Config()
        check("Re-run with cryptography completes the migration with the domain",
              "[[site]]" in open(s.Config.CONFIG_FILE).read()
              and c5.sites[0].domain == "legacy.example.com")
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
        # No door produces a control-character value any more — every field
        # refuses them at write and at load alike — so this machinery is
        # pure defense in depth: if a future path ever plants one, save()
        # must still write TOML the parser accepts (an unescaped control
        # character writes a file tomllib refuses, stopping the next
        # start), and the load door must then refuse the VALUE by policy,
        # with its sentence — not choke on the file.
        nasty = "a\x00b\tc\x1bd\ne\rf\x7fg"
        c.sites[0].username = nasty
        c.save()
        import tomllib as _tl
        with open(s.Config.CONFIG_FILE, "rb") as f:
            _parsed = _tl.load(f)
        check("A control-char value saves as valid, faithful TOML",
              _parsed["site"][0]["username"] == nasty)
        _refused_policy = False
        try:
            with contextlib.redirect_stdout(io.StringIO()) as _rbuf:
                s.Config()
        except SystemExit:
            _refused_policy = "control characters" in _rbuf.getvalue()
        check("...which the load door then refuses by policy, named",
              _refused_policy)
        c.sites[0].username = ""
        c.save()
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

        # A deactivated site is invisible to TLS as it is to routing: no
        # context is built for it — so a paused site's unreadable cert
        # cannot refuse the whole start — and its hostname claims no SNI
        # entry, falling to the closed-system default like any unrecognized
        # name.
        site_b2.active    = False
        site_b2.cert_file = os.path.join(tls_dir, "deleted-since.pem")
        site_b2.key_file  = os.path.join(tls_dir, "deleted-since.key")
        try:
            default_ctx3 = s._build_site_ssl_contexts()
            built = True
        except Exception:
            built = False
        check("A paused site's unloadable certificate does not refuse the build",
              built)
        if built:
            fake_paused = _FakeSSLSocket(default_ctx3)
            default_ctx3.sni_callback(fake_paused, "b.example.com", default_ctx3)
            check("A paused site's hostname falls to the closed-system default",
                  fake_paused.context is default_ctx3)
        site_b2.active = True
    finally:
        s.config.sites = saved_sites2
        shutil.rmtree(tls_dir, ignore_errors=True)
        if not default_cert_existed and os.path.exists(s._DEFAULT_CERT_FILE):
            shutil.rmtree(s._DEFAULT_CERT_DIR, ignore_errors=True)

    section("Versioning")

    check("__version__ is set",              bool(s.__version__))
    check("__version__ has 3 parts",         len(s.__version__.split(".")) == 3)
    check("__version__ major is 0",          s.__version__.split(".")[0] == "0")

    section("Cache-Control header — a concrete per-site toggle")

    site0 = s.config.sites[0]
    site0.username, site0.cache = "", "yes"
    check("public, yes → copies re-checked",
          s._cache_control_header(site0) == "public, no-cache")

    site0.username, site0.cache = "alice", "no"
    check("private, no → no copies at all",
          s._cache_control_header(site0) == "no-store")

    site0.cache = "yes"
    check("yes on a private site: the media site keeps re-checked copies",
          s._cache_control_header(site0) == "private, no-cache")

    site0.username, site0.cache = "", "no"
    check("no on a public site: the app with secrets leaves no copies",
          s._cache_control_header(site0) == "no-store")

    # The defaults land at construction (a file without the key) and at
    # every access flip in the shared validator — loudly at each surface.
    check("a new public site defaults to kept copies",
          s.Site().cache == "yes")
    check("a private site's file without the key defaults to none",
          s.Site({"username": "a"}).cache == "no")
    _flip = s.Site()
    s._set_site_value(_flip, "username", "bob")
    check("going private resets the toggle to none",
          _flip.cache == "no")
    _flip.cache = "yes"                      # the operator's override...
    s._set_site_value(_flip, "username", "carol")
    check("...survives a username change that does not flip access",
          _flip.cache == "yes")
    s._set_site_value(_flip, "username", "")
    check("going public resets the toggle to kept",
          _flip.cache == "yes")

    site0.cache = "yes"

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

    section("Rate-limit bucketing (_bucket_key)")

    # A subscriber holds at least a /64 (RFC 6177): keyed per address, rotating
    # the low 64 bits handed every request a fresh bucket, switching off the
    # rate limit, the auth throttle, and the connection cap for IPv6 clients.
    check("IPv4 buckets per address",      s._bucket_key("10.0.0.1") == "10.0.0.1")
    check("Mapped IPv4 buckets as IPv4",   s._bucket_key("::ffff:c0a8:0101") == "192.168.1.1")
    check("An IPv6 /64 shares one bucket",
          s._bucket_key("2001:db8:1:2::1") == s._bucket_key("2001:db8:1:2:ffff:ffff:ffff:ffff"))
    check("Different /64s get different buckets",
          s._bucket_key("2001:db8:1:2::1") != s._bucket_key("2001:db8:1:3::1"))
    check("Non-address passes through",    s._bucket_key("unknown") == "unknown")
    # The connection cap and the request path share the same bucketing.
    check("The per-IP connection cap keys on the bucket",
          s._CappedThreadingHTTPServer._ip_key(("2001:db8:1:2::9", 1234))
          == s._bucket_key("2001:db8:1:2::1"))

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

    # #51: the dotfile rule applies to the *resolved* target too, so a
    # plain-named symlink inside serve_dir cannot be used to reach a hidden
    # file. Build a real .git/config and a symlink to it whose own name passes
    # the request-path check; before the resolved-path check this served the
    # file (name passes, realpath stays within serve_dir).
    _sd = os.path.realpath(s.config.sites[0].serve_dir)
    os.makedirs(os.path.join(_sd, ".git"), exist_ok=True)
    with open(os.path.join(_sd, ".git", "config"), "w") as f:
        f.write("[core]\n")
    os.symlink(os.path.join(_sd, ".git", "config"), os.path.join(_sd, "gitlink"))
    path, status = s._resolve_request_path("/gitlink", s.config.sites[0].serve_dir)
    check("Symlink to a hidden target → 403 (#51)", path is None and status == 403)
    # Targeted, not blunt: a plain-named symlink to a non-hidden target still
    # resolves, so ordinary symlinks inside serve_dir keep working.
    os.symlink(os.path.join(_sd, "style.css"), os.path.join(_sd, "alias.css"))
    path, status = s._resolve_request_path("/alias.css", s.config.sites[0].serve_dir)
    check("Symlink to a non-hidden target still resolves (200)",
          path is not None and status == 200)

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

    section("Raising a rate limit takes effect for already-active IPs")

    # A deque keeps the maxlen it was born with; without the rebuild, an IP
    # tracked under the old limit could never accumulate enough entries to
    # exceed a raised one — a permanent exemption for active attackers.
    rl_tracker = {}
    for _ in range(3):
        s._rate_limit_exceeded(rl_tracker, "203.0.113.9", 2)
    check("Over the old limit, the IP is throttled",
          s._rate_limit_exceeded(rl_tracker, "203.0.113.9", 2, record=False))
    check("Under a raised limit, the same IP is admitted again",
          not s._rate_limit_exceeded(rl_tracker, "203.0.113.9", 10, record=False))
    check("The deque is rebuilt at the new limit",
          rl_tracker["203.0.113.9"].maxlen == 11)
    for _ in range(9):
        s._rate_limit_exceeded(rl_tracker, "203.0.113.9", 10)
    check("The raised limit is enforceable, not a permanent exemption",
          s._rate_limit_exceeded(rl_tracker, "203.0.113.9", 10, record=False))

    section("Private keys are 0600 from creation")

    kd = tempfile.mkdtemp()
    saved_umask = os.umask(0o022)   # a permissive umask — the case the fix closes
    try:
        kp = os.path.join(kd, "k.pem")
        s._write_private_key(kp, b"key material")
        check("_write_private_key creates the file 0600",
              os.stat(kp).st_mode & 0o777 == 0o600)
        check("Key contents written intact", open(kp, "rb").read() == b"key material")
        cert_p, key_p = os.path.join(kd, "c.pem"), os.path.join(kd, "k2.pem")
        s._generate_self_signed_cert(cert_p, key_p)
        check("Self-signed private key is 0600 from creation",
              os.stat(key_p).st_mode & 0o777 == 0o600)
    finally:
        os.umask(saved_umask)
        shutil.rmtree(kd, ignore_errors=True)

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

    # Routing is under test here, not elevation policy (which has its own
    # section). Dispatch is exercised as root, because as an unprivileged user
    # run_command correctly elevates restore-site instead of dispatching —
    # and on CI runners, whose sudo is passwordless, that spawned REAL elevated
    # children while the stubs sat unused. Caught by CI's non-root run; the
    # suite had only ever been run as root locally.
    saved_dispatch_euid = s.os.geteuid
    s.os.geteuid = lambda: 0

    # Spy on the handlers so we verify routing without their side effects, and
    # feed scripted input. 'quit' calls stop_server, so stub it to keep the
    # live test server up for the integration tests that follow.
    calls       = []
    saved       = {n: getattr(s, n) for n in
                   ("cmd_status", "cmd_start", "stop_server",
                    "cmd_restore_site", "cmd_admin", "_startup_refresh")}
    saved_input = builtins.input
    try:
        s.cmd_status       = lambda json_mode=False: calls.append("status")
        s.cmd_start        = lambda: calls.append("start")
        s.stop_server      = lambda: calls.append("stop")
        s.cmd_restore_site = lambda site: calls.append(("restore-site", site))
        s.cmd_admin        = lambda: calls.append("admin")
        s._startup_refresh = lambda: print("STARTUP-NOTICE-MARKER")
        script = iter(["status", "start", "restore-site 0", "admin",
                       "restore-site 99", "pull 0", "publish", "bogus", "quit"])
        builtins.input = lambda prompt="": next(script, "quit")
        with contextlib.redirect_stdout(io.StringIO()) as launch_buf:
            s.shell()
    finally:
        builtins.input = saved_input
        for n, fn in saved.items():
            setattr(s, n, fn)
        s.os.geteuid = saved_dispatch_euid

    launch_out = launch_buf.getvalue()
    check("A startup notice is the last thing before the prompt, not buried above the help",
          launch_out.index("Commands") < launch_out.index("STARTUP-NOTICE-MARKER"))

    check("'status' routed to cmd_status", "status" in calls)
    check("'start' routed to cmd_start",   "start" in calls)
    check("'restore-site 0' routes to cmd_restore_site with site 0",
          ("restore-site", s.config.sites[0]) in calls)
    check("'admin' routed to cmd_admin", "admin" in calls)
    restore_calls = [c for c in calls if isinstance(c, tuple) and c[0] == "restore-site"]
    check("'restore-site 99' (bad site index) does not call the command",
          len(restore_calls) == 1)
    # 'pull' is a retired word; the shell must say so rather than silently
    # accepting a verb it dropped. 'publish' returned as a different thing:
    # the publish-from-folder command the tunnel channel's ruling promised,
    # not the old sub-shell.
    check("'pull' is not a command any more, and never elevates",
          "pull" not in {c.split()[0] for c, _ in s._COMMANDS}
          and not s._needs_root("pull"))
    check("'quit' stops server and exits", calls[-1] == "stop")


    # The publish sub-shell stays gone: cmd_publish is the folder command
    # (it takes args), and none of the sub-shell's scaffolding — the menu
    # table, the help, the display — ever came back with it.
    check("The publish sub-shell has not returned with the publish command",
          not any(hasattr(s, n) for n in
                  ("_publish_show", "_PUBLISH_COMMANDS", "PUBLISH_HELP"))
          and "folder" in (s.cmd_publish.__doc__ or ""))
    check("...and restore-site kept its top-level home",
          "restore-site" in [c.split()[0] for c, _ in s._COMMANDS]
          and s._needs_root("restore-site"))

    # The admin door clears its own stale predecessor (ruled): a dropped
    # SSH session leaves 'servette admin' holding the port, and no user
    # should need pkill to get back in.
    if not s._IS_MACOS:
        free = _free_port()
        decoy = subprocess.Popen(
            [sys.executable, "-c",
             "import socket, time; s = socket.socket(); "
             f"s.bind(('127.0.0.1', {free})); s.listen(1); time.sleep(60)",
             "servette", "admin"])
        try:
            deadline = time.time() + 5
            while time.time() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", free), 0.2).close()
                    break
                except OSError:
                    time.sleep(0.05)
            pids = s._stale_admin_pids()
            check("A stale admin run is found by its command line, never ourselves",
                  decoy.pid in pids and os.getpid() not in pids)
            saved_uiport = s._UI_PORT
            try:
                s._UI_PORT = free
                httpd, code = s._reclaim_admin_port(s.config.sites[0],
                                                    s._UI_ADMIN_PAGE)
                check("Re-running admin ends the stale run and takes its port",
                      httpd is not None and bool(code)
                      and decoy.poll() is not None)
                if httpd is not None:
                    s._stop_ui(httpd)
                # A port held by something that is NOT an admin run is
                # refused, never killed.
                blocker = socket.socket()
                blocker.bind(("127.0.0.1", free))
                blocker.listen(1)
                try:
                    httpd2, _ = s._reclaim_admin_port(s.config.sites[0],
                                                      s._UI_ADMIN_PAGE)
                    check("A foreign holder of the port is refused, not killed",
                          httpd2 is None
                          and blocker.fileno() != -1)
                finally:
                    blocker.close()
            finally:
                s._UI_PORT = saved_uiport
        finally:
            if decoy.poll() is None:
                decoy.kill()
            decoy.wait()

    section("Admin command")

    # The door to the browser half: the page server brackets exactly this
    # command's run, and a busy port is one printed sentence, not a traceback.
    adm_calls  = []
    ui_started = []

    class _FakeUI:
        pass
    fake_ui = _FakeUI()

    saved_adm = {n: getattr(s, n) for n in ("_start_ui", "_stop_ui")}
    saved_input = builtins.input
    try:
        s._start_ui = lambda site, page, port=None: (
            ui_started.append((site, page)) or (fake_ui, "abc123"))
        s._stop_ui  = lambda h: adm_calls.append(("stop", h))
        script = iter(["help", "back"])
        prompts = []
        builtins.input = lambda prompt="": (prompts.append(prompt)
                                            or next(script, "back"))
        with contextlib.redirect_stdout(io.StringIO()) as adm_buf:
            s.cmd_admin()

        s._start_ui = lambda site, page, port=None: (
            (_ for _ in ()).throw(OSError(98, "Address already in use")))
        with contextlib.redirect_stdout(io.StringIO()) as busy_buf:
            s.cmd_admin()
    finally:
        builtins.input = saved_input
        for n, fn in saved_adm.items():
            setattr(s, n, fn)

    adm_out = adm_buf.getvalue()
    check("admin starts the page server with site 0 and the embedded page",
          ui_started == [(s.config.sites[0], s._UI_ADMIN_PAGE)])
    check("...prints the stable link and this run's passcode side by side",
          f"http://localhost:{s._UI_PORT}/" in adm_out
          and "passcode    abc123" in adm_out)
    # Nothing between the two labelled lines and the prompt: the label says
    # what the address is, so a header announcing the page adds nothing, and
    # the two words worth typing are named in the prompt itself rather than
    # on lines of their own above it.
    check("...with nothing printed above them",
          adm_out.startswith(f"  admin page  http://localhost:{s._UI_PORT}/\n"))
    check("...and the words worth typing named in the prompt itself",
          "'help'" in prompts[0] and "'back'" in prompts[0])
    check("...and 'help' summons the tunnel line and reprints the passcode",
          f"LocalForward {s._UI_PORT} 127.0.0.1:{s._UI_PORT}" in adm_out
          and "passcode: abc123" in adm_out)
    check("...sets the terminal narration hook",
          callable(getattr(fake_ui, "on_publish", None)))
    check("...and closes the page on the way out, tab included",
          adm_calls == [("stop", fake_ui)] and "Page closed" in adm_out
          and "close the browser tab" in adm_out)
    check("A busy port is one sentence, and no page to close",
          "Could not open the page" in busy_buf.getvalue()
          and len(adm_calls) == 1)

    # The embedded page itself: inlined by the build, tabbed, key-free by ruling.
    check("The admin page is inlined whole, marker consumed",
          s._UI_ADMIN_PAGE.startswith("<!DOCTYPE html>")
          and "@@ADMIN_HTML@@" not in s._UI_ADMIN_PAGE)
    check("...carries the Sites, Server, and Statistics tabs, reading the status feed",
          "tab-sites" in s._UI_ADMIN_PAGE and "tab-server" in s._UI_ADMIN_PAGE
          and "tab-stats" in s._UI_ADMIN_PAGE
          and "getJSON('/status')" in s._UI_ADMIN_PAGE)
    check("...posts to the upload endpoint with the run's code",
          "api('/upload'" in s._UI_ADMIN_PAGE)
    check("...keys card state by the site's folder, the identity that survives",
          "siteData.dir || siteData.domain" in s._UI_ADMIN_PAGE)
    check("...names redirected traffic and totals the unnamed remainder",
          "'Redirected'" in s._UI_ADMIN_PAGE
          and "row('Other'" in s._UI_ADMIN_PAGE)
    # The passcode is attached in one place rather than at each call site,
    # so no request can be written that forgets it.
    check("...with every request's passcode attached by one helper",
          "const api = (path, params)" in s._UI_ADMIN_PAGE
          and "{ t: CODE }" in s._UI_ADMIN_PAGE
          and "?t=" not in s._UI_ADMIN_PAGE)
    check("...and carries no key ceremony — SSH is the authentication",
          "Ed25519" not in s._UI_ADMIN_PAGE
          and "indexedDB" not in s._UI_ADMIN_PAGE)
    check("...offers the drop door beside the picker, sharing one intake",
          "webkitGetAsEntry" in s._UI_ADMIN_PAGE
          and "dragover" in s._UI_ADMIN_PAGE
          and "useFolder" in s._UI_ADMIN_PAGE)
    check("...with a drop strip visible before anything is dragged",
          "dropstrip" in s._UI_ADMIN_PAGE)
    # A drop target the size of one line of text is a target you have to aim
    # at. The strip carries its own lead line and takes the click itself, so
    # the picker is not reachable only through four exact words.
    check("...sized and clickable as a drop target, not a caption",
          "drop-lead" in s._UI_ADMIN_PAGE
          and "q('.dropstrip').addEventListener" in s._UI_ADMIN_PAGE)
    # Links come from the parser, and the host is compared as a host. A
    # substring test would also pass on evil-servette.org.example.
    _admin_links, _admin_js = page_bits(s._UI_ADMIN_PAGE)
    check("...and the footer saying where more is written down",
          any(urllib.parse.urlsplit(u).netloc == "servette.org"
              for u in _admin_links))
    # A card can wear two badges at once: the fault it has, and what
    # publishing is doing. They are separate elements because writing the
    # second over the first would erase a standing fault the moment a
    # folder was read.
    check("...with a card's fault badge and its publish badge kept apart",
          "badge state badge-dim" in s._UI_ADMIN_PAGE
          and "q('.badge.state')" in s._UI_ADMIN_PAGE
          and "BADGE_VARIANTS" in s._UI_ADMIN_PAGE)
    # role="tab" without aria-selected announces a tab strip and then never
    # says which tab is current.
    check("...and the tab strip saying which tab is current",
          'aria-selected="true"' in s._UI_ADMIN_PAGE
          and "setAttribute('aria-selected'" in s._UI_ADMIN_PAGE)
    # The ring on the page: a list that is present always, not only after a
    # publish — "put yesterday's back" is wanted on a day you published
    # nothing. Restore goes through the same /sites door every other site op
    # uses, so it runs the terminal's core.
    check("...carries the kept versions and a way back to any of them",
          "getJSON('/versions'" in s._UI_ADMIN_PAGE
          and "op: 'restore'" in s._UI_ADMIN_PAGE
          and "loadVersions" in s._UI_ADMIN_PAGE
          and "restore-site" not in s._UI_ADMIN_PAGE)
    check("...and reads its site index at call time, not at build time",
          "const siteIndex = () =>" in s._UI_ADMIN_PAGE)
    # Redirects are a setting, so the page edits them through the settings
    # write both surfaces share — not through a door of their own.
    # Preview and download on the page. The frame withholds
    # The preview opens in its own tab (ruled: full size, not a 420px
    # frame). rel=noopener is the isolation now — the draft's tab must hold
    # no handle back to the page whose address carries the passcode. Read
    # the attribute itself, not the page text: prose about noopener is not
    # noopener, and an assertion that cannot tell them apart would pass on
    # a comment while the link ran wide open.
    check("...offers a preview in a tab that cannot reach back",
          re.search(r'class="action preview-open"[^>]*rel="noopener"',
                    s._UI_ADMIN_PAGE) is not None
          and "api('/preview'" in s._UI_ADMIN_PAGE)
    check("...whose link carries the preview token, never the passcode",
          "'/preview/' + encodeURIComponent(data.token)" in s._UI_ADMIN_PAGE)
    # Download is removed by ruling: a sys admin already knows how to copy
    # a folder off their own box, and the terminal's own tools do it better.
    check("...and offers no download — the terminal already knows how",
          "/download" not in s._UI_ADMIN_PAGE
          and "Download" not in s._UI_ADMIN_PAGE)
    # The running dot lost its styling when the status row moved onto a
    # switch-row and a `.rows .dot` rule stopped matching: still in the
    # markup, simply invisible. The rule is unscoped now.
    # A change typed and not saved used to borrow the fault colour, so an
    # unsaved intention looked like something broken.
    check("...telling a fault from an intention that is merely unsaved",
          ".fault {" in s._UI_ADMIN_PAGE and ".pending {" in s._UI_ADMIN_PAGE
          and "class=\"pending\"" in s._UI_ADMIN_PAGE
          and "not saved yet" in s._UI_ADMIN_PAGE)
    # A favicon in the page kills the /favicon.ico request every browser
    # makes unasked — the one console error every browser run reported.
    _pages = (s._UI_ADMIN_PAGE, s._NOT_FOUND_PAGE.decode(),
              s._CONNECTION_PAGE.decode())
    check("...and every page carries the mark, so no browser asks for one",
          all('rel="icon"' in page and "data:image/svg+xml," in page
              for page in _pages)
          # Inline, because a page that demonstrates a self-hosted server
          # has no business fetching its own icon from anywhere.
          and "servette-mark.svg" not in s._UI_ADMIN_PAGE)
    # One drawing, one file. The pages name a marker the build fills from
    # assets/servette-mark.svg, so a change to the mark cannot reach two
    # pages and miss the third — which is what four hand-copied
    # transcriptions of the same SVG invited.
    _icons = {re.search(r'rel="icon" href="([^"]+)"', page).group(1)
              for page in _pages}
    check("...the same mark on all three, because there is one source for it",
          len(_icons) == 1)
    _built = io.open(os.path.abspath(s.__file__), encoding="utf-8").read()
    check("...with the marker consumed, never shipped",
          "@@MARK_ICON@@" not in _built)
    # The encoding is the whole risk: '#' would truncate the SVG at its first
    # colour and '"' would close the href, so the icon must decode back to
    # exactly the file on disk.
    _svg = re.sub(r"\s+", " ",
                  io.open(os.path.join(os.path.dirname(os.path.abspath(s.__file__)),
                                       "assets", "servette-mark.svg"),
                          encoding="utf-8").read()).strip()
    _decoded = urllib.parse.unquote(
        _icons.pop()[len("data:image/svg+xml,"):])
    check("...and it decodes back to the mark, closing tag and all",
          _decoded == _svg and _decoded.endswith("</svg>"))
    check("...and the running dot is styled where it actually sits",
          ".rows .dot {" not in s._UI_ADMIN_PAGE
          and "\n    .dot {" in s._UI_ADMIN_PAGE)
    check("...building one bundle for both, so they cannot diverge",
          s._UI_ADMIN_PAGE.count("gzipBytes(buildTar(") == 1)
    check("...and edits redirects through the shared settings write",
          "redir-save" in s._UI_ADMIN_PAGE
          and "redirect: from + ',' + to" in s._UI_ADMIN_PAGE
          and "_redirects" not in s._UI_ADMIN_PAGE)
    # The ruled per-rule choice on the page: a Permanent/Temporary select
    # whose first (default) option is Permanent, saved as the terminal's own
    # third token, with temporary rules saying so on their row.
    check("...offering the per-rule permanence choice, permanent first",
          '<option value="">Permanent</option>' in s._UI_ADMIN_PAGE
          and '<option value="temporary">Temporary</option>'
              in s._UI_ADMIN_PAGE
          and "(kind ? ',' + kind : '')" in s._UI_ADMIN_PAGE
          and "redirects_temporary" in s._UI_ADMIN_PAGE
          and "' (temporary)'" in s._UI_ADMIN_PAGE)
    check("...and the outside check, a Test button on the Serving row",
          "outside" in s._UI_ADMIN_PAGE
          and "servette-check" in s._UI_ADMIN_PAGE
          and ">Test</button>" in s._UI_ADMIN_PAGE
          and "Test connection" not in s._UI_ADMIN_PAGE)
    check("...and the Server panel wired to the set vocabulary",
          "panel-server" in s._UI_ADMIN_PAGE
          and "getJSON('/config')" in s._UI_ADMIN_PAGE
          and "post('/config'" in s._UI_ADMIN_PAGE)
    # The Settings card names its two families — the two-bucket principle
    # applied to the card's own layout, so a performance knob never wears
    # a security heading.
    check("...its Settings card splitting Security from Performance",
          '<div class="cfg-group">Security</div>' in s._UI_ADMIN_PAGE
          and '<div class="cfg-group">Performance</div>' in s._UI_ADMIN_PAGE
          and "SECURITY_FIELDS" in s._UI_ADMIN_PAGE
          and "PERFORMANCE_FIELDS" in s._UI_ADMIN_PAGE)
    check("...and the cross-tab banner skips quiet rows",
          "!c.ok && !c.quiet" in s._UI_ADMIN_PAGE)
    check("...with browser caching a per-site toggle on the card, not a host field",
          "cache-switch" in s._UI_ADMIN_PAGE
          and "cache-mode" not in s._UI_ADMIN_PAGE
          and "'cache_policy'" not in s._UI_ADMIN_PAGE
          and "'cache_max_age'" not in s._UI_ADMIN_PAGE)
    check("...with every site's facts on its own card and the server's on the server tab",
          "auth-switch" in s._UI_ADMIN_PAGE and "host-rows" in s._UI_ADMIN_PAGE
          and "cfg-site-select" not in s._UI_ADMIN_PAGE)
    check("...and the server tab reading the journal summary, charted with a scale",
          "getJSON('/traffic'" in s._UI_ADMIN_PAGE
          and "lineSVG" in s._UI_ADMIN_PAGE and "chart-y" in s._UI_ADMIN_PAGE)

    # Traffic: the journal re-read as counts. The lines are built through
    # the program's OWN log formatter and then wrapped in journalctl's
    # prefix, because hand-written lines were the bug: they matched the
    # parser's assumption rather than what Servette actually writes (the
    # formatter's timestamp and level sit between the two), so the parse
    # counted nothing on a real box while the suite stayed green.
    def _journal_line(day, message):
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(logging.getLogger().handlers[0].formatter)
        handler.setLevel(logging.INFO)
        s.log.addHandler(handler)
        try:
            s.log.info("%s", message)
        finally:
            s.log.removeHandler(handler)
        return f"{day}T09:00:00+0000 box servette[1]: " + buf.getvalue().strip()

    tlines = [
        _journal_line("2026-08-20", "200 /index.html to 1.2.3.4"),
        _journal_line("2026-08-20", "304 Not Modified /style.css to 1.2.3.4"),
        _journal_line("2026-08-21", "404 /nope from 5.6.7.8"),
        _journal_line("2026-08-21", "404 /nope from 1.2.3.4"),
        _journal_line("2026-08-21", "404 /wp-login.php from 5.6.7.8"),
        _journal_line("2026-08-21", "200 /index.html to 5.6.7.8"),
        _journal_line("2026-08-21", "Config reloaded from disk"),
        _journal_line("2026-08-21", "Rate limited 9.9.9.9"),
        # systemd's own line: no level, and never traffic.
        "2026-08-21T09:00:05+0000 box systemd[1]: Started servette.service.",
    ]
    check("A real log line carries the formatter's timestamp and level",
          "INFO" in tlines[0] and tlines[0].endswith("200 /index.html to 1.2.3.4"))
    tt = s._parse_traffic(tlines, now=datetime.datetime(2026, 8, 21, 12, 0))
    check("Traffic tallies days, statuses, and top paths from response lines only",
          tt["days"][-2:] == [("2026-08-20", 2), ("2026-08-21", 4)]
          and tt["statuses"] == {"200": 2, "304": 1, "404": 3}
          and tt["top_paths"][0] == ("/index.html", 2)
          and tt["bucket"] == "day")
    check("...zero-filling the window's quiet days, so the x-axis is real time",
          len(tt["days"]) == 8
          and all(n == 0 for _, n in tt["days"][:-2]))
    hourly = s._parse_traffic(tlines, days=1,
                              now=datetime.datetime(2026, 8, 21, 12, 0))
    hd = dict(hourly["days"])
    check("...and buckets by hour on a short window, quiet hours included",
          hourly["bucket"] == "hour"
          and hd["2026-08-20 09"] == 2 and hd["2026-08-21 09"] == 4
          and len(hourly["days"]) >= 25
          and sum(hd.values()) == 6)
    check("...and never carries a visitor's IP",
          "1.2.3.4" not in json.dumps(tt) and "5.6.7.8" not in json.dumps(tt))
    saved_tl = s._traffic_lines
    s._traffic_lines = lambda days=7: tlines
    with contextlib.redirect_stdout(io.StringIO()) as tbuf:
        s.cmd_traffic()
    s._traffic_lines = saved_tl
    check("The traffic command prints the same summary",
          "Requests: 6" in tbuf.getvalue() and "/index.html" in tbuf.getvalue())
    check("...and the Publish tab as site cards, add/move/remove/domain wired to /sites",
          "site-cards" in s._UI_ADMIN_PAGE and "btn-add-site" in s._UI_ADMIN_PAGE
          and "post('/sites'" in s._UI_ADMIN_PAGE
          and "attachCardDrag" in s._UI_ADMIN_PAGE
          and "dom-input" in s._UI_ADMIN_PAGE)
    check("...naming and certifying stay two acts, two ops",
          "op: 'name'" in s._UI_ADMIN_PAGE
          and "op: 'certificate'" in s._UI_ADMIN_PAGE
          and "Get certificate" in s._UI_ADMIN_PAGE)
    # Read the code, not the page text. Prose about alert() is not a call
    # to alert(), and a substring pin that cannot tell them apart fails on
    # a comment while a real call would sail through a reworded one.
    # _admin_js came from the parser above; an empty extraction would make
    # every check below pass without reading a line of the page, so it is
    # an assertion rather than a hope.
    check("The admin page's script is extracted before anything reads it",
          len(_admin_js) > 10000)
    _admin_js = re.sub(r"/\*.*?\*/", "", _admin_js, flags=re.S)  # comments, not tags
    _admin_js = re.sub(r"//[^\n]*", "", _admin_js)
    check("...whose remove panel offers delete, deactivate, cancel — no browser popup",
          "do-delete" in s._UI_ADMIN_PAGE and "do-deactivate" in s._UI_ADMIN_PAGE
          and "do-reactivate" in s._UI_ADMIN_PAGE and "do-cancel" in s._UI_ADMIN_PAGE
          and not re.search(r"\b(alert|confirm|prompt)\s*\(", _admin_js))
    # ...and it opens where the button that opens it is, not at the far end
    # of a long card.
    check("...anchored under the button, drawn by the page",
          ".site-card .confirm {" in s._UI_ADMIN_PAGE
          and "position: absolute;" in s._UI_ADMIN_PAGE
          and "q('.card-head').insertAdjacentHTML" in s._UI_ADMIN_PAGE)
    check("...as a public/private switch plus host basics — the advanced knobs stay in the terminal",
          "auth-switch" in s._UI_ADMIN_PAGE
          and "has_password" in s._UI_ADMIN_PAGE
          and "cfg-port" not in s._UI_ADMIN_PAGE
          and "trusted_proxy" not in s._UI_ADMIN_PAGE
          and "publish_url" not in s._UI_ADMIN_PAGE)

    section("Loopback page server")

    # The carve-out's edges, each attempted rather than argued: the bind is
    # loopback-only, the code gates everything but the pairing page, five
    # wrong guesses end the run, uploads land through the shared pipeline,
    # and the server dies with the command.
    def _ui_tar(entries):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, content in entries:
                data = content.encode()
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    ui_dir = tempfile.mkdtemp()
    os.makedirs(os.path.join(ui_dir, "live"))
    with open(os.path.join(ui_dir, "live", "old.html"), "w") as f:
        f.write("old")
    saved_ui_serve = s.config.sites[0].serve_dir
    s.config.sites[0].serve_dir = os.path.join(ui_dir, "live")
    httpd, ui_code = s._start_ui(s.config.sites[0], "<html>publish page</html>", port=0)
    ui_port = httpd.socket.getsockname()[1]

    def ui_req(method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", ui_port, timeout=10)
        conn.request(method, path, body=body)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, data

    def ui_header(path, name):
        conn = http.client.HTTPConnection("127.0.0.1", ui_port, timeout=10)
        conn.request("GET", path)
        r = conn.getresponse()
        r.read()
        conn.close()
        return r.getheader(name)

    try:
        check("The server binds loopback only",
              httpd.socket.getsockname()[0] == "127.0.0.1")
        # The page URL carries the run passcode as ?t=; no-referrer keeps it
        # out of the Referer when a card opens the public site in a new tab.
        check("Every loopback response carries Referrer-Policy: no-referrer",
              ui_header("/", "Referrer-Policy") == "no-referrer")

        st, body = ui_req("GET", "/")
        check("The bare URL answers the login page, never content",
              st == 200 and b"Passcode" in body
              and b"Login" in body
              and b"one-time passcode" in body
              and b"publish page" not in body)
        check("...and the login page does not leak the passcode",
              ui_code.encode() not in body)
        st, body = ui_req("GET", f"/?t={ui_code}")
        check("The printed URL's code opens the page",
              st == 200 and b"publish page" in body)

        st, body = ui_req("GET", f"/status?t={ui_code}")
        check("GET /status with the code answers the inside view",
              st == 200 and b'"version"' in body and b'"sites"' in body
              and b'"checks"' in body)

        health_keys = {r["key"] for r in s._health_checks()}
        check("The health rows cover the roster, green included",
              {"service", "cert", "password", "disk"} <= health_keys
              and (s._IS_MACOS or {"netwatch", "swap"} <= health_keys))

        # Disk: the outage every other row assumes is not happening. Two
        # thresholds, because one does not fit a Pi card and a VPS both.
        disk = s._status_data()["disk"]
        check("The status snapshot carries free and total disk",
              set(disk) == {"free_mb", "total_mb"}
              and disk["free_mb"] is not None and disk["total_mb"] > 0)
        # Each clause isolated: this case is low ONLY by the floor (400 MB
        # is 40% of a 1 GB disk, well above the fraction), so deleting the
        # floor clause would fail it — the old case (100 MB of 100 GB) was
        # under both and proved neither alone.
        check("...low by the absolute floor, on a small disk with headroom by fraction",
              s._disk_is_low({"free_mb": 400.0, "total_mb": 1000.0}))
        check("...low by the fraction, on a disk with plenty left in MB",
              s._disk_is_low({"free_mb": 5000.0, "total_mb": 200000.0}))
        check("...and roomy is not low",
              not s._disk_is_low({"free_mb": 50000.0, "total_mb": 200000.0}))
        check("...an unreadable disk is not reported as low",
              not s._disk_is_low({"free_mb": None, "total_mb": None}))
        # Severity, not just fault: one colour cannot say both "visitors
        # cannot use this site" and "it serves, and something wants doing".
        rows = {r["key"]: r for r in s._health_checks()}
        check("Every health row carries a severity, not only a verdict",
              all("blocking" in r for r in s._health_checks()))
        # The rule, not the mood of this particular run: a stopped service
        # blocks precisely when it is stopped.
        check("...a stopped service blocks, a running one does not",
              rows["service"]["blocking"] == (not rows["service"]["ok"]))
        saved_sd = s.config.sites[0].serve_dir
        try:
            s.config.sites[0].serve_dir = "no-such-folder-xyz"
            dir_row = [r for r in s._health_checks() if r["key"] == "dir"][0]
            check("...a missing folder blocks: nothing is served at all",
                  dir_row["blocking"])
            # #123, ruled: a hand-edited serve_dir outside the data
            # directory is observed, not refused — and only where the
            # consequence exists. The site serves from anywhere; it is the
            # systemd sandbox (writes under BASE_DIR only) that makes
            # publishing fail there, working in a manual run and dying
            # under the service. So the row fires where the unit exists,
            # a session server carries no trap to name, and the config
            # loads either way: the value is valid, its circumstances are
            # the problem.
            outside = tempfile.mkdtemp()
            saved_sp = s.SERVICE_PATH
            try:
                s.config.sites[0].serve_dir = outside
                unit_marker = os.path.join(outside, "unit-present")
                open(unit_marker, "w").close()
                s.SERVICE_PATH = unit_marker
                dir_row = [r for r in s._health_checks()
                           if r["key"] == "dir"][0]
                check("...a folder outside the data directory, under the "
                      "service, blocks and says why",
                      dir_row["blocking"]
                      and "outside" in dir_row["detail"]
                      and "publish" in dir_row["detail"])
                check("...and the terminal's readiness list names it too",
                      any("outside" in i and "publish" in i
                          for i in s._production_issues()))
                s.SERVICE_PATH = os.path.join(outside, "no-unit-here")
                check("...while a session server, with no sandbox, has no "
                      "trap to name",
                      not [r for r in s._health_checks()
                           if r["key"] == "dir"])
            finally:
                s.SERVICE_PATH = saved_sp
                shutil.rmtree(outside, ignore_errors=True)
        finally:
            s.config.sites[0].serve_dir = saved_sd
        check("...while swap, disk, and the watchdog do not",
              not rows["swap"]["blocking"] and not rows["disk"]["blocking"]
              and (s._IS_MACOS or not rows["netwatch"]["blocking"]))
        if not s._IS_MACOS:
            # A swapfile on disk but not swapped on is neither "no swap"
            # (untrue) nor healthy — both surfaces name the real state and
            # the real fix, activation.
            saved_sizes, saved_offer = s._swap_sizes, s._swap_offer
            saved_swp = s._SWAP_PATH
            _swpfd, _swppath = tempfile.mkstemp()
            os.close(_swpfd)
            try:
                s._SWAP_PATH = _swppath
                s._swap_sizes = lambda: (None, 0)
                s._swap_offer = lambda *a: ("no swap active", "skip")
                srow = [r for r in s._health_checks()
                        if r["key"] == "swap"][0]
                check("An inactive swapfile is reported as inactive, not absent",
                      "inactive" in srow["detail"]
                      and any("inactive" in i for i in s._production_issues()))
                # Ruled: the shortfall warns amber on its own row (and in
                # the terminal), but never as the cross-tab banner — the
                # row carries `quiet`, and the page's band skips quiet
                # rows.
                s._swap_sizes = lambda: (999, 0)
                srow = [r for r in s._health_checks()
                        if r["key"] == "swap"][0]
                check("An active swap below the recommendation warns on its row only",
                      not srow["ok"] and srow.get("quiet") is True
                      and "MB active" in srow["detail"])
            finally:
                s._swap_sizes, s._swap_offer = saved_sizes, saved_offer
                s._SWAP_PATH = saved_swp
                os.unlink(_swppath)
        # The certificate is the one row with two severities: an untrusted
        # certificate is an interstitial for every visitor to a name the
        # site advertises, and simply where a nameless site starts.
        saved_dom = s.config.sites[0].domain
        saved_cert = s.config.sites[0].cert_file
        try:
            s.config.sites[0].cert_file = ""      # nothing trusted to present
            s.config.sites[0].domain = ""
            check("An untrusted certificate on a nameless site does not block",
                  not [r for r in s._health_checks() if r["key"] == "cert"][0]["blocking"])
            s.config.sites[0].domain = "example.test"
            check("...but does the moment the site advertises a name",
                  [r for r in s._health_checks() if r["key"] == "cert"][0]["blocking"])
        finally:
            s.config.sites[0].domain = saved_dom
            s.config.sites[0].cert_file = saved_cert
        check("The disk row is host-wide, not hung on a site",
              all(r["site"] is None for r in s._health_checks() if r["key"] == "disk"))
        # Both surfaces say the same thing: the page reads the health row,
        # the terminal reads the issue list, and neither may know something
        # the other does not.
        saved_disk_snap = s._disk_snapshot
        s._disk_snapshot = lambda: {"free_mb": 12.0, "total_mb": 100000.0}
        try:
            check("...and a low disk reaches the terminal's issue list too",
                  any("free where content lands" in i for i in s._production_issues())
                  and any(r["key"] == "disk" and not r["ok"] for r in s._health_checks()))
        finally:
            s._disk_snapshot = saved_disk_snap
        check("...with the mode row labeled for what it describes",
              any(r["key"] == "service" and r["label"] == "Mode"
                  for r in s._health_checks()))

        # The folder reports only when it is gone: where content lives is
        # not the operator's question (the folder-retirement ruling).
        check("A present folder is not a row",
              not any(r["key"] == "dir" for r in s._health_checks()))
        saved_dir = s.config.sites[0].serve_dir
        s.config.sites[0].serve_dir = "no-such-folder-xyz"
        check("...a missing one is a row that needs review",
              any(r["key"] == "dir" and not r["ok"] for r in s._health_checks()))
        s.config.sites[0].serve_dir = saved_dir

        load = s._status_data()["load"]
        check("The status snapshot carries the utilization figures, raw counter included",
              set(load) == {"cpu_percent", "memory_mb", "uptime_s",
                            "started_at", "cpu_ns", "sampled_at"}
              and load["sampled_at"] > 0)

        # The page's live meter polls the snapshot every few seconds, so
        # what it costs is paid on every tick: systemd is asked once, and
        # each site's certificate is parsed at most twice (rows + health),
        # not once per fact.
        saved_probe, saved_load_cert = s._service_is_active, s._load_cert
        probe_calls, cert_loads = [], []
        s._service_is_active = lambda: (probe_calls.append(1), False)[1]
        s._load_cert = lambda p: (cert_loads.append(p), saved_load_cert(p))[1]
        s._status_data()
        s._service_is_active, s._load_cert = saved_probe, saved_load_cert
        check("One snapshot asks systemd exactly once, however many rows it feeds",
              len(probe_calls) == 1)
        check("...and parses a site's certificate at most twice, not once per fact",
              cert_loads and len(cert_loads) <= 2 * len(s.config.sites))

        # The pull channel is retired, so it can no longer be a row at all —
        # and no site row may carry a stale key the page still has a word for.
        check("The retired publish channel is not a health row",
              not any(r["key"] == "channel" for r in s._health_checks()))
        check("...and no site row carries the channel's old fields",
              not any("publish" in r for r in s._site_rows()))

        saved_hc = (s.config.sites[0].username, s.config.sites[0].password_hash)
        s.config.sites[0].username, s.config.sites[0].password_hash = "", ""
        pw = [r for r in s._health_checks()
              if r["key"] == "password" and r["site"] == 0][0]
        check("No password is healthy — public is a choice, not a defect",
              pw["ok"] and "public" in pw["detail"])
        s.config.sites[0].username, s.config.sites[0].password_hash = "u", ""
        pw = [r for r in s._health_checks()
              if r["key"] == "password" and r["site"] == 0][0]
        check("...but a username with nothing stored to check is flagged",
              not pw["ok"])
        check("...and the terminal lists that same half-state as the issue",
              any("locked out" in i for i in s._production_issues())
              and not any("no password" in i for i in s._production_issues()))
        # Every door refuses a colon username now, the load door included —
        # a hand-edited file cannot carry one into a running config, so the
        # health surface has nothing left to flag for it.
        _colon_raised = False
        try:
            s.Site({"username": "team:alpha"})
        except s._ConfigInvalid as e:
            _colon_raised = "colon" in str(e)
        check("A colon-username in a hand-edited file refuses the file",
              _colon_raised)
        (s.config.sites[0].username, s.config.sites[0].password_hash) = saved_hc
        st, _ = ui_req("GET", "/status")
        check("GET /status without the code is refused", st == 403)
        # The run credential travels one way — the ?t= query api() sends. A
        # header fallback was a second door nothing used; it is gone from
        # the program, not merely unused.
        check("The passcode has exactly one door — no header fallback",
              "X-Servette-Code" not in io.open(os.path.abspath(s.__file__),
                                               encoding="utf-8").read())

        st, body = ui_req("GET", f"/config?t={ui_code}")
        check("GET /config with the code answers the set vocabulary with values",
              st == 200 and b'"trusted_proxy"' in body and b'"sites"' in body
              and b'"has_password"' in body and b'"active"' in body)
        st, _ = ui_req("GET", "/config")
        check("GET /config without the code is refused", st == 403)

        st, body = ui_req("GET", f"/traffic?t={ui_code}")
        check("GET /traffic answers the summary shape",
              st == 200 and b"window_days" in body and b"top_paths" in body)
        st, _ = ui_req("GET", "/traffic")
        check("GET /traffic without the code is refused", st == 403)

        # Telling is all the page does about upgrades; installing stays in
        # the terminal, and the check is asked for rather than volunteered.
        check("A newer release reads as newer, an older one does not",
              s._version_parts("0.26.240") > s._version_parts("0.26.234")
              and s._version_parts("0.27.1") > s._version_parts("0.26.999")
              and not s._version_parts("0.26.234") > s._version_parts("0.26.234"))
        saved_latest = s._latest_release
        s._latest_release = lambda ttl=0: "0.99.999"
        check("...so a newer PyPI release is offered as news",
              s._upgrade_available() == "0.99.999")
        s._latest_release = lambda ttl=0: s.__version__
        check("...and the current one is not",
              s._upgrade_available() is None)
        s._latest_release = lambda ttl=0: None
        check("...nor is silence from PyPI mistaken for anything",
              s._upgrade_available() is None)
        st, body = ui_req("GET", f"/update?t={ui_code}")
        check("GET /update answers the question the page asks",
              st == 200 and b'"latest"' in body)
        st, _ = ui_req("GET", "/update")
        check("...and is code-gated like every other route", st == 403)
        s._latest_release = saved_latest

        # Download is removed by ruling — the route must be gone, not
        # merely unlinked from the page.
        st, _ = ui_req("GET", f"/download?t={ui_code}&site=0")
        check("The removed /download route answers 404 like any unknown path",
              st == 404)

        # The swap size the terminal has always asked for, asked for here —
        # the same core underneath, guarded before it can reach the disk.
        # Allocated and active are different numbers on purpose: /proc/swaps
        # reports usable space, a page short of the file, so a field showing
        # the active number would make typing the recommended size look like
        # a resize that silently did not take.
        check("The status snapshot carries the swap figures, allocated apart from active",
              set(s._status_data()["swap"])
              == {"allocated_mb", "active_mb", "recommended_mb"})
        check("...and the page's field reads the allocated one",
              "sw.allocated_mb != null ? sw.allocated_mb" in s._UI_ADMIN_PAGE
              and "sw.active_mb" not in s._UI_ADMIN_PAGE)
        st, _ = ui_req("POST", "/swap", body=b'{"mb": 512}')
        check("The swap endpoint is code-gated like every other", st == 403)
        st, body = ui_req("POST", f"/swap?t={ui_code}", body=b'{"mb": "big"}')
        check("...refusing a size that is not a number", st == 422)
        st, body = ui_req("POST", f"/swap?t={ui_code}", body=b'{"mb": 4}')
        check("...and one outside the sane range, before touching the disk",
              st == 422 and b"64-65536" in body)
        saved_apply = s._apply_swapfile
        seen_mb = []
        s._apply_swapfile = lambda mb: seen_mb.append(mb) or ""
        st, _ = ui_req("POST", f"/swap?t={ui_code}", body=b'{"mb": 512}')
        check("...running the same core the terminal's prompt runs",
              st == 200 and seen_mb == [512])
        s._apply_swapfile = lambda mb: "Not enough free disk for it."
        st, body = ui_req("POST", f"/swap?t={ui_code}", body=b'{"mb": 512}')
        check("...and reporting that core's own refusal",
              st == 422 and b"free disk" in body)
        s._apply_swapfile = saved_apply

        # The page may move the service toward serving and no further.
        st, _ = ui_req("POST", "/service", body=b"{}")
        check("The service endpoint is code-gated like every other", st == 403)
        # A lifecycle request must say which transition it means: a garbled
        # request defaulting to 'start' was the fail-open bug — a truncated
        # stop performing the opposite transition with a 200.
        st, _ = ui_req("POST", f"/service?t={ui_code}", body=b"not json{")
        check("...refuses a body it cannot parse instead of defaulting", st == 400)
        st, body = ui_req("POST", f"/service?t={ui_code}", body=b'{"op": "stopp"}')
        check("...and an op it does not know",
              st == 422 and b"start, restart or stop" in body)
        st, _ = ui_req("POST", f"/service?t={ui_code}", body=b"{}")
        check("...and a body naming no op at all", st == 422)
        saved_unit = s._service_file_exists
        s._service_file_exists = lambda: False
        st, body = ui_req("POST", f"/service?t={ui_code}", body=b'{"op": "start"}')
        check("...and refuses to start a service that was never installed",
              st == 422 and b"enable" in body)
        s._service_file_exists = saved_unit
        handler_src = inspect.getsource(s._UIHandler)
        check("...running the lifecycle but never the installation",
              '"systemctl", verb' in handler_src
              and '("start", "restart", "stop")' in handler_src
              and '"disable"' not in handler_src and '"enable"' not in handler_src)

        saved_cfg_user = s.config.sites[0].username
        st, _ = ui_req("POST", f"/config?t={ui_code}",
                       body=json.dumps({"site": 0,
                                        "values": {"username": "cfg-probe"}}).encode())
        check("POST /config applies through the same path as `set`",
              st == 200 and s.config.sites[0].username == "cfg-probe")
        # Sign-in joins user:password and the server splits at the first
        # colon, so a stored username containing one locks every visitor
        # out while the health row still reads private-and-healthy.
        st, body = ui_req("POST", f"/config?t={ui_code}",
                          body=json.dumps({"site": 0,
                                           "values": {"username": "team:alpha"}}).encode())
        check("...refuses a colon in a username — sign-in could never match it",
              st == 422 and b"colon" in body
              and s.config.sites[0].username == "cfg-probe")
        check("...with the same judgment on every surface that writes one",
              s._set_site_value(s.Site(), "username", "a:b") != ""
              and s._set_site_value(s.Site(), "username", "alpha") == "")
        st, body = ui_req("POST", f"/config?t={ui_code}",
                          body=json.dumps({"values": {"port": "99999"}}).encode())
        check("...refuses what `set` refuses, with `set`'s own sentence",
              st == 422 and b"port must be 1-65535" in body)
        st, _ = ui_req("POST", f"/config?t={ui_code}",
                       body=json.dumps({"values": {"bogus_key": "1"}}).encode())
        check("...and an unknown setting", st == 422)

        # The page's deactivate/reactivate is a settings write like any other.
        st, _ = ui_req("POST", f"/config?t={ui_code}",
                       body=json.dumps({"site": 0,
                                        "values": {"active": "no"}}).encode())
        check("Deactivation is a settings write",
              st == 200 and s.config.sites[0].active is False)
        st, _ = ui_req("POST", f"/config?t={ui_code}",
                       body=json.dumps({"site": 0,
                                        "values": {"active": "yes"}}).encode())
        check("...and reactivation restores serving",
              st == 200 and s.config.sites[0].active is True)
        st, _ = ui_req("POST", f"/config?t={ui_code}", body=b"not json{")
        check("...and a malformed settings body", st == 400)

        # The password travels only here — never on argv — and mirrors the
        # terminal prompt's rules: username first, blank means unchanged.
        saved_pw = (s.config.sites[0].password_hash, s.config.sites[0].password_salt)
        s.config.sites[0].username = ""
        st, body = ui_req("POST", f"/config?t={ui_code}",
                          body=json.dumps({"values": {"password": "pw-probe"}}).encode())
        check("A password without a username is refused, like the terminal",
              st == 422 and b"set a username first" in body)
        st, _ = ui_req("POST", f"/config?t={ui_code}",
                       body=json.dumps({"values": {"username": "cfg-auth",
                                                   "password": "pw-probe"}}).encode())
        check("Username and password land together, hashed server-side",
              st == 200 and s.config.sites[0].username == "cfg-auth"
              and s._check_password("pw-probe", s.config.sites[0].password_hash,
                                    s.config.sites[0].password_salt))
        st, _ = ui_req("POST", f"/config?t={ui_code}",
                       body=json.dumps({"site": 0,
                                        "values": {"username": "",
                                                   "password": "pw-2"}}).encode())
        check("A password riding with an emptied username is refused whole",
              st == 422 and s.config.sites[0].username == "cfg-auth")
        st, _ = ui_req("POST", f"/config?t={ui_code}",
                       body=json.dumps({"site": 0,
                                        "values": {"username": ""}}).encode())
        check("Clearing the username over HTTP deletes the stored password with it",
              st == 200 and s.config.sites[0].username == ""
              and s.config.sites[0].password_hash == ""
              and s.config.sites[0].password_salt == "")
        s.config.sites[0].username = saved_cfg_user
        s.config.sites[0].password_hash, s.config.sites[0].password_salt = saved_pw
        s.config.save()

        st, _ = ui_req("POST", "/upload")
        check("An upload without the code is refused", st == 403)
        st, _ = ui_req("POST", f"/upload?t={ui_code}", body=b"")
        check("An empty upload is refused", st == 400)

        st, body = ui_req("POST", f"/upload?t={ui_code}",
                          body=_ui_tar([("new.html", "fresh")]))
        check("A paired upload lands through the shared pipeline",
              st == 200 and b'"published"' in body
              and os.path.exists(os.path.join(ui_dir, "live", "new.html")))
        # The tree it replaced is kept — as a version in the ring now, not
        # as a single .bak that the next publish would overwrite.
        check("...keeping the tree it replaced as a version",
              any(os.path.exists(os.path.join(path, "old.html"))
                  for path, _stamp in s._version_dirs(os.path.join(ui_dir, "live"))))

        st, body = ui_req("POST", f"/upload?t={ui_code}",
                          body=_ui_tar([("../evil.html", "pwned")]))
        check("A malicious upload hits the same extraction guards",
              st == 422 and b'"rejected"' in body
              and not os.path.exists(os.path.join(ui_dir, "evil.html"))
              and os.path.exists(os.path.join(ui_dir, "live", "new.html")))

        # Preview (#116): the same bundle, staged where only this page can
        # see it. Everything below is a boundary, not a nicety — a preview
        # is the operator's own unvetted content running in their browser.
        st, body = ui_req("POST", f"/preview?t={ui_code}&site=0",
                          body=_ui_tar([("index.html", "DRAFT"),
                                        ("a/b.css", "body{}")]))
        preview_token = json.loads(body)["token"] if st == 200 else ""
        check("A preview stages without touching the live tree",
              st == 200 and b'"staged"' in body
              and open(os.path.join(ui_dir, "live", "new.html")).read() == "fresh")
        check("...on its own token, which is not the run's passcode",
              preview_token and preview_token != ui_code)
        # The reason for the separate token: a previewed page can read its
        # own URL. If that URL carried the passcode, a script in the
        # operator's own draft could publish with it.
        check("...and that token buys nothing but the preview",
              ui_req("GET", f"/status?t={preview_token}")[0] == 403
              and ui_req("POST", f"/upload?t={preview_token}",
                         body=_ui_tar([("x.html", "no")]))[0] == 403)
        st, body = ui_req("GET", f"/preview/{preview_token}/0/")
        check("The staged root is served over the tunnel", st == 200 and body == b"DRAFT")
        # The token is a path segment because a draft's relative links drop
        # the query: with it in the query, the page loaded and every
        # stylesheet 403'd. Found in a browser, pinned here.
        check("...with relative paths resolving, which is why it is staged at all",
              ui_req("GET", f"/preview/{preview_token}/0/a/b.css")[1] == b"body{}")
        check("...refusing traversal through the server's own resolver",
              ui_req("GET", f"/preview/{preview_token}/0/../../etc/passwd")[0] == 403)
        check("...and refusing a wrong or absent preview token",
              ui_req("GET", "/preview/wrong/0/")[0] == 403
              and ui_req("GET", "/preview/")[0] == 404)
        st, body = ui_req("POST", f"/preview?t={ui_code}&site=0",
                          body=_ui_tar([("../evil.html", "pwned")]))
        check("A bundle a publish would refuse, a preview refuses identically",
              st == 422 and not os.path.exists(os.path.join(ui_dir, "evil.html")))

        # Site management ops — the page's card row runs the same cores the
        # terminal's add-site / remove-site / move-site run. Reload guards
        # are stubbed: these tests exercise config truth, not the restart.
        saved_running = s._server_running
        saved_active  = s._service_is_active
        s._server_running    = lambda: False
        s._service_is_active = lambda: False
        added = None
        try:
            st, _ = ui_req("POST", "/sites",
                           body=json.dumps({"op": "add"}).encode())
            check("Site ops without the code are refused", st == 403)

            n0 = len(s.config.sites)
            st, _ = ui_req("POST", f"/sites?t={ui_code}",
                           body=json.dumps({"op": "add"}).encode())
            added = s.config.sites[-1]
            check("op=add appends a site with an assigned folder and its own cert pair",
                  st == 200 and len(s.config.sites) == n0 + 1
                  and added.serve_dir.startswith("site-")
                  and os.path.isdir(s._resolve(added.serve_dir))
                  and os.path.exists(s._resolve(added.cert_file))
                  and added.cert_file != s.config.sites[0].cert_file)
            added_base = s._resolve(added.serve_dir)

            st, _ = ui_req("POST", f"/sites?t={ui_code}",
                           body=json.dumps({"op": "move", "from": n0, "to": 0}).encode())
            check("op=move reorders — the new site leads the list",
                  st == 200 and s.config.sites[0] is added)
            st, _ = ui_req("POST", f"/sites?t={ui_code}",
                           body=json.dumps({"op": "move", "from": 0, "to": n0}).encode())
            check("...and moves back", st == 200 and s.config.sites[-1] is added)
            st, _ = ui_req("POST", f"/sites?t={ui_code}",
                           body=json.dumps({"op": "move", "from": 0, "to": 99}).encode())
            check("op=move refuses an index off the list", st == 422)
            st, _ = ui_req("POST", f"/sites?t={ui_code}",
                           body=json.dumps({"op": "sudo"}).encode())
            check("An unknown op is refused", st == 422)

            st, _ = ui_req("POST", f"/upload?t={ui_code}&site={n0}",
                           body=_ui_tar([("second.html", "two")]))
            check("An upload naming a site lands on that site, not the command's",
                  st == 200
                  and os.path.exists(os.path.join(added_base, "second.html"))
                  and not os.path.exists(os.path.join(ui_dir, "live", "second.html")))
            st, _ = ui_req("POST", f"/upload?t={ui_code}&site=99",
                           body=_ui_tar([("x.html", "x")]))
            check("An upload naming a site off the list is rejected", st == 422)

            # op=domain runs the terminal's issuance core; stubbed here, since
            # only a real box can talk to a certificate authority. The core
            # assigns site.domain only on its success path, which is exactly
            # what the handler judges by.
            st, _ = ui_req("POST", f"/sites?t={ui_code}",
                           body=json.dumps({"op": "name", "site": n0,
                                            "domain": "card.example"}).encode())
            check("op=name is a config write, no authority involved",
                  st == 200 and s.config.sites[n0].domain == "card.example")
            # The one door where a domain enters config without an issuance
            # to vet it, so syntax is judged there — locally, no DNS asked.
            bad_names = ["https://card.example", "card example.com",
                         "card.example.", "-card.example", "a" * 254 + ".com"]
            bad_results = [ui_req("POST", f"/sites?t={ui_code}",
                                  body=json.dumps({"op": "name", "site": n0,
                                                   "domain": bad}).encode())
                           for bad in bad_names]
            check("...refusing a string that could never route or be issued for",
                  all(st == 422 for st, _ in bad_results)
                  and s.config.sites[n0].domain == "card.example")
            st, body = ui_req("POST", f"/sites?t={ui_code}",
                              body=json.dumps({"op": "name", "site": 0,
                                               "domain": "card.example"}).encode())
            check("...refusing a domain another site already holds",
                  st == 422 and b"already used" in body)

            # op=certificate is the slow act, reported by the issuance's own
            # verdict — the domain is set before it runs, so comparing the
            # domain afterwards would always look like success.
            saved_obtain = s._obtain_trusted_cert
            s._obtain_trusted_cert = lambda domain, site_obj: None
            st, _ = ui_req("POST", f"/sites?t={ui_code}",
                           body=json.dumps({"op": "certificate", "site": n0}).encode())
            check("op=certificate reports the issuance's own success",
                  st == 200)
            s._obtain_trusted_cert = lambda domain, site_obj: "refused"
            st, body = ui_req("POST", f"/sites?t={ui_code}",
                              body=json.dumps({"op": "certificate", "site": n0}).encode())
            check("...and its refusal, with the DNS question that usually explains it",
                  st == 422 and b"DNS" in body)
            s._obtain_trusted_cert = lambda domain, site_obj: "transient"
            st, body = ui_req("POST", f"/sites?t={ui_code}",
                              body=json.dumps({"op": "certificate", "site": n0}).encode())
            check("...telling a transient failure apart from a refusal",
                  st == 422 and b"try again" in body)
            s.config.sites[n0].domain = ""
            st, body = ui_req("POST", f"/sites?t={ui_code}",
                              body=json.dumps({"op": "certificate", "site": n0}).encode())
            check("...and refusing to ask for a certificate with no name to put on it",
                  st == 422 and b"set a domain first" in body)
            s.config.sites[n0].domain = "card.example"
            s._obtain_trusted_cert = saved_obtain

            saved_sites_list = s.config.sites
            s.config.sites = [s.config.sites[0]]
            st, body = ui_req("POST", f"/sites?t={ui_code}",
                              body=json.dumps({"op": "remove", "site": 0}).encode())
            check("The last site can't be removed from the page either",
                  st == 422 and b"only site" in body)
            s.config.sites = saved_sites_list

            st, _ = ui_req("POST", f"/sites?t={ui_code}",
                           body=json.dumps({"op": "remove",
                                            "site": len(s.config.sites) - 1}).encode())
            check("op=remove drops the config and deletes the server copies",
                  st == 200 and len(s.config.sites) == n0
                  and added not in s.config.sites
                  and not any(os.path.exists(added_base + suf)
                              for suf in ("", ".a", ".b", ".bak"))
                  and os.path.exists(s._resolve(added.cert_file)))

            # A folder another site still points at is spared by removal.
            twin_dir = s._invent_site_dir()
            t1 = s.Site({"serve_dir": twin_dir})
            t2 = s.Site({"serve_dir": twin_dir})
            s.config.sites.extend([t1, t2])
            err = s._remove_site(len(s.config.sites) - 1)
            check("...but a folder another site still points at is spared",
                  err == "" and t2 not in s.config.sites
                  and os.path.isdir(s._resolve(twin_dir)))
            s.config.sites.remove(t1)
            s.config.save()
            shutil.rmtree(s._resolve(twin_dir), ignore_errors=True)

            # Removal must reclaim EVERY derived tree, not just the shapes
            # that predate the version ring. The ring shipped without this
            # function being updated, so a removed site left its whole kept
            # history on disk — which is the compounding-folders trap the
            # remove ruling exists to prevent.
            saved_chown_rm = s._chown_operator
            s._chown_operator = lambda path, strip_world=False: None

            def _one_file_bundle(body):
                buf = io.BytesIO()
                with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                    data = body.encode()
                    info = tarfile.TarInfo(name="index.html")
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
                return buf.getvalue()

            try:
                doomed_dir = s._invent_site_dir()
                di = s._append_site(doomed_dir)
                dsite = s.config.sites[di]
                for body in ("one", "two", "three"):
                    s._land_bundle(dsite, _one_file_bundle(body), "test")
                dbase = s._resolve(doomed_dir).rstrip(os.sep)
                # A legacy slot, a pre-ring backup marker, an abandoned
                # staging tree, and a staged preview: every shape removal
                # is supposed to reclaim.
                for extra in (".a", ".bak", ".new"):
                    os.makedirs(dbase + extra, exist_ok=True)
                s._stage_preview(dsite, _one_file_bundle("draft"))

                # A neighbour whose folder name starts with the victim's: a
                # prefix sweep would take it too.
                near_dir = doomed_dir + "-extra"
                os.makedirs(s._resolve(near_dir), exist_ok=True)
                ni = s._append_site(near_dir)
                s._land_bundle(s.config.sites[ni], _one_file_bundle("near"), "test")
                near_cert = s.config.sites[ni].cert_file
                near_key  = s.config.sites[ni].key_file
                near_versions_before = {p for p, _ in s._version_dirs(near_dir)}

                ring_before = len(s._version_dirs(doomed_dir))
                check("A published site has a ring to reclaim",
                      ring_before >= 3 and os.path.isdir(dbase + ".preview"))

                err_rm = s._remove_site(di)
                leftovers = sorted(f for f in os.listdir(s.BASE_DIR)
                                   if f.startswith(os.path.basename(dbase))
                                   and not f.startswith(os.path.basename(dbase) + "-"))
                check("remove-site reclaims every tree in the ring",
                      err_rm == "" and leftovers == [])
                check("...the preview, the legacy slot, the backup and the staging tree with it",
                      not any(os.path.lexists(dbase + suf)
                              for suf in (".preview", ".a", ".b", ".bak", ".new")))
                check("...and a neighbour whose name merely starts the same is untouched",
                      {p for p, _ in s._version_dirs(near_dir)} == near_versions_before
                      and near_versions_before)
                for stray in (near_cert, near_key):
                    sp = os.path.join(s.BASE_DIR, stray)
                    if os.path.exists(sp):
                        os.remove(sp)
                for leftover in [f for f in os.listdir(s.BASE_DIR)
                                 if f.startswith(os.path.basename(dbase))]:
                    lp = os.path.join(s.BASE_DIR, leftover)
                    if os.path.islink(lp):
                        os.unlink(lp)
                    else:
                        shutil.rmtree(lp, ignore_errors=True)
                s.config.sites = [x for x in s.config.sites
                                  if x.serve_dir not in (doomed_dir, near_dir)]
                s.config.save()
            finally:
                s._chown_operator = saved_chown_rm

            # Deactivation: invisible to routing on every matching path —
            # exact domain, the www pairing, and the domainless catch-all.
            saved_sites_all = s.config.sites
            sa = s.Site({"domain": "on.example"})
            sb = s.Site({"domain": "off.example"}); sb.active = False
            sc = s.Site({});                        sc.active = False
            sd = s.Site({})
            s.config.sites = [sa, sb, sc, sd]
            check("A deactivated site is invisible to routing",
                  s._select_site("off.example") is sd      # falls to the catch-all
                  and s._select_site("on.example") is sa
                  and s._select_site("anything.else") is sd)  # skips inactive sc
            s.config.sites = [sa, sb, sc]
            check("...and with no active catch-all its Host is a closed-system miss",
                  s._select_site("off.example") is None
                  and s._select_site("www.off.example") is None)
            s.config.sites = saved_sites_all

            check("move-site is in the config sub-shell's vocabulary",
                  any(c.startswith("move-site") for c, _ in s._CONFIG_COMMANDS))
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                s._config_move_site(["1"])
            check("move-site wants two indexes", "Usage" in buf.getvalue())
        finally:
            s._server_running    = saved_running
            s._service_is_active = saved_active
            if added is not None:
                if added in s.config.sites:
                    s.config.sites.remove(added)
                    s.config.save()
                base = s._resolve(added.serve_dir)
                for suffix in ("", ".a", ".b", ".bak", ".new"):
                    p = base + suffix
                    if os.path.islink(p):
                        os.unlink(p)
                    elif os.path.isdir(p):
                        shutil.rmtree(p, ignore_errors=True)
                for leftover in (added.cert_file, added.key_file):
                    try:
                        os.remove(s._resolve(leftover))
                    except OSError:
                        pass

        # An oversize claim must be refused before the body is read — sent
        # raw, because http.client would insist on sending a real body.
        sk = socket.create_connection(("127.0.0.1", ui_port), timeout=10)
        sk.sendall((f"POST /upload?t={ui_code} HTTP/1.1\r\nHost: ui\r\n"
                    f"Content-Length: {s._MAX_BUNDLE_BYTES + 1}\r\n\r\n").encode())
        first_line = sk.recv(200).split(b"\r\n")[0]
        sk.close()
        check("An oversize claim is refused before the body is read",
              b"413" in first_line)

        for _ in range(s._UI_MAX_BAD_CODES):
            ui_req("GET", "/?t=wrong")
        st, _ = ui_req("GET", f"/?t={ui_code}")
        st2, _ = ui_req("POST", f"/upload?t={ui_code}",
                        body=_ui_tar([("late.html", "late")]))
        check("Five wrong guesses end the run's authentication — even for the right code",
              st == 403 and st2 == 403
              and not os.path.exists(os.path.join(ui_dir, "live", "late.html")))

        # A predecessor killed without _stop_ui never swept its drafts; the
        # next run's door reclaims them on the way in.
        stale_pv = s._preview_dir(s.config.sites[0])
        os.makedirs(stale_pv, exist_ok=True)
        httpd2, _code2 = s._start_ui(s.config.sites[0], "x", port=0)
        try:
            check("Starting the page sweeps a dead run's staged previews",
                  not os.path.exists(stale_pv))
        finally:
            httpd2.shutdown()
            httpd2.server_close()
    finally:
        s._stop_ui(httpd)
        s.config.sites[0].serve_dir = saved_ui_serve
        shutil.rmtree(ui_dir, ignore_errors=True)

    try:
        ui_req("GET", "/")
        ui_stopped = False
    except OSError:
        ui_stopped = True
    check("The page dies with the command: the port refuses after stop", ui_stopped)

    section("One-shot CLI: run_command and set")

    # The read half: status --json / sites --json parse and carry the shape
    # external tooling depends on.
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        handled = s.run_command("status", ["--json"])
    data = json.loads(buf.getvalue())
    check("status --json is handled and parses",  handled and isinstance(data, dict))
    check("status --json carries version/running/sites/issues",
          {"version", "running", "mode", "sites", "issues", "warnings"} <= set(data))
    check("status --json reports the running version", data["version"] == s.__version__)
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        s.run_command("sites", ["--json"])
    sites = json.loads(buf.getvalue())
    check("sites --json lists every site with its shape",
          len(sites) == len(s.config.sites)
          and {"index", "domain", "active", "serve_dir",
               "auth", "cert_days"} == set(sites[0]))
    saved_walkers = (s._cache_warnings, s._service_is_active)
    walked = []
    try:
        s._cache_warnings    = lambda: walked.append("walk") or []
        s._service_is_active = lambda: walked.append("systemctl") or False
        with contextlib.redirect_stdout(io.StringIO()):
            s.run_command("sites", ["--json"])
        check("sites --json pays no status-wide cost (no walk, no systemctl)",
              walked == [])
        with contextlib.redirect_stdout(io.StringIO()):
            s.run_command("status", ["--json"])
        check("status --json still gathers the full snapshot", set(walked) == {"walk", "systemctl"})
    finally:
        s._cache_warnings, s._service_is_active = saved_walkers
    check("An unknown command is not handled (the argv form exits 2 on this)",
          s.run_command("bogus", []) is False)

    # The write half: set validates every pair before applying any.
    saved_set   = {n: getattr(s.config, n) for n in ("port", "trusted_proxy")}
    saved_save  = s.Config.save
    save_count  = []
    try:
        s.Config.save = lambda self: save_count.append(1)
        # One site pair and one host pair in a single call: the point is that
        # both levels apply from one validated batch.
        with contextlib.redirect_stdout(io.StringIO()):
            s.cmd_set(["0", "username=batched", "port=8444"])
        check("set applies validated site and host pairs",
              s.config.sites[0].username == "batched"
              and s.config.port == 8444)
        check("set saves once per successful call", save_count == [1])

        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_set(["port=99999", "trusted_proxy=10.0.0.1"])
        check("set rejects a bad pair and applies nothing from the call",
              "port" in buf.getvalue() and s.config.port == 8444
              and s.config.trusted_proxy == saved_set["trusted_proxy"]
              and save_count == [1])

        # The retired channel's two keys must be refused like any other word
        # the vocabulary does not hold — not accepted onto a Site that has
        # nowhere to put them.
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_set(["publish_url=https://cdn.example/b.tar.gz", "publish_key=" + "ab" * 32])
        check("the retired channel's keys are refused, not stored",
              "Unknown or malformed" in buf.getvalue()
              and not hasattr(s.config.sites[0], "publish_url")
              and not hasattr(s.config.sites[0], "publish_key"))

        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_set(["password=hunter2"])
        check("set refuses unknown keys (password is interactive-only)",
              "Unknown or malformed" in buf.getvalue())

        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_set(["active=maybe"])
        check("set rejects a non-yes/no active", "yes or no" in buf.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            s.cmd_set(["active=no"])
        deactivated = s.config.sites[0].active is False
        with contextlib.redirect_stdout(io.StringIO()):
            s.cmd_set(["active=yes"])
        check("set active=no/yes is the deactivation switch",
              deactivated and s.config.sites[0].active is True)

        # Reactivation makes the certificate load-bearing again (ruled):
        # startup skips a paused site's cert but fails closed on an active
        # one, so the door refuses to save the flip over a pair that does
        # not load. The scratch pass carries the site's real cert paths and
        # active state, so the whole call is refused before any pair applies.
        saved_cert_pair = (s.config.sites[0].cert_file, s.config.sites[0].key_file)
        with contextlib.redirect_stdout(io.StringIO()):
            s.cmd_set(["active=no"])
        s.config.sites[0].cert_file = "/nonexistent/rotted.pem"
        s.config.sites[0].key_file  = "/nonexistent/rotted.key"
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_set(["active=yes", "username=never-applied"])
        check("Reactivating over an unloadable certificate is refused, naming the fix",
              "does not load" in buf.getvalue()
              and "config cert" in buf.getvalue()
              and s.config.sites[0].active is False)
        check("...and the refusal applies nothing from the call",
              s.config.sites[0].username != "never-applied")
        (s.config.sites[0].cert_file, s.config.sites[0].key_file) = saved_cert_pair
        with contextlib.redirect_stdout(io.StringIO()):
            s.cmd_set(["active=yes"])
        check("With the certificate back, reactivation succeeds",
              s.config.sites[0].active is True)

        saved_auth = (s.config.sites[0].username, s.config.sites[0].password_hash,
                      s.config.sites[0].password_salt, s.config.sites[0].cache)
        s.config.sites[0].username = "probe"
        s.config.sites[0].password_hash = "stale-hash"
        s.config.sites[0].password_salt = "stale-salt"
        s.config.sites[0].cache = "no"
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_set(["username="])
        check("set username= is the one auth switch — the stored password clears with it",
              s.config.sites[0].username == ""
              and s.config.sites[0].password_hash == ""
              and s.config.sites[0].password_salt == "")
        # The flip reset the cache toggle AND said so — loudly, by ruling.
        check("...and the access flip resets browser copies, announced",
              s.config.sites[0].cache == "yes"
              and "Browser copies reset" in buf.getvalue())
        (s.config.sites[0].username, s.config.sites[0].password_hash,
         s.config.sites[0].password_salt, s.config.sites[0].cache) = saved_auth

        # The folder left the vocabulary by ruling: Servette assigns it, so
        # there is no key to answer wrongly. 'set dir=' is now as unknown as
        # any other invented key — the useful pin is that it is refused
        # rather than silently ignored.
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_set(["dir=/etc"])
        check("'dir' is not a setting any more, and saying so is not silent",
              "Unknown or malformed" in buf.getvalue()
              and "dir" not in s._SET_SITE_KEYS + s._SET_HOST_KEYS)
        check("...and nothing was written",
              s.config.sites[0].serve_dir != "/etc")

        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_set(["99", "username=x"])
        check("set refuses a site index that doesn't exist", "No site 99" in buf.getvalue())

        # Reaching cmd_set without root now means elevation did not happen —
        # run_command elevates first, so this is the sudo-unavailable backstop.
        # It must still fail with a usable sentence rather than a traceback.
        s.Config.save = lambda self: (_ for _ in ()).throw(PermissionError())
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_set(["port=8445"])
        check("set without root fails with a hint, not a traceback",
              "needs root" in buf.getvalue())
        s.Config.save = lambda self: save_count.append(1)
    finally:
        s.Config.save = saved_save
        for n, v in saved_set.items():
            setattr(s.config, n, v)

    # Every save restores the config's ownership — a root-owned 0600 config from
    # `sudo servette set` would otherwise kill the running service and send the
    # operator's own read-only commands looking for a password.
    saved_chown = s._chown_config
    chowned = []
    try:
        s._chown_config = lambda path: chowned.append(path)
        s.config.save()
        check("save() restores the config's ownership",
              chowned == [s.config.CONFIG_FILE])
    finally:
        s._chown_config = saved_chown

    # One-shot dispatch: --serve is positional, so a stray flag in a command's
    # arguments stays an argument instead of silently becoming the server.
    saved_argv  = sys.argv
    saved_main  = {n: getattr(s, n) for n in ("run_command", "start_server")}
    try:
        routed = []
        s.run_command  = lambda cmd, args: routed.append((cmd, args)) or True
        s.start_server = lambda: routed.append("SERVE")
        sys.argv = ["servette", "status", "--serve"]
        s.main()
        check("A trailing --serve stays a command argument",
              routed == [("status", ["--serve"])])
    finally:
        sys.argv = saved_argv
        for n, v in saved_main.items():
            setattr(s, n, v)

    section("Startup refresh (stale units)")

    # The package manager delivers new code but cannot touch systemd units;
    # _startup_refresh reconciles at shell launch. The version stamp makes a
    # pip upgrade (which changes no directive) read as stale, and the
    # environment-drift gate keeps a stale unit from being adopted by a shell
    # launched from a different data dir or interpreter.
    udir = tempfile.mkdtemp()
    saved = {n: getattr(s, n) for n in
             ("SERVICE_PATH", "NETWATCH_PATH", "_service_file_exists",
              "_write_unit_files", "_service_is_active", "_reload_server")}
    try:
        s.SERVICE_PATH  = os.path.join(udir, "servette.service")
        s.NETWATCH_PATH = os.path.join(udir, "servette-netwatch")
        s._service_file_exists = lambda: os.path.exists(s.SERVICE_PATH)
        check("No service installed: nothing is stale", s._stale_units() == [])

        texts = s._desired_units()
        for path, unit_text in texts.items():
            with open(path, "w") as f:
                f.write(unit_text)
        check("Exactly what this version writes: nothing is stale", s._stale_units() == [])
        check("Every unit carries the generating version stamp",
              all(t.startswith(f"# generated by servette {s.__version__}\n")
                  for t in texts.values()))
        check("Matching environment: no drift", s._service_env_drift() == [])

        # A pip upgrade changes no directive — the stamp alone must flag it,
        # or an upgraded host's service would keep running the old code.
        saved_ver = s.__version__
        s.__version__ = "9.9.9"
        stale = s._stale_units()
        s.__version__ = saved_ver
        check("A version change alone marks every unit stale", len(stale) == 3)

        os.remove(s.NETWATCH_PATH + ".timer")
        check("A missing unit file is stale (a release that adds one)",
              s.NETWATCH_PATH + ".timer" in s._stale_units())

        calls = []
        s._write_unit_files  = lambda: calls.append("write") or True
        s._service_is_active = lambda: True
        s._reload_server     = lambda: calls.append("reload")
        with contextlib.redirect_stdout(io.StringIO()):
            s._startup_refresh()
        check("Stale units, matching environment: refreshed and reloaded",
              calls == ["write", "reload"])

        # Environment drift: stale, but never silently adopted.
        with open(s.SERVICE_PATH, "w") as f:
            f.write("# generated by servette 0.0.0\n[Unit]\n[Service]\n"
                    "Environment=SERVETTE_HOME=/somewhere/else\n"
                    f"ExecStart={s._unit_python_path()} -m servette --serve\n")
        check("A different data directory reads as drift",
              any("data directory" in d for d in s._service_env_drift()))
        calls = []
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s._startup_refresh()
        check("Drifted environment: reported, units left untouched",
              calls == [] and "different environment" in buf.getvalue())

        # A unit that predates the data directory is drift too — migration
        # is the operator's decision, made through an explicit 'enable'.
        with open(s.SERVICE_PATH, "w") as f:
            f.write("[Unit]\n[Service]\nExecStart=/usr/bin/python3 /root/servette.py --serve\n")
        check("A pre-data-dir unit reads as drift",
              any("predates" in d for d in s._service_env_drift()))

        # A pinned interpreter that vanished, in an environment that can
        # name no replacement: _stale_units answers empty (nothing it could
        # write), and the crash-loop report used to be silenced with it.
        with open(s.SERVICE_PATH, "w") as f:
            f.write(f"# generated by servette {s.__version__}\n[Unit]\n[Service]\n"
                    f"Environment=SERVETTE_HOME={s.BASE_DIR}\n"
                    "ExecStart=/nonexistent/python3 -m servette --serve\n")
        saved_upp = s._unit_python_path
        s._unit_python_path = lambda: None
        try:
            check("No writable interpreter: nothing reads as stale",
                  s._stale_units() == [])
            with contextlib.redirect_stdout(io.StringIO()) as obuf:
                s._startup_refresh()
        finally:
            s._unit_python_path = saved_upp
        check("...yet a vanished service interpreter is still reported at launch",
              "no longer exists" in obuf.getvalue()
              and "cannot start" in obuf.getvalue())

        # Stale with matching environment but no root: fails soft with a hint.
        for path, unit_text in texts.items():
            with open(path, "w") as f:
                f.write(unit_text)
        with open(s.SERVICE_PATH, "w") as f:
            f.write(texts[s.SERVICE_PATH].replace(s.__version__, "0.0.0", 1))
        s._write_unit_files = lambda: (_ for _ in ()).throw(PermissionError())
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s._startup_refresh()
        check("A refresh that needs root fails soft with a hint",
              "run 'enable'" in buf.getvalue())
        # Option A (#99): the hint must not tell the operator to type sudo —
        # enable elevates itself, and sudo-in-the-message is the retired world.
        check("...and the hint never says sudo", "sudo" not in buf.getvalue())
    finally:
        for n, v in saved.items():
            setattr(s, n, v)
        shutil.rmtree(udir, ignore_errors=True)

    section("An empty site folder is left empty (the placeholder is gone)")

    # Setup must still never finish with nothing to serve (#37), but it no
    # longer keeps that promise by writing a file: a folder with no index.html
    # answers its domain with the embedded error page. So Step 1 creates
    # the missing folder, writes nothing into it, and says what will answer.
    # urlopen is stubbed to raise, so the public-IP lookup falls back as before
    # and nothing here can reach the network.
    def _no_network(*a, **k):
        raise urllib.error.URLError("network touched in a no-network test")

    setup_dir = os.path.join(s.BASE_DIR, "t2-setup-" + os.urandom(3).hex())
    saved_setup = {n: getattr(s, n) for n in
                   ("_config_cert", "_config_username", "_config_password", "_prompt")}
    saved_serve_dir = s.config.sites[0].serve_dir
    saved_urlopen   = s.urllib.request.urlopen
    try:
        s.urllib.request.urlopen = _no_network
        s.config.sites[0].serve_dir = setup_dir
        s._config_cert     = lambda site: None
        s._config_username = lambda site: None
        s._config_password = lambda site: None
        s._prompt = lambda *a, **k: False        # ready to start? no
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_setup()
        out = buf.getvalue()
        check("Setup creates the missing serve_dir", os.path.isdir(setup_dir))
        check("Setup writes nothing into the empty folder",
              os.listdir(setup_dir) == [])
        check("Setup says the error page will answer until they publish",
              "error page" in out)
        check("Setup no longer offers to install a placeholder",
              "placeholder" not in out.lower())

        # With content in place setup reports serving it, unchanged.
        with open(os.path.join(setup_dir, "index.html"), "w") as f:
            f.write("<!doctype html>the operator's own page")
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            s.cmd_setup()
        check("Setup with content in place reports serving it", "Serving" in buf.getvalue())
    finally:
        for n, v in saved_setup.items():
            setattr(s, n, v)
        s.config.sites[0].serve_dir = saved_serve_dir
        s.urllib.request.urlopen    = saved_urlopen
        shutil.rmtree(setup_dir, ignore_errors=True)

    section("Root is requested, not required of the operator")

    # Servette needs root for the systemd unit, the service user, the config the
    # service reads, and the site folders it serves. It asks sudo for that itself
    # rather than making the operator prefix every invocation — which is what
    # forced the console script onto sudo's secure_path, and so forced an install
    # to put it there.
    check("Read-only commands never elevate",
          not any(s._needs_root(c) for c in ("status", "sites", "log")))
    check("Privileged commands do",
          all(s._needs_root(c) for c in
              ("setup", "config", "enable", "disable", "set", "admin", "restore-site")))

    # start and stop are the conditional pair: root for the systemd path, but a
    # session server lives in *this* process, where an elevated child could
    # neither keep it alive after exiting nor reach the parent's to stop it.
    saved_sfe, saved_isact, saved_srun = \
        s._service_file_exists, s._service_is_active, s._server_running
    try:
        s._service_file_exists = lambda: True
        s._service_is_active   = lambda: True
        s._server_running      = lambda: False
        check("start elevates when a unit is installed", s._needs_root("start"))
        check("stop elevates when the service is what is running",
              s._needs_root("stop"))

        s._service_file_exists = lambda: False
        s._service_is_active   = lambda: False
        check("start stays put with no unit to drive", not s._needs_root("start"))

        s._service_is_active = lambda: True
        s._server_running    = lambda: True
        check("stop stays put while a session server runs here",
              not s._needs_root("stop"))
    finally:
        s._service_file_exists, s._service_is_active, s._server_running = \
            saved_sfe, saved_isact, saved_srun

    # A configured host keeps servette.toml at mode 600 for the service user, so
    # an operator who has not elevated cannot read it. Two things must hold: the
    # program still reaches its dispatcher (the crash this replaced happened at
    # import, before any command could elevate), and it does not pass the
    # stand-in defaults off as the operator's settings.
    # Mode 000 would not reproduce it here — this suite may run as root, for whom
    # permissions are advisory — so the denial is injected instead: a module-level
    # `open` shadows the builtin for Servette's own code, and only while the
    # config is being read.
    unreadable_home = tempfile.mkdtemp()
    unreadable_cfg  = os.path.join(unreadable_home, "servette.toml")
    with open(unreadable_cfg, "w", encoding="utf-8") as f:
        f.write('port = 8443\n')
    saved_cfg_file = s.Config.CONFIG_FILE

    def _denied(*a, **k):
        raise PermissionError(13, "Permission denied")

    try:
        s.Config.CONFIG_FILE = unreadable_cfg
        s.open = _denied
        try:
            probe = s.Config()
        finally:
            del s.open                  # back to the builtin
        check("An unreadable config is not a fatal one", probe.unreadable)
        check("An unreadable config stands in defaults, not the file's values",
              probe.port == 443)

        # Construction tolerates the unreadable file; the live RELOAD must not.
        # Adopting defaults there would swap a protected site's real config —
        # auth and all — for no-auth defaults because a file's ownership broke.
        # Demonstrated live during review: a running 401 became 404 (request
        # processed with no challenge) the instant the config went unreadable.
        good = s.Config()   # a readable one, from the real (readable) test config
        good.sites[0].username = "op"
        good.sites[0].password_hash = "deadbeef"
        good._mtime = 0                              # force "changed on disk"
        good.CONFIG_FILE = unreadable_cfg            # now points at the unreadable file
        s.open = _denied
        raised = adopted = None
        try:
            good.reload_if_changed()                 # must keep the last good config
            adopted = good.unreadable
        except SystemExit:
            raised = "exit"
        finally:
            s.__dict__.pop("open", None)
        check("A reload of an unreadable config neither exits nor adopts defaults",
              raised is None and good.sites[0].username == "op")
        check("...and keeps the authenticated site's password", good.sites[0].password_hash == "deadbeef")

        # The unreadable state is usually a save caught mid-replace: os.replace
        # has installed the temp file, _chown_config has not yet restored its
        # ownership. The old code stamped the new mtime on the failed reload,
        # and the later chown/chmod change only ctime — so when the file became
        # readable again a beat later, the change detector saw nothing to do
        # and the server sat on the old config until the NEXT save. Reproduced
        # live during review: disk said port 8080, memory served 443, forever.
        good.reload_if_changed()             # the shadow is gone: the next request
        check("The reload RECOVERS once the file is readable again (mtime unmoved)",
              good.port == 8443)

        # A failed reload must also leave the unreadable FLAG as it found it.
        # The old code cleared it at the top of _load before the read it was
        # about to fail — after which a long-lived unprivileged shell stopped
        # elevating its read-only commands and reported the built-in defaults
        # as the operator's settings: the exact lie the flag exists to prevent.
        flagged = s.Config()
        flagged.unreadable = True                    # a shell holding defaults
        flagged._mtime     = 0                       # file "changed on disk"
        flagged.CONFIG_FILE = unreadable_cfg
        s.open = _denied
        try:
            flagged.reload_if_changed()              # still unreadable: must fail
        finally:
            s.__dict__.pop("open", None)
        check("A failed reload preserves unreadable=True (keeps elevating)",
              flagged.unreadable is True)
    finally:
        s.Config.CONFIG_FILE = saved_cfg_file
        s.__dict__.pop("open", None)
        shutil.rmtree(unreadable_home, ignore_errors=True)

    # Invalid TOML is the opposite case: a bad EDIT stays bad until someone
    # edits again, so there the failed reload stamps the mtime — one parse and
    # one warning per bad edit, not one per request.
    bad_home = tempfile.mkdtemp()
    bad_cfg  = os.path.join(bad_home, "servette.toml")
    with open(bad_cfg, "w", encoding="utf-8") as f:
        f.write("port = 8443\n")
    try:
        s.Config.CONFIG_FILE = bad_cfg
        parses = s.Config()
        with open(bad_cfg, "w", encoding="utf-8") as f:
            f.write("port = = broken\n")
        os.utime(bad_cfg, (1, 1))                    # a distinct, stable mtime
        parses.reload_if_changed()
        check("An invalid edit keeps the last good config", parses.port == 8443)
        check("...and stamps its mtime so the bad file is parsed once",
              parses._mtime == os.path.getmtime(bad_cfg))
    finally:
        s.Config.CONFIG_FILE = saved_cfg_file
        shutil.rmtree(bad_home, ignore_errors=True)

    # The migration save is guarded: an unprivileged operator (or the sandboxed
    # service) can read a legacy flat config but cannot write the root-owned
    # data directory. The old code let save()'s PermissionError escape
    # Config.__init__ — which runs at import — so `servette status` died with a
    # traceback and a service restart-looped, over a file this process was
    # never going to write. Reproduced live during review with real users.
    legacy_home = tempfile.mkdtemp()
    legacy_cfg  = os.path.join(legacy_home, "servette.toml")
    with open(legacy_cfg, "w", encoding="utf-8") as f:
        f.write('serve_dir = "site"\nusername = "op"\n')   # flat: pre-[[site]]
    saved_save = s.Config.save
    try:
        s.Config.CONFIG_FILE = legacy_cfg
        s.Config.save = lambda self: (_ for _ in ()).throw(
            PermissionError(13, "Permission denied"))
        try:
            migrated = s.Config()
            check("A legacy config in an unwritable dir still constructs", True)
        except PermissionError:
            migrated = None
            check("A legacy config in an unwritable dir still constructs (raised)", False)
        check("...with the migration applied in memory",
              migrated is not None and migrated.sites[0].username == "op")
    finally:
        s.Config.save = saved_save
        s.Config.CONFIG_FILE = saved_cfg_file
        shutil.rmtree(legacy_home, ignore_errors=True)

    # The shell's defaults-stand-in affordance must never reach the SERVE path:
    # the defaults carry no password, so serving them would open a protected
    # site because a file's ownership broke. Demonstrated live during review —
    # a 0600 root-owned config served "OPERATOR-ONLY CONTENT" at 200 with no
    # credentials. --serve now refuses instead.
    saved_start, saved_argv = s.start_server, sys.argv[:]
    saved_unreadable_serve = s.config.unreadable
    started = []
    try:
        s.start_server = lambda: started.append(True)
        s.config.unreadable = True
        sys.argv[:] = ["servette", "--serve"]
        code = None
        logging.disable(logging.CRITICAL)
        try:
            s.main()
        except SystemExit as e:
            code = e.code
        finally:
            logging.disable(logging.NOTSET)
        check("--serve with an unreadable config exits nonzero", code == 1)
        check("...without ever starting the server", not started)
    finally:
        s.start_server = saved_start
        sys.argv[:] = saved_argv
        s.config.unreadable = saved_unreadable_serve

    # The one-shot form is documented as the way scripts drive Servette, and a
    # script's first move is a pipe: `servette status | head` must end at the
    # consumer's convenience, not in a BrokenPipeError traceback. A subprocess
    # is required — the handler dup2s over the true stdout fd, which no
    # StringIO can stand in for. The pipe's read end is closed BEFORE the child
    # runs, so its first write raises EPIPE deterministically; the first
    # version piped through `head -c 5`, and status output small enough to fit
    # the 64K pipe buffer meant head could exit after the child had already
    # finished writing — no SIGPIPE, a flaky pass. 141 is 128+SIGPIPE: what
    # the shell reports for any tool that dies on a closed pipe.
    pipe_r, pipe_w = os.pipe()
    os.close(pipe_r)
    env_pipe = dict(os.environ, SERVETTE_HOME=SERVETTE_DIR)
    r = subprocess.run(
        [sys.executable, os.path.join(SERVETTE_DIR, "servette.py"), "status"],
        stdout=pipe_w, stderr=subprocess.PIPE, env=env_pipe, timeout=60)
    os.close(pipe_w)
    check("A closed stdout ends the one-shot quietly, exit 141",
          r.returncode == 141 and b"Traceback" not in r.stderr)

    # _needs_root reads the live singleton, so drive that flag directly rather
    # than swapping the whole config out from under the rest of the suite.
    saved_unreadable = s.config.unreadable
    try:
        s.config.unreadable = True
        check("Read-only commands elevate when the config is out of reach",
              all(s._needs_root(c) for c in ("status", "sites", "log")))
    finally:
        s.config.unreadable = saved_unreadable

    saved_run, saved_euid = s.subprocess.run, s.os.geteuid
    captured = []
    sudo_status = [0]

    class _Done:                      # stands in for a CompletedProcess
        def __init__(self, rc): self.returncode = rc

    # These tests are about the argv handed to sudo, so sudo's PRESENCE is
    # controlled, not inherited: Debian 12's CI container ships no sudo, and
    # _elevate correctly took its sudo-is-not-installed branch there — leaving
    # captured empty and this section crashing on captured[0] instead of
    # testing anything. The absent-sudo branch gets its own test below.
    saved_which = s.shutil.which
    try:
        s.shutil.which = lambda name, *a, **k: (
            "/usr/bin/sudo" if name == "sudo" else saved_which(name, *a, **k))

        def _fake_run(argv, *a, **k):
            captured.append(argv)
            return _Done(sudo_status[0])
        s.subprocess.run = _fake_run

        with contextlib.redirect_stderr(io.StringIO()) as buf:
            s._elevate("enable", [])
        argv = captured[0]
        # An absolute interpreter is the whole mechanism: sudo resolves it
        # without consulting PATH, so nothing has to live on secure_path.
        check("Elevation names an absolute interpreter, not a PATH lookup",
              argv[0] == "sudo" and os.path.isabs(argv[argv.index("-m") - 1]))
        check("Elevation re-runs the same command as a module",
              argv[argv.index("-m") + 1:] == ["servette", "enable"])
        # sudo speaks for itself: it prompts when it wants a password and is
        # silent when the timestamp is still warm. A line of ours ahead of it
        # is noise in both cases.
        check("Elevation announces nothing of its own on the way in",
              buf.getvalue() == "")

        # sudo resets the environment. Losing SERVETTE_HOME would point the
        # elevated run at a different data directory than the operator is in —
        # worse than not elevating at all.
        captured.clear()
        os.environ["SERVETTE_HOME"] = "/tmp/servette-elevate-probe"
        with contextlib.redirect_stdout(io.StringIO()):
            s._elevate("set", ["port=8443"])
        check("Elevation carries SERVETTE_HOME across sudo",
              "--preserve-env=SERVETTE_HOME" in captured[0])
        check("Elevation passes the command's own arguments through",
              captured[0][-3:] == ["servette", "set", "port=8443"])

        # A refused password must not read as success to whatever is driving
        # `servette <command>` over SSH: the work happened in the child, so its
        # status is the only honest one to exit with.
        sudo_status[0] = 1
        with contextlib.redirect_stderr(io.StringIO()):
            s._elevate("enable", [])
        check("A failed elevation is remembered as a failure",
              s._elevated_status == 1)
        sudo_status[0] = 0
        with contextlib.redirect_stderr(io.StringIO()):
            s._elevate("enable", [])
        check("A successful one is not", s._elevated_status == 0)

        # A host with no sudo at all — Debian's CI container is one — must be
        # told plainly, spawn nothing, and register the failure.
        captured.clear()
        s.shutil.which = lambda name, *a, **k: (
            None if name == "sudo" else saved_which(name, *a, **k))
        with contextlib.redirect_stderr(io.StringIO()) as nobuf:
            s._elevate("enable", [])
        check("Without sudo, elevation explains and spawns nothing",
              "sudo is not installed" in nobuf.getvalue() and captured == [])
        check("...and the one-shot would exit nonzero", s._elevated_status == 1)

        # Already root: the dispatcher must do the work, not re-invoke itself.
        captured.clear()
        s.os.geteuid = lambda: 0
        s._service_is_active, s._server_running = (lambda: True), (lambda: False)
        with contextlib.redirect_stdout(io.StringIO()):
            s.run_command("stop", [])
        check("Running as root does the work instead of re-invoking sudo",
              captured and not any(a and a[0] == "sudo" for a in captured)
              and captured[0][:2] == ["systemctl", "stop"])
    finally:
        s.subprocess.run, s.os.geteuid = saved_run, saved_euid
        s.shutil.which = saved_which
        s._service_is_active, s._server_running = saved_isact, saved_srun
        os.environ.pop("SERVETTE_HOME", None)

    section("Site management (add/remove/select)")

    saved_sites7  = list(s.config.sites)  # a copy: add-site/remove-site mutate the
                                          # list in place, so a bare reference here
                                          # wouldn't actually restore anything
    saved_reload  = s._reload_server
    saved_ssrv    = s._server_running
    saved_sact    = s._service_is_active
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
            # add-site: domain (blank → self-signed), username (blank). The
            # folder is not asked for — Servette invents it — and nothing is
            # written into it, so an empty folder is left empty.
            script = iter(["", ""])
            builtins.input = lambda prompt="": next(script, "")
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                s._config_add_site()
            check("add-site appends exactly one site", len(s.config.sites) == 2)
            check("add-site invents the folder rather than asking for one",
                  re.fullmatch(r"site-[0-9a-f]{6}", s.config.sites[1].serve_dir)
                  and os.path.isdir(s._resolve(s.config.sites[1].serve_dir)))
            check("...and says where content will land, without asking",
                  s.config.sites[1].serve_dir in buf.getvalue()
                  and "serve_dir:" not in buf.getvalue())
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
            script = iter(["", "", "", ""])
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

            script2 = iter(["", ""])
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
        saved_input3 = builtins.input
        try:
            script3 = iter(["domain-test.example.com", ""])
            builtins.input = lambda prompt="": next(script3, "")
            with contextlib.redirect_stdout(io.StringIO()):
                s._config_add_site()
        finally:
            builtins.input = saved_input3
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
        saved_input3c = builtins.input
        try:
            script3c = iter(["issued.example.com", ""])
            builtins.input = lambda prompt="": next(script3c, "")
            with contextlib.redirect_stdout(io.StringIO()):
                s._config_add_site()
        finally:
            builtins.input = saved_input3c
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
        saved_input3b = builtins.input
        try:
            script3b = iter(["unreachable.example.com", ""])
            builtins.input = lambda prompt="": next(script3b, "")
            with contextlib.redirect_stdout(io.StringIO()):
                s._config_add_site()
        finally:
            builtins.input = saved_input3b
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
        saved_input4 = builtins.input
        try:
            script4 = iter(["taken.example.com", ""])
            builtins.input = lambda prompt="": next(script4, "")
            with contextlib.redirect_stdout(io.StringIO()) as buf:
                s._config_add_site()
        finally:
            builtins.input = saved_input4
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

        # A serve_dir outside BASE_DIR breaks the publish pipeline's
        # same-filesystem atomic swap and the systemd sandbox's
        # ReadWritePaths. That used to be two refusals, on add-site and on
        # 'dir'. With the folder out of the vocabulary there is nothing left
        # to refuse — the invariant is now that every folder Servette hands
        # out is inside BASE_DIR, which is what this pins. A hand-edited
        # servette.toml is the only remaining way past it.
        invented = [s._invent_site_dir() for _ in range(8)]
        try:
            check("Every invented folder lands inside the data directory",
                  all(s._is_within_base_dir(s._resolve(d)) for d in invented))
            check("...and none of them collides with another",
                  len(set(invented)) == len(invented))
            check("...and none of them is a folder holding Servette's secrets",
                  not any(s._serve_dir_exposes_secrets(s._resolve(d)) for d in invented))
        finally:
            for d in invented:
                shutil.rmtree(s._resolve(d), ignore_errors=True)
    finally:
        for fname in generated_files:
            p = os.path.join(s.BASE_DIR, fname)
            if os.path.exists(p):
                os.remove(p)
        s._reload_server     = saved_reload2
        s._server_running    = saved_ssrv2
        s._service_is_active = saved_sact2
        s._chown_servette    = saved_chown
        s._obtain_trusted_cert = saved_obtain
        s.config.sites        = saved_sites10

    section("Issued-certificate persistence (the renewal path)")

    # The retry loop retries exactly one thing: the ACME exchange. The live
    # deployment's review found local persistence inside it — the sandboxed
    # service cannot write the data directory, so a renewal that ISSUED fine
    # then "retried" the save as if Let's Encrypt had refused: three duplicate
    # certificates burned per pass, and the reload never reached, so the fresh
    # cert sat on disk while the served one marched to expiry.
    persist_dir = tempfile.mkdtemp()
    saved_persist = {n: getattr(s, n) for n in
                     ("_reload_server", "_server_running", "_service_is_active",
                      "_chown_servette")}
    saved_psave = s.Config.save
    psite = s.Site({"serve_dir": "site"})
    try:
        reloads_p, saves_p = [], []
        s._reload_server     = lambda: reloads_p.append(1)
        s._server_running    = lambda: True
        s._service_is_active = lambda: False
        s._chown_servette    = lambda path: None
        s.Config.save        = lambda self: saves_p.append(1)

        with contextlib.redirect_stdout(io.StringIO()):
            s._persist_issued_cert("p.test", psite, persist_dir,
                                   "CERT-PEM", b"KEY-PEM", "p.test")
        cert_p = os.path.join(persist_dir, "fullchain.pem")
        key_p  = os.path.join(persist_dir, "privkey.pem")
        check("First issuance writes the pair and saves once",
              open(cert_p).read() == "CERT-PEM" and open(key_p, "rb").read() == b"KEY-PEM"
              and saves_p == [1])
        check("...points the site at the pair", psite.cert_file == cert_p
              and psite.key_file == key_p and psite.domain == "p.test")
        check("...leaves no temp files behind",
              not [f for f in os.listdir(persist_dir) if f.endswith(".tmp")])
        check("...keeps the key 0600", os.stat(key_p).st_mode & 0o777 == 0o600)
        check("...and reloads the running server", reloads_p == [1])

        # Renewal: the site already points at these exact paths — nothing to
        # save, so the sandboxed service's inability to write the data
        # directory costs nothing.
        saves_p.clear(); reloads_p.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            s._persist_issued_cert("p.test", psite, persist_dir,
                                   "CERT-PEM-2", b"KEY-PEM-2", "p.test")
        check("Renewal skips the config save (nothing changed)",
              saves_p == [] and open(cert_p).read() == "CERT-PEM-2")
        check("...but still reloads onto the new certificate", reloads_p == [1])

        # And when a first issuance's save DOES fail, the certificate that is
        # already on disk and about to be served is not reported as a failure.
        psite2 = s.Site({"serve_dir": "site"})
        s.Config.save = lambda self: (_ for _ in ()).throw(
            PermissionError(13, "Permission denied"))
        reloads_p.clear()
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                s._persist_issued_cert("p.test", psite2, persist_dir,
                                       "CERT-PEM-3", b"KEY-PEM-3", "p.test")
            check("A failed config save does not fail the issuance", True)
        except Exception as e:
            check(f"A failed config save does not fail the issuance (raised {e})", False)
        check("...the pair is on disk and the server reloaded onto it",
              open(cert_p).read() == "CERT-PEM-3" and reloads_p == [1])
    finally:
        s.Config.save = saved_psave
        for n, v in saved_persist.items():
            setattr(s, n, v)
        shutil.rmtree(persist_dir, ignore_errors=True)

    # Structural: issuance retries must contain no persistence to mis-retry.
    import inspect as _inspect
    obtain_src = _inspect.getsource(s._obtain_trusted_cert)
    check("The ACME retry loop persists nothing (local failure ≠ re-issuance)",
          "config.save" not in obtain_src
          and "_persist_issued_cert" in obtain_src)

    section("ACME failures are classified: a refusal is not retried, a blip is")

    # The shared issuance core vets the domain's own syntax first: the
    # page's name op refuses these shapes before issuance can run, but the
    # terminal's prompts pass their input straight here — where two lines
    # later it becomes a PATH component (certs/<domain>).
    with contextlib.redirect_stdout(io.StringIO()) as gate_buf:
        gate_verdict = s._obtain_trusted_cert("../../escape", s.config.sites[0])
    check("The issuance core refuses an unroutable domain before touching disk",
          gate_verdict == "refused" and "domain" in gate_buf.getvalue()
          and not os.path.exists(
              os.path.normpath(os.path.join(s.BASE_DIR, "certs", "../../escape"))))

    # "Let's Encrypt answered no" and "the network ate a request" used to get
    # identical treatment — three full orders each. Retrying a refusal burns
    # fresh validation attempts against LE's per-hostname limits while the
    # cause (usually DNS) hasn't changed; retrying a blip is what retries are
    # for. The classification also feeds the watchdog: refusals cool down six
    # hours, blips keep the ordinary hourly retry.
    saved_acme = {n: getattr(s, n) for n in
                  ("_ACMEClient", "_server_running", "_chown_servette")}
    saved_sleep_a = s.time.sleep
    acme_home = tempfile.mkdtemp()
    saved_base_a, saved_rt_a = s.BASE_DIR, s.RUNTIME_DIR
    issue_calls = []
    class _StubClient:
        def __init__(self, url, key): pass
        def new_account(self, email): pass
        def issue(self, names, csr, challenge_dir):
            issue_calls.append(list(names))
            raise _StubClient.error
    saved_webroot_a = s.ACME_WEBROOT
    try:
        s.BASE_DIR        = acme_home   # account key and certs land here
        # ACME_WEBROOT is an absolute constant OUTSIDE BASE_DIR — left real,
        # the function's makedirs writes /var/lib/letsencrypt: silently
        # succeeding as root (and polluting the machine), PermissionError on
        # an unprivileged runner. The local unprivileged run even passed once
        # because a root run had already created it — order-dependent truth.
        s.ACME_WEBROOT    = os.path.join(acme_home, "webroot")
        s._ACMEClient     = _StubClient
        s._server_running = lambda: True     # no temporary port-80 listener
        s._chown_servette = lambda path: None
        s.time.sleep      = lambda n: None
        asite = s.Site({"serve_dir": "site"})

        _StubClient.error = s._ACMEError("authorization failed", failed={"cls.test"})
        issue_calls.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            outcome = s._obtain_trusted_cert("cls.test", asite)
        check("A CA refusal is classified 'refused'", outcome == "refused")
        check("...and asked exactly once, not retried",
              len(issue_calls) == 1)

        _StubClient.error = OSError("connection reset")
        issue_calls.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            outcome = s._obtain_trusted_cert("cls.test", asite)
        check("A network failure is classified 'transient'", outcome == "transient")
        check("...and retried the full ACME_RETRIES times",
              len(issue_calls) == s.ACME_RETRIES)
    finally:
        for n, v in saved_acme.items():
            setattr(s, n, v)
        s.time.sleep   = saved_sleep_a
        s.ACME_WEBROOT = saved_webroot_a
        s.BASE_DIR, s.RUNTIME_DIR = saved_base_a, saved_rt_a
        shutil.rmtree(acme_home, ignore_errors=True)

    # The watchdog acts on the classification: a refusal pushes the next
    # attempt ~6 hours out; success (None) leaves the hourly cadence alone.
    saved_obtain_w = s._obtain_trusted_cert
    saved_days_w   = s._cert_days_remaining
    wsite = s.Site({"serve_dir": "site", "cert_file": "cert.pem"})
    wsite.domain = "cool.test"
    saved_sites_w = s.config.sites
    try:
        s.config.sites         = [wsite]
        s._cert_days_remaining = lambda p: 10
        s._obtain_trusted_cert = lambda d, st: "refused"
        s._last_renewal_attempt.pop("cool.test", None)
        s._cert_watchdog_tick()
        now = s.time.monotonic()
        check("A refusal cools the watchdog down ~6 hours",
              s._last_renewal_attempt["cool.test"] > now + 4 * 3600)
        s._obtain_trusted_cert = lambda d, st: None
        s._last_renewal_attempt.pop("cool.test", None)
        s._cert_watchdog_tick()
        check("Success keeps the ordinary hourly stamp",
              abs(s._last_renewal_attempt["cool.test"] - s.time.monotonic()) < 60)
        # And never-attempted means "attempt now": with no stamp for the
        # domain, one tick must reach the obtain call itself. (The old 0.0
        # default read as "attempted at boot" and made a young host refuse
        # every renewal for its first hour.) Asserted on the CALL, not on
        # the stamp the earlier checks already forced into existence.
        _renew_calls = []
        s._obtain_trusted_cert = lambda d, st: _renew_calls.append(d)
        s._last_renewal_attempt.pop("cool.test", None)
        s._cert_watchdog_tick()
        check("A never-attempted domain is attempted on the very next tick",
              _renew_calls == ["cool.test"])
    finally:
        s._obtain_trusted_cert = saved_obtain_w
        s._cert_days_remaining = saved_days_w
        s.config.sites         = saved_sites_w
        s._last_renewal_attempt.pop("cool.test", None)

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
            with contextlib.redirect_stdout(io.StringIO()) as setup_buf:
                s.cmd_setup()
            check("cmd_setup runs end to end without raising", True)
            check("setup prints the one-time LocalForward line for the browser half",
                  f"LocalForward {s._UI_PORT} 127.0.0.1:{s._UI_PORT}"
                  in setup_buf.getvalue())
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

    section("Auth timing: the hash runs regardless of the username")

    # Both credential checks are evaluated before they are combined, so a
    # wrong username must not skip the scrypt call — an early-out would make
    # response timing confirm which usernames exist. Pinned behaviorally:
    # the hash runs exactly once for a wrong user and a wrong password alike.
    saved_auth_site = (s.config.sites[0].username, s.config.sites[0].password_hash,
                       s.config.sites[0].password_salt, s.config.sites[0].serve_dir)
    saved_checkpw = s._check_password
    authdir = tempfile.mkdtemp()
    hash_calls = []
    try:
        s.config.sites[0].username      = "realuser"
        s.config.sites[0].password_hash = "ab" * 32
        s.config.sites[0].password_salt = "cd" * 16
        s.config.sites[0].serve_dir     = authdir
        s._check_password = lambda pw, h, salt: hash_calls.append(pw) or False
        s._auth_fail_times.clear()   # a prior test's strikes must not 429 this

        def basic_msg(user, pw):
            m = http.client.HTTPMessage()
            m["Authorization"] = "Basic " + base64.b64encode(
                f"{user}:{pw}".encode()).decode()
            return m

        st1, _, _ = s._handle_request("GET", "/", basic_msg("realuser", "wrong"), "127.0.0.1")
        st2, _, _ = s._handle_request("GET", "/", basic_msg("ghost", "wrong"), "127.0.0.1")
        check("Both attempts are refused", st1 == 401 and st2 == 401)
        check("A wrong password and a wrong username each ran the hash exactly once",
              hash_calls == ["wrong", "wrong"])
    finally:
        s._check_password = saved_checkpw
        (s.config.sites[0].username, s.config.sites[0].password_hash,
         s.config.sites[0].password_salt, s.config.sites[0].serve_dir) = saved_auth_site
        s._auth_fail_times.clear()
        shutil.rmtree(authdir, ignore_errors=True)

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

        # Pre-PEP-706 interpreters (e.g. Debian 12's 3.11.2) have no
        # extractall(filter=) — simulate one and prove both that extraction
        # still works and that the hand-rolled guards still reject traversal
        # without the library's help. The simulation is a proxy module that
        # hides data_filter from servette's probe while delegating everything
        # else — deleting the real attribute would break 3.14's extractall,
        # whose default-filter path resolves the module global internally.
        class _PrePEP706Tarfile:
            def __getattr__(self, name):
                if name == "data_filter":
                    raise AttributeError(name)
                return getattr(tarfile, name)
        saved_mod = s.tarfile
        s.tarfile = _PrePEP706Tarfile()
        try:
            dest_nf = os.path.join(extract_root, "nofilter")
            s._extract_bundle(good, dest_nf)
            check("Bundle extracts without tarfile.data_filter (old 3.11)",
                  os.path.isfile(os.path.join(dest_nf, "sub", "page.html")))
            raised = False
            try:
                s._extract_bundle(make_tar_gz([("../evil2.txt", "pwned")]),
                                  os.path.join(extract_root, "nofilter-trav"))
            except ValueError:
                raised = True
            check("Traversal still rejected without data_filter", raised and
                  not os.path.exists(os.path.join(extract_root, "evil2.txt")))
        finally:
            s.tarfile = saved_mod

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

        # The byte cap counts payload, so a bundle of many zero-size members
        # slips under it while still burning CPU and memory. A companion
        # count cap bounds their number.
        saved_members = s._MAX_BUNDLE_MEMBERS
        try:
            s._MAX_BUNDLE_MEMBERS = 3
            manyfiles = make_tar_gz([(f"f{n}.txt", "") for n in range(8)])
            dest5 = os.path.join(extract_root, "manymembers")
            raised = False
            try:
                s._extract_bundle(manyfiles, dest5)
            except ValueError:
                raised = True
            check("A bundle with too many entries is rejected, zero-size included",
                  raised)
        finally:
            s._MAX_BUNDLE_MEMBERS = saved_members

        # The size cap must run DURING the member walk, not after it: walking
        # a gzip stream decompresses it, and getmembers() paid the full
        # decompression cost of a bomb before the cap ever looked. next()
        # lets the walk abort at the ceiling.
        import inspect as _inspect_eb
        eb_src = _inspect_eb.getsource(s._extract_bundle)
        check("The member walk can abort at the cap (next(), not getmembers())",
              "tf.getmembers()" not in eb_src and "tf.next()" in eb_src)
    finally:
        shutil.rmtree(extract_root, ignore_errors=True)

    section("Every scalar knob has one terminal door: set")

    # The prompt layer that wrapped `set` is gone by ruling; the knobs it
    # carried live in the set vocabulary now, each behind the same shared
    # validator every surface uses.
    import builtins
    _sc = type("S", (), {})()
    check("trusted_proxy refuses a non-IP at the one door",
          "must be an IP" in s._set_host_value(_sc, "trusted_proxy", "not-an-ip")
          and s._set_host_value(_sc, "trusted_proxy", "203.0.113.7") == ""
          and _sc.trusted_proxy == "203.0.113.7")
    # One canonical spelling (the redirect-source precedent): the request
    # path compares this value against a normalized socket address, and an
    # uppercase or zero-padded spelling stored as typed would never match —
    # silently collapsing every proxied visitor into one rate-limit bucket.
    check("...and stores the one canonical spelling",
          s._set_host_value(_sc, "trusted_proxy", "2001:0DB8::1") == ""
          and _sc.trusted_proxy == "2001:db8::1")
    _core_src2 = inspect.getsource(s._handle_request)
    check("...while the request path normalizes both sides of the compare",
          "_normalize_ip(config.trusted_proxy)" in _core_src2)
    # The client's query is echoed into the Location header; the same
    # printable-ASCII bound every header value in the program holds is
    # applied to it on the way through.
    check("...and the redirect filters the echoed query to printable ASCII",
          "0x20 <= ord(c) <= 0x7E" in _core_src2)
    # TLS matches routing's rule wholesale: inactive sites are skipped
    # before any context is built (deleting that filter re-creates both the
    # cert/content mismatch _domain_in_use exists to prevent and the paused
    # site whose rotted cert refuses the whole start).
    _tls_src = inspect.getsource(s._build_site_ssl_contexts)
    check("The TLS builder skips inactive sites before loading anything",
          "if not site.active:" in _tls_src and "continue" in _tls_src)
    # The retired pair is refused as unknown, not silently accepted; the
    # per-site `cache` key is the surviving door, a choice stated in its
    # refusal.
    check("the retired cache keys have left the vocabulary",
          "cache_policy" not in s._SET_HOST_KEYS
          and "cache_max_age" not in s._SET_HOST_KEYS)
    _site_sc = s.Site()
    check("cache is a choice, stated and refused outside it",
          "yes" in s._set_site_value(_site_sc, "cache", "sometimes")
          and s._set_site_value(_site_sc, "cache", "no") == ""
          and _site_sc.cache == "no")
    _bad_cache_raised = False
    try:
        s.Site({"cache": "max-age"})
    except s._ConfigInvalid as e:
        _bad_cache_raised = "yes" in str(e)
    check("the load door refuses a cache value no door would save",
          _bad_cache_raised)
    check("a saved override survives the config round-trip",
          s.Site({"cache": "no"}).cache == "no"
          and s.Site({"username": "a", "cache": "yes"}).cache == "yes")
    check("tls_min_version is 1.2 or 1.3, nothing else",
          s._set_host_value(_sc, "tls_min_version", "1.1") != ""
          and s._set_host_value(_sc, "tls_min_version", "1.3") == "")
    # The cipher string's only arbiter is OpenSSL, asked at the door — the
    # alternative was a refusal at the next server start, which fails
    # closed: the site down over a typo saved months earlier.
    check("ciphers are judged by OpenSSL before saving",
          s._set_host_value(_sc, "ciphers", "GARBAGE-THAT-SELECTS-NOTHING") != ""
          and s._set_host_value(_sc, "ciphers", "DEFAULT") == ""
          and s._set_host_value(_sc, "ciphers", "") == "")
    # csp and permissions_policy go out verbatim as header values; a
    # control character there is header injection.
    check("header-valued settings refuse control characters",
          s._set_host_value(_sc, "csp", "default-src 'self'\r\nX-Evil: 1") != ""
          and s._set_host_value(_sc, "csp", "default-src 'self'") == ""
          and s._set_host_value(_sc, "permissions_policy", "camera=()") == "")
    check("...and the sub-shell no longer carries a second door for any of them",
          not any(hasattr(s, f) for f in
                  ("_config_limits", "_config_cache", "_config_trusted_proxy",
                   "_config_tls", "_config_set")))

    section("Ownership plans")

    # The plan is computed apart from the run so this is testable without root.
    saved_sue = s._servette_user_exists
    try:
        s._servette_user_exists = lambda: True
        plan = s._operator_chown_plan("/x", strip_world=True)
        check("strip_world removes world bits in the same chmod",
              ["chmod", "-R", "g+rX,o-rwx", "/x"] in plan)
        plan = s._operator_chown_plan("/x")
        check("...and an operator-filled tree keeps its own modes (g+rX only)",
              ["chmod", "-R", "g+rX", "/x"] in plan
              and not any("o-rwx" in " ".join(argv) for argv in plan))
    finally:
        s._servette_user_exists = saved_sue

    # The serve_dir readability warning must accept the group-only grant the
    # plan just made — the old check demanded world bits and told the operator
    # to add them, undoing the grant two lines above it.
    probe_dir = tempfile.mkdtemp()
    saved_gid = s._servette_gid
    try:
        os.chmod(probe_dir, 0o755)
        check("World-readable serve_dir passes", s._serve_dir_readable(probe_dir))
        os.chmod(probe_dir, 0o750)
        s._servette_gid = lambda: os.stat(probe_dir).st_gid
        check("Group-only serve_dir passes when the group is servette",
              s._serve_dir_readable(probe_dir))
        s._servette_gid = lambda: -1
        check("...and fails when it is some other group",
              not s._serve_dir_readable(probe_dir))
        os.chmod(probe_dir, 0o700)
        s._servette_gid = lambda: os.stat(probe_dir).st_gid
        check("Owner-only serve_dir fails regardless",
              not s._serve_dir_readable(probe_dir))
    finally:
        s._servette_gid = saved_gid
        shutil.rmtree(probe_dir, ignore_errors=True)

    section("Atomic site-content swap and the version ring")

    saved_serve_dir = s.config.sites[0].serve_dir
    swap_root = tempfile.mkdtemp()

    def _publish(root, name, text, link):
        """Land one tree through the real swap, as a publish would."""
        d = os.path.join(root, name)
        os.makedirs(d)
        with open(os.path.join(d, "marker.txt"), "w") as f:
            f.write(text)
        s._swap_site_content(d, link)

    def _marker(path):
        return open(os.path.join(path, "marker.txt")).read()

    try:
        link = os.path.join(swap_root, "site")   # does not exist yet
        s.config.sites[0].serve_dir = link

        _publish(swap_root, "new1", "v1", link)
        check("First swap: content is live", _marker(link) == "v1")
        check("First swap: serve_dir is a symlink into a dated version tree",
              os.path.islink(link)
              and os.path.realpath(link)
                  in [os.path.realpath(p) for p, _ in s._version_dirs(link)])
        check("First swap: one version, and it is the live one",
              [r["live"] for r in s._site_versions(s.config.sites[0])] == [True])

        link_before = os.path.realpath(link)
        _publish(swap_root, "new2", "v2", link)
        check("Second swap: new content is live", _marker(link) == "v2")
        check("Second swap: the link moved to a new tree — no rename gap",
              os.path.islink(link) and os.path.realpath(link) != link_before)
        check("Second swap: the tree it replaced is kept",
              any(_marker(p) == "v1" for p, _ in s._version_dirs(link)))

        _publish(swap_root, "new3", "v3", link)
        # The whole point of the ring: v1 survives a second publish, where
        # the single-shot backup it replaced would have dropped it.
        markers = {_marker(p) for p, _ in s._version_dirs(link)}
        check("Third swap: the ring is a history, not a single-shot backup",
              markers == {"v1", "v2", "v3"})
        check("...ordered newest first",
              _marker(s._version_dirs(link)[0][0]) == "v3")

        rows = s._site_versions(s.config.sites[0])
        check("Versions report their name, time, size, and which is live",
              len(rows) == 3 and rows[0]["live"] and not rows[1]["live"]
              and all(r["files"] == 1 and r["bytes"] == 2 for r in rows)
              and all(isinstance(r["published"], int) for r in rows)
              and all("/" not in r["name"] for r in rows))

        # Restore through the core, then through the command.
        saved_chownop_r = s._chown_operator
        restore_chowns = []
        try:
            s._chown_operator = lambda path, strip_world=False: restore_chowns.append((path, strip_world))
            err = s._restore_site(s.config.sites[0], rows[2]["name"])
        finally:
            s._chown_operator = saved_chownop_r
        check("Restore to a named version serves it", err == "" and _marker(link) == "v1")
        check("...re-establishing operator ownership (a tree was extracted as root)",
              (os.path.realpath(link), True) in restore_chowns)
        check("...and the version rolled away is NOT consumed — the ring keeps it",
              {_marker(p) for p, _ in s._version_dirs(link)} == {"v1", "v2", "v3"})
        check("...so restoring back again is possible",
              s._restore_site(s.config.sites[0], rows[0]["name"]) == ""
              and _marker(link) == "v3")

        check("Restoring the live version is refused by name, not by silence",
              "already the live one" in
              s._restore_site(s.config.sites[0], s._version_dirs(link)[0][0].split("/")[-1]))
        check("A version name the ring does not hold is refused",
              "No kept version named" in s._restore_site(s.config.sites[0], "site.v1"))
        # The name crosses the wire from the page, so it must never be taken
        # as a path — only matched against what the ring actually holds.
        check("...and a traversal dressed as a version name is refused too",
              "No kept version named" in
              s._restore_site(s.config.sites[0], "../../../etc"))

        # No argument means the plain undo: the newest tree that is not live.
        s._restore_site(s.config.sites[0], None)
        check("Restore with no version named undoes the last publish", _marker(link) == "v2")

        saved_input = builtins.input
        try:
            builtins.input = lambda prompt="": "1"
            with contextlib.redirect_stdout(io.StringIO()) as rbuf:
                s.cmd_restore_site(s.config.sites[0])
        finally:
            builtins.input = saved_input
        check("The command lists the kept versions and takes a number",
              "1. " in rbuf.getvalue() and "(live)" not in rbuf.getvalue()
              and _marker(link) == "v3" and "restored" in rbuf.getvalue())

        saved_input = builtins.input
        try:
            builtins.input = lambda prompt="": ""
            with contextlib.redirect_stdout(io.StringIO()) as cbuf:
                s.cmd_restore_site(s.config.sites[0])
        finally:
            builtins.input = saved_input
        check("...and Enter cancels without touching the live content",
              "cancelled" in cbuf.getvalue() and _marker(link) == "v3")

        # Pruning: the ring has a depth, and the live tree is never swept.
        for n in range(4, 4 + s._KEEP_VERSIONS):
            _publish(swap_root, f"new{n}", f"v{n}", link)
        check("The ring prunes to its depth",
              len(s._version_dirs(link)) == s._KEEP_VERSIONS)
        check("...dropping the oldest, keeping the newest",
              _marker(s._version_dirs(link)[0][0]) == f"v{3 + s._KEEP_VERSIONS}")
        # The guarantee: a version that is LIVE is never pruned, however old
        # it is — an operator serving a year-old version is serving it, and
        # content being served is not garbage. Restore to the oldest, then
        # prune to a depth that would otherwise sweep it away.
        oldest = s._site_versions(s.config.sites[0])[-1]["name"]
        s._restore_site(s.config.sites[0], oldest)
        live_path, live_text = os.path.realpath(link), _marker(link)
        s._prune_versions(link, keep=1)
        kept = [os.path.realpath(p) for p, _ in s._version_dirs(link)]
        check("A live version is never pruned, however old it is",
              live_path in kept and os.path.isdir(live_path)
              and _marker(link) == live_text)
        # Two survive a keep=1 prune, and only two: the newest, which the
        # depth keeps, and the live one, which the rule keeps.
        check("...while everything past the depth beside it is gone",
              len(kept) == 2)

        # A missing new tree must fail loudly BEFORE anything moves: the old
        # design raised on its second rename; a symlink flip would happily
        # "succeed" dangling and serve nothing.
        ghost = os.path.join(swap_root, "never-created")
        live_before = _marker(link)
        raised_swap = False
        try:
            s._swap_site_content(ghost, link)
        except OSError:
            raised_swap = True
        check("A failed swap raises instead of passing as silence", raised_swap)
        check("...and the live content is untouched, not gone",
              _marker(link) == live_before)

        # Legacy conversion, shape one: a real directory (the pre-flip
        # layout) becomes a linked site on its first swap, its old content
        # adopted into the ring rather than lost.
        legacy = os.path.join(swap_root, "legacy-site")
        os.makedirs(legacy)
        with open(os.path.join(legacy, "marker.txt"), "w") as f:
            f.write("pre-flip")
        s.config.sites[0].serve_dir = legacy
        # Before any swap it is the oldest shape of all: a plain directory
        # that has never been through the ring — and still published content.
        plain_rows = s._site_versions(s.config.sites[0])
        check("A plain directory reports as published, not as nothing",
              len(plain_rows) == 1 and plain_rows[0]["live"]
              and plain_rows[0]["files"] == 1 and plain_rows[0]["bytes"] > 0)
        check("...and offers no restore, being already what is live",
              all(r["live"] for r in plain_rows))
        _publish(swap_root, "fresh", "post-flip", legacy)
        check("Legacy real directory converts: symlink, new content live",
              os.path.islink(legacy) and _marker(legacy) == "post-flip")
        check("...and its old content is a version, not a lost directory",
              any(_marker(p) == "pre-flip" for p, _ in s._version_dirs(legacy)))
        check("...restorable like any other", s._restore_site(s.config.sites[0]) == ""
              and _marker(legacy) == "pre-flip")

        # Legacy conversion, shape two: the two-slot .a/.b layout with its
        # single-shot .bak symlink. Both slots join the ring; the marker goes.
        two = os.path.join(swap_root, "two-slot")
        slot_a, slot_b = two + ".a", two + ".b"
        for slot, text in ((slot_a, "slot-a"), (slot_b, "slot-b")):
            os.makedirs(slot)
            with open(os.path.join(slot, "marker.txt"), "w") as f:
                f.write(text)
        os.symlink(slot_a, two)
        os.symlink(slot_b, two + ".bak")
        s.config.sites[0].serve_dir = two
        check("A two-slot site has no versions before its next publish",
              s._version_dirs(two) == [])
        # But it IS serving something, and saying otherwise told an operator
        # with a live, working site that nothing was published.
        two_rows = s._site_versions(s.config.sites[0])
        check("...yet its live tree is still reported as live and sized",
              len(two_rows) == 1 and two_rows[0]["live"]
              and two_rows[0]["files"] == 1)
        _publish(swap_root, "afterslots", "post-slots", two)
        check("Two-slot conversion: the new content is live",
              _marker(two) == "post-slots")
        check("...the idle slots are adopted into the ring",
              {_marker(p) for p, _ in s._version_dirs(two)}
              >= {"slot-a", "slot-b", "post-slots"})
        check("...and the single-shot .bak marker is gone",
              not os.path.lexists(two + ".bak"))

        # A failed flip hands the staged tree back: it was already renamed
        # into the ring, and without the hand-back a publish the caller
        # reports 'rejected' would leave never-published content for
        # restore-site to offer as the newest version.
        s.config.sites[0].serve_dir = link
        ring_before = [p for p, _ in s._version_dirs(link)]
        live_before = os.path.realpath(link)
        stage = os.path.join(swap_root, "doomed")
        os.makedirs(stage)
        with open(os.path.join(stage, "marker.txt"), "w") as f:
            f.write("never-live")
        real_replace = os.replace
        def _failing_replace(a, b, *args, **kw):
            if os.path.abspath(b) == os.path.abspath(link):
                raise OSError(28, "No space left on device")
            return real_replace(a, b, *args, **kw)
        os.replace = _failing_replace
        try:
            flip_raised = False
            try:
                s._swap_site_content(stage, link)
            except OSError:
                flip_raised = True
        finally:
            os.replace = real_replace
        check("A failed flip raises instead of reporting success", flip_raised)
        check("...leaves the old content live",
              os.path.realpath(link) == live_before
              and _marker(link) != "never-live")
        check("...and hands the staged tree back — the ring gained nothing",
              [p for p, _ in s._version_dirs(link)] == ring_before
              and os.path.isdir(stage) and _marker(stage) == "never-live")

        # Legacy conversion where the old tree's mtime sits in the new
        # publish's own second (or later — a skewed clock): the kept tree's
        # stamp is clamped strictly below the new one's, or the ring would
        # read the OLD content as the newest version.
        same = os.path.join(swap_root, "same-second")
        os.makedirs(same)
        with open(os.path.join(same, "marker.txt"), "w") as f:
            f.write("old-now")
        ahead = time.time() + 5
        os.utime(same, (ahead, ahead))
        s.config.sites[0].serve_dir = same
        _publish(swap_root, "new-now", "new-now", same)
        vd_same = s._version_dirs(same)
        check("Same-second legacy conversion keeps the new tree newest in the ring",
              len(vd_same) == 2
              and os.path.realpath(same) == os.path.realpath(vd_same[0][0])
              and _marker(vd_same[1][0]) == "old-now")
    finally:
        s.config.sites[0].serve_dir = saved_serve_dir
        shutil.rmtree(swap_root, ignore_errors=True)

    section("remove-site reclaims the trees behind a trailing-slash serve_dir")

    # The derived-tree helpers all rstrip serve_dir; the removal's own base
    # must too, or a hand-edited 'site/' aims the .bak/.new/base deletions
    # at names that do not exist and leaves the trees behind.
    ts_base = os.path.join(s.BASE_DIR, "slash-probe")
    os.makedirs(ts_base)
    os.makedirs(ts_base + ".bak")
    os.makedirs(ts_base + ".new")
    probe_site = s.Site()
    probe_site.serve_dir = "slash-probe/"          # the hand-edited shape
    s.config.sites.append(probe_site)
    saved_run_ts, saved_act_ts = s._server_running, s._service_is_active
    s._server_running = s._service_is_active = lambda: False
    try:
        ts_err  = s._remove_site(len(s.config.sites) - 1)
        # Judged before the belt-cleanup below, which would otherwise make
        # these checks pass vacuously.
        ts_gone = (not os.path.exists(ts_base),
                   not os.path.exists(ts_base + ".bak"),
                   not os.path.exists(ts_base + ".new"))
    finally:
        s._server_running, s._service_is_active = saved_run_ts, saved_act_ts
        shutil.rmtree(ts_base, ignore_errors=True)      # belt, if a check fails
        shutil.rmtree(ts_base + ".bak", ignore_errors=True)
        shutil.rmtree(ts_base + ".new", ignore_errors=True)
    check("The removal deletes the base tree despite the trailing slash",
          ts_err == "" and ts_gone[0])
    check("...and its .bak and .new siblings with it",
          ts_gone[1] and ts_gone[2])

    section("Landing a bundle — the tail every content channel shares")

    # These checks used to drive the pull channel's fetch-and-verify pipeline.
    # The channel is retired; what it shared with the page — extraction into
    # staging, ownership repair before the flip, the swap under one lock — is
    # what actually guards a publish, so the coverage moves onto _land_bundle
    # directly. The door in front of it (upload size cap, tunnel
    # authentication) is checked in the page's own section.
    bundle_bytes = make_tar_gz([("index.html", "published content")])

    saved_serve_dir2 = s.config.sites[0].serve_dir
    swap_root2 = tempfile.mkdtemp()
    try:
        s.config.sites[0].serve_dir = os.path.join(swap_root2, "site")

        # The staged tree was extracted by this process — root, when the
        # command elevated — so landing must re-establish operator ownership
        # itself, with world bits stripped, BEFORE the tree goes live.
        saved_chownop = s._chown_operator
        chown_calls = []
        s._chown_operator = lambda path, strip_world=False: chown_calls.append((path, strip_world))
        try:
            result = s._land_bundle(s.config.sites[0], bundle_bytes, "test")
        finally:
            s._chown_operator = saved_chownop
        check("A landed bundle is live",
              open(os.path.join(s.config.sites[0].serve_dir, "index.html")).read() == "published content")
        check("Returns 'published'", result == "published")
        live2 = s._resolve(s.config.sites[0].serve_dir).rstrip(os.sep)
        check("Landing re-establishes operator ownership BEFORE the tree goes live",
              (live2 + ".new", True) in chown_calls)
        check("...and leaves the trees it replaces alone — they were live a moment ago",
              not any(p != live2 + ".new" for p, _ in chown_calls))

        # A bundle the extractor refuses must change nothing: no ownership
        # call, no staging left behind, the live tree untouched.
        chown_calls.clear()
        s._chown_operator = lambda path, strip_world=False: chown_calls.append((path, strip_world))
        logging.disable(logging.CRITICAL)
        try:
            result = s._land_bundle(s.config.sites[0], b"not a tar.gz at all", "test")
        finally:
            s._chown_operator = saved_chownop
            logging.disable(logging.NOTSET)
        check("A rejected bundle re-establishes nothing (nothing changed)",
              chown_calls == [])
        check("...leaves the live content exactly as it was",
              open(os.path.join(s.config.sites[0].serve_dir, "index.html")).read() == "published content")
        check("...returns 'rejected'", result == "rejected")
        check("...and leaves no staging tree behind",
              not os.path.exists(live2 + ".new"))

        section("Publish serialization")

        # One lock across every content mutation: two sessions landing into
        # the same site must not overlap inside the swap.
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
            threads = [threading.Thread(target=s._land_bundle,
                                        args=(s.config.sites[0], bundle_bytes, "test"))
                       for _ in range(3)]
            for th in threads:
                th.start()
            for th in threads:
                th.join()
            check("Concurrent publishes never overlap inside the swap (max concurrent == 1)",
                  max(max_concurrent) == 1)
        finally:
            s._swap_site_content = saved_swap

        section("publish — the terminal half of the pair")

        # `publish [n] <folder>` tars a folder under the same cap, hidden
        # paths excluded by the serving rule, and hands it to the identical
        # _land_bundle — the core never knows which door called it.
        pubsrc = tempfile.mkdtemp(dir=swap_root2)
        with open(os.path.join(pubsrc, "index.html"), "w") as f:
            f.write("from the terminal")
        os.makedirs(os.path.join(pubsrc, ".git"), exist_ok=True)
        with open(os.path.join(pubsrc, ".git", "secret"), "w") as f:
            f.write("history")
        with open(os.path.join(pubsrc, ".env"), "w") as f:
            f.write("secret")
        with contextlib.redirect_stdout(io.StringIO()) as pbuf:
            s.cmd_publish([pubsrc])
        check("publish lands a folder as the site's live content",
              "Published to" in pbuf.getvalue()
              and open(os.path.join(s.config.sites[0].serve_dir,
                                    "index.html")).read() == "from the terminal")
        check("...hidden paths are not published, by the serving rule",
              not os.path.exists(os.path.join(s.config.sites[0].serve_dir,
                                              ".git"))
              and not os.path.exists(os.path.join(s.config.sites[0].serve_dir,
                                                  ".env")))
        check("...and the content it replaced is in the ring",
              any(not r["live"] for r in
                  s._site_versions(s.config.sites[0])))
        with contextlib.redirect_stdout(io.StringIO()) as pbuf:
            s.cmd_publish([os.path.join(pubsrc, "index.html")])
        check("...a path that is not a folder is refused with a sentence",
              "not a folder" in pbuf.getvalue())
        empty_src = tempfile.mkdtemp(dir=swap_root2)
        with contextlib.redirect_stdout(io.StringIO()) as pbuf:
            s.cmd_publish([empty_src])
        check("...an empty folder is refused, not published as a blank site",
              "no publishable files" in pbuf.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as pbuf:
            s.cmd_publish(["3", pubsrc])
        check("...and a bad site index is the [n] convention's own refusal",
              "No site 3" in pbuf.getvalue())
        # The one guard on the source: Servette's own config and keys never
        # go out through the publish door, however root the caller is.
        saved_exposes = s._serve_dir_exposes_secrets
        s._serve_dir_exposes_secrets = lambda path: True
        try:
            with contextlib.redirect_stdout(io.StringIO()) as pbuf:
                s.cmd_publish([pubsrc])
        finally:
            s._serve_dir_exposes_secrets = saved_exposes
        check("...a folder holding Servette's secrets is refused",
              "publishing it would publish them" in pbuf.getvalue())
        check("...the command is offered, and it elevates like restore-site",
              any(c.startswith("publish") for c, _ in s._COMMANDS)
              and "publish" in s._ROOT_COMMANDS)
        # The door's ceiling counts UNCOMPRESSED bytes — the quantity
        # _extract_bundle enforces and the page's builder sums. A
        # compressed count waved well-compressing folders through, only
        # for the core to refuse them with a log line instead of the
        # door's sentence.
        big_src = tempfile.mkdtemp(dir=swap_root2)
        with open(os.path.join(big_src, "a.html"), "w") as f:
            f.write("x" * 2_000_000)
        _blob2, _prob2 = s._tar_folder(big_src, cap=1_000_000)
        check("publish's cap counts uncompressed bytes, like every other door",
              _blob2 is None and "too large" in _prob2)
        # 'publish 2' alone reads as an index missing its folder — the miss
        # says so instead of calling 2 a folder and stopping.
        with contextlib.redirect_stdout(io.StringIO()) as pbuf:
            s.cmd_publish(["7"])
        check("...and a bare digit miss explains the two-argument form",
              "publish 7 <folder>" in pbuf.getvalue())

        section("The retired pull channel leaves nothing behind")

        # A removal is only done when the names are gone from the program, not
        # merely unreachable from a menu.
        gone = ("cmd_pull", "_check_for_content_update", "_publish_sig_url",
                "_config_publish")
        check("The channel's functions are gone from the program",
              not any(hasattr(s, n) for n in gone))
        check("...its two settings are gone from a Site",
              not hasattr(s.Site(), "publish_url")
              and not hasattr(s.Site(), "publish_key"))
        check("...the shell offers no 'pull'",
              "pull" not in [c.split()[0] for c, _ in s._COMMANDS])
        check("...the config sub-shell offers no 'channel' or 'publish' verb",
              not any(c.split()[0] in ("channel", "publish")
                      for c, _ in s._CONFIG_COMMANDS))
        # Signature verification was this channel's trust mechanism and had no
        # other caller: nothing in the program should still reach for Ed25519.
        check("...and no Ed25519 verification is left in the program",
              "Ed25519" not in io.open(os.path.abspath(s.__file__),
                                       encoding="utf-8").read())
    finally:
        s.config.sites[0].serve_dir = saved_serve_dir2
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

    section("Per-IP connection cap")

    # Drive process_request directly with thread start patched to a no-op, so each
    # accepted connection stays "open" — its global slot and per-IP count held.
    import socketserver as _ss
    saved_pr = _ss.ThreadingMixIn.process_request
    saved_pt = _ss.ThreadingMixIn.process_request_thread
    percap   = s._CappedThreadingHTTPServer(("127.0.0.1", 0), s._RedirectHandler,
                                            max_per_ip=3)
    shed     = {"n": 0}
    percap.shutdown_request = lambda req: shed.__setitem__("n", shed["n"] + 1)
    try:
        _ss.ThreadingMixIn.process_request        = lambda self, req, addr: None
        _ss.ThreadingMixIn.process_request_thread = lambda self, req, addr: None

        for i in range(3):
            percap.process_request(object(), ("10.0.0.1", 1000 + i))
        check("Up to the cap, connections from one IP are accepted", shed["n"] == 0)

        percap.process_request(object(), ("10.0.0.1", 1099))
        check("Past the cap, the same IP is shed", shed["n"] == 1)

        percap.process_request(object(), ("::ffff:10.0.0.1", 1100))
        check("IPv6-mapped spelling shares the bucket and is shed", shed["n"] == 2)

        percap.process_request(object(), ("10.0.0.2", 2000))
        check("A second IP is unaffected", shed["n"] == 2)

        # A finished connection frees its per-IP count: the source is admitted again.
        percap.process_request_thread(object(), ("10.0.0.1", 1000))
        percap.process_request(object(), ("10.0.0.1", 1101))
        check("After one connection closes, the source is admitted again", shed["n"] == 2)

        # With the global pool exhausted, the per-IP count must not leak.
        nopool = s._CappedThreadingHTTPServer(("127.0.0.1", 0), s._RedirectHandler,
                                              max_connections=0, max_per_ip=3)
        nopool.shutdown_request = lambda req: None
        try:
            nopool.process_request(object(), ("10.0.0.7", 1))
            check("Global-capacity shed leaves no per-IP count behind",
                  nopool._ip_counts == {})
        finally:
            nopool.server_close()

        # Thread-start failure must reclaim the per-IP count (as it does the slot).
        def _boom(self, req, addr):
            raise RuntimeError("cannot start thread")
        _ss.ThreadingMixIn.process_request = _boom
        try:
            percap.process_request(object(), ("10.0.0.9", 1))
        except RuntimeError:
            pass
        check("Per-IP count reclaimed after failed thread start",
              "10.0.0.9" not in percap._ip_counts)
        _ss.ThreadingMixIn.process_request = lambda self, req, addr: None

        # Behind a declared trusted_proxy every connection shares the proxy's
        # address, so the cap is not enforced — but counting still runs.
        saved_tp = s.config.trusted_proxy
        s.config.trusted_proxy = "192.0.2.1"
        try:
            before = shed["n"]
            for i in range(5):   # well past max_per_ip=3
                percap.process_request(object(), ("10.0.0.3", 3000 + i))
            check("With trusted_proxy set, the per-IP cap is not enforced",
                  shed["n"] == before)
            check("Connections are still counted while unenforced",
                  percap._ip_counts.get("10.0.0.3") == 5)
        finally:
            s.config.trusted_proxy = saved_tp
    finally:
        _ss.ThreadingMixIn.process_request        = saved_pr
        _ss.ThreadingMixIn.process_request_thread = saved_pt
        percap.server_close()

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

    section("Cache recency — LRU in fact, not only in name")

    # A hit refreshes recency: without it the OrderedDict evicts by
    # insertion age and a hot index.html dies as readily as a file served
    # once — FIFO wearing LRU's name.
    lruA = os.path.join(serve_dir, "lru-a.html")
    lruB = os.path.join(serve_dir, "lru-b.html")
    for p, body in ((lruA, "aaa"), (lruB, "bbb")):
        with open(p, "w") as f:
            f.write(body)
    try:
        s._get_cached_file(lruA)
        s._get_cached_file(lruB)
        s._get_cached_file(lruA)   # the hit that must refresh recency
        with s._file_cache_lock:
            order = [p for p in s._file_cache if p in (lruA, lruB)]
        check("A cache hit refreshes recency, so eviction is truly LRU",
              order == [lruB, lruA])
    finally:
        for p in (lruA, lruB):
            os.unlink(p)
            with s._file_cache_lock:
                s._file_cache.pop(p, None)

    section("Cache invalidation — the publish shape")

    # A pull swaps in tar-extracted files whose mtimes come from the archive at
    # whole-second granularity: two bundles of a file edited and repacked
    # within the same second (or built by pinned-timestamp tooling) carry the
    # SAME mtime with different bytes. Keyed on mtime alone, the cache served
    # the old bytes indefinitely. The key is now (mtime_ns, size, inode) — a
    # swap always lands a fresh inode, so it can never impersonate the entry.
    twin = os.path.join(serve_dir, "twin.html")
    with open(twin, "w") as f:
        f.write("OLD-CONTENT!")
    os.utime(twin, (1000000, 1000000))
    raw_old, _, _ = s._get_cached_file(twin)
    check("First read is cached", raw_old == b"OLD-CONTENT!" and twin in s._file_cache)
    staged_twin = twin + ".staged"
    with open(staged_twin, "w") as f:
        f.write("NEW-CONTENT!")                        # same length, same mtime
    os.utime(staged_twin, (1000000, 1000000))
    os.replace(staged_twin, twin)                      # the swap: a new inode
    raw_new, _, etag_new = s._get_cached_file(twin)
    check("Same-mtime same-size replacement is still detected",
          raw_new == b"NEW-CONTENT!")
    os.remove(twin)
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

    section("Redirects (#117) — a setting, never a file in the site")

    class _NoFollow(urllib.request.HTTPRedirectHandler):
        """urlopen follows a 301 by default; the 301 IS the thing under test."""
        def redirect_request(self, *_a, **_kw):
            return None

    _nofollow = urllib.request.build_opener(
        _NoFollow, urllib.request.HTTPSHandler(context=SSL_CTX))

    def hop(path):
        """(status, Location) for one request, without following it."""
        try:
            r = _nofollow.open(BASE_URL + path)
            return r.getcode(), r.headers.get("Location")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Location")

    saved_redirects = s.config.sites[0].redirects
    saved_redirects_temp = s.config.sites[0].redirects_temp
    try:
        s.config.sites[0].redirects = s._clean_redirects({
            "/old": "/index.html",
            "/blog/": "/writing",
            "/gone": "https://example.com/moved",
            "/my%20page": "/index.html",
        })

        st, loc = hop("/old")
        check("A redirected path answers 301 with the new location",
              st == 301 and loc == "/index.html")
        # A 301 is cacheable by default and browsers hold it hard — which is
        # what makes a wrong one frightening. Explicit no-cache overrides
        # that default, so the browser re-asks and a corrected rule takes
        # effect. The header is recoverability; permanence-vs-temporary is
        # the separate, ruled per-rule choice tested below.
        try:
            _r = _nofollow.open(BASE_URL + "/old")
            _cache = _r.headers.get("Cache-Control")
        except urllib.error.HTTPError as _e:
            _cache = _e.headers.get("Cache-Control")
        check("...and is sent no-cache, so a wrong redirect is recoverable",
              _cache == "no-cache")
        check("...and one rule covers both /old and /old/",
              hop("/old/") == (301, "/index.html"))
        check("...a trailing slash in the rule is normalised the same way",
              hop("/blog") == (301, "/writing") and hop("/blog/") == (301, "/writing"))
        check("...an absolute http(s) target is sent as written",
              hop("/gone") == (301, "https://example.com/moved"))
        # The lookup matches the DECODED path, the same one file resolution
        # sees — so a source with a space fires when the browser sends it
        # percent-encoded, and a rule cannot be skipped by encoding a letter.
        check("...a rule fires for the percent-encoded form of its source",
              hop("/old/") == (301, "/index.html")
              and hop("/%6fld") == (301, "/index.html"))
        check("...and a rule WRITTEN percent-encoded fires for its wire form",
              hop("/my%20page") == (301, "/index.html"))
        # A campaign link points at the OLD path with its query attached;
        # dropping it would silently break every one of them.
        check("...and the query string rides along",
              hop("/old?utm=x") == (301, "/index.html?utm=x"))
        check("A path with no rule is served, not redirected",
              hop("/index.html")[0] == 200)
        check("A missing path with no rule is still a 404",
              hop("/nope-not-here")[0] == 404)

        # The ruled per-rule choice (DECISIONS.md): a rule is permanent (301,
        # the default — the old path's standing moves to the new address) or
        # temporary (302 — the old path stays the real one), held in a
        # sibling table so one validator covers both.
        s.config.sites[0].redirects_temp = s._clean_redirects(
            {"/away": "/index.html"})
        st, loc = hop("/away")
        check("A temporary rule answers 302 with the new location",
              st == 302 and loc == "/index.html")
        try:
            _r = _nofollow.open(BASE_URL + "/away")
            _tcache = _r.headers.get("Cache-Control")
        except urllib.error.HTTPError as _e:
            _tcache = _e.headers.get("Cache-Control")
        check("...and is sent no-cache, exactly like the permanent one",
              _tcache == "no-cache")

        # The invariant this feature could have broken: a redirect is a dict
        # lookup on the loaded config, never a read of anything on disk.
        redirect_src = inspect.getsource(s._handle_request)
        check("The lookup is a dict read, and runs before any path resolution",
              "site.redirects.get(" in redirect_src
              and redirect_src.index("site.redirects.get(")
                  < redirect_src.index("_resolve_request_path("))

        # Validation, at the one door both surfaces use.
        check("A javascript: target is refused — a redirect is an open door",
              s._clean_redirects({"/x": "javascript:alert(1)"}) == {})
        check("A data: target is refused too",
              s._clean_redirects({"/x": "data:text/html,<script>"}) == {})
        check("A CR or LF in a target is refused — that is response splitting",
              s._clean_redirects({"/x": "/y\r\nX-Evil: 1"}) == {})
        # A non-ASCII target would be dropped byte-by-byte by the ASCII-only
        # Location encoding at serve time, sending the visitor to a mangled
        # path. Refused at the one validating door, so `set` and the page
        # refuse it too; the operator percent-encodes it themselves.
        check("A non-ASCII character in a target is refused, not silently mangled",
              s._clean_redirects({"/x": "/café"}) == {}
              and s._clean_redirects({"/x": "/caf%C3%A9"}) == {"/x": "/caf%C3%A9"})
        check("...and one in a source is refused the same way",
              s._clean_redirects({"/café": "/x"}) == {})
        # Sources are stored in ONE canonical percent-encoded spelling, the
        # same one the lookup computes from the wire: a rule written
        # /my%20page (or with a literal space, or lowercase hex) is one
        # rule, and /caf%C3%A9 is how an ASCII-only table spells a
        # non-ASCII source.
        check("Every spelling of a source canonicalizes to one stored key",
              s._clean_redirects({"/my%20page": "/x"}) == {"/my%20page": "/x"}
              and s._clean_redirects({"/my page": "/x"}) == {"/my%20page": "/x"}
              and s._clean_redirects({"/caf%c3%a9": "/x"}) == {"/caf%C3%A9": "/x"})
        # The canonical form is a fixed point. Bare decoding was not: a
        # stored space re-decoded on the next load, a %2520 drifted one
        # escape per save/load cycle, the ring check misread its own
        # shrinking output as a ring, and /a%0d planted a literal CR in
        # the TOML file — unparseable on the next restart.
        once = s._clean_redirects({"/my%20page": "/x", "/x%2520y": "/q",
                                   "/caf%C3%A9": "/z"})
        check("The table is a fixed point of its own validator",
              s._clean_redirects(once) == once)
        cr = s._clean_redirects({"/a%0d": "/x"})
        check("An encoded control character stays encoded — no raw CR ever "
              "reaches the config file",
              cr == {"/a%0D": "/x"}
              and not any(ord(c) < 0x20 for k in cr for c in k))
        check("...and one buried inside a source, where strip() cannot reach it",
              s._clean_redirects({"/x\ny": "/z"}) == {})
        check("...while a trailing newline is simply stripped away",
              s._clean_redirects({"/x\n": "/y"}) == {"/x": "/y"})
        check("A source that is not a site path is refused",
              s._clean_redirects({"old": "/new"}) == {}
              and s._clean_redirects({"https://elsewhere/x": "/new"}) == {})
        check("A redirect pointing at itself is refused",
              s._clean_redirects({"/loop": "/loop/"}) == {})
        # A ring of rules is the self-loop one hop longer: the server serves
        # one hop per request, so a ring is a browser bouncing to its cap.
        check("A ring of redirects is refused whole, like the self-loop it is",
              s._clean_redirects({"/a": "/b", "/b": "/a"}) == {})
        # The walk follows targets the way the browser will — decoded, query
        # dropped — or a ring spelled /%62 or /b?x=1 walks free while the
        # visitor bounces.
        check("...a ring spelled with a percent-escape is still a ring",
              s._clean_redirects({"/a": "/%62", "/b": "/a"}) == {}
              and s._clean_redirects({"/x": "/%78"}) == {})
        check("...and one whose target carries a query string",
              s._clean_redirects({"/a": "/b?x=1", "/b": "/a"}) == {})
        check("...however many hops the ring takes",
              s._clean_redirects({"/a": "/b", "/b": "/c", "/c": "/a"}) == {})
        check("...and a rule that leads into a ring goes with it",
              s._clean_redirects({"/x": "/a", "/a": "/b", "/b": "/a"}) == {})
        check("...while a chain that ends somewhere real is kept whole",
              s._clean_redirects({"/a": "/b", "/b": "/c"})
              == {"/a": "/b", "/b": "/c"})
        check("A non-table redirects value is ignored, not fatal",
              s._clean_redirects("nonsense") == {})
        # Canonicalization percent-expands, so a raw source under the cap
        # can canonicalize past it; judged on the canonical form, so the
        # validator's output is a fixed point of the validator.
        check("A source whose canonical spelling exceeds the cap is refused",
              s._clean_redirects({"/" + "a " * 999: "/x"}) == {})

        # The two tables load and validate together: one source lives in one
        # table, a ring hopping between them is still a ring, and what the
        # config writes it reads back unchanged.
        _rt = s.Site({"redirects": {"/p": "/q"},
                      "redirects_temporary": {"/t": "/u"}})
        check("A site loads both redirect tables",
              _rt.redirects == {"/p": "/q"}
              and _rt.redirects_temp == {"/t": "/u"})
        import tomllib as _tomllib
        _back = s.Site(_tomllib.loads("[[site]]\n"
                                      + s._redirect_toml(_rt))["site"][0])
        check("...and both survive a save/load round trip",
              _back.redirects == _rt.redirects
              and _back.redirects_temp == _rt.redirects_temp)
        # The load door is strict (the load-door principle): a rule the
        # write doors would refuse does not load minus the rule — it
        # refuses the file, with the sentence naming what is wrong.
        def _site_refuses(data, word):
            try:
                s.Site(data)
            except s._ConfigInvalid as e:
                return word in str(e)
            return False
        check("A source written in both tables refuses the file",
              _site_refuses({"redirects": {"/x": "/y"},
                             "redirects_temporary": {"/x": "/z"}},
                            "both tables"))
        check("A ring that hops between the tables refuses the file",
              _site_refuses({"redirects": {"/a": "/b"},
                             "redirects_temporary": {"/b": "/a"}}, "ring"))
        check("A bad rule in a hand-edited table refuses the file, not the rule",
              _site_refuses({"redirects": {"/x": "javascript:alert(1)"}},
                            "not a path")
              and _site_refuses({"redirects": {"/café": "/x"}}, "non-ASCII")
              and _site_refuses({"redirects": "nonsense"}, "not a table"))
        check("...while the write doors' filter still drops and reports",
              s._clean_redirects({"/x": "javascript:alert(1)"}) == {})
        check("A hand-edited domain is judged by the same syntax door",
              _site_refuses({"domain": "https://example.com"}, "no scheme"))
        check("...and active must be a real TOML boolean",
              _site_refuses({"active": "yes"}, "true or false"))
        check("...and a non-text field is named, not crashed on",
              _site_refuses({"serve_dir": 5}, "must be text"))
        check("The table is capped",
              len(s._clean_redirects({f"/p{n}": "/q" for n in range(400)}))
              == s._MAX_REDIRECTS)
        check("...and one bad entry does not discard the good ones",
              s._clean_redirects({"/good": "/fine", "/bad": "javascript:x"})
              == {"/good": "/fine"})

        # The terminal half of the pair: `set` speaks in scalars, so a pair
        # is one token, and removal is the pair with nothing after the comma.
        probe = s.Site()
        check("set adds a redirect", s._set_site_value(probe, "redirect", "/a,/b") == ""
              and probe.redirects == {"/a": "/b"})
        check("...replaces one", s._set_site_value(probe, "redirect", "/a,/c") == ""
              and probe.redirects == {"/a": "/c"})
        check("...removes one", s._set_site_value(probe, "redirect", "/a,") == ""
              and probe.redirects == {})
        check("...reports a removal that removes nothing",
              "no redirect from" in s._set_site_value(probe, "redirect", "/a,"))
        check("...refuses a token that is not a pair",
              "a pair" in s._set_site_value(probe, "redirect", "/a"))
        check("...and refuses what the config load would refuse",
              s._set_site_value(probe, "redirect", "/a,javascript:x") != "")
        # Each pair is valid alone; only the table shows the ring. Refused
        # at set time, not silently dropped at the next config load.
        check("...and refuses the pair that closes a ring with a saved rule",
              s._set_site_value(probe, "redirect", "/r1,/r2") == ""
              and "closes a ring" in s._set_site_value(probe, "redirect", "/r2,/r1")
              and probe.redirects == {"/r1": "/r2"})
        # A percent-spelled source through the set door: accepted, no false
        # ring from re-validating its own stored form, removable by its
        # stored key or any spelling of it, and later rules unaffected.
        check("...accepts a percent-spelled source and stays self-consistent",
              s._set_site_value(probe, "redirect", "/caf%C3%A9,/x") == ""
              and s._set_site_value(probe, "redirect", "/plain,/y") == ""
              and s._set_site_value(probe, "redirect", "/caf%c3%a9,") == ""
              and "/caf%C3%A9" not in probe.redirects
              and s._set_site_value(probe, "redirect", "/plain,") == "")
        # At the cap, the refusal names the cap — the load validator's
        # truncation shrinks the table too, and that is not a ring.
        full_probe = s.Site()
        full_probe.redirects = s._clean_redirects(
            {f"/p{n}": "/q" for n in range(s._MAX_REDIRECTS)})
        check("...and a table at the cap refuses with the cap's own sentence",
              "full" in s._set_site_value(full_probe, "redirect", "/p-extra,/q")
              and len(full_probe.redirects) == s._MAX_REDIRECTS)
        # The third token is the ruled per-rule choice: nothing means
        # permanent, ',temporary' is the 302, and re-adding a source moves
        # it between the tables rather than doubling it.
        tprobe = s.Site()
        check("set's third token lands a rule in the temporary table",
              s._set_site_value(tprobe, "redirect", "/t1,/t2,temporary") == ""
              and tprobe.redirects_temp == {"/t1": "/t2"}
              and tprobe.redirects == {})
        check("...an explicit ',permanent' is the default said out loud",
              s._set_site_value(tprobe, "redirect", "/t3,/t4,permanent") == ""
              and tprobe.redirects == {"/t3": "/t4"})
        check("...re-adding a source moves it between the tables",
              s._set_site_value(tprobe, "redirect", "/t1,/t2") == ""
              and tprobe.redirects.get("/t1") == "/t2"
              and "/t1" not in tprobe.redirects_temp)
        check("...removal reaches whichever table holds the rule",
              s._set_site_value(tprobe, "redirect", "/t5,/t6,temporary") == ""
              and s._set_site_value(tprobe, "redirect", "/t5,") == ""
              and tprobe.redirects_temp == {})
        check("...a ring closed across the two tables is refused",
              "closes a ring"
              in s._set_site_value(tprobe, "redirect", "/t4,/t3,temporary"))
        # The cap covers the tables' sum, or 200 permanent plus 200
        # temporary would sail past what the load validator keeps.
        check("...and the cap counts both tables together",
              "full" in s._set_site_value(full_probe, "redirect",
                                          "/p-extra,/q,temporary"))
        # ',,temporary' is not a flag on an empty pair — the empty target is
        # judged as written and refused, never misread as a removal.
        check("...and a flag on an empty target is refused, not a removal",
              s._set_site_value(tprobe, "redirect", "/t1,,temporary") != ""
              and tprobe.redirects.get("/t1") == "/t2")

        # Removing through _apply_settings must validate against the site's
        # real table, not against a blank scratch object.
        live_site = s.config.sites[0]
        saved_live = dict(live_site.redirects)
        try:
            check("A removal through the shared settings path sees the real table",
                  s._apply_settings(live_site, [("redirect", "/old,")]) == ""
                  and "/old" not in live_site.redirects)
        finally:
            live_site.redirects = saved_live
            s.config.save()
    finally:
        s.config.sites[0].redirects = saved_redirects
        s.config.sites[0].redirects_temp = saved_redirects_temp
        s.config.save()

    section("Fields refuse what they cannot save")

    # The ruled principle: no wrong answer is saved — every field states
    # what a valid entry looks like (or what invalidates one) and refuses
    # the rest, at every door, rather than repairing it quietly or letting
    # it surface as a failure far from the typo.
    import builtins
    _scratch = type("S", (), {})()
    check("The email door refuses what could never be a mailbox",
          s._set_host_value(_scratch, "email", "not-an-email") != ""
          and s._set_host_value(_scratch, "email", "two@ats@example.com") != ""
          and s._set_host_value(_scratch, "email", "a b@example.com") != "")
    check("...naming the half after the @ when that is the wrong half",
          "after the @" in s._set_host_value(_scratch, "email", "you@-bad-.com"))
    check("...and accepts a mailbox, or empty to clear",
          s._set_host_value(_scratch, "email", "you@example.com") == ""
          and _scratch.email == "you@example.com"
          and s._set_host_value(_scratch, "email", "") == ""
          and _scratch.email == "")
    # The write door refuses what the load door refuses — a username with
    # a control character saved today would brick the next restart.
    check("A control character in a username is refused at the write door",
          "control characters" in s._set_site_value(s.Site(), "username",
                                                    "a\tb"))

    saved_input_v = builtins.input

    # The certificate prompt judges domain syntax locally — the same
    # sentence as the page's name door — instead of handing garbage to the
    # authority for a network round trip that could only ever fail.
    _issuance_calls = []
    _saved_obtain = s._obtain_trusted_cert
    _saved_domain = s.config.sites[0].domain
    try:
        s._obtain_trusted_cert = lambda *a, **k: _issuance_calls.append(a)
        builtins.input = lambda prompt="": "https://example.com"
        with contextlib.redirect_stdout(io.StringIO()) as _certbuf:
            s._config_cert(s.config.sites[0])
    finally:
        s._obtain_trusted_cert = _saved_obtain
        builtins.input = saved_input_v
    check("The certificate prompt judges domain syntax before any network",
          "no scheme" in _certbuf.getvalue() and not _issuance_calls
          and s.config.sites[0].domain == _saved_domain)

    # The swap prompt refuses out-of-bounds sizes with the page's own
    # sentence — it used to round 10 up to a 64 MB file silently, a wrong
    # answer repaired instead of refused.
    if not s._IS_MACOS:
        _swap_calls = []
        _saved_apply, _saved_offer = s._apply_swapfile, s._swap_offer
        try:
            s._apply_swapfile = lambda mb: _swap_calls.append(mb) or ""
            s._swap_offer = lambda *a: ("no swap configured", "skip")
            builtins.input = lambda prompt="": "10"
            with contextlib.redirect_stdout(io.StringIO()) as _swapbuf:
                s._ensure_swap()
        finally:
            s._apply_swapfile, s._swap_offer = _saved_apply, _saved_offer
            builtins.input = saved_input_v
        check("The swap prompt refuses a size below 64 MB instead of rounding it up",
              "64-65536" in _swapbuf.getvalue() and not _swap_calls)

    section("The opt-in balancer health check")

    # Terminal-only by ruling: a host setting, off by default, answering an
    # unauthenticated 204 to any Host — before the limiter, which must not
    # starve a probe into a false dead — and absent from the admin page.
    check("The health path door refuses what could shadow or mangle",
          s._set_host_value(_scratch, "health_path", "healthz") != ""
          and s._set_host_value(_scratch, "health_path", "/café") != ""
          and "reserved" in s._set_host_value(_scratch, "health_path",
                                              "/.well-known/x"))
    check("...and accepts a plain path, or empty to turn the check off",
          s._set_host_value(_scratch, "health_path", "/healthz") == ""
          and _scratch.health_path == "/healthz"
          and s._set_host_value(_scratch, "health_path", "") == ""
          and _scratch.health_path == "")
    check("With no health path configured, the path is an ordinary miss",
          req("GET", path="/lb-health").status == 404)
    s.config.health_path = "/lb-health"
    try:
        _hr = req("GET", path="/lb-health")
        check("A configured health path answers 204 with no body",
              _hr.status == 204 and _hr.body == b"")
        check("...to HEAD as well, and with the query string ignored",
              req("HEAD", path="/lb-health").status == 204
              and req("GET", path="/lb-health?probe=1").status == 204)
        _core_src = inspect.getsource(s._handle_request)
        check("...answered before the limiter and before site selection",
              _core_src.index("config.health_path")
              < _core_src.index("_rate_limit_exceeded")
              and _core_src.index("config.health_path")
              < _core_src.index("_select_site("))
        check("...and no neighbouring path borrows the answer",
              req("GET", path="/lb-health2").status == 404)
        check("...while the page never renders the setting",
              "health_path" not in s._UI_ADMIN_PAGE)
    finally:
        s.config.health_path = ""

    section("404 and custom 404.html")

    check("Non-existent path returns 404",
          req("GET", path="/nonexistent.html").status == 404)

    # With no 404.html of the operator's own, a miss is answered by the
    # embedded error page rather than a bare line of text: every server needs an
    # error page, and this one also reports that the server is up and what it is
    # actually sending. The status stays 404 — the path really is not there —
    # and the body is HTML so the page can run.
    resp = req("GET", path="/nonexistent.html")
    check("Default 404 body is the embedded error page",
          resp.status == 404 and b"notfound-path" in resp.body)
    check("Default 404 is served as HTML",
          "text/html" in resp.headers.get("Content-Type", ""))
    check("Default 404 is no longer the bare line",
          resp.body != b"Not found.")
    # The page probes the URL it was served from, so a 404 carrying no
    # validators would make it report a defect that is really this response's
    # shape.
    etag_404 = resp.headers.get("ETag")
    check("Default 404 carries ETag and Cache-Control",
          bool(etag_404) and bool(resp.headers.get("Cache-Control")))
    # Guarded on the ETag existing: without the guard a regression that drops
    # the validator sends If-None-Match: None and takes the whole suite down
    # with a TypeError instead of reporting one clean failure.
    check("Default 404 revalidates to 304",
          bool(etag_404) and req("GET", path="/nonexistent.html",
                                 headers={"If-None-Match": etag_404}).status == 304)
    # The page has one role now, so no path is exempt from being a miss: what
    # was the reserved 200 path is an ordinary 404 like any other.
    check("The former reserved path is an ordinary miss",
          req("GET", path="/selftest/").status == 404)
    check("...answered by the same page, byte for byte",
          req("GET", path="/selftest/").body == resp.body)

    # An error page must never sit in a cache with a positive lifetime:
    # the operator publishes the file that was missing and cached clients
    # would keep the 404. Revalidate-always is now true by construction —
    # this pins that no mode reintroduces a lifetime.
    cc_404 = req("GET", path="/nonexistent.html").headers.get("Cache-Control", "")
    check("Default 404 carries no positive lifetime",
          "max-age" not in cc_404 and "no-cache" in cc_404)

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

    check("Removing 404.html restores the embedded page as the default body",
          b"notfound-path" in req("GET", path="/nonexistent.html").body)

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

            # A matched host's 429 carries HSTS like every other response —
            # site selection runs before the limiter now, because the old
            # order left rate-limited responses as the one un-pinned path a
            # browser could be downgraded on. Unmatched hosts still throttle
            # (and still get nothing: the closed system owes them no HSTS).
            saved_rl = s.config.rate_limit
            try:
                s.config.rate_limit = 0    # every request is over the limit
                resp429 = req("GET", headers={"Host": "first.example.com"})
                check("A matched host's 429 carries HSTS",
                      resp429.status == 429 and
                      resp429.headers.get("Strict-Transport-Security") is not None)
                resp429u = req("GET", headers={"Host": "unrecognized.example.com"})
                check("An unmatched Host still throttles, without HSTS",
                      resp429u.status == 429 and
                      resp429u.headers.get("Strict-Transport-Security") is None)
            finally:
                s.config.rate_limit = saved_rl
                with s._rate_lock:
                    s._request_times.clear()
        finally:
            original_site.domain = saved_orig_domain
            s.config.sites = saved_sites
    finally:
        shutil.rmtree(second_dir, ignore_errors=True)

    section("Version discovery endpoint")

    s._auth_fail_times.clear()

    # Gated on auth: never disclosed to an anonymous client. On a no-auth site the
    # path falls through to a normal 404 — the endpoint is invisible to the public.
    check("No-auth site: /.well-known/servette is not disclosed (404)",
          req("GET", "/.well-known/servette").status == 404)

    s.config.sites[0].username = "testuser"
    s.config.sites[0].password_hash, s.config.sites[0].password_salt = s._hash_password("testpass")

    check("Auth site, no credentials → 401",
          req("GET", "/.well-known/servette").status == 401)

    resp = req("GET", "/.well-known/servette", auth=("testuser", "testpass"))
    check("Auth site, correct credentials → 200 with JSON content-type",
          resp.status == 200 and "application/json" in resp.headers.get("Content-Type", ""))
    data = json.loads(resp.body)
    check("Reports the running version", data["running"] == s.__version__)
    check("Reports nothing else — the running version is the whole body",
          set(data) == {"running"})

    check("HEAD with credentials → 200 with an empty body",
          req("HEAD", "/.well-known/servette", auth=("testuser", "testpass")).status == 200
          and req("HEAD", "/.well-known/servette", auth=("testuser", "testpass")).body == b"")

    s.config.sites[0].username      = ""
    s.config.sites[0].password_hash = ""
    s.config.sites[0].password_salt = ""
    s._auth_fail_times.clear()

    section("The connection test on its reserved path")

    chk = req("GET", path="/.well-known/servette-check")
    check("The check page answers 200 as HTML on its reserved path",
          chk.status == 200 and b"Connection test" in chk.body
          and "text/html" in chk.headers.get("Content-Type", ""))
    etag_chk = chk.headers.get("ETag")
    check("...with validators, revalidating to 304",
          bool(etag_chk)
          and req("GET", path="/.well-known/servette-check",
                  headers={"If-None-Match": etag_chk}).status == 304)
    check("...rendering every row pending upfront — dim, then resolve",
          b"t-row pending" in chk.body and b"classList.remove('pending')" in chk.body)
    check("The slim 404 links the check instead of running it",
          b"run the connection test" in req("GET", path="/nonexistent.html").body
          and b"t-log" not in req("GET", path="/nonexistent.html").body)

    # The split's whole point: an operator's 404.html takes the miss body by
    # existing — and can never take the check page with it.
    live_root = os.path.realpath(s._resolve(s.config.sites[0].serve_dir))
    custom = os.path.join(live_root, "404.html")
    try:
        with open(custom, "w") as f:
            f.write("<h1>my own miss page</h1>")
        check("A custom 404.html wins the miss body",
              b"my own miss page" in req("GET", path="/nonexistent.html").body)
        check("...and cannot shadow the check page",
              b"Connection test" in req("GET", path="/.well-known/servette-check").body)
    finally:
        os.remove(custom)
        s._file_cache.clear()

    section("The embedded error page under auth")

    # It is a response like any other: it rides the site's own gate. An error
    # page that answered past auth would leak the server's identity, its
    # headers, and whether the site is published to anyone who guessed a wrong
    # path on a private site.
    check("HEAD on a miss answers with an empty body",
          req("HEAD", "/nonexistent.html").status == 404
          and req("HEAD", "/nonexistent.html").body == b"")

    s.config.sites[0].username = "testuser"
    s.config.sites[0].password_hash, s.config.sites[0].password_salt = s._hash_password("testpass")
    try:
        check("On an auth site a miss is challenged, not diagnosed",
              req("GET", "/nonexistent.html").status == 401)
        got = req("GET", "/nonexistent.html", auth=("testuser", "testpass"))
        check("...and serves the page with credentials",
              got.status == 404 and b"notfound-path" in got.body)
    finally:
        s.config.sites[0].username      = ""
        s.config.sites[0].password_hash = ""
        s.config.sites[0].password_salt = ""
        s._auth_fail_times.clear()

    section("Cache-Control on the wire — derived, and overridable")

    s.config.sites[0].cache = "yes"
    check("public site: no-cache in response",
          "no-cache" in req("GET").headers.get("Cache-Control", ""))

    s.config.sites[0].cache = "no"
    check("cache=no: no-store in response",
          "no-store" in req("GET").headers.get("Cache-Control", ""))

    s.config.sites[0].cache = "yes"

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

    # From the trusted proxy, only a value that IS an address is adopted: a
    # passthrough proxy forwarding client-written XFF verbatim must not let
    # arbitrary bytes mint fresh rate-limit buckets (a limiter bypass) or
    # reach the operator's log lines as the "IP".
    s._request_times.clear()
    s.config.trusted_proxy = "127.0.0.1"   # the test client IS the proxy now

    req("GET", headers={"X-Forwarded-For": "junk-not-an-address-one"})
    req("GET", headers={"X-Forwarded-For": "junk-not-an-address-two"})
    check("Junk XFF from the trusted proxy shares the proxy's own bucket → 429",
          req("GET", headers={"X-Forwarded-For": "junk-not-an-address-three"}).status == 429)

    s._request_times.clear()
    req("GET", headers={"X-Forwarded-For": "1.2.3.4"})
    req("GET", headers={"X-Forwarded-For": "5.6.7.8"})
    check("...while real addresses are still adopted, each with its own bucket",
          req("GET", headers={"X-Forwarded-For": "9.10.11.12"}).status != 429)

    # Stock proxies (Azure's gateway among them) append the client as
    # ip:port or [v6]:port; the port is theirs to add and ours to drop —
    # or every visitor behind such a proxy would share the proxy's bucket.
    s._request_times.clear()
    req("GET", headers={"X-Forwarded-For": "1.2.3.4:1111"})
    req("GET", headers={"X-Forwarded-For": "5.6.7.8:2222"})
    check("An ip:port XFF is adopted as its address, not lumped as junk",
          req("GET", headers={"X-Forwarded-For": "[2001:db8::7]:443"}).status != 429)

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

    section("Concurrent scrypt hashing is bounded (#49)")

    # The per-IP limiter above cannot bound concurrency across IPs: many distinct
    # sources each get a first hash before their own limiter engages. _SCRYPT_SLOTS
    # caps how many scrypt verifications run at once; excess callers block briefly
    # rather than fail. Wrap hashlib.scrypt to measure true concurrency under a
    # 12-thread burst — it must never exceed the semaphore's 4, and every
    # legitimate login must still succeed.
    ph, psalt   = s._hash_password("hunter2")
    real_scrypt = s.hashlib.scrypt
    conc  = {"cur": 0, "max": 0}
    clock = threading.Lock()

    def slow_scrypt(*a, **kw):
        with clock:
            conc["cur"] += 1
            conc["max"]  = max(conc["max"], conc["cur"])
        time.sleep(0.05)   # hold the permit long enough for the burst to pile up
        try:
            return real_scrypt(*a, **kw)
        finally:
            with clock:
                conc["cur"] -= 1

    s.hashlib.scrypt = slow_scrypt
    try:
        results = []
        rlock   = threading.Lock()

        def attempt():
            ok = s._check_password("hunter2", ph, psalt)
            with rlock:
                results.append(ok)

        burst = [threading.Thread(target=attempt) for _ in range(12)]
        for t in burst:
            t.start()
        for t in burst:
            t.join()
        check("A 12-thread burst never runs more than 4 hashes at once",
              conc["max"] <= s._SCRYPT_MAX_CONCURRENT)
        check("The semaphore admits real concurrency (max observed ≥ 2)",
              conc["max"] >= 2)
        check("All 12 legitimate logins succeed under load",
              len(results) == 12 and all(results))
    finally:
        s.hashlib.scrypt = real_scrypt


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

    # An unprivileged process cannot give files away: on a host where the
    # servette user EXISTS, a non-root _chown_servette must skip, not raise —
    # check=True on the chown turned that into a crash at Config() import
    # (save() runs it), found by running the suite as a non-root user.
    saved_chk_euid, saved_chk_sue = s.os.geteuid, s._servette_user_exists
    chk_file = os.path.join(tmpdir, "chown-skip-probe")
    open(chk_file, "w").write("x")
    try:
        s._servette_user_exists = lambda: True
        s.os.geteuid = lambda: 12345          # neither root nor the service user
        try:
            s._chown_servette(chk_file)
            check("Unprivileged _chown_servette skips instead of raising", True)
        except Exception as e:
            check(f"Unprivileged _chown_servette skips instead of raising (raised {e})", False)
    finally:
        s.os.geteuid, s._servette_user_exists = saved_chk_euid, saved_chk_sue

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

    section("Config file permissions")

    # servette.toml is the operator's file about the operator's box. Owned 0600
    # by the service user, every read-only command elevated to read it and
    # config.unreadable stayed true, firing the fail-closed reload guard during
    # correct operation. The file is now servette:<operator group> 0640.
    check("_operator_group returns a non-empty name",
          isinstance(s._operator_group(), str) and s._operator_group() != "")
    saved_og_env = os.environ.get("SUDO_USER")
    try:
        os.environ["SUDO_USER"] = "nosuchuser-servette-probe"
        check("_operator_group falls back to the username when the group is unresolvable",
              s._operator_group() == "nosuchuser-servette-probe")
    finally:
        if saved_og_env is None:
            os.environ.pop("SUDO_USER", None)
        else:
            os.environ["SUDO_USER"] = saved_og_env

    cfg_probe = os.path.join(tmpdir, "perm-probe.toml")
    open(cfg_probe, "w").write("port = 443\n")
    os.chmod(cfg_probe, 0o600)
    saved_cfg_euid, saved_cfg_sue = s.os.geteuid, s._servette_user_exists
    try:
        # No servette user (session mode, macOS, tests): nothing to hand over,
        # so the mode the writer chose stands.
        s._servette_user_exists = lambda: False
        s._chown_config(cfg_probe)
        check("_chown_config leaves the mode alone with no service user",
              os.stat(cfg_probe).st_mode & 0o777 == 0o600)

        # A process that is neither root nor the service user cannot hand the
        # file over at all, and must not try — the same crash _chown_servette
        # learned to avoid, on the same import-time save() path.
        s._servette_user_exists = lambda: True
        s.os.geteuid = lambda: 12345
        try:
            s._chown_config(cfg_probe)
            check("Unprivileged _chown_config skips instead of raising", True)
        except Exception as e:
            check(f"Unprivileged _chown_config skips instead of raising (raised {e})", False)
        check("Unprivileged _chown_config changes nothing",
              os.stat(cfg_probe).st_mode & 0o777 == 0o600)

        # Root's path: the chown is best-effort (it fails here, with no such
        # group), the chmod is not. That ordering is what makes the widening
        # fail closed — a group that could not be handed over leaves the file
        # readable by servette, which already owns it.
        s.os.geteuid = lambda: 0
        s._chown_config(cfg_probe)
        check("_chown_config sets 0640, group-readable and never world-readable",
              os.stat(cfg_probe).st_mode & 0o777 == 0o640)

        # Failure must degrade toward the SERVICE. A SUDO_USER deleted since
        # the sudo (or an NSS outage) makes the operator-group chown fail
        # wholesale — and the file it would leave behind is save()'s
        # root:root os.replace result, which the service cannot read: reload
        # dead, next restart refusing to serve. The fallback hands the file
        # to servette:servette instead — the operator loses the no-password
        # read until the next enable; the site loses nothing.
        saved_run = s.subprocess.run
        chowns = []
        class _Rc:
            def __init__(self, rc): self.returncode = rc
        def fake_run(argv, **k):
            if argv[0] == "chown":
                chowns.append(argv)
                return _Rc(1 if len(chowns) == 1 else 0)  # operator group fails
            return saved_run(argv, **k)
        try:
            s.subprocess.run = fake_run
            s._chown_config(cfg_probe)
        finally:
            s.subprocess.run = saved_run
        check("A failed operator-group chown falls back to servette:servette",
              len(chowns) == 2 and chowns[1][:2] == ["chown", "servette:servette"])
        check("...and the mode is still 0640",
              os.stat(cfg_probe).st_mode & 0o777 == 0o640)
    finally:
        s.os.geteuid, s._servette_user_exists = saved_cfg_euid, saved_cfg_sue

    # A root shell never elevates, so before this no path re-read the file for
    # it: a long-lived root session acted on hours-old state and its next save
    # silently reverted anything written since. The dispatcher now refreshes.
    saved_euid_rc  = s.os.geteuid
    saved_reload   = s.Config.reload_if_changed
    reloads = []
    try:
        s.os.geteuid = lambda: 0
        s.Config.reload_if_changed = lambda self: reloads.append(1)
        with contextlib.redirect_stdout(io.StringIO()):
            s.run_command("sites", [])
        check("A root shell re-reads the config before dispatching", len(reloads) == 1)
    finally:
        s.os.geteuid = saved_euid_rc
        s.Config.reload_if_changed = saved_reload

    # save() writes through a mkstemp temp file, which arrives 0600, and
    # os.replace installs that mode over the live config. Without the restore
    # every `config` run would take the readable file away again.
    save_probe    = os.path.join(tmpdir, "save-probe.toml")
    saved_cf      = s.Config.CONFIG_FILE
    saved_sv_euid = s.os.geteuid
    saved_sv_sue  = s._servette_user_exists
    try:
        s.Config.CONFIG_FILE    = save_probe
        s._servette_user_exists = lambda: True
        s.os.geteuid            = lambda: 0
        s.Config().save()
        check("save() leaves the config 0640, not the temp file's 0600",
              os.stat(save_probe).st_mode & 0o777 == 0o640)
    finally:
        s.Config.CONFIG_FILE = saved_cf
        s.os.geteuid, s._servette_user_exists = saved_sv_euid, saved_sv_sue

    section("Service file content")

    # Test the real generated unit, not a reconstructed copy.
    module_path = os.path.abspath(s.__file__)
    service     = s._systemd_unit(sys.executable, module_path)
    check("Service runs as the least-privilege user",  "User=servette" in service)
    check("Capabilities bounded to net-bind only",     "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in service)
    check("NoNewPrivileges is set",                    "NoNewPrivileges=yes" in service)
    check("Filesystem is read-only (ProtectSystem=strict)", "ProtectSystem=strict" in service)
    check("Private /tmp",                              "PrivateTmp=yes" in service)
    check("Writes confined to BASE_DIR + ACME webroot",
          f"ReadWritePaths={s.BASE_DIR} {s.ACME_WEBROOT}" in service)
    check("The service resolves the same data dir the enabling shell did",
          f"Environment=SERVETTE_HOME={s.BASE_DIR}" in service)
    ro_line = next((l for l in service.splitlines() if l.startswith("ReadOnlyPaths=")), "")
    check("The module is pinned read-only — holds even for a checkout inside the data dir (#47)",
          module_path in ro_line)
    for directive in ("PrivateDevices=yes", "ProtectClock=yes", "ProtectHostname=yes",
                      "ProtectKernelLogs=yes", "ProtectProc=invisible",
                      "RestrictRealtime=yes", "RestrictNamespaces=yes",
                      "SystemCallArchitectures=native",
                      "Environment=PYTHONDONTWRITEBYTECODE=1"):
        check(f"Unit carries {directive.split('=')[0]}", directive in service)
    check("The service starts the package with the enabling shell's interpreter",
          f"ExecStart={sys.executable} -m servette --serve" in service)
    check("PYTHONPATH resolves -m servette for checkout deployments",
          f"Environment=PYTHONPATH={os.path.dirname(module_path)}" in service)
    pip_unit = s._systemd_unit(sys.executable, "/v/lib/python3.11/site-packages/servette.py")
    check("A pip-installed package gets no PYTHONPATH (nothing to widen)",
          "PYTHONPATH" not in pip_unit)

    section("The runtime the service can reach")

    # The service runs as an unprivileged user that owns nothing and is in no
    # group but its own. A per-user install sits under a home directory Debian
    # and Ubuntu create mode 0750, which that user cannot traverse — so the unit
    # would name an interpreter and a package it cannot read, and the host would
    # restart-loop on ModuleNotFoundError after the next reboot.
    # Not under tmpdir: mkdtemp makes 0700 directories, which would make every
    # path below one unreachable and the negative cases pass for the wrong
    # reason. This tree is traversable from / down, so each mode change below is
    # the only thing the answer can turn on.
    reach = tempfile.mkdtemp()
    home  = os.path.join(reach, "home")
    leaf  = os.path.join(home, "pkg", "mod.py")
    try:
        os.makedirs(os.path.join(home, "pkg"))
        with open(leaf, "w") as f:
            f.write("x = 1\n")
        subprocess.run(["chmod", "-R", "a+rX", reach], check=True)
        check("A traversable path is reachable by the service user",
              s._reachable_by_service(leaf))
        os.chmod(home, 0o750)                        # what `useradd -m` gives
        check("...and a 0750 home hides everything under it",
              not s._reachable_by_service(leaf))
        os.chmod(home, 0o755)
        os.chmod(leaf, 0o640)
        check("...as does a file the service user cannot read",
              not s._reachable_by_service(leaf))
        check("A path that does not exist is not reachable",
              not s._reachable_by_service(os.path.join(reach, "nope", "mod.py")))
    finally:
        shutil.rmtree(reach, ignore_errors=True)

    # What gets copied is read from installed metadata, not from a list here:
    # cryptography declares cffi, cffi declares pycparser, and cffi's compiled
    # backend is a bare .so beside the packages. A hand-kept list said
    # "cryptography" and produced a runtime that could not import it.
    required = s._required_distributions()
    check("The dependency closure is resolved, not remembered",
          any(d.lower() == "cryptography" for d in required))
    check("...and the program itself is not one of its own dependencies",
          not any(d.lower() == "servette" for d in required))
    # Asserted present, not skipped when absent: cryptography declares cffi on
    # CPython, so a closure without it is itself a resolution failure — and a
    # conditional check here once meant the .so probe could silently never run.
    cffi_dist = next((d for d in required if d.lower() == "cffi"), None)
    check("cffi is in the closure (cryptography declares it on CPython)",
          cffi_dist is not None)
    check("A distribution's bare compiled module is found too, not just its package",
          cffi_dist is not None
          and any(p.endswith(".so") for p in s._distribution_paths(cffi_dist)))

    # Python 3.13 deprecated re.split's positional maxsplit, and `-m servette`
    # runs as __main__, where deprecation warnings print to the operator: the
    # first Debian 13 setup showed one mid-wizard, from this very reader.
    # Executed with DeprecationWarning promoted to an error, so the next one
    # fails here instead of in a wizard.
    import warnings as _warnings
    try:
        with _warnings.catch_warnings():
            _warnings.simplefilter("error", DeprecationWarning)
            s._required_distributions()
        check("The closure reader raises no DeprecationWarning", True)
    except DeprecationWarning as e:
        check(f"The closure reader raises no DeprecationWarning (raised {e})", False)

    # The seed for a checkout, which has no dist-info of its own to read, must
    # be what the package actually declares — a dependency added to pyproject
    # and not here would give a runtime missing a module.
    declared = re.findall(r'"([A-Za-z0-9_.\-]+)\s*[><=!~]',
                          re.search(r"dependencies\s*=\s*\[(.*?)\]",
                                    open(os.path.join(SERVETTE_DIR, "pyproject.toml"),
                                         encoding="utf-8").read(), re.S).group(1))
    check("The checkout seed matches pyproject's dependencies",
          [d.lower() for d in declared] == [d.lower() for d in s._DECLARED_DEPENDENCIES])

    # Provisioning: the whole closure, root-owned, world-readable, and replaced
    # wholesale so an older version cannot leave a module behind. Build and
    # commit are separate steps so verification can run between them — the old
    # single call swapped first and verified after, so a refused runtime was
    # already installed (and the good copy destroyed) when the refusal printed.
    saved_rt, saved_base_rt = s.RUNTIME_DIR, s.BASE_DIR
    try:
        s.RUNTIME_DIR = os.path.join(tmpdir, "runtime")
        os.makedirs(os.path.join(s.RUNTIME_DIR, "stale_leftover"), exist_ok=True)
        staged = s._build_runtime()
        check("Building alone leaves the live runtime untouched",
              os.path.exists(os.path.join(s.RUNTIME_DIR, "stale_leftover"))
              and os.path.exists(os.path.join(staged, "servette.py")))
        s._commit_runtime(staged)
        landed = set(os.listdir(s.RUNTIME_DIR))
        check("The runtime holds the program", "servette.py" in landed)
        wanted = {os.path.basename(p) for p in s._runtime_sources()}
        check("...and every path the closure named", wanted <= landed)
        check("...and nothing an earlier version left", "stale_leftover" not in landed)
        modes = []
        for root, _d, files in os.walk(s.RUNTIME_DIR):
            modes.append(os.stat(root).st_mode & 0o777)
            modes += [os.stat(os.path.join(root, f)).st_mode & 0o777 for f in files]
        check("The service can read all of it", all(m & 0o004 for m in modes))
        check("...and write none of it", all(not m & 0o022 for m in modes))
        check("No temporary tree is left beside it",
              not os.path.exists(s.RUNTIME_DIR + ".new")
              and not os.path.exists(s.RUNTIME_DIR + ".old"))

        # Which paths the unit names follows from reachability, one predicate
        # shared by the writer and the drift check.
        saved_reach, saved_syspy = s._installed_runtime_reachable, s._system_python
        try:
            s._installed_runtime_reachable = lambda: False
            s._system_python = lambda: "/usr/bin/python3"
            check("Unreachable: the unit imports from the runtime copy",
                  s._unit_module_path() == os.path.join(s.RUNTIME_DIR, "servette.py"))
            check("...with an interpreter outside the install",
                  s._unit_python_path() == "/usr/bin/python3")
            unit = s._systemd_unit(s._unit_python_path(), s._unit_module_path())
            check("...on PYTHONPATH, since the copy is not site-packages",
                  f"Environment=PYTHONPATH={s.RUNTIME_DIR}" in unit)
            check("...and the WHOLE copy pinned read-only, dependencies included",
                  f"ReadOnlyPaths={s.RUNTIME_DIR}\n" in unit)
            check("An interpreter path with whitespace is refused, not encoded",
                  s._unsafe_unit_path() is None)
            s._system_python = lambda: "/home/my user/.venv/bin/python"
            check("...including when it is the interpreter that carries it",
                  s._unsafe_unit_path() == "/home/my user/.venv/bin/python")
            s._system_python = lambda: None
            check("No matching interpreter means nothing is stale to rewrite",
                  s._stale_units() == [])
        finally:
            s._installed_runtime_reachable = saved_reach
            s._system_python = saved_syspy
    finally:
        s.RUNTIME_DIR, s.BASE_DIR = saved_rt, saved_base_rt
        shutil.rmtree(os.path.join(tmpdir, "runtime"), ignore_errors=True)

    # An interpreter of another minor version cannot load the cryptography build
    # the runtime copy carries, so it is refused rather than named.
    saved_minor = s._python_minor
    try:
        s._python_minor = lambda p: "2.7"
        check("A version-mismatched interpreter is refused, not used",
              s._system_python() is None)
    finally:
        s._python_minor = saved_minor
    check("This interpreter reports its own version",
          s._python_minor(sys.executable) == "%d.%d" % sys.version_info[:2])
    check("An interpreter that cannot run reports nothing",
          s._python_minor(os.path.join(tmpdir, "not-a-python")) is None)

    # Every part of the reasoning above is inference about another user's view of
    # the filesystem, so the conclusion is executed before a unit is written:
    # import the program and the certificate machinery, from the paths the unit
    # names, as the service user where the host can drop privileges.
    check("A runtime that works verifies",
          s._verify_runtime(sys.executable, os.path.abspath(s.__file__)) is None)

    # The probe must judge the service against the config the unit will carry,
    # which means the same SERVETTE_HOME — without it, a shell run with a
    # non-default data directory verified against the default one's config.
    saved_probe_run = s.subprocess.run
    probe_envs = []
    class _Ok:
        returncode, stdout, stderr = 0, "", ""
    try:
        s.subprocess.run = lambda *a, **k: probe_envs.append(k.get("env")) or _Ok()
        s._verify_runtime(sys.executable, os.path.abspath(s.__file__))
        check("The probe carries the unit's own SERVETTE_HOME",
              probe_envs and all(e and e.get("SERVETTE_HOME") == s.BASE_DIR
                                 for e in probe_envs))
    finally:
        s.subprocess.run = saved_probe_run
    # The broken runtime is a PLANTED broken module, not a missing directory:
    # PYTHONPATH outranks site-packages, so the plant wins on any interpreter —
    # including CI's venv, where servette is pip-installed and a merely-missing
    # path let the probe resolve the installed copy and verify clean. The plant
    # lives in its own world-traversable directory, not under tmpdir: mkdtemp
    # makes 0700 homes, and when the suite runs as root the privilege-dropped
    # probe could not even see a plant buried there — it reported the module
    # missing instead of broken.
    bad_rt = tempfile.mkdtemp()
    try:
        with open(os.path.join(bad_rt, "servette.py"), "w") as f:
            f.write("raise ImportError('unusable-runtime-probe')\n")
        os.chmod(bad_rt, 0o755)
        os.chmod(os.path.join(bad_rt, "servette.py"), 0o644)
        problem = s._verify_runtime(sys.executable, os.path.join(bad_rt, "servette.py"))
        check("...and one whose module cannot import does not",
              isinstance(problem, str) and "unusable-runtime-probe" in problem)
    finally:
        shutil.rmtree(bad_rt, ignore_errors=True)

    # The refusal is what makes verification worth running: a host that would
    # restart-loop after the next reboot must be turned away here, with no unit
    # written and no systemctl called.
    saved_w = {n: getattr(s, n) for n in
               ("_servette_user_exists", "_installed_runtime_reachable",
                "_verify_runtime", "_service_file_exists", "_unsafe_unit_path")}
    saved_sub    = s.subprocess.run
    saved_euid_w = s.os.geteuid
    ran = []
    try:
        s.os.geteuid                  = lambda: 0   # past the writer's root gate
        s._servette_user_exists       = lambda: True
        s._installed_runtime_reachable = lambda: True
        s._verify_runtime             = lambda p, d: "ModuleNotFoundError: no servette"
        s._service_file_exists        = lambda: False
        s._unsafe_unit_path           = lambda: None
        s.subprocess.run              = lambda argv, *a, **k: ran.append(argv)
        refused = None
        with contextlib.redirect_stdout(io.StringIO()) as wbuf:
            try:
                s._write_unit_files()
            except ValueError as e:
                refused = str(e)
        check("A runtime the service cannot use refuses the write",
              refused is not None and "unusable" in refused)
        check("...before systemd is touched", ran == [])
        check("...and says what the service could not do",
              "ModuleNotFoundError" in wbuf.getvalue())

        # An unprivileged caller is turned away BEFORE the runtime swap, not
        # at the unit write: the old order let an unprivileged startup
        # refresh (in a checkout the operator owns) replace the runtime copy,
        # then fail at the unit file — a version-skewed, operator-owned
        # runtime behind a unit still describing the old one.
        s.os.geteuid = lambda: 1000
        ran.clear()
        early = None
        try:
            s._write_unit_files()
        except PermissionError:
            early = "refused"
        check("An unprivileged writer is refused before anything is touched",
              early == "refused" and ran == [])
    finally:
        for n, v in saved_w.items():
            setattr(s, n, v)
        s.subprocess.run = saved_sub
        s.os.geteuid     = saved_euid_w

    # The staged-copy gate: a runtime that fails verification is discarded
    # with the live runtime untouched — structurally, the writer verifies the
    # staged tree before committing it.
    import inspect as _inspect2
    writer_src = _inspect2.getsource(s._write_unit_files)
    check("The writer verifies the staged runtime before committing it",
          0 < writer_src.find("_build_runtime")
            < writer_src.find("_verify_runtime")
            < writer_src.find("_commit_runtime"))

    # A pinned interpreter an OS upgrade removed is reported as the outage it
    # is, not as generic environment drift.
    saved_svc_path = s.SERVICE_PATH
    gone_unit = os.path.join(tmpdir, "gone-interp.service")
    with open(gone_unit, "w") as f:
        f.write(f"Environment=SERVETTE_HOME={s.BASE_DIR}\n"
                "ExecStart=/nonexistent/python3.9 -m servette --serve\n")
    try:
        s.SERVICE_PATH = gone_unit
        drift = s._service_env_drift()
        check("A vanished service interpreter is named as unable to start",
              any("no longer exists" in d and "cannot start" in d for d in drift))
    finally:
        s.SERVICE_PATH = saved_svc_path

    # A deliberate reload-stop is logged as a restart, not as an unexpected
    # death: without the flag every certificate rotation wrote an error line
    # to the journal, teaching the operator the error line is routine.
    saved_argv_rl = sys.argv[:]
    saved_stop_rl = s.stop_server
    try:
        sys.argv = ["servette", "--serve"]
        stops = []
        s.stop_server = lambda: stops.append(1)
        s._reload_requested = False
        s._reload_server()
        check("An in-service reload stops the server and marks the exit deliberate",
              stops == [1] and s._reload_requested is True)
    finally:
        sys.argv = saved_argv_rl
        s.stop_server = saved_stop_rl
        s._reload_requested = False

    # A unit the writer refuses must not take the shell launch down with it:
    # _startup_refresh calls the writer on every interactive start, and the
    # whitespace-path refusal raises rather than returning.
    saved_r = {n: getattr(s, n) for n in
               ("_unsafe_unit_path", "_service_file_exists", "_stale_units",
                "_service_env_drift", "_servette_user_exists")}
    try:
        s._unsafe_unit_path    = lambda: "/bad path/servette"
        s._service_file_exists = lambda: True
        s._stale_units         = lambda: [s.SERVICE_PATH]
        s._service_env_drift   = lambda: []
        s._servette_user_exists= lambda: True
        crashed = None
        with contextlib.redirect_stdout(io.StringIO()) as rbuf:
            try:
                s._startup_refresh()
            except Exception as e:
                crashed = e
        check("A refused unit write does not crash the shell launch", crashed is None)
        check("...and says the existing service was left alone",
              "Leaving the existing service untouched" in rbuf.getvalue())
    finally:
        for n, v in saved_r.items():
            setattr(s, n, v)

    # Paths systemd cannot carry are refused, not encoded wrongly.
    saved_base = s.BASE_DIR
    saved_sfe  = s._service_file_exists
    try:
        s.BASE_DIR = "/tmp/has space"
        check("A whitespace path is flagged unsafe for units",
              s._unsafe_unit_path() == "/tmp/has space")
        s._service_file_exists = lambda: True
        check("Unsafe paths short-circuit staleness (no rewrite loop)",
              s._stale_units() == [])
    finally:
        s.BASE_DIR = saved_base
        s._service_file_exists = saved_sfe
    check("A clean path is not flagged", s._unsafe_unit_path() is None)

    # Validate the real unit with systemd-analyze where available (Ubuntu CI has it;
    # skipped on macOS / non-systemd hosts). Catches typo'd or unknown directives.
    if shutil.which("systemd-analyze"):
        unit_path = os.path.join(tmpdir, "servette.service")
        with open(unit_path, "w") as f:
            f.write(s._systemd_unit(sys.executable, module_path))
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
    # One minute, not the original five: `ip route get` sends no packets (a
    # local table lookup), so the interval buys only recovery time — the route
    # drill measured ~5 dark minutes at the old setting, ~1 at this one.
    check("Timer fires every minute",                "OnUnitActiveSec=1min" in watch_timer)
    check("Timer starts checking after boot",        "OnBootSec=1min" in watch_timer)
    # The run that acts must say so — in the drill's journal, the firing that
    # recovered the box logged identically to every no-op around it, leaving
    # no evidence of what fixed the host.
    check("A watchdog run that acts logs that it acted",
          'logger -t servette-netwatch' in watch_service)

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

    section("Site content ownership (operator, not service)")

    # The servette user only reads site content; the operator must be able to
    # scp into the folder without sudo. _operator_user picks the human behind
    # sudo when there is one.
    saved_sudo = os.environ.get("SUDO_USER")
    try:
        os.environ["SUDO_USER"] = "deploybot"
        check("Under sudo, the site folder goes to the invoking user",
              s._operator_user() == "deploybot")
        os.environ.pop("SUDO_USER")
        import getpass as _getpass
        check("Without sudo, it goes to the current user",
              s._operator_user() == _getpass.getuser())

        # The plan grants read to the servette group alone — never the world,
        # so a .env/.git dragged into a site isn't flipped world-readable.
        os.environ["SUDO_USER"] = "deploybot"
        saved_exists = s._servette_user_exists
        s._servette_user_exists = lambda: True
        plan = s._operator_chown_plan("/data/site")
        check("With the service user: owner operator, group servette, g+rX only",
              plan == [["chown", "-R", "deploybot:servette", "/data/site"],
                       ["chmod", "-R", "g+rX", "/data/site"]])
        check("No world-readable bit anywhere in the plan",
              not any("a+rX" in " ".join(argv) for argv in plan))
        s._servette_user_exists = lambda: False
        check("Before the service user exists: ownership only",
              s._operator_chown_plan("/data/site") == [["chown", "-R", "deploybot", "/data/site"]])
        s._servette_user_exists = saved_exists
    finally:
        if saved_sudo is not None:
            os.environ["SUDO_USER"] = saved_sudo

    section("Swap recommendation (supply and demand)")

    MB    = 1024         # 1 MB expressed in kB, matching /proc/meminfo units
    GB_KB = 1024 * 1024  # 1 GB in kB
    # Demand is Committed_AS — the kernel's worst case if every allocation it
    # handed out were used — plus the cache ceiling not already inside it,
    # plus the spike allowance. The incident box: 414 MB RAM, 238 MB committed,
    # 50 MB cache. Demand = 238 + 50 + 700 = 988; deficit over RAM = 574;
    # recommendation = 2 × deficit, rounded to 2 significant digits.
    rec = s._swap_recommendation(414 * MB, 238 * MB, 50)
    check("Incident-class host gets a recommendation", rec is not None)
    check("Recommendation is twice the demand deficit, rounded to 2 significant digits",
          rec == 1200 * 1024 ** 2)  # 2 × 574 MB deficit = 1148 → 1200

    check("Round-up: 1148 → 1200",  s._round_up_2sig(1148) == 1200)
    check("Round-up: 575 → 580",    s._round_up_2sig(575) == 580)
    check("Round-up: 2049 → 2100",  s._round_up_2sig(2049) == 2100)
    check("Round-up: 99 stays 99",  s._round_up_2sig(99) == 99)
    check("Round-up: exact 1200 stays 1200", s._round_up_2sig(1200) == 1200)
    check("Idle big host → no recommendation (demand fits)",
          s._swap_recommendation(4 * GB_KB, 500 * MB, 50) is None)
    check("Committed big host → still recommended (threshold is demand, not a RAM ceiling)",
          s._swap_recommendation(2 * GB_KB, 2 * GB_KB, 50) is not None)
    check("Small deficit floors at 512 MB",
          s._swap_recommendation(1024 * MB, 424 * MB, 50) == 512 * 1024 ** 2)
    check("Recommendation capped at 2 GB",
          s._swap_recommendation(414 * MB, 2 * GB_KB, 1024) == 2 * 1024 ** 3)
    check("Unreadable meminfo → no recommendation",
          s._swap_recommendation(None, None, 50) is None)

    # Unlike the old resident-usage signal, MemTotal does NOT cancel out: the
    # same commitment on a bigger host needs less swap to absorb, which is the
    # answer an operator would expect and the old formula could not give.
    small = s._swap_recommendation(512 * MB, 300 * MB, 0)
    big   = s._swap_recommendation(4 * GB_KB, 300 * MB, 0)
    check("A bigger host with the same commitment needs less swap (or none)",
          big is None or big < small)

    section("Swap: the cache is counted once, not twice")

    # A warm cache is anonymous memory the kernel has already committed —
    # measured during review: 200 MB of cached files raised Committed_AS by
    # 201 MB. Charging the configured ceiling on top double-counts it, and the
    # doubling turns a 128 MB default into 256 MB of swap the host never needs.
    saved_run_c  = s._server_running
    saved_svc_c  = s._service_is_active
    try:
        s._server_running, s._service_is_active = (lambda: False), (lambda: False)
        check("Nothing serving: the cache ceiling is charged (it is not in the signal yet)",
              s._cache_headroom_mb(128) == 128)
        s._server_running = lambda: True
        check("A session server is running: the ceiling is not charged again",
              s._cache_headroom_mb(128) == 0)
        s._server_running, s._service_is_active = (lambda: False), (lambda: True)
        check("The systemd service is running: likewise not charged again",
              s._cache_headroom_mb(128) == 0)

        # The ordering property that removes the resize nag entirely: the offer
        # is computed with nothing serving, the later check with the service up,
        # so the check can never exceed the size the operator just accepted.
        s._server_running, s._service_is_active = (lambda: False), (lambda: False)
        committed_cold = 250 * MB
        offer_rec = s._swap_recommendation(442 * MB, committed_cold,
                                           s._cache_headroom_mb(128)) // (1024 ** 2)
        s._service_is_active = lambda: True
        # the service is now up and its cache has filled: the same megabytes,
        # now inside Committed_AS instead of charged on top
        status_rec = s._swap_recommendation(442 * MB, committed_cold + 128 * MB,
                                            s._cache_headroom_mb(128)) // (1024 ** 2)
        check("Offer and later status agree once the cache has filled",
              offer_rec == status_rec)
        check("...so a host that accepted the offer is never told to resize",
              s._swap_offer(status_rec, True, offer_rec, 0) is None)
        # and with a half-filled cache the check comes in BELOW the offer,
        # which is the safe direction: quiet, never nagging.
        half_rec = s._swap_recommendation(442 * MB, committed_cold + 64 * MB,
                                          s._cache_headroom_mb(128)) // (1024 ** 2)
        check("A half-filled cache leaves the check below the offer, not above",
              half_rec <= offer_rec
              and s._swap_offer(half_rec, True, offer_rec, 0) is None)
    finally:
        s._server_running, s._service_is_active = saved_run_c, saved_svc_c

    section("Swap offer")

    check("No swap → offer, declining skips",
          s._swap_offer(1200, False, None, 0) == ("no swapfile", "skip"))
    check("Foreign swap (partition, distro-managed) → no offer",
          s._swap_offer(1200, False, None, 600) is None)
    check("Our swapfile, big enough → no offer",
          s._swap_offer(1200, True, 1200, 0) is None)
    check("Our swapfile, undersized → offer, declining keeps current",
          s._swap_offer(1200, True, 600, 0) == ("a 600 MB swapfile", "keep 600"))
    # The sizes are per-device from /proc/swaps, not SwapTotal: with a foreign
    # partition alongside, SwapTotal printed a size the swapfile does not have
    # and let partition + file sum past the recommendation, hiding a real
    # undersize.
    check("Our undersized swapfile is offered even when a partition tops up the total",
          s._swap_offer(1200, True, 600, 1024) == ("a 600 MB swapfile", "keep 600"))
    # The live box took a 1400 MB offer and SwapTotal came back 1399 MB: mkswap
    # spends the first page on a header and the MB arithmetic floors the rest.
    # Compared exactly, that host is told to resize to the size it already has,
    # forever, and resizing reproduces the same shortfall.
    check("Our swapfile, short by mkswap's header → no offer",
          s._swap_offer(1400, True, 1399, 0) is None)
    check("Our swapfile, short by exactly the slack → no offer",
          s._swap_offer(1200, True, 1200 - s._SWAP_SLACK_MB, 0) is None)
    check("Our swapfile, short by more than the slack → still offered",
          s._swap_offer(1200, True, 1200 - s._SWAP_SLACK_MB - 1, 0)
          == (f"a {1200 - s._SWAP_SLACK_MB - 1} MB swapfile",
              f"keep {1200 - s._SWAP_SLACK_MB - 1}"))
    # The slack forgives less than the recommendation's own rounding already
    # does: _round_up_2sig moves a four-digit estimate in 100 MB steps, so the
    # tolerance cannot swallow a size difference the recommendation could see.
    check("Slack is smaller than the recommendation's rounding step",
          s._SWAP_SLACK_MB < s._round_up_2sig(1101) - s._round_up_2sig(1001))
    check("Our swapfile, inactive → offer, declining skips",
          s._swap_offer(1200, True, None, 0) == ("an inactive swapfile", "skip"))
    check("No recommendation → no offer",
          s._swap_offer(None, False, None, 0) is None)

    ours_probe, foreign_probe = s._swap_sizes()
    check("_swap_sizes reads /proc/swaps without crashing",
          (ours_probe is None or isinstance(ours_probe, int))
          and isinstance(foreign_probe, int))

    mem_kb, avail_kb, committed_kb = s._meminfo()
    check("_meminfo returns a consistent triple",
          (mem_kb is None and avail_kb is None and committed_kb is None)
          or (isinstance(mem_kb, int) and isinstance(avail_kb, int)
              and isinstance(committed_kb, int) and mem_kb > 0))
    check("_meminfo reads Committed_AS, the signal the sizing is built on",
          committed_kb is None or committed_kb > 0)
    check("_root_on_sd_card returns bool (no crash on any host)",
          isinstance(s._root_on_sd_card(), bool))

    section("Host health warning")

    # Every sub-test pins whether /swapfile exists: GitHub's runners HAVE one,
    # so a test that leaves os.path.exists real asserts about the runner's
    # disk, not about the code — the first CI run of this section failed on
    # exactly that, green locally (no /swapfile here) and red on the runner.
    saved_meminfo   = s._meminfo
    saved_sizes     = s._swap_sizes
    saved_exists_hh = s.os.path.exists
    def _pin_swapfile(present):
        s.os.path.exists = (lambda real: lambda p:
                            present if p == s._SWAP_PATH else real(p))(saved_exists_hh)
    try:
        # (MemTotal, MemAvailable, Committed_AS) — the third field is the
        # demand signal now, so it carries the incident box's commitment.
        s._meminfo    = lambda: (414 * 1024, 176 * 1024, 238 * 1024)
        s._swap_sizes = lambda: (None, 0)
        _pin_swapfile(False)
        check("No-swap host under demand pressure is flagged",
              any("no swap" in issue for issue in s._production_issues()))
        s._swap_sizes = lambda: (None, 1024)
        check("Host with a foreign swap partition is not flagged",
              not any("swap" in issue for issue in s._production_issues()))
        # The nag names OUR file's size from /proc/swaps — with a partition
        # alongside, SwapTotal printed a number the swapfile does not have.
        _pin_swapfile(True)
        s._swap_sizes = lambda: (600, 1024)
        flagged = [i for i in s._production_issues() if "swapfile" in i]
        check("An undersized swapfile is named by its own size, not SwapTotal",
              flagged and "swapfile 600 MB" in flagged[0])
    finally:
        s._meminfo       = saved_meminfo
        s._swap_sizes    = saved_sizes
        s.os.path.exists = saved_exists_hh

    # The half-built pull channel used to be one of the conditions this
    # function reported. With the channel retired there is no half-state to
    # report, and a stale sentence about one would be worse than silence.
    check("No issue mentions the retired publish channel",
          not any("publish channel" in issue for issue in s._production_issues()))

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
    import datetime as _dt
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



# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def run_platform_tests(s):
    # The macOS session-mode seam: every branch keyed on _IS_MACOS, exercised
    # both ways by forcing the flag — these run identically on any host, so a
    # green Linux CI actually covers the macOS branches.
    section("Platform seam (_IS_MACOS)")
    check("_IS_MACOS reflects sys.platform", s._IS_MACOS == sys.platform.startswith("darwin"))

    saved_flag = s._IS_MACOS
    try:
        s._IS_MACOS = True
        # Session mode never elevates: the data directory is the operator's own
        # and there is no systemd, so a sudo prompt would be for nothing — the
        # bug this pins was every privileged-on-Linux command demanding a
        # password on macOS and then writing root-owned files into ~/.servette.
        check("macOS: no command elevates",
              not any(s._needs_root(c) for c in
                      ("setup", "config", "set", "pull", "restore-site", "start", "stop")))
        saved_unreadable_mac = s.config.unreadable
        try:
            s.config.unreadable = True
            check("...except to read a config the sudo era left root-owned",
                  s._needs_root("status"))
        finally:
            s.config.unreadable = saved_unreadable_mac

        # _ensure_swap: inert on macOS even when RAM numbers would recommend swap
        saved_meminfo = s._meminfo
        # (MemTotal, MemAvailable, Committed_AS): a small-RAM host committed
        # past its own memory — would offer swap on Linux.
        s._meminfo = lambda: (512 * 1024, 100 * 1024, 400 * 1024)
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                s._ensure_swap()   # must return without prompting (any prompt would block/EOFError)
            check("_ensure_swap is inert on macOS", buf.getvalue() == "")
        finally:
            s._meminfo = saved_meminfo

        # cmd_log: macOS explains where the log lives instead of asking about systemd
        saved_run = s.subprocess.run
        def _raise_fnf(*a, **k): raise FileNotFoundError()
        s.subprocess.run = _raise_fnf
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                s.cmd_log()
            check("cmd_log names the terminal on macOS", "No journal on macOS" in buf.getvalue())
            s._IS_MACOS = False
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                s.cmd_log()
            check("cmd_log keeps the systemd question on Linux", "systemd" in buf.getvalue())
        finally:
            s.subprocess.run = saved_run

        # cmd_start: macOS never offers the systemd-only service install
        s._IS_MACOS = True
        saved = (s._service_file_exists, s.start_server, s._server_running, s._prompt)
        s._service_file_exists = lambda: False
        s.start_server         = lambda: None
        s._server_running      = lambda: True
        s._prompt              = lambda *a: check("cmd_start must not prompt on macOS", False) or False
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                s.cmd_start()
            # Two lines, and the second says only what the first does not:
            # there is no service to install here, and tmux is the substitute.
            out = buf.getvalue()
            check("cmd_start explains session mode on macOS",
                  "session only" in out and "needs Linux" in out
                  and "tmux" in out and out.count("when you quit") == 1)
        finally:
            s._service_file_exists, s.start_server, s._server_running, s._prompt = saved

        # _runtime_stats: the macOS memory row comes from ps and parses as MB
        class _PsOut:
            stdout = "51200\n"   # KB → 50.0 MB
        saved_run = s.subprocess.run
        s.subprocess.run = lambda *a, **k: _PsOut()
        try:
            rows = dict(s._runtime_stats(False))
            check("_runtime_stats memory via ps on macOS", rows.get("Memory") == "50.0 MB")
        finally:
            s.subprocess.run = saved_run
    finally:
        s._IS_MACOS = saved_flag


# The write primitives. A module base is required for the ambiguous names, so
# text.replace() is not mistaken for os.replace(); extractall and the pathlib
# writers are unambiguous and counted wherever they appear.
_WRITE_MODULES = {"os", "shutil", "tarfile", "path"}
_WRITE_CALLS   = {"makedirs", "mkdir", "remove", "unlink", "rmdir", "replace",
                  "rename", "rmtree", "copytree", "copy2", "copyfile", "chmod",
                  "chown", "symlink", "truncate"}
_WRITE_ANYWHERE = {"extractall", "write_text", "write_bytes"}


def _writing_functions(module_src):
    """Every function in the program that writes to the filesystem, as
    {name: {primitives}}. Read from the syntax tree rather than by grep, so a
    write cannot hide behind a line break or an unusual spelling."""
    import ast
    found = {}
    for node in ast.walk(ast.parse(module_src)):
        if not isinstance(node, ast.FunctionDef):
            continue
        writes = set()
        for n in ast.walk(node):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if isinstance(f, ast.Attribute) and f.attr in _WRITE_ANYWHERE:
                writes.add(f.attr)
            elif isinstance(f, ast.Attribute) and f.attr in _WRITE_CALLS:
                base = f.value
                root = base.id if isinstance(base, ast.Name) else (
                    base.attr if isinstance(base, ast.Attribute) else None)
                if root in _WRITE_MODULES:
                    writes.add(f.attr)
            elif isinstance(f, ast.Name) and f.id == "open":
                mode = ""
                if len(n.args) > 1 and isinstance(n.args[1], ast.Constant):
                    mode = n.args[1].value or ""
                for kw in n.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = kw.value.value or ""
                if any(c in mode for c in "wax+"):
                    writes.add("open-for-write")
        if writes:
            found[node.name] = writes
    return found


def run_invariant_tests(s, serve_dir, tmpdir):
    """The three claims the documents lean on hardest, each pinned so the
    sentence and the check move together. Verified by hand once and tracked by
    nothing since, which is how a true sentence becomes a stale one (#93)."""
    sys.path.insert(0, os.path.join(SERVETTE_DIR, "src"))
    import build

    section("Invariant: writes are where the design says they are")

    # The detector first, on source written to trip it: a pin that cannot fail
    # pins nothing, and the ambiguous names are the risk in both directions.
    probe_src = (
        "def writes():\n    os.replace(a, b)\n\n"
        "def also_writes():\n    open(p, 'w')\n\n"
        "def unpacks():\n    tar.extractall(d)\n\n"
        "def reads_only():\n    open(p, 'rb')\n\n"
        "def just_a_string():\n    return s.replace('a', 'b')\n")
    found = _writing_functions(probe_src)
    check("The write detector sees os.replace, a write-mode open, and extractall",
          set(found) == {"writes", "also_writes", "unpacks"})
    check("...and does not mistake str.replace or a read for a write",
          "just_a_string" not in found and "reads_only" not in found)

    module_src = build.build(os.path.join(SERVETTE_DIR, "src"))
    writers = _writing_functions(module_src)

    # The whole write surface, frozen. A new writer anywhere in the program
    # fails this until it is added here — which is the point: it forces someone
    # to say which of the claims below it belongs to.
    expected = {
        # Site content: the publish pipeline, and nothing else. _land_bundle
        # is the shared landing every channel funnels through — pull after
        # its signature check, the loopback page after its pairing code —
        # and _drop_backup retires the pre-ring backup marker for both the
        # flip era (a symlink) and the era before it (a directory).
        # _restore_site flips the link to a kept version and _prune_versions
        # drops the trees past the ring's depth — the only writer that
        # deletes content an operator might still want, which is why it
        # never touches the live tree. _adopt_legacy_slots renames a
        # two-slot site's idle trees into the ring rather than deleting
        # them. _remove_site deletes a removed site's server copies (derived
        # from the operator's originals; deactivation is the keep-everything
        # path), sparing folders another site still points at.
        "_land_bundle", "_swap_site_content", "_restore_site",
        "_prune_versions", "_adopt_legacy_slots",
        "_drop_backup", "_remove_site",
        # A preview is a draft nobody published: staged beside the site's
        # tree, never inside it, and cleared when the command that made it
        # exits. It writes content, so it is claimed here — but never the
        # live tree, which is the whole point of previewing.
        "_stage_preview", "_clear_previews",
        # A site FOLDER, created empty — setup must never leave nothing to
        # serve, and a page-added site gets a Servette-named folder because
        # the folder is not a question an operator should have to answer.
        "cmd_setup", "_invent_site_dir",
        # Servette's own state: config, certificates, the ACME account.
        "save", "_generate_self_signed_cert", "_ensure_default_cert",
        "_obtain_trusted_cert", "_persist_issued_cert", "issue",
        # Writes no content — sets the config's mode, which is a write all the
        # same, and the one kind of write the detector should never let past
        # unclaimed on a file holding a password hash.
        "_chown_config",
        # The host, at install time and as root.
        "_write_unit_files", "_build_runtime", "_commit_runtime", "cmd_disable",
        "_apply_swapfile", "_make_swapfile",
        # Staging: unpacks a verified bundle into a temporary directory.
        "_extract_bundle",
        # Removes a site's own generated certificate when the site goes.
        "_config_add_site",
    }
    surprise = set(writers) - expected
    missing  = expected - set(writers)
    check("The program's write surface is exactly what is pinned here",
          not surprise and not missing)
    if surprise:
        print(f"      new writers, unclaimed by any invariant: {sorted(surprise)}")
    if missing:
        print(f"      pinned writers that no longer write: {sorted(missing)}")

    # Which of those touch site CONTENT is carried by the exact-surface pin
    # above: the expected set names each writer's claim, and a new content
    # writer would surface there as an unclaimed surprise. (An earlier
    # check here restated "only the publish channel writes content" with a
    # condition that intersected two literal sets from this test — it could
    # not fail, so it is gone.)

    section("Invariant: no request ever reaches a write")

    # Not argued from the code — attempted. Every write primitive is made to
    # raise, then a battery of requests runs. Anything that tried to write would
    # fail its own response, so the statuses are the evidence.
    denied = []

    def _deny(name):
        def fail(*a, **k):
            denied.append(name)
            raise AssertionError(f"a request reached {name}")
        return fail

    saved_os = {n: getattr(s.os, n) for n in
                ("makedirs", "mkdir", "remove", "unlink", "rmdir", "replace",
                 "rename", "chmod", "chown")}
    saved_sh = {n: getattr(s.shutil, n) for n in ("rmtree", "copytree", "copy2")}
    real_open = open

    def guarded_open(f, mode="r", *a, **k):
        if any(c in mode for c in "wax+"):
            denied.append(f"open({mode})")
            raise AssertionError(f"a request opened {f} for writing")
        return real_open(f, mode, *a, **k)

    with open(os.path.join(serve_dir, "index.html"), "w") as f:
        f.write(TEST_HTML)
    s._file_cache.clear()
    before = sorted((p, os.stat(os.path.join(dp, p)).st_mtime)
                    for dp, _d, fs in os.walk(serve_dir) for p in fs)
    try:
        for n, fn in saved_os.items():
            setattr(s.os, n, _deny(f"os.{n}"))
        for n, fn in saved_sh.items():
            setattr(s.shutil, n, _deny(f"shutil.{n}"))
        s.open = guarded_open

        battery = [
            ("GET",  "/",                     200),
            ("GET",  "/index.html",            200),
            ("HEAD", "/index.html",            200),
            ("GET",  "/nothing-here",          404),   # the embedded error page
            ("GET",  "/.well-known/servette-check", 200),  # the reserved check page
            ("POST", "/index.html",            405),
            ("GET",  "/../etc/passwd",         403),
            ("GET",  "/.well-known/servette",  404),   # no password on this site
        ]
        statuses = []
        for method, path, want in battery:
            got = req(method, path=path)
            statuses.append((method, path, got.status, want))
        etag = req("GET", path="/index.html").headers.get("ETag", "")
        cond = req("GET", path="/index.html", headers={"If-None-Match": etag}).status
        gz   = req("GET", path="/index.html", headers={"Accept-Encoding": "gzip"}).status

        check("Every kind of response completes with no write attempted",
              all(g == w for _m, _p, g, w in statuses) and not denied)
        for m, p, g, w in statuses:
            if g != w:
                print(f"      {m} {p} → {g}, expected {w}")
        check("...including a revalidation and a compressed response",
              cond == 304 and gz == 200 and not denied)

        # The guards themselves, proven live — otherwise the section above
        # passes just as well with them doing nothing at all. Probed with calls
        # that write nothing even when permitted: driving a real writer through
        # them left half-written temp files in the data directory.
        caught = 0
        for attempt in (lambda: s.os.remove(os.path.join(tmpdir, "nothing")),
                        lambda: s.open(os.path.join(tmpdir, "nothing"), "w")):
            try:
                attempt()
            except AssertionError:
                caught += 1
            except Exception:
                pass
        check("The guards are real: a write outside the request path is caught",
              caught == 2)
        denied.clear()
    finally:
        for n, fn in saved_os.items():
            setattr(s.os, n, fn)
        for n, fn in saved_sh.items():
            setattr(s.shutil, n, fn)
        s.__dict__.pop("open", None)

    after = sorted((p, os.stat(os.path.join(dp, p)).st_mtime)
                   for dp, _d, fs in os.walk(serve_dir) for p in fs)
    check("...and the served directory is byte-for-byte untouched", before == after)

    section("Invariant: the wheel is Python only")

    # The error page is inlined at build time so an operator cannot delete it.
    # That only holds while nothing rides along as data — and with the program
    # as one module, "nothing beside it" is now structural: py-modules ships
    # exactly the named file, so the first check is that pyproject still says
    # py-modules and not packages.
    with open(os.path.join(SERVETTE_DIR, "pyproject.toml"), encoding="utf-8") as f:
        py_settings = [l.split("#", 1)[0] for l in f.read().splitlines()]
    check("The program ships as a single module (py-modules, not packages)",
          any("py-modules" in l and "servette" in l for l in py_settings)
          and not any(l.strip().startswith("packages") for l in py_settings))

    with open(os.path.join(SERVETTE_DIR, "pyproject.toml"), encoding="utf-8") as f:
        # Declarations only. A comment saying there is no package data is not a
        # declaration of package data — the first version of this check read the
        # words rather than the settings, and failed on the comment explaining
        # why the setting is absent.
        settings = [l.split("#", 1)[0] for l in f.read().splitlines()]
    check("pyproject declares no package data to carry",
          not any("package-data" in l or "include-package-data" in l for l in settings))

    # `build` cannot be probed by importing it: this suite puts src/ on the path,
    # where build.py is Servette's own. Asking the interpreter to run the module
    # resolves it the way the release does.
    #
    # A stale ./build/lib from an older layout fails the wheel check below —
    # setuptools sweeps leftovers into the wheel. That is a true positive (the
    # wheel really would carry them); `rm -rf build` is the fix, and this very
    # check is what caught the residue when the layout changed.
    probe = subprocess.run([sys.executable, "-m", "build", "--version"],
                           capture_output=True, text=True, cwd=SERVETTE_DIR)
    if probe.returncode == 0:
        out = os.path.join(tmpdir, "wheel")
        r = subprocess.run([sys.executable, "-m", "build", "--wheel",
                            "--no-isolation", "--outdir", out, SERVETTE_DIR],
                           capture_output=True, text=True)
        wheels = [w for w in os.listdir(out)] if os.path.isdir(out) else []
        if r.returncode == 0 and wheels:
            import zipfile
            with zipfile.ZipFile(os.path.join(out, wheels[0])) as z:
                names = z.namelist()
            program = [n for n in names if not n.split("/")[0].endswith(".dist-info")]
            check("The built wheel's program is exactly servette.py",
                  program == ["servette.py"])
            if program != ["servette.py"]:
                print(f"      wheel carries: {program}")
        else:
            print("  ‣ skipped building a wheel: python -m build failed here "
                  f"(exit {r.returncode})")
    else:
        print("  ‣ skipped building a wheel: the `build` module is not installed. "
              "The two checks above still hold the invariant.")


def run_doc_check_tests(tmpdir):
    """The docs checker, checked. A gate nothing exercises is a gate that can
    quietly stop gating: an over-eager pattern gets it switched off, and a
    too-narrow one passes everything. Both failure modes are tested here."""
    section("The docs checker (build.py --check-docs)")

    sys.path.insert(0, os.path.join(SERVETTE_DIR, "src"))
    import build

    hay = "def _needs_root(cmd):\n    pass\n--check-counts\n"

    # It must judge only the shapes it can judge. Prose, header names and TOML
    # keys live in backticks too, and guessing at them is what produces the
    # false positives that get a check turned off for good.
    check("A real file resolves",
          build.token_problem("README.md", "DESIGN.md", SERVETTE_DIR, hay) is None)
    check("A file named from the document beside it resolves",
          build.token_problem("build.py", "src/SHELL.md", SERVETTE_DIR, hay) is None)
    check("A file named by basename alone resolves",
          build.token_problem("test.py", "DESIGN.md", SERVETTE_DIR, hay) is None)
    check("A file that no longer exists is caught",
          build.token_problem("src/diagnostics.html", "DESIGN.md", SERVETTE_DIR, hay)
          == "no such file in the repository")
    check("An identifier in the program resolves",
          build.token_problem("_needs_root()", "DESIGN.md", SERVETTE_DIR, hay) is None)
    check("An identifier that does not exist is caught",
          build.token_problem("_gone_away", "DESIGN.md", SERVETTE_DIR, hay)
          == "not in the program, the build, or the suite")
    check("A flag a tool accepts resolves",
          build.token_problem("--check-counts", "DESIGN.md", SERVETTE_DIR, hay) is None)
    check("A flag no tool accepts is caught",
          build.token_problem("--invented", "DESIGN.md", SERVETTE_DIR, hay)
          == "no tool accepts that flag")
    for prose in ("HSTS", "TLS", "Cache-Control", "pip install servette",
                  "serve_dir", "/var/lib/servette", "~/.local/bin",
                  "https://servette.org"):
        if prose == "serve_dir":
            continue        # a real config key AND a real identifier; judged
        check(f"Not judged: `{prose}`",
              build.token_problem(prose, "DESIGN.md", SERVETTE_DIR, hay) is None)

    # Fenced code is the thing being documented, not a claim about it.
    md = "before\n\n```python\n_only_in_a_fence = 1\n```\n\n> a comment\nafter\n"
    check("Fenced code is not scanned",
          "_only_in_a_fence" not in build._prose_only(md))
    check("Prose around a fence is",
          "before" in build._prose_only(md) and "after" in build._prose_only(md))
    check("A blockquote is code for src/*.md and dropped there",
          "a comment" not in build._prose_only(md, drop_blockquotes=True)
          and "a comment" in build._prose_only(md))

    # GitHub hyphenates per space, not per run of spaces, so a heading with an
    # ampersand anchors with the gap it leaves.
    check("An anchor slug matches GitHub's, ampersand and all",
          build._slug("## Scope & non-goals") == "scope--non-goals")
    check("...and a plain heading's",
          build._slug("### Releasing (maintainer task)") == "releasing-maintainer-task")

    # `log [n]` in the README and ("log [n]", …) in the shell are one claim.
    check("Command names are read without their argument specs",
          build._command_names('_COMMANDS = [\n    ("log [n]", "x"),\n'
                               '    ("setup", "y"),\n]\n', "_COMMANDS")
          == {"log", "setup"})
    check("A renamed command list reads as empty rather than as agreement",
          build._command_names("nothing here", "_COMMANDS") == set())

    # Litter must not satisfy the checker — in tracked mode. The tracked set is
    # INJECTED, because whether the host has git must not decide what this test
    # asserts: Debian's CI container ships no git, its checkout is a downloaded
    # tarball with no .git, and there the checker legitimately runs in its
    # filesystem-fallback mode — where this file resolving is the documented
    # behavior, not the failure. Both modes are pinned.
    litter = os.path.join(SERVETTE_DIR, "litter-probe-only.md")
    with open(litter, "w") as f:
        f.write("x")
    saved_tracked = dict(build._TRACKED_CACHE)
    try:
        build._TRACKED_CACHE[SERVETTE_DIR] = {"README.md"}    # tracked mode
        check("Tracked mode: an untracked file at the root does not resolve",
              build.token_problem("litter-probe-only.md", "DESIGN.md",
                                  SERVETTE_DIR, "") == "no such file in the repository")
        build._TRACKED_CACHE[SERVETTE_DIR] = None             # no git to ask
        check("Fallback mode (no git): the filesystem answers instead",
              build.token_problem("litter-probe-only.md", "DESIGN.md",
                                  SERVETTE_DIR, "") is None)
    finally:
        build._TRACKED_CACHE.clear()
        build._TRACKED_CACHE.update(saved_tracked)
        os.remove(litter)

    # The interpreter-version probe runs once per path, not per ask — the
    # staleness chain asks several times per launch, and each ask used to
    # spawn every candidate interpreter again.
    probe_calls = []
    fake = os.path.join(tmpdir, "never-a-python")
    import servette as s_mod
    saved_srun2 = s_mod.subprocess.run
    def counting_run(argv, **k):
        probe_calls.append(argv)
        raise OSError("no such interpreter")
    try:
        s_mod.subprocess.run = counting_run
        r1 = s_mod._python_minor(fake)
        r2 = s_mod._python_minor(fake)
        check("A failed interpreter probe is asked once and remembered",
              r1 is None and r2 is None and len(probe_calls) == 1)
    finally:
        s_mod.subprocess.run = saved_srun2

    # And the gate itself, against the real repository.
    with contextlib.redirect_stdout(io.StringIO()) as out:
        rc = build.check_docs(os.path.join(SERVETTE_DIR, "src"), SERVETTE_DIR)
    check("Every name the documents state resolves", rc == 0)
    if rc != 0:
        print(out.getvalue())


def run_browser_tests(s, tmpdir):
    """Load the admin page in a real browser and drive it.

    Every other check in this file reads the page as TEXT — that a tab
    exists, that an endpoint is named, that no browser dialog is called.
    None of them execute a line of its JavaScript, so a typo'd identifier,
    a selector that no longer matches, or a token in the wrong half of a
    URL passes every one of them and reaches an operator. Four such bugs
    reached this branch and were caught by hand in a browser:

      - cardIndex() answered -1 while a card was still being built, so the
        first version fetch asked for site -1;
      - the preview token sat in the query, where a draft's own relative
        links drop it, so the page loaded and every stylesheet was refused;
      - the running dot lost its styling when the status row moved, and was
        present in the markup and invisible;
      - a path and its count rendered with nothing between them.

    This runs only where Playwright and a browser are installed. Absent
    either, it reports itself skipped and the rest of the suite is
    unaffected — the dependency is real and a contributor should not need
    it to run the tests. CI installs it, so it gates there.
    """
    section("The admin page, in a browser (skipped without Playwright)")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("  ·  skipped: pip install playwright && playwright install chromium")
        return

    # The site the page will describe: a real published history, so the
    # version list, the restore buttons, and the sizes all have something
    # to render rather than an empty state that proves little.
    site = s.config.sites[0]
    saved = (site.serve_dir, site.domain, dict(site.redirects))
    root = tempfile.mkdtemp(dir=tmpdir)
    httpd = None
    try:
        site.domain = "browser-check.test"
        site.serve_dir = os.path.join(root, "site")
        for n, text in enumerate(["one", "two"], 1):
            d = os.path.join(root, f"v{n}")
            os.makedirs(d)
            with open(os.path.join(d, "index.html"), "w") as f:
                f.write(f"<h1 id=live>{text}</h1>")
            s._swap_site_content(d, site.serve_dir)
            time.sleep(1.05)      # distinct publish seconds, so the ring orders

        port = _free_port()
        httpd, code = s._start_ui(site, s._UI_ADMIN_PAGE, port=port)
        base = f"http://127.0.0.1:{port}"

        console = []
        with sync_playwright() as pw:
            # `playwright install chromium` puts the browser where launch()
            # looks, which is what CI does. SERVETTE_TEST_BROWSER names one
            # already on the box, for an environment that ships a browser
            # but not the build this Playwright expects.
            try:
                browser = pw.chromium.launch()
            except Exception as first:
                alt = os.environ.get("SERVETTE_TEST_BROWSER", "")
                if not alt:
                    print("  ·  skipped: no browser available "
                          f"({str(first).splitlines()[0][:60]})")
                    return
                try:
                    browser = pw.chromium.launch(executable_path=alt)
                except Exception as e:
                    print(f"  ·  skipped: SERVETTE_TEST_BROWSER unusable ({e})")
                    return
            page = browser.new_page()
            page.on("console", lambda m: console.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: console.append("pageerror: " + str(e)))
            page.goto(f"{base}/?t={code}")
            page.wait_for_timeout(1500)

            check("The page runs: the app is visible and one card is rendered",
                  page.is_visible("#app")
                  and page.locator("#site-cards .site-card").count() == 1)

            # The bug a text pin cannot see: a card asking for site -1.
            vs = page.locator(".ver-state").first.inner_text()
            check("...the version state rendered, so its site index resolved",
                  "·" in vs and vs.strip().endswith("B"))
            # History is one dropdown with a single Restore that acts on
            # the selection: dim while the live version is selected, armed
            # the moment another one is.
            check("...with history a dropdown whose Restore arms off the live pick",
                  page.evaluate("""() => {
                    const pick = document.querySelector('.ver-pick');
                    const b = document.querySelector('.ver-restore');
                    if (!pick || !b || pick.options.length !== 2) return false;
                    if (!b.disabled) return false;
                    const other = [...pick.options].find(o => !o.selected);
                    pick.value = other.value;
                    pick.dispatchEvent(new Event('change'));
                    return !b.disabled;
                  }"""))

            # The dot is markup either way; only CSS decides it is a dot.
            check("...and the running dot is a dot where the status row puts it",
                  page.evaluate("""() => {
                    const el = document.getElementById('status-state');
                    el.innerHTML = '<span class=dot></span>running';
                    const c = getComputedStyle(el.querySelector('.dot'));
                    return c.width === '7px' && c.borderRadius === '50%';
                  }"""))

            # The load meter samples from login, not from first opening the
            # Statistics tab: its rows are already rendered while Sites is
            # still the visible panel.
            check("...the load meter is sampling before the stats tab is opened",
                  page.evaluate(
                      "() => document.getElementById('load-rows').innerHTML !== ''"))

            # The Serving link left .rows for its own switch-row; an anchor
            # no rule reaches falls back to the browser default — visited
            # purple. The pin is computed colour, which a text pin cannot
            # see.
            check("...the serving link wears the page's colour, not the browser's",
                  page.evaluate("""() => {
                    const a = document.querySelector('.serving-state a');
                    if (!a) return false;
                    const probe = document.createElement('span');
                    probe.style.color = 'var(--brand)';
                    document.body.appendChild(probe);
                    const want = getComputedStyle(probe).color;
                    probe.remove();
                    return getComputedStyle(a).color === want;
                  }"""))

            for tab in ("server", "stats", "sites"):
                page.click(f"#tab-{tab}")
                page.wait_for_timeout(700)
                check(f"...the {tab} tab renders",
                      page.is_visible(f"#panel-{tab if tab != 'sites' else 'sites'}"))

            # The address is the deep link the tabs promise: hash carries
            # the tab, search keeps the passcode OUTSIDE the fragment, and
            # a reload lands on the tab the address names — the old
            # '#tab?t=CODE' shape parsed back as no tab at all.
            page.click("#tab-server")
            page.wait_for_timeout(400)
            check("...the address carries the tab beside the search, not around it",
                  page.evaluate("() => location.hash") == "#server"
                  and page.evaluate("() => location.search").startswith("?t="))
            page.reload()
            page.wait_for_timeout(1200)
            check("...and a reload lands on the tab the address names",
                  page.is_visible("#panel-server")
                  and not page.is_visible("#panel-sites"))
            page.click("#tab-sites")
            page.wait_for_timeout(700)

            # The remove panel: drawn by the page, and where the button is.
            page.locator("button.del").first.click()
            page.wait_for_timeout(300)
            box_b = page.locator("button.del").first.bounding_box()
            box_p = page.locator(".site-card .confirm").first.bounding_box()
            check("...the remove panel opens under the button that opens it",
                  box_p is not None
                  and 0 < box_p["y"] - (box_b["y"] + box_b["height"]) < 60)
            page.locator(".do-cancel").first.click()

            # Folding: the body goes, the head stays — so a folded card
            # still says which site it is and whether it needs attention.
            page.locator("button.fold").first.click()
            page.wait_for_timeout(300)
            check("...folding hides the body and keeps the head",
                  not page.locator(".site-card .card-body").first.is_visible()
                  and page.locator(".site-card .card-title").first.is_visible())
            # It has to survive a re-render, or every save would spring it
            # open again.
            page.click("#tab-server")
            page.wait_for_timeout(600)
            page.click("#tab-sites")
            page.wait_for_timeout(900)
            check("...and survives the re-render that follows every op",
                  not page.locator(".site-card .card-body").first.is_visible())
            page.locator("button.fold").first.click()
            page.wait_for_timeout(300)
            check("...unfolding brings it back",
                  page.locator(".site-card .card-body").first.is_visible())

            # A fault is said once, on the row that carries its fix, plus
            # the head pill a folded card still shows. Counting them a third
            # time above the rows made one certificate read as three
            # problems. This needs a site that HAS a fault: asserting the
            # absence of a count on a healthy card proves nothing, which is
            # exactly how the first version of this check passed.
            saved_cert = s.config.sites[0].cert_file
            try:
                s.config.sites[0].cert_file = ""      # nothing trusted to present
                page.click("#tab-server")
                page.wait_for_timeout(400)
                page.click("#tab-sites")
                page.wait_for_timeout(900)
                info = page.locator(".info").first.inner_text()
                # Two indicators for one fault, and exactly two: the Status
                # line, which is also the only place the card says it is
                # well, and the row that carries the fix. The head pill is
                # the folded card's Status line, so it must be hidden while
                # this one is showing.
                check("...a faulted card counts it once and marks it once",
                      "1 to review" in info
                      # The count does not name its members — each is named
                      # on its own row, and four of them would be unreadable.
                      and "certificate" not in info.lower()
                      and page.locator(".cert-state .warn, .cert-state .fault"
                                       ).count() == 1
                      and not page.locator(".badge.needs").first.is_visible())
                # Folded, the pill takes over — the count does not vanish
                # just because the body is hidden.
                page.locator("button.fold").first.click()
                page.wait_for_timeout(300)
                check("...and folding hands that count to the pill",
                      page.locator(".badge.needs").first.is_visible())
                page.locator("button.fold").first.click()
                page.wait_for_timeout(300)
            finally:
                s.config.sites[0].cert_file = saved_cert
                page.click("#tab-sites")
                page.wait_for_timeout(800)

            # The pill mirrors the Status line both ways (the ruled shape):
            # a healthy folded card wears the green all-clear rather than
            # nothing, so an empty head never has to mean two things.
            page.locator("button.fold").first.click()
            page.wait_for_timeout(300)
            _pill = page.locator(".badge.needs").first
            check("A healthy folded card wears the green all-clear pill",
                  _pill.is_visible() and "healthy" in _pill.inner_text()
                  and "badge-green" in (_pill.get_attribute("class") or ""))
            page.locator("button.fold").first.click()
            page.wait_for_timeout(300)

            # An unfinished login is treated as exactly what every other
            # thing to review is treated as: counted once, marked once on
            # the row that fixes it, with no third register anywhere. The
            # card said "healthy" beside a red refusal before this.
            # Every fault state, walked in one place, because the model is
            # only right if it is right for all of them: a count, and one
            # mark on the row that fixes it. Nothing else, ever.
            saved_state = (s.config.sites[0].cert_file,
                           s.config.sites[0].serve_dir,
                           s.config.sites[0].username,
                           s.config.sites[0].password_hash)
            def _card_marks():
                page.reload(); page.wait_for_timeout(1400)
                return page.evaluate("""() => {
                  const c = document.querySelector('.site-card');
                  const at = (sel) => !!c.querySelector(sel + ' .warn, ' + sel + ' .fault');
                  return {status: c.querySelector('.info').innerText,
                          cert: at('.cert-state'), access: at('.auth-state'),
                          published: at('.ver-state')};
                }""")
            try:
                site0 = s.config.sites[0]
                site0.cert_file = ""
                m = _card_marks()
                check("...a certificate fault: counted once, marked on its own row",
                      "1 to review" in m["status"] and m["cert"]
                      and not m["access"] and not m["published"])
                site0.cert_file = saved_state[0]
                site0.serve_dir = "gone-xyz"
                m = _card_marks()
                check("...a missing folder: marked where publishing would fix it",
                      "1 to review" in m["status"] and m["published"]
                      and not m["cert"] and not m["access"])
                site0.serve_dir = saved_state[1]
                site0.username, site0.password_hash = "someone", ""
                m = _card_marks()
                check("...a half-authenticated site: marked on the access row",
                      "1 to review" in m["status"] and m["access"]
                      and not m["cert"] and not m["published"])
                site0.cert_file = ""
                site0.serve_dir = "gone-xyz"
                m = _card_marks()
                check("...and three at once count three and mark three",
                      "3 to review" in m["status"]
                      and m["cert"] and m["access"] and m["published"])
            finally:
                (site0.cert_file, site0.serve_dir,
                 site0.username, site0.password_hash) = saved_state
                page.reload(); page.wait_for_timeout(1400)

            # The walk above reloaded the page, so the switch is back where
            # it started; flip it again for the checks that follow.
            page.locator(".auth-switch").first.check()
            page.wait_for_timeout(400)
            info = page.locator(".info").first.inner_text()
            check("...an unfinished login counts, and the card stops saying healthy",
                  "1 to review" in info and "healthy" not in info
                  and page.locator(".auth-state .warn, .auth-state .fault"
                                   ).count() == 1)
            check("...with Save dim rather than a refusal to print",
                  page.locator("button.save-site").first.is_disabled()
                  and not page.locator(".site-card .error").first.is_visible())
            # This card was HEALTHY when it was built, so its pill exists
            # only because a hidden one is always emitted — a client-side
            # fault has no rebuild to emit one, and a folded card's Status
            # row is the pill or nothing.
            page.locator("button.fold").first.click()
            page.wait_for_timeout(300)
            pill_loc = page.locator(".site-card .badge.needs").first
            check("...and folding a card faulted client-side still shows the pill",
                  pill_loc.is_visible()
                  and "1 to review" in pill_loc.inner_text())
            page.locator("button.fold").first.click()
            page.wait_for_timeout(300)
            # Typing the login completes it, so the count follows.
            page.locator("#cfg-username-0").fill("someone")
            page.locator("#cfg-password-0").fill("a-password")
            page.wait_for_timeout(300)
            check("...and completing it clears the count and frees Save",
                  "healthy" in page.locator(".info").first.inner_text()
                  and not page.locator("button.save-site").first.is_disabled())
            page.locator(".auth-switch").first.uncheck()
            page.wait_for_timeout(300)

            # Preview: staged, framed, and its relative assets resolving —
            # the check that would have caught the token-in-the-query bug.
            draft = tempfile.mkdtemp(dir=tmpdir)
            with open(os.path.join(draft, "index.html"), "w") as f:
                f.write("<h1 id=d>DRAFT</h1><link rel=stylesheet href=s.css>")
            with open(os.path.join(draft, "s.css"), "w") as f:
                f.write("h1{color:rgb(1,2,3)}")
            page.set_input_files('input[type="file"]', draft)
            page.wait_for_timeout(600)
            page.locator("button.prev").first.click()
            page.wait_for_timeout(2000)
            # One line — date · size is short enough never to reach the
            # button (ruled: no file counts) — and the row centres its
            # label and button against it.
            check("...the published line is one line, clear of its button",
                  page.evaluate("""() => {
                    const st = document.querySelector('.ver-state');
                    const rows = st.querySelectorAll('span');
                    if (rows.length !== 1) return false;
                    const a = rows[0].getBoundingClientRect();
                    const btn = document.querySelector('.switch-act button.ver-refresh')
                                        .getBoundingClientRect();
                    return a.right <= btn.left &&
                           Math.abs((btn.top + btn.bottom) / 2 -
                                    (a.top + a.bottom) / 2) < 6;
                  }"""))
            # The staged draft opens in its own tab (ruled: a 420px frame
            # was not an honest representation). The link's address carries
            # the preview token in the path and never the run's passcode,
            # and noopener leaves the draft's tab no handle back to the
            # page that staged it.
            open_link = page.locator("a.preview-open").first
            href = open_link.get_attribute("href") or ""
            check("...a staged preview offers its own tab, passcode-free",
                  href.startswith("/preview/") and code not in href
                  and (open_link.get_attribute("rel") or "") == "noopener")
            with page.context.expect_page() as popped:
                open_link.click()
            draft_tab = popped.value
            draft_tab.wait_for_load_state()
            check("...the preview tab renders the chosen draft",
                  draft_tab.locator("#d").inner_text() == "DRAFT")
            check("...with its relative stylesheet resolving",
                  draft_tab.locator("#d").evaluate(
                      "e => getComputedStyle(e).color") == "rgb(1, 2, 3)")
            check("...and the tab holds no handle back to the admin page",
                  draft_tab.evaluate("() => window.opener === null"))
            draft_tab.close()

            # A redirect, added and removed through the page's own form.
            page.locator("button.redir-add").first.click()
            page.wait_for_timeout(200)
            page.locator(".redir-from").first.fill("/browser-check")
            page.locator(".redir-to").first.fill("/index.html")
            page.locator("button.redir-save").first.click()
            page.wait_for_timeout(1500)
            check("...a redirect added through the form reaches the config",
                  "/browser-check" in s.config.sites[0].redirects)

            # A picked folder must survive the re-render that follows
            # every op. The redirect save above just re-rendered the
            # cards, and the draft was picked before it — losing it here
            # was the regression: summary reset, Publish dim, the drag to
            # be done again.
            check("...and the folder picked before that save is still read in",
                  not page.locator("button.pub").first.is_disabled()
                  and "2 files" in page.locator(".summary").first.inner_text())
            page.click("#tab-server")
            page.wait_for_timeout(500)
            page.click("#tab-sites")
            page.wait_for_timeout(900)
            check("...and it survives a tab round-trip, ready to publish",
                  not page.locator("button.pub").first.is_disabled()
                  and "2 files" in page.locator(".summary").first.inner_text())

            # The host form is never rewritten under the operator's
            # fingers: a refresh landing mid-edit must not discard typed
            # text or focus — for any field, not only the swap size.
            page.click("#tab-server")
            page.wait_for_timeout(600)
            page.locator("#cfg-email").click()
            page.locator("#cfg-email").fill("half-typed@exam")
            page.evaluate("() => renderHostFields()")
            check("...typing in any host field holds off the form rewrite",
                  page.locator("#cfg-email").input_value() == "half-typed@exam"
                  and page.evaluate(
                      "() => document.activeElement.id === 'cfg-email'"))

            # The group headers are marked apart from the field labels they
            # govern (ruled): apart by weight and the rule above, NOT by
            # colour or size — green is the page's healthy colour, so a
            # header in it read as a verdict, and a subsection must not
            # outrank the card title.
            check("...the settings groups read apart from their fields, not louder",
                  page.evaluate("""() => {
                    const gs = document.querySelectorAll('#cfg-host-fields .cfg-group');
                    const label = document.querySelector('#cfg-host-fields .cfg-field label');
                    if (gs.length < 2 || !label) return false;
                    const g0 = getComputedStyle(gs[0]);
                    const g1 = getComputedStyle(gs[1]);
                    const l = getComputedStyle(label);
                    return g0.color === l.color &&
                           g0.fontSize === l.fontSize &&
                           parseInt(g0.fontWeight) > parseInt(l.fontWeight) &&
                           parseFloat(g1.borderTopWidth) > 0;
                  }"""))

            # Caching is per-site: a literal toggle on the card (ruled:
            # two states get a switch, not a menu), on for a public site,
            # and no cache field left on the Server tab.
            page.click("#tab-sites")
            page.wait_for_timeout(300)
            check("...caching is a toggle on the card, on for a public site",
                  page.evaluate("""() => {
                    const sw = document.querySelector('.cache-switch');
                    return !!sw && sw.type === 'checkbox' && sw.checked &&
                           sw.classList.contains('switch') &&
                           !document.querySelector('.cache-mode') &&
                           !document.getElementById('cfg-cache_policy');
                  }"""))

            # The access flip's reset is said BEFORE Save (loudly, by
            # ruling): arming the switch on a public site narrates both
            # the sign-in and the caching turn-off.
            page.locator(".auth-switch").first.check()
            page.wait_for_timeout(200)
            check("...arming private narrates the caching turn-off, loudly",
                  "caching turns off"
                  in (page.locator(".auth-hint").first.text_content() or "")
                  and page.evaluate("""() => {
                    const h = document.querySelector('.auth-hint');
                    return getComputedStyle(h).color === 'rgb(251, 191, 36)';
                  }"""))
            page.locator(".auth-switch").first.uncheck()
            page.wait_for_timeout(200)

            browser.close()

        # The console is a check in itself: every failure above is silent
        # to a text pin, and most of them shout here.
        noise = [m for m in console if "favicon" not in m.lower()
                 and "404 (Not Found)" not in m]
        check("The page ran with a clean console", not noise)
        if noise:
            for m in noise[:5]:
                print(f"      {m}")
    finally:
        if httpd is not None:
            s._stop_ui(httpd)
        site.serve_dir, site.domain, site.redirects = saved
        shutil.rmtree(root, ignore_errors=True)


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
        run_platform_tests(s)
        run_invariant_tests(s, serve_dir, tmpdir)
        run_doc_check_tests(tmpdir)
        run_browser_tests(s, tmpdir)
    finally:
        teardown(tmpdir, saved_config, config_path, s)

    print(f"\n──────────────────────────────────────────────────────")
    total = _passed + _failed
    print(f"  {_passed} / {total} passed" + ("  — all good!" if _failed == 0 else f"  — {_failed} failed"))
    print(f"──────────────────────────────────────────────────────\n")

    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
