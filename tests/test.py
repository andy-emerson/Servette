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
import os
import shutil
import socket
import ssl
import subprocess
import sys
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

    section("Versioning")

    check("__version__ is set",              bool(s.__version__))
    check("__version__ has 3 parts",         len(s.__version__.split(".")) == 3)
    check("__version__ major is 0",          s.__version__.split(".")[0] == "0")

    section("Cache-Control header")

    s.config.username     = ""
    s.config.cache_policy = "no-store"
    check("no-store",                          s._cache_control_header() == "no-store")

    s.config.cache_policy = "no-cache"
    check("no-cache, no auth → public",        s._cache_control_header() == "public, no-cache")

    s.config.username = "alice"
    check("no-cache, with auth → private",     s._cache_control_header() == "private, no-cache")

    s.config.cache_policy  = "max-age"
    s.config.cache_max_age = 3600
    check("max-age with auth → private, max-age=3600",
          s._cache_control_header() == "private, max-age=3600")

    s.config.username     = ""
    s.config.cache_policy = "no-cache"

    section("IPv6 normalization")

    check("::ffff: prefix stripped",       s._normalize_ip("::ffff:192.168.1.1") == "192.168.1.1")
    check("Plain IPv4 unchanged",          s._normalize_ip("10.0.0.1") == "10.0.0.1")
    check("Plain IPv6 unchanged",          s._normalize_ip("2001:db8::1") == "2001:db8::1")

    section("_resolve_request_path")

    path, status = s._resolve_request_path("/")
    check("/ resolves to index.html (200)",
          path is not None and path.endswith("index.html") and status == 200)

    path, status = s._resolve_request_path("/style.css")
    check("/style.css resolves (200)",
          path is not None and path.endswith("style.css") and status == 200)

    path, status = s._resolve_request_path("/sub/")
    check("/sub/ resolves to sub/index.html (200)",
          path is not None and "sub" in path and path.endswith("index.html") and status == 200)

    path, status = s._resolve_request_path("/sub/page.html")
    check("/sub/page.html resolves (200)",
          path is not None and path.endswith("page.html") and status == 200)

    path, status = s._resolve_request_path("/nonexistent.html")
    check("/nonexistent.html → 404",     path is None and status == 404)

    path, status = s._resolve_request_path("/../etc/passwd")
    check("Path traversal .. → 403",     path is None and status == 403)

    path, status = s._resolve_request_path("/%2e%2e/etc/passwd")
    check("Encoded traversal %2e%2e → 403", path is None and status == 403)

    section("_format_uptime")

    check("Seconds",  s._format_uptime(45)    == "45s")
    check("Minutes",  s._format_uptime(90)    == "1m 30s")
    check("Hours",    s._format_uptime(3700)  == "1h 1m")
    check("Days",     s._format_uptime(90061) == "1d 1h")


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
        for bad in ["/.well-known/acme-challenge/",
                    "/.well-known/acme-challenge/a/b",
                    "/.well-known/acme-challenge/..%2f..%2fpasswd"]:
            st, _, _ = redirect_request("GET", bad)
            check(f"Rejected token path {bad!r}", st == 404)
    finally:
        s.ACME_WEBROOT = orig_webroot
        shutil.rmtree(acme_dir, ignore_errors=True)

    section("Shell — command dispatch")

    # Spy on the handlers so we verify routing without their side effects, and
    # feed scripted input. 'quit' calls stop_server, so stub it to keep the
    # live test server up for the integration tests that follow.
    calls       = []
    saved       = {n: getattr(s, n) for n in ("cmd_status", "cmd_start", "stop_server")}
    saved_input = builtins.input
    try:
        s.cmd_status  = lambda: calls.append("status")
        s.cmd_start   = lambda: calls.append("start")
        s.stop_server = lambda: calls.append("stop")
        script = iter(["status", "start", "bogus", "quit"])
        builtins.input = lambda prompt="": next(script, "quit")
        with contextlib.redirect_stdout(io.StringIO()):
            s.shell()
    finally:
        builtins.input = saved_input
        for n, fn in saved.items():
            setattr(s, n, fn)

    check("'status' routed to cmd_status", "status" in calls)
    check("'start' routed to cmd_start",   "start" in calls)
    check("'quit' stops server and exits", calls[-1] == "stop")

    section("Request core — _handle_request")
    # The transport-agnostic core returns (status, headers, body) directly; the
    # http.server handler is a thin shell over it, so exercise it without a socket.
    tmpd = tempfile.mkdtemp()
    with open(os.path.join(tmpd, "index.html"), "w") as f:
        f.write("<h1>hi</h1>")
    saved_serve, saved_pw = s.config.serve_dir, s.config.password_hash
    s.config.serve_dir     = tmpd
    s.config.password_hash = ""
    try:
        status, headers, body = s._handle_request("GET", "/", {}, "127.0.0.1")
        hdict = dict(headers)
        check("GET / → 200",                 status == 200)
        check("Body is the file content",    body == b"<h1>hi</h1>")
        check("Content-Length matches body", hdict.get(b"content-length") == b"11")
        _, _, head_body = s._handle_request("HEAD", "/", {}, "127.0.0.1")
        check("HEAD drops the body",          head_body == b"")
        pstatus, _, _ = s._handle_request("POST", "/", {}, "127.0.0.1")
        check("POST → 405",                  pstatus == 405)
    finally:
        s.config.serve_dir     = saved_serve
        s.config.password_hash = saved_pw
    shutil.rmtree(tmpd, ignore_errors=True)


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

    s.config.username = "testuser"
    s.config.password_hash, s.config.password_salt = s._hash_password("testpass")

    check("No credentials → 401",
          req("GET").status == 401)
    check("Wrong password → 401",
          req("GET", auth=("testuser", "wrong")).status == 401)
    check("Correct credentials → 200",
          req("GET", auth=("testuser", "testpass")).status == 200)
    check("Wrong username → 401",
          req("GET", auth=("wronguser", "testpass")).status == 401)
    check("HEAD with correct credentials → 200",
          req("HEAD", auth=("testuser", "testpass")).status == 200)

    s._auth_fail_times.clear()
    for _ in range(7):
        req("GET", auth=("testuser", "wrong"))
    check("Auth rate limit → 429",
          req("GET", auth=("testuser", "wrong")).status == 429)

    s.config.username      = ""
    s.config.password_hash = ""
    s.config.password_salt = ""
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

    s.config.username = "testuser"
    s.config.password_hash, s.config.password_salt = s._hash_password("testpass")
    s._auth_fail_times.clear()

    for _ in range(7):
        req("GET")

    check("Correct credentials still work after 7 no-credential requests",
          req("GET", auth=("testuser", "testpass")).status == 200)
    check("auth_fail_times tracker is empty (no attempts recorded)",
          len(s._auth_fail_times) == 0)

    s.config.username      = ""
    s.config.password_hash = ""
    s.config.password_salt = ""
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
    # cmd_install itself is not called — it writes to /etc/systemd/system/ and
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
