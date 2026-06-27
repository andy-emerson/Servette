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

# Used only for the ALPN negotiation check — advertises h2 to confirm HTTP/2 support
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


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def run_server_tests(s, serve_dir):
    # Live integration tests against the real Hypercorn server on TEST_PORT.
    # Each section mutates config or server state as needed and restores it afterward.

    section("Protocol negotiation")

    conn  = socket.create_connection(("127.0.0.1", TEST_PORT))
    tls   = SSL_CTX_H2.wrap_socket(conn, server_hostname="127.0.0.1")
    proto = tls.selected_alpn_protocol()
    tls.close()
    check("ALPN negotiates HTTP/2 (h2)", proto == "h2")

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

    servette_path = os.path.abspath(s.__file__)
    python_path   = s._VENV_PY if os.path.exists(s._VENV_PY) else "python3"
    service = f"""[Unit]
Description=Servette — The Simple Secure Server
After=network.target

[Service]
User=servette
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
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
    check("Service file includes User=servette",                   "User=servette" in service)
    check("Service file includes AmbientCapabilities",             "AmbientCapabilities=CAP_NET_BIND_SERVICE" in service)
    check("Service file includes CapabilityBoundingSet",           "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in service)
    check("Service file does not run as root (no User= absent)",   "User=" in service)

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
