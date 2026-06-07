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
import json
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

SERVETTE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_PORT    = 8443
BASE_URL     = f"https://127.0.0.1:{TEST_PORT}"
TEST_HTML    = "<!DOCTYPE html><html><body><p>Servette test</p></body></html>"

# Used for regular requests — advertises HTTP/1.1 only so urllib can read responses
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE
SSL_CTX.set_alpn_protocols(["http/1.1"])

# Used only for the ALPN negotiation check — advertises h2 to confirm HTTP/2 support
SSL_CTX_H2 = ssl.create_default_context()
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

    html_path = os.path.join(tmpdir, "test.html")
    with open(html_path, "w") as f:
        f.write(TEST_HTML)

    config_path  = os.path.join(SERVETTE_DIR, "servette.json")
    saved_config = None
    if os.path.exists(config_path):
        with open(config_path, "rb") as f:
            saved_config = f.read()

    with open(config_path, "w") as f:
        json.dump({
            "html_file":          html_path,
            "port":               TEST_PORT,
            "cert_file":          cert_path,
            "key_file":           key_path,
            "username":           "",
            "password_hash":      "",
            "password_salt":      "",
            "log_file":           os.path.join(tmpdir, "test.log"),
            "rate_limit":         200,
            "auth_rate_limit":    6,
            "cache_policy":       "no-cache",
            "cache_max_age":      3600,
            "email":              "",
            "csp":                "",
            "permissions_policy": "",
        }, f, indent=2)

    import servette
    # Reset module-level state from any previous test run
    servette.config._load()
    servette._request_times.clear()
    servette._auth_fail_times.clear()
    servette._file_cache.path = None

    servette.start_server()
    time.sleep(1.0)  # give Hypercorn a moment to bind

    if not servette._server_running():
        print(f"ERROR: Server failed to start on port {TEST_PORT}.")
        teardown(tmpdir, saved_config, config_path, servette)
        sys.exit(1)

    return tmpdir, html_path, saved_config, config_path, servette


def teardown(tmpdir, saved_config, config_path, servette):
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

    section("Password hashing")

    h1, salt1 = s._hash_password("hello")
    h2, salt2 = s._hash_password("hello")
    check("Same password produces different salts each time", salt1 != salt2)
    check("Correct password verifies",    s._check_password("hello", h1, salt1))
    check("Wrong password fails",         not s._check_password("wrong", h1, salt1))
    check("Empty hash returns False",     not s._check_password("hello", "", salt1))
    check("Empty salt returns False",     not s._check_password("hello", h1, ""))

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


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def run_server_tests(s, html_path):

    section("Protocol negotiation (M2)")

    conn  = ssl.create_connection(("127.0.0.1", TEST_PORT))
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

    resp = req("GET")
    etag = resp.headers.get("ETag")
    check("Response includes ETag",               etag is not None)

    resp = req("GET", headers={"If-None-Match": etag})
    check("Matching ETag returns 304",            resp.status == 304)
    check("304 body is empty",                    resp.body == b"")

    resp = req("GET", headers={"If-None-Match": '"stale-etag"'})
    check("Stale ETag returns 200",               resp.status == 200)

    with open(html_path, "w") as f:
        f.write(TEST_HTML + "<!-- updated -->")
    time.sleep(0.05)

    resp_updated = req("GET")
    new_etag = resp_updated.headers.get("ETag")
    check("ETag changes after file edit",         new_etag != etag)

    resp_old = req("GET", headers={"If-None-Match": etag})
    check("Old ETag no longer triggers 304",      resp_old.status == 200)

    with open(html_path, "w") as f:
        f.write(TEST_HTML)

    section("Security headers")

    resp = req("GET")
    check("HSTS present",
          "max-age=31536000" in resp.headers.get("Strict-Transport-Security", ""))
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

    section("Method handling")

    check("POST returns 405",   req("POST").status   == 405)
    check("PUT returns 405",    req("PUT").status    == 405)
    check("DELETE returns 405", req("DELETE").status == 405)
    check("PATCH returns 405",  req("PATCH").status  == 405)

    section("404 — file not found")

    real_path = s.config.html_file
    s.config.html_file = "/tmp/does_not_exist_servette_test.html"
    s._file_cache.path = None
    check("Missing file returns 404",     req("GET").status == 404)
    s.config.html_file = real_path
    s._file_cache.path = None

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

    section("CSP and Permissions-Policy headers")

    s.config.csp                = ""
    s.config.permissions_policy = ""
    check("CSP absent when not configured",
          req("GET").headers.get("Content-Security-Policy") is None)
    check("Permissions-Policy absent when not configured",
          req("GET").headers.get("Permissions-Policy") is None)

    s.config.csp = "default-src 'self'; object-src 'none'"
    check("CSP header sent when configured",
          req("GET").headers.get("Content-Security-Policy") == "default-src 'self'; object-src 'none'")

    s.config.permissions_policy = "camera=(), microphone=()"
    check("Permissions-Policy header sent when configured",
          req("GET").headers.get("Permissions-Policy") == "camera=(), microphone=()")

    s.config.csp                = ""
    s.config.permissions_policy = ""

    section("Request rate limiting")

    s._request_times.clear()
    s.config.rate_limit = 2

    req("GET")
    req("GET")
    check("Third request over limit → 429",  req("GET").status == 429)

    s.config.rate_limit = 200
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
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def run_cert_tests(s, tmpdir):

    section("Self-signed certificate generation (M3)")

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

    # Verify it works on the test cert (generated by openssl in setup)
    test_cert = os.path.join(tmpdir, "cert.pem")
    days2 = s._cert_days_remaining(test_cert)
    check("reads test cert expiry correctly", days2 is not None and days2 > 0)


def main():
    print("\n──────────────────────────────────────────────────────")
    print("  Servette Test Suite")
    print("──────────────────────────────────────────────────────")

    tmpdir, html_path, saved_config, config_path, s = setup()

    try:
        run_unit_tests(s)
        run_server_tests(s, html_path)
        run_cert_tests(s, tmpdir)
    finally:
        teardown(tmpdir, saved_config, config_path, s)

    print(f"\n──────────────────────────────────────────────────────")
    total = _passed + _failed
    print(f"  {_passed} / {total} passed" + ("  — all good!" if _failed == 0 else f"  — {_failed} failed"))
    print(f"──────────────────────────────────────────────────────\n")

    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
