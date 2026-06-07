# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running

```bash
sudo python3 servette.py          # interactive shell (bootstrap re-execs into venv every time)
python3 servette.py --serve       # non-interactive service mode (used by systemd)
```

First run creates `.servette-env/` (a managed virtualenv), installs `hypercorn cryptography acme josepy` into it, then re-execs itself inside that environment. Subsequent runs skip straight to re-exec.

## Tests

```bash
.servette-env/bin/python3 test.py
```

Requires `openssl` on PATH (only used by test setup to generate a throwaway cert). The suite starts a real Hypercorn server on port 8443, runs checks, and tears down. It backs up and restores any existing `servette.toml`.

Three areas are intentionally not covered: the interactive shell/config commands, systemd integration, and Let's Encrypt cert issuance.

## Architecture

Everything lives in one file (`servette.py`) with no runtime dependencies beyond stdlib (Python 3.11+) plus the four packages installed into `.servette-env/`. Settings persist to `servette.toml` in the same directory.

**Bootstrap (`_bootstrap`)** — runs before any other code. If `sys.prefix` isn't the managed venv, it creates `.servette-env/`, installs dependencies, and `os.execv`s back into itself inside the venv.

**Config** — a `Config` object reads/writes `servette.toml`. Every field has a default. `reload_if_changed()` is called on every incoming request so edits to `servette.toml` take effect without a restart. Passwords are hashed PBKDF2-HMAC-SHA256 at 260,000 iterations; plaintext `password` fields in old configs are migrated on first load. The config file is written `0o600`.

**Two ASGI apps run under Hypercorn** in a background daemon thread (its own `asyncio` event loop, started by `start_server()`):
- `https_app` — HTTPS on `config.port` (default 443). Handles rate limiting → auth → path resolution → file serving with gzip, ETag, and security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CSP, Permissions-Policy, HSTS when a domain cert is active).
- `redirect_app` — HTTP on port 80. Serves ACME HTTP-01 challenge tokens from `ACME_WEBROOT` and 301-redirects everything else to HTTPS.

Shutdown is coordinated via a `threading.Event` passed to Hypercorn's `shutdown_trigger`.

**File serving** — `_resolve_request_path()` resolves URL paths within `config.serve_dir`, enforces path traversal protection, and falls back directories to `index.html`. Files are read once, gzip-compressed, and cached in `_file_cache` keyed by path; the cache refreshes automatically when `mtime` changes. Both raw and compressed bytes are stored; the right one is sent based on `Accept-Encoding`.

**Rate limiter** — two independent in-memory sliding-window dicts (`_request_times`, `_auth_fail_times`), protected by a `threading.Lock`. The auth limiter only activates when credentials are actually submitted, not on unauthenticated requests. Stale-IP eviction and the IP cap are enforced by a background `_rate_sweep` thread every 30 seconds, not on the request hot path.

**Certificates** — self-signed certs are generated with the `cryptography` library (`_generate_self_signed_cert`). Let's Encrypt certs use `acme`+`josepy` (`_run_acme`); the ACME HTTP-01 flow temporarily starts `redirect_app` on port 80 if the main server isn't running. `_run_acme` retries up to 3 times with 5s/10s backoff and skips the terminal spinner when stdout is not a TTY (background auto-renewal calls).

**Cert watchdog (`_cert_watchdog`)** — daemon thread started alongside the server. Every 60 seconds: if a domain is configured and the cert expires in < 30 days, calls `_run_acme` to renew (at most once per hour on failure). For certs without a domain (self-signed), detects external file changes by mtime and calls `_reload_server()`. `_wait_for_port_free()` gates restarts on the TCP port actually being free before re-binding.

**Shell** — the interactive REPL shown when running without `--serve`. Dispatches to `cmd_setup`, `cmd_config`, `cmd_install`/`cmd_uninstall`, `cmd_start`/`cmd_stop`, `cmd_status`, `cmd_log`, `cmd_update`. The `config` sub-shell writes each setting to `servette.toml` immediately. `enable`/`disable` write and manage `/etc/systemd/system/servette.service`. `cmd_install` also creates the `servette` system user and chowns cert/key/config files to it. `cmd_update` hits the GitHub releases API, downloads `servette.py` and `servette.py.sig` from the latest release assets, verifies the Ed25519 signature against `_SIGNING_PUBLIC_KEY`, validates syntax, and swaps it in atomically.

**Entry point** — `_bootstrap()` runs first (no-op if already in venv), then either `start_server()` + sleep loop (for `--serve`) or `shell()`.

## Releases

Updates are distributed via GitHub Releases, not raw `main`. The release process:

1. Bump `__version__` in `servette.py` and commit/push to `main`.
2. Sign the file with the Ed25519 private key (`servette_signing.pem`, gitignored):
   ```bash
   .servette-env/bin/python3 -c "
   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
   from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
   import base64, sys
   key = Ed25519PrivateKey.from_private_bytes(
       __import__('cryptography').hazmat.primitives.serialization.load_pem_private_key(
           open('servette_signing.pem','rb').read(), password=None
       ).private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
   )
   sig = key.sign(open('servette.py','rb').read())
   open('servette.py.sig','wb').write(sig)
   print('Signed.')
   "
   ```
3. Create a GitHub release tagged with the version string (e.g. `0.26.200`).
4. Attach `servette.py` and `servette.py.sig` as release assets.
5. Delete `servette.py.sig` locally (it's per-release, not a permanent artifact).

`servette.py.sig` is gitignored via `*.sig` — do not commit it. The public key is pinned in `_SIGNING_PUBLIC_KEY` in `servette.py`. The private key (`servette_signing.pem`) must never be committed.

## Git

Remote: `git@github.com:andy-emerson/servette.git`

```bash
git push origin main
```

The only collaborator is andy-emerson. Do not add Claude as a collaborator.

**NEVER use `Co-Authored-By` in commit messages.** GitHub permanently records it as a contributor. This instruction was stated repeatedly and explicitly violated on the first commit — do not repeat that mistake.

## Key constants

| Name | Value | Purpose |
|---|---|---|
| `_VENV_DIR` | `<BASE_DIR>/.servette-env` | Managed virtualenv |
| `SERVICE_PATH` | `/etc/systemd/system/servette.service` | systemd unit |
| `ACME_WEBROOT` | `/var/lib/letsencrypt/webroot` | ACME challenge file root |
| `RATE_WINDOW` | `60` seconds | Sliding window for both rate limits |
