# SHELL

*The operator's side of Servette: the loopback page server, the content
pipeline, the settings doors, and the terminal commands that drive them.*

*Ordered for the reader auditing the attack surface. After the shared menu
furniture, the one network door — the loopback page server, what
authenticates it, and every request it answers. Then the content pipeline an
accepted upload runs through: the ceilings, the extraction guards, the
atomic swap, the version ring. Then the write doors every setting passes,
whichever surface it came from. The interactive commands follow — they
drive the same cores, in a guided voice — and the shell loop with its root
elevation closes the file.*

*Authored here. `servette.py` is generated from the Markdown sources in `src/` — by the package build itself ([`_literate_backend.py`](_literate_backend.py)), or by hand with [`build.py`](build.py). Edit the Markdown, never the module; the committed copy exists to be read, and `--check` holds it equal to the sources.*

## Menus and prompts

Menus are generated so the right-hand column always begins at the same place (2-space indent + a 22-wide label) as the status and config displays. The full-width banner is reserved for the two moments a user enters a new mode: the shell launching, the setup wizard.

```python
# Menu metrics
_PAD = 22

# When free disk is worth saying out loud. Two thresholds because one does
# not fit both a 4 GB Pi card and a 200 GB VPS: an absolute floor a publish
# plus its kept versions can exhaust, and a fraction that catches a large
# disk filling steadily.
_DISK_LOW_MB       = 512
_DISK_LOW_FRACTION = 0.10


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
    ("traffic",          "requests, statuses, and top paths from the last 7 days"),
    ("admin",            "open the browser admin page over your SSH tunnel"),
    ("publish <folder>", "publish a folder on this box as a site's content (site index first on a multi-site box)"),
    ("restore-site [n]", "roll back a site's content to a kept version"),
    ("help",             "show this message"),
    ("quit",             "exit"),
]
HELP = _section_text("Commands") + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _COMMANDS)

```

The config sub-shell holds the flows that genuinely need a guided prompt: the site list, certificate issuance, and the login pair (the password is excluded from `set` because a secret on argv leaks into shell history and the process table). Every scalar knob has exactly one terminal door — `set key=value` — rather than a prompt that re-asks what `set` already validates. `cert`/`username`/`password` take an optional site index (default 0) — the same `[n]` convention as the top-level `log [n]`.

Absent by ruling: the folder. Where a site's content lives is Servette-assigned, not a question with a wrong answer for the operator to get wrong ([the folder is not a setting](../DECISIONS.md#the-folder-is-not-a-setting-serve_dir-has-left-the-vocabulary)). `show` and `sites` still report the path — knowing where the files are is not the same as choosing it.

```python
# The config commands
_CONFIG_COMMANDS = [
    ("sites",           "list configured sites"),
    ("add-site",        "add a new site (domain and password)"),
    ("remove-site <n>", "remove a site"),
    ("move-site <n> <to>", "reorder sites (the first domainless one answers unmatched Hosts)"),
    ("cert [n]",        "SSL certificate and key"),
    ("username [n]",    "login username"),
    ("password [n]",    "login password"),
    ("show",            "show current settings"),
    ("back",            "return to main shell"),
]
CONFIG_HELP = (_section_text("Commands")
               + "".join(f"  {c:<{_PAD}} — {d}\n" for c, d in _CONFIG_COMMANDS)
               + "  Every scalar setting is one door: set [n] key=value, from "
                 "the main shell.\n")


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

## Loopback page server

The browser half of a paired command. It binds 127.0.0.1 only and lives only while the operator's command runs, reached through the operator's SSH tunnel — the shell wearing a friendlier skin, not a third surface (the DECISIONS record "Multi-step features pair a shell flow with a loopback browser page"). One six-character passcode per run is the login: the terminal prints the stable link and the passcode side by side, the login page marries the two, and five wrong guesses end authentication for the run.

```python
# The loopback server's shape
_UI_HOST          = "127.0.0.1"
_UI_PORT          = 8377  # the LocalForward line in the operator's ssh config names it
_UI_MAX_BAD_CODES = 5     # then the run stops authenticating anyone: a six-character
                          # code holds against five guesses, not against a local
                          # process free to try millions over loopback


```

The login page is what the bare, bookmarkable URL answers with: the admin tool's front door, in the admin tool's own dress, asking for the passcode the terminal printed and submitting it as the same `t` everything else carries. The bookmark holds the link; the passcode is the per-run half no bookmark can hold.

```python
# The login page
_UI_LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Servette — Log in</title>
<style>
  body { background: #0e0e0e; color: #e8e8e8; min-height: 100vh; margin: 0;
         display: flex; flex-direction: column; align-items: center;
         justify-content: center; padding: 2rem; box-sizing: border-box;
         font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo,
                      Consolas, 'Liberation Mono', 'Courier New', monospace; }
  /* The cursor is absolute so it adds no width: the page centers on
     "Servette", not "Servette_". */
  .logo { font-size: 3rem; font-weight: 500; line-height: 1; position: relative; }
  .logo .ette { color: #5A8466; }
  .logo .cursor { position: absolute; animation: blink 1.1s steps(1) infinite; }
  @keyframes blink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }
  .tagline { margin-top: 0.5rem; color: #555; font-size: 0.75rem;
             letter-spacing: 0.08em; text-transform: uppercase; }
  .card { margin-top: 3rem; width: 100%; max-width: 26rem; background: #161616;
          border: 1px solid #2a2a2a; border-radius: 8px; padding: 1.25rem; }
  label { display: block; color: #555; font-size: 0.7rem;
          letter-spacing: 0.1em; text-transform: uppercase;
          margin-bottom: 0.35rem; }
  input { width: 100%; box-sizing: border-box; font-family: inherit;
          font-size: 0.9rem; color: #e8e8e8; background: #0e0e0e;
          border: 1px solid #2a2a2a; border-radius: 4px;
          padding: 0.6rem 0.7rem; }
  input:focus { outline: none; border-color: rgba(90,132,102,0.8);
                box-shadow: 0 0 0 2px rgba(90,132,102,0.25); }
  button { margin-top: 0.75rem; font-family: inherit; font-size: 0.75rem;
           color: #e8e8e8; background: rgba(90,132,102,0.15);
           border: 1px solid rgba(90,132,102,0.6); border-radius: 4px;
           padding: 0.5rem 0.9rem; cursor: pointer; }
  .hint { margin-top: 0.75rem; color: #555; font-size: 0.72rem;
          line-height: 1.7; }
</style></head>
<body>
<div class="logo">Serv<span class="ette">ette</span><span class="cursor">_</span></div>
<div class="tagline">Login</div>
<div class="card">
  <form method="get" action="/">
    <label for="t">Passcode</label>
    <input id="t" name="t" autofocus autocomplete="off">
    <button>Log in</button>
  </form>
  <p class="hint">Run 'servette admin' in your SSH console to generate a
  one-time passcode.</p>
</div>
</body></html>
"""


```

The admin page is inlined by the build exactly as the 404 page is — authored as `src/admin.html`, counted apart from the Python figures. One page, three tabs — Sites (one card per site: publish, preview, domain, certificate, access, redirects, history), Server, Statistics — so everything shares one scaffold, one bookmark, one code. Publishing is the pub tool's bundle builder with every trace of key custody removed: on this page, being here is the authentication.

```python
# The admin page
_UI_ADMIN_PAGE = """@@ADMIN_HTML@@"""


```

One page, one passcode, and every endpoint behind it: requests without the run's passcode get the login page or a refusal — never content, and never a write. The code is compared in constant time; the upload is capped before it is read and lands through the same `_land_bundle` as every other channel.

```python
# The loopback handler
class _UIHandler(http.server.BaseHTTPRequestHandler):
    """The loopback server's one handler. GET is the page and its read half
    (/status /config /traffic /update /versions, and /preview on its own
    per-staging token); POST is the write half (/upload /preview /config
    /sites /service /swap). Everything but the login page and /preview
    requires this run's passcode; after _UI_MAX_BAD_CODES wrong guesses
    the run stops authenticating anyone, including the right code —
    re-run the command for a fresh one."""

    def log_message(self, fmt, *args):
        log.info("ui: " + fmt % args)  # the default writes to stderr, past the log

    def _respond(self, status, body, ctype="text/html; charset=utf-8", extra=()):
        # `body` is text for every JSON and message answer, and bytes for
        # the one that hands back a file: a preview asset.
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        # The page URL carries this run's passcode as ?t=, and a card can
        # open the operator's public site in a new tab. no-referrer keeps
        # the passcode out of that navigation's Referer — the public server
        # already sends the same header on every response.
        self.send_header("Referrer-Policy", "no-referrer")
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _serve_preview(self, path):
        """Serve one file out of a staged preview: /preview/TOKEN/SITE/rest.

        The token rides in the PATH, not the query, and that is the whole
        reason a preview is staged server-side at all. A draft's own
        `<link href="s.css">` resolves against the path and drops any query
        string, so a token in the query would authenticate the page and then
        403 every stylesheet and image it asks for — a preview showing
        unstyled text. With the token as a path segment, every relative
        reference inside the draft resolves and works, which is exactly what
        an operator is previewing for. (Found in a browser: the page loaded,
        the stylesheet did not.)

        Everything the draft could reach is bounded here. The token is not
        the run's passcode — a previewed page can read its own URL, and a
        script in someone's own content must not learn the credential that
        publishes. The tree is the staging directory, never the live one.
        Resolution is the server's own _resolve_request_path, so traversal
        and hidden paths are refused by the code that refuses them on the
        public side. And the response says twice that this is untrusted
        content: nosniff, and a CSP sandbox so the draft has an opaque
        origin even if it is opened outside the page's own frame."""
        rest = path[len("/preview"):]
        parts = rest[1:].split("/", 2) if rest.startswith("/") else []
        if len(parts) < 2:
            return self._respond(404, "Not a live preview.")
        token = getattr(self.server, "preview_code", "")
        if not token or not hmac.compare_digest(parts[0], token):
            return self._respond(403, "Not a live preview.")
        try:
            idx = int(parts[1])
        except ValueError:
            return self._respond(400, "site must be a whole number.")
        if not (0 <= idx < len(config.sites)):
            return self._respond(404, "No such site.")
        staged = _preview_dir(config.sites[idx])
        if not os.path.isdir(staged):
            return self._respond(404, "Nothing staged for this site.")
        file_path, status = _resolve_request_path("/" + (parts[2] if len(parts) > 2 else ""),
                                                  staged)
        if status != 200 or file_path is None:
            return self._respond(status, "Not in this preview."
                                 if status == 404 else "Refused.")
        try:
            with open(file_path, "rb") as f:
                body = f.read(_MAX_BUNDLE_BYTES)
        except OSError:
            return self._respond(404, "Not in this preview.")
        return self._respond(200, body, _mime_type(file_path), [
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "sandbox allow-scripts allow-forms"),
        ])

    def _auth(self):
        """"ok", "locked", "bad", or "none". A wrong code is a guess and is
        counted; a missing one is not. Compared as bytes so any input gets
        the constant-time path rather than a TypeError."""
        qs   = parse_qs(urlsplit(self.path).query)
        # The passcode travels one way: the ?t= query every api() call
        # carries. A second door for the run credential is a second thing
        # to audit, so there is none.
        code = (qs.get("t") or [""])[0]
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

        # Preview content, on its own per-staging token — why it is not the
        # run's passcode, and why it rides the path: see _serve_preview.
        if path == "/preview" or path.startswith("/preview/"):
            return self._serve_preview(path)

        if path not in ("/", "/status", "/config", "/traffic", "/update",
                        "/versions"):
            return self._respond(404, "Not found.")
        auth = self._auth()
        if auth == "locked":
            return self._respond(403, "Too many wrong passcodes. Close this page and re-run the command.")
        if path == "/status":
            # The inside view, for the Server tab's Status card: exactly what
            # `status --json` prints, because it is the same function.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            return self._respond(200, json.dumps(_status_data()), "application/json")
        if path == "/config":
            # The settings read half, for the Server tab and the site cards:
            # exactly the vocabulary `set`
            # accepts, plus current values to fill the forms — and
            # has_password, a boolean only, so the page can show whether
            # protection is on without the hash ever crossing the wire.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            return self._respond(200, json.dumps({
                "host":  {k: getattr(config, k) for k in _SET_HOST_KEYS},
                "sites": [{"index": i, "domain": s.domain, "dir": s.serve_dir,
                           "active": s.active,
                           "cache": s.cache,
                           "username": s.username,
                           "redirects": s.redirects,
                           "redirects_temporary": s.redirects_temp,
                           "has_password": bool(s.password_hash)}
                          for i, s in enumerate(config.sites)],
            }), "application/json")
        if path == "/update":
            # Asked, never volunteered: the page requests this when the
            # operator opens it, and the answer is cached for six hours.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            return self._respond(200, json.dumps({"latest": _upgrade_available()}),
                                 "application/json")

        if path == "/versions":
            # One site's kept trees — its own endpoint for the cost reason
            # in _site_versions.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            try:
                idx = int(parse_qs(urlsplit(self.path).query).get("site", ["0"])[0])
            except ValueError:
                return self._respond(400, "site must be a whole number.")
            if not (0 <= idx < len(config.sites)):
                return self._respond(404, "No such site.")
            return self._respond(200, json.dumps(
                {"versions": _site_versions(config.sites[idx]),
                 "keep": _KEEP_VERSIONS}), "application/json")

        if path == "/traffic":
            # The Statistics tab's feed: the journal re-read as counts, and
            # never carrying a visitor's IP. The window is the reader's
            # choice, bounded — a request for a year would read a year of
            # journal to draw a chart nobody asked for.
            if auth != "ok":
                return self._respond(403, "Not logged in.")
            try:
                days = int(parse_qs(urlsplit(self.path).query).get("days", ["7"])[0])
            except ValueError:
                days = 7
            return self._respond(200, json.dumps(_traffic_summary(max(1, min(days, 90)))),
                                 "application/json")
        if auth == "ok":
            return self._respond(200, self.server.page)
        return self._respond(200, _UI_LOGIN_PAGE)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/upload", "/preview", "/config", "/sites", "/service",
                        "/swap"):
            return self._respond(404, "Not found.")
        if self._auth() != "ok":
            return self._respond(403, "Not logged in.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self._respond(400, "Empty upload.")

        if path == "/service":
            # The page runs the service's lifecycle but never its
            # installation: start, restart, stop. Stopping was withheld while
            # the fear was that a misclick could darken a box with no way
            # back — it cannot, because this page is served by the admin
            # command's own process, not the server's, so Start survives a
            # stopped server. `disable` stays terminal-only: removing the
            # unit is installation, and it would take this page's own way
            # back with it.
            if length > 512:
                return self._respond(413, "Body too large.")
            # A lifecycle request must say which transition it means: a
            # garbled or unknown op is refused, never defaulted — a
            # truncated stop must not become a start.
            try:
                body_op = str(json.loads(self.rfile.read(length)).get("op") or "")
            except (ValueError, TypeError):
                return self._respond(400, "Malformed body.")
            if body_op not in ("start", "restart", "stop"):
                return self._respond(422, json.dumps(
                    {"error": "op must be start, restart or stop"}),
                    "application/json")
            if not _service_file_exists():
                return self._respond(422, json.dumps(
                    {"error": "no system service installed — run 'enable' in the terminal"}),
                    "application/json")
            verb = body_op
            try:
                subprocess.run(["systemctl", verb, "servette"],
                               check=True, capture_output=True)
            except (OSError, subprocess.CalledProcessError) as e:
                return self._respond(500, json.dumps(
                    {"error": f"could not {verb} the service ({e})"}), "application/json")
            return self._respond(200, json.dumps({"result": "ok"}), "application/json")

        if path == "/swap":
            # The size the terminal asks for at setup, asked for here
            # instead — the same _apply_swapfile underneath, so the two
            # surfaces cannot drift on disk checks, fstab, or the
            # restore-the-old-size path when a resize fails.
            if length > 512:
                return self._respond(413, "Body too large.")
            try:
                mb = int(json.loads(self.rfile.read(length)).get("mb"))
            except (ValueError, TypeError):
                return self._respond(422, json.dumps(
                    {"error": "a size in MB is needed"}), "application/json")
            if not (64 <= mb <= 65536):
                return self._respond(422, json.dumps(
                    {"error": "swap size must be 64-65536 MB"}), "application/json")
            err = _apply_swapfile(mb)
            return self._respond(200 if not err else 422,
                                 json.dumps({"result": "ok"} if not err
                                            else {"error": err}),
                                 "application/json")

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
                elif op in ("name", "certificate"):
                    # Naming and certifying are two acts, and the page shows
                    # them as two. `name` is a config write: instant, and it
                    # cannot fail on someone else's DNS. `certificate` is the
                    # slow, network-dependent one — the same
                    # _obtain_trusted_cert the terminal runs, which persists
                    # and reloads on success. Between them a site can sit
                    # named but self-signed; that state is honest and loud on
                    # the card rather than hidden inside one button.
                    try:
                        idx = int(body.get("site"))
                    except (TypeError, ValueError):
                        idx = -1
                    if not (0 <= idx < len(config.sites)):
                        err = f"no site {idx}"
                    elif op == "name":
                        # The one door where a domain enters config without
                        # an issuance to vet it (the terminal assigns only on
                        # ACME success), so syntax is judged here — locally,
                        # keeping the name-write instant.
                        domain = str(body.get("domain") or "").strip().lower()
                        problem = ("a domain is needed" if not domain
                                   else _domain_problem(domain))
                        if problem:
                            err = problem
                        elif _domain_in_use(domain, excluding=config.sites[idx]):
                            err = f"{domain} is already used by another site on this box"
                        else:
                            config.sites[idx].domain = domain
                            config.save()
                            err = ""
                            if _server_running() or _service_is_active():
                                _reload_server()
                    else:
                        target = config.sites[idx]
                        if not target.domain:
                            err = "set a domain first — a certificate is issued for a name"
                        else:
                            outcome = _obtain_trusted_cert(target.domain, target)
                            err = ("" if outcome is None else
                                   "the authority refused — is the domain's DNS "
                                   "pointing at this server? The terminal has the "
                                   "detail" if outcome == "refused" else
                                   "could not reach the certificate authority — "
                                   "try again in a moment")
                elif op == "restore":
                    # The same _restore_site the terminal's numbered list
                    # runs. The version arrives as a name over the wire and
                    # is matched against the ring inside the core, never
                    # taken as a path.
                    try:
                        idx = int(body.get("site"))
                    except (TypeError, ValueError):
                        idx = -1
                    if not (0 <= idx < len(config.sites)):
                        err = f"no site {idx}"
                    else:
                        want = body.get("version")
                        err = _restore_site(config.sites[idx],
                                            str(want) if want else None)
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
            # The settings write half: the same validate-then-apply path
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

        if path == "/preview":
            # The same bundle, staged where only this page can see it. A
            # fresh token per staging, so a preview's reach ends when the
            # next one is staged or the command exits.
            result = _stage_preview(site, self.rfile.read(length))
            if result != "staged":
                return self._respond(422, json.dumps({"result": result}),
                                     "application/json")
            self.server.preview_code = os.urandom(8).hex()
            return self._respond(200, json.dumps(
                {"result": "staged", "token": self.server.preview_code}),
                "application/json")

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
    # A predecessor killed without _stop_ui (kill -9, a dropped box) never
    # swept its drafts; the next run's door reclaims them. After the bind,
    # deliberately: a second admin refused for the busy port must not
    # delete the live run's staged previews on its way out.
    _clear_previews()
    httpd.site, httpd.page = site, page
    httpd.code, httpd.bad_codes = os.urandom(3).hex(), 0
    httpd.preview_code = ""      # minted by the first staging, not before
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.code


def _stop_ui(httpd):
    """The page dies with the command: stop accepting, close the socket, and
    drop any staged preview — a draft nobody published has no business
    outliving the session that made it."""
    httpd.shutdown()
    httpd.server_close()
    _clear_previews()


```

`admin` is the door: it runs the page server for exactly its own lifetime, prints the two ways in, narrates what the browser does, and closes the page on the way out. Its terminal side is deliberately thin — every capability the page exposes already has its own shell command.

```python
# admin
def _stale_admin_pids():
    """PIDs of OTHER 'servette admin' runs owned by this same user, read
    from /proc. The service (no 'admin' argument) never matches, and
    neither does the calling process. Empty on hosts without /proc
    (macOS) — the caller then has nothing it can safely clear."""
    pids = []
    me, uid = os.getpid(), os.getuid()
    for name in os.listdir("/proc") if os.path.isdir("/proc") else []:
        if not name.isdigit() or int(name) == me:
            continue
        entry = os.path.join("/proc", name)
        try:
            if os.stat(entry).st_uid != uid:
                continue
            with open(os.path.join(entry, "cmdline"), "rb") as f:
                argv = [a.decode("utf-8", "replace")
                        for a in f.read().split(b"\0") if a]
        except OSError:
            continue                     # raced away, or unreadable
        if "admin" in argv[1:] and any(
                os.path.basename(a).startswith("servette") for a in argv):
            pids.append(int(name))
    return pids


def _reclaim_admin_port(site, page):
    """After a refused bind: end this user's stale admin runs and retry.
    A dropped SSH session does not always end the admin command it was
    running, and the leftover holds the port. Running 'admin' again IS
    the statement that the old session is over (ruled: clear it, never
    ask) — and its passcode dying with it is what this page wants anyway.
    Returns (httpd, code), or (None, None) when the port's holder is not
    ours to clear."""
    stale = _stale_admin_pids()
    for pid in stale:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass                         # already gone
    if stale:
        for _ in range(20):              # up to ~2 s for the socket to free
            time.sleep(0.1)
            try:
                return _start_ui(site, page)
            except OSError:
                continue
    return None, None


def cmd_admin():
    site = config.sites[0]  # the fallback when an upload names no site
    try:
        httpd, code = _start_ui(site, _UI_ADMIN_PAGE)
    except OSError:
        httpd, code = _reclaim_admin_port(site, _UI_ADMIN_PAGE)
        if httpd is None:
            # Not ours to kill, so the refusal names the finder and the fix.
            print(f"  Could not open the page: port {_UI_PORT} is taken by "
                  "another program.")
            print(f"  Find it with 'sudo ss -ltnp | grep {_UI_PORT}', stop "
                  "it, then run 'admin' again.")
            return
        print("  An earlier admin session was still running — closed it and "
              "took its place (its passcode no longer works).")
    httpd.on_publish = lambda s: print(
        f"\n  Published from browser to {s.domain or s.serve_dir}: "
        "content swapped in — restore-site undoes it.")

    try:
        # Two labelled lines and nothing above them. The address is stable
        # and worth a bookmark, the passcode is this run's, and the login
        # page marries the two — printing them apart keeps a bookmark free
        # of the secret. Each label says what its line IS, which is why no
        # header announces the page: it could only repeat the label.
        print(f"  admin page  http://localhost:{_UI_PORT}/")
        print(f"  passcode    {code}")
        print()
        while True:
            try:
                # The prompt is where a reader looks when wondering what to
                # type, so the two things they might want are named there
                # rather than on lines of their own above. 'close the page'
                # names what 'back' actually ends — the page server this
                # command started — and matches the line printed on the way
                # out; the browser tab is the operator's to close.
                raw = input("  type 'help' if the page will not load, "
                            "'back' to close the page: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if raw in ("help", "?"):
                print("  A page that won't load means this SSH connection isn't carrying")
                print("  the tunnel. Add this line once to ~/.ssh/config on the computer")
                print("  you ssh FROM, inside this server's entry, then reconnect:")
                print(f"      LocalForward {_UI_PORT} 127.0.0.1:{_UI_PORT}")
                print(f"  The address is worth a bookmark — the login page it")
                print(f"  opens asks for this run's passcode: {code}")
                continue
            if raw in ("back", "done", "exit", "quit", "q"):
                break
    finally:
        _stop_ui(httpd)
        # An abandoned tab keeps asking for a port nothing answers on any
        # more, and the operator's own terminal is where SSH prints the
        # refusals ('channel N: open failed'). Cheaper to say than to
        # diagnose later.
        print("  Page closed — close the browser tab too, or your terminal")
        print("  will collect 'channel N: open failed' notices from it.")


```

## Site content publishing

> The update channel for a site's *content*: a tar.gz bundle the operator
> uploads over their own SSH tunnel, extracted into a staging tree and made
> live with one atomic link flip, the tree it replaces kept in the ring for
> 'restore-site' to flip back to. Nothing arrives from the network unasked —
> the doors are the loopback page, reachable only through the operator's
> tunnel, and the terminal's `publish`, taring a folder already on this
> box. (Servette's own code updates travel through the package manager,
> not through Servette.)

```python
# The bundle ceiling
_MAX_BUNDLE_BYTES = 500 * 1024 * 1024  # generous for a static site; bounds a decompression-bomb bundle
# A companion ceiling on entry COUNT: the byte cap counts payload, so a
# bundle of millions of zero-size members (512 header bytes each,
# ~1000:1 gzip) slips under it while still exhausting CPU and memory. A
# static site of a million files is already absurd.
_MAX_BUNDLE_MEMBERS = 1_000_000


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
        # abort at the ceiling. (Only a bundle the operator uploaded over
        # their own tunnel gets here at all, so this bounds a buggy build of
        # their own site, not the anonymous internet.)
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
            # The byte cap counts payload only, so zero-size members never
            # trip it; this bounds their number, and with it the CPU the
            # walk burns and the members list it grows.
            if len(members) >= _MAX_BUNDLE_MEMBERS:
                raise ValueError(f"bundle has more than {_MAX_BUNDLE_MEMBERS} entries")
            members.append(m)
        # The PEP 706 feature probe: data_filter exists exactly when
        # extractall() accepts filter=. Debian 12's 3.11.2 predates the
        # backport — there the checks above are the (sufficient) guard.
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest_dir, members=members, filter="data")
        else:
            tf.extractall(dest_dir, members=members)


```

The content lives in dated sibling trees behind a symlink, so the swap is one atomic link flip and the trees behind the live one are the history. The publish time is *in the directory's name* — `<link>.v<epoch>` — so the ring orders itself with no sidecar file to keep in step, and a tree copied elsewhere still says when it was made. Two shapes from before this design convert on their next publish: the two-slot `.a`/`.b` pair with its single-shot `.bak` symlink, and a plain real directory at `serve_dir`.

```python
# The kept versions
_KEEP_VERSIONS = 5   # trees kept per site, the live one included


def _content_slots(serve_dir):
    """The two sibling trees the pre-ring design flipped between. Kept only
    so a site published under it can be adopted into the ring."""
    base = _resolve(serve_dir).rstrip(os.sep)
    return base + ".a", base + ".b"


def _drop_backup(bak):
    """Remove the single-shot backup marker the pre-ring design left: a
    symlink from the flip era (the tree it names is adopted separately), or
    a real directory from before that."""
    if os.path.islink(bak):
        os.remove(bak)
    elif os.path.isdir(bak):
        shutil.rmtree(bak, ignore_errors=True)


def _version_dirs(serve_dir):
    """Every kept tree for this site, newest first, as (path, epoch).

    A name that does not parse is not a version and is left alone — the
    scan is a filter over siblings, never a prefix match that could sweep
    up a directory Servette did not create."""
    base = _resolve(serve_dir).rstrip(os.sep)
    head, tail = os.path.split(base)
    try:
        names = os.listdir(head or ".")
    except OSError:
        return []
    out = []
    for name in names:
        if not name.startswith(tail + ".v"):
            continue
        stamp, _dot, extra = name[len(tail) + 2:].partition(".")
        path = os.path.join(head, name)
        if not (stamp.isdigit() and os.path.isdir(path) and not os.path.islink(path)):
            continue
        # Two publishes inside one second share an epoch and are told apart
        # by the sequence suffix — which must sort with the clock, not
        # against it, or the newer of the two would read as the older.
        out.append((path, int(stamp), int(extra) if extra.isdigit() else 1))
    out.sort(key=lambda r: (-r[1], -r[2]))
    return [(path, stamp) for path, stamp, _seq in out]


def _new_version_dir(serve_dir, when=None):
    """An unused version-directory path for a tree published at `when`
    (default now). Two publishes inside one second take '.2', '.3': the
    name must be unique, or the second would land on top of the first."""
    base  = _resolve(serve_dir).rstrip(os.sep)
    stamp = int(when if when is not None else time.time())
    path  = f"{base}.v{stamp}"
    n = 2
    while os.path.lexists(path):
        path = f"{base}.v{stamp}.{n}"
        n += 1
    return path


def _adopt_legacy_slots(serve_dir):
    """Bring a two-slot site's trees into the ring, after the flip that made
    them idle. Renaming a tree the live symlink points at would break the
    link, so the live one is skipped — it is adopted on the publish after
    this one, when it is no longer live. The `.bak` symlink goes: the ring
    is the history now."""
    base = _resolve(serve_dir).rstrip(os.sep)
    _drop_backup(base + ".bak")
    live = os.path.realpath(base)
    for slot in _content_slots(serve_dir):
        if not os.path.isdir(slot) or os.path.islink(slot):
            continue
        if os.path.realpath(slot) == live:
            continue
        try:
            os.rename(slot, _new_version_dir(serve_dir, os.path.getmtime(slot)))
        except OSError:
            pass          # a slot that will not move is left, never deleted


def _prune_versions(serve_dir, keep=None):
    """Drop the oldest trees past the ring's depth. The live tree is never a
    candidate however old it is: an operator who restored a year-old version
    is serving it, and content being served is not garbage."""
    keep = _KEEP_VERSIONS if keep is None else keep
    live = os.path.realpath(_resolve(serve_dir).rstrip(os.sep))
    for path, _stamp in _version_dirs(serve_dir)[keep:]:
        if os.path.realpath(path) != live:
            shutil.rmtree(path, ignore_errors=True)


```

The swap itself. A converted site never shows a missing directory: the flip is one `os.replace` of a symlink, and a crash leaves old or new content live — never neither. The pre-flip design was two renames back to back, and between them the live directory did not exist: a microseconds 404 window on every publish, and a crash there left the site with no content at all. That window now survives only in one place, paid once — the first swap on a legacy real directory, which converts it.

```python
# The content swap
def _swap_site_content(new_dir, serve_dir):
    """Make new_dir the live content behind serve_dir, keeping the trees
    behind it as the ring `restore-site` chooses from.

    new_dir's tree is renamed to a fresh `<link>.v<epoch>` sibling and one
    atomic os.replace flips the link — no window, crash-safe. Pruning runs
    after the flip, so a publish that fills the disk fails in staging with
    every kept version still there.

    A legacy real directory at serve_dir is converted on its first swap: the
    old content becomes a version and the link lands — the one swap that
    still carries the old rename gap, once per site ever, with the same
    rollback the old design had (a failed conversion must never leave NO
    live directory — every request a 404 — while the caller reports merely
    'rejected')."""
    if not os.path.isdir(new_dir):
        # A dangling symlink would "succeed" — the old rename raised here,
        # and the flip must fail just as loudly rather than serve nothing.
        raise FileNotFoundError(f"new content tree missing: {new_dir}")
    live = _resolve(serve_dir).rstrip(os.sep)
    now  = int(time.time())
    dest = _new_version_dir(serve_dir, now)

    if os.path.islink(live):
        os.rename(new_dir, dest)
        try:
            flip = live + ".flip"
            if os.path.lexists(flip):
                os.remove(flip)                  # a crash's leftover, harmless
            os.symlink(dest, flip)
            os.replace(flip, live)               # the swap: one atomic syscall
        except OSError:
            # The tree was already renamed into the ring; a failed flip
            # hands it back to staging, so a publish the caller reports
            # 'rejected' leaves no never-published "version" behind for
            # restore-site to offer.
            os.rename(dest, new_dir)
            raise
        _adopt_legacy_slots(serve_dir)
        _prune_versions(serve_dir)
        return

    # Legacy: a real directory (or nothing yet) at serve_dir — convert.
    had_live = os.path.isdir(live)
    os.rename(new_dir, dest)
    kept = None
    if had_live:
        # Dated by its own mtime, not by now — it is the older content, and
        # the ring sorts on the name — but clamped strictly below dest's
        # stamp: an mtime in dest's own second would collide into a higher
        # sequence suffix, and the ring would read the OLD tree as newer.
        kept = _new_version_dir(serve_dir,
                                min(int(os.path.getmtime(live)), now - 1))
        os.rename(live, kept)
    try:
        os.symlink(dest, live)
    except OSError:
        if had_live:
            os.rename(kept, live)
        os.rename(dest, new_dir)   # same hand-back as the flip above
        raise
    _adopt_legacy_slots(serve_dir)
    _prune_versions(serve_dir)


```

The lock that serializes every content mutation.

```python
_publish_lock = threading.Lock()  # serializes site-content mutation across every
                                   # site: a page publish and 'restore-site' can
                                   # run from two sessions at once, and the swap
                                   # is several unguarded filesystem ops, not one.


```

Every publish lands here — validated extraction into staging, atomic swap, ownership repair, under the publish lock. Two doors, one tail: the page's upload over the operator's SSH tunnel, and the terminal's `publish` taring a folder on this box. Neither carries a signature, because the operator's identity is already proven — SSH for the tunnel, holding the shell for the terminal ([tunnel uploads are authenticated by SSH](../DECISIONS.md#tunnel-uploads-are-authenticated-by-ssh-the-pull-channel-is-removed)). `source` names the door in the log line.

```python
# Landing a bundle
def _land_bundle(site, bundle, source):
    """Extract `bundle` into staging and swap it live for `site`, keeping the
    previous trees in the ring, with ownership repair — the shared tail of
    every content channel. `source` is only for the log line. Returns
    "rejected" or "published"."""
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
            # and must honour the never-world-bits promise. Kept versions
            # need nothing: each was the live tree once and keeps the
            # ownership it already has. A failed extraction dies here, in
            # staging, with the live content and the ring untouched.
            _chown_operator(staging, strip_world=True)
            _swap_site_content(staging, site.serve_dir)
        except Exception as e:
            log.error("Publish bundle rejected: %s", e)
            shutil.rmtree(staging, ignore_errors=True)
            return "rejected"

    log.info("Published new content for %s from %s", site.domain or site.serve_dir, source)
    return "published"


```

The terminal door to the same tail. `publish [n] <folder>` tars a folder on this box in memory — under the same cap, hidden paths excluded by the same rule the server serves by — and hands it to `_land_bundle` exactly as the page's upload does, so both doors run identical ceilings, extraction guards, atomic swap, and version ring, and the core never knows which door called it. The one guard on the source is the secrets predicate every serve_dir runs: a sys admin may publish any folder they can name, except one that would publish Servette's own config or TLS keys.

```python
# publish
def _tar_folder(root, cap=_MAX_BUNDLE_BYTES):
    """A folder as the gzipped tar bundle the publish door takes —
    (bytes, "") — or (None, sentence) where it cannot be one. Hidden paths
    are excluded on the way in by the rule the server serves by: a
    dot-path is never served, so it is never published."""
    buf, files, total = io.BytesIO(), 0, 0
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for base, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs
                       if not d.startswith(".") or d == ".well-known"]
            for name in sorted(names):
                if name.startswith("."):
                    continue
                full = os.path.join(base, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue    # regular files only, as the extractor accepts
                try:
                    size = os.path.getsize(full)
                    tf.add(full, arcname=os.path.relpath(full, root),
                           recursive=False)
                except OSError:
                    continue
                files += 1
                # The cap counts UNCOMPRESSED bytes — the same quantity
                # _extract_bundle enforces and the page's builder sums. A
                # compressed count would wave a well-compressing 8 GB folder
                # through this door only for the core to refuse it with a
                # log line instead of this sentence.
                total += size
                if total > cap:
                    return None, (f"more than {cap // (1024 * 1024)} MB of "
                                  "content — too large to publish as one "
                                  "bundle")
    if not files:
        return None, ("no publishable files (hidden paths are not served, "
                      "so they are not published)")
    return buf.getvalue(), ""


def cmd_publish(args):
    """Publish a folder on this box as a site's content — the terminal half
    of the pair whose browser half is the page's Publish button."""
    if not args:
        print("  Usage: publish <folder>")
        print("  (On a multi-site box, the site index comes first: publish 1 <folder>)")
        return
    if len(args) >= 2:
        site, folder = _config_site_arg([args[0]]), args[1]
    else:
        site, folder = _config_site_arg([]), args[0]
    if site is None:
        return
    root = os.path.realpath(os.path.abspath(folder))
    if not os.path.isdir(root):
        print(f"  {folder} is not a folder on this box.")
        if folder.isdigit():
            # 'publish 2' alone reads as a site index missing its folder,
            # not as a folder named 2 — say so instead of the bare miss.
            print(f"  (A site index needs the folder too: publish {folder} <folder>)")
        return
    if _serve_dir_exposes_secrets(root):
        print("  That folder holds Servette's own config or TLS keys — "
              "publishing it would publish them.")
        return
    blob, problem = _tar_folder(root)
    if problem:
        print(f"  {folder}: {problem}")
        return
    result = _land_bundle(site, blob, "terminal publish")
    if result == "published":
        print(f"  Published to {site.domain or site.serve_dir}.")
    else:
        print("  Publish rejected — the log has the reason; the live "
              "content and the kept versions are untouched.")


```

Preview staging, the version rows both surfaces render, and restoring. `_stage_preview` runs the same extractor a publish runs, into a sibling the public server never sees; `_restore_site` is the core both surfaces run — the terminal's numbered list and the page's Restore button reach the same flip, so the two cannot disagree about what restoring means.

```python
# preview
def _preview_dir(site):
    """Where a staged preview lives: a sibling of the site's tree, never
    inside it. Inside, the public server would serve the unpublished draft
    to the internet."""
    return _resolve(site.serve_dir).rstrip(os.sep) + ".preview"


def _stage_preview(site, bundle):
    """Extract `bundle` where the loopback server can serve it, without
    going near the live tree. Returns "staged" or "rejected".

    The same _extract_bundle every content channel runs, so a bundle the
    publish door would refuse the preview refuses identically — a preview
    that accepted more than a publish would be a preview of something that
    can never ship."""
    dest = _preview_dir(site)
    shutil.rmtree(dest, ignore_errors=True)
    try:
        _extract_bundle(bundle, dest)
    except Exception as e:
        log.error("Preview bundle rejected: %s", e)
        shutil.rmtree(dest, ignore_errors=True)
        return "rejected"
    log.info("Staged a preview for %s", site.domain or site.serve_dir)
    return "staged"


def _clear_previews():
    """Drop every staged preview. A preview belongs to one `admin` run: it is
    a draft nobody published, and leaving it on disk would keep an
    unpublished tree beside a live site indefinitely."""
    for site in config.sites:
        shutil.rmtree(_preview_dir(site), ignore_errors=True)


def _tree_size(path):
    """(files, bytes) under path. A file that vanishes mid-walk is skipped,
    not raised: this is a description, and a racing publish must not make
    describing the site an error."""
    files = total = 0
    for root, _dirs, names in os.walk(path):
        for name in names:
            try:
                total += os.path.getsize(os.path.join(root, name))
                files += 1
            except OSError:
                pass
    return files, total


def _site_versions(site):
    """The kept trees of one site as rows both surfaces render: the name to
    restore by, when it was published, how many files and bytes it holds, and
    which one is live. Answering walks every tree on disk — which is why the
    page fetches it as its own /versions call instead of a field on the
    /status it polls every few seconds.

    The live tree is ALWAYS reported, ring member or not. A site published
    before the ring existed serves a tree the ring does not hold — it joins
    on its next publish — and reporting an empty list would tell an operator
    with a live, working site that nothing is published, which is both false
    and alarming. That tree carries its own mtime as its date and is never
    offered for restore, because it is already live.

    Walking every tree is why this is its own call rather than part of the
    status snapshot — it runs when an operator asks to see the history, not
    on every poll of a page that refreshes itself."""
    live_link = _resolve(site.serve_dir).rstrip(os.sep)
    live      = os.path.realpath(live_link)
    rows, in_ring = [], False
    for path, stamp in _version_dirs(site.serve_dir):
        files, total = _tree_size(path)
        is_live = os.path.realpath(path) == live
        in_ring = in_ring or is_live
        rows.append({"name": os.path.basename(path), "published": stamp,
                     "files": files, "bytes": total, "live": is_live})
    if not in_ring and os.path.isdir(live):
        files, total = _tree_size(live)
        try:
            stamp = int(os.path.getmtime(live))
        except OSError:
            stamp = 0
        rows.insert(0, {"name": os.path.basename(live), "published": stamp,
                        "files": files, "bytes": total, "live": True})
    return rows


def _restore_site(site, version=None):
    """Serve a kept version again. `version` is a name as _site_versions
    reports it; None means the newest tree that is not already live — plain
    'undo the last publish'. Returns "" on success, or a sentence saying why
    not.

    The flip is the publish's flip, so a restore has no window either. The
    tree is NOT consumed: it stays in the ring, so restoring the wrong one
    is itself undoable. That is the whole difference from the single-shot
    backup this replaced."""
    live_path = _resolve(site.serve_dir).rstrip(os.sep)
    versions  = _version_dirs(site.serve_dir)
    if not versions:
        return ("Nothing to restore — a kept version appears the first time "
                "new content replaces old.")
    if not os.path.islink(live_path):
        return ("This site's folder is not yet behind the version link — "
                "publish once, and the content it replaces joins the ring.")

    live = os.path.realpath(live_path)
    if version is None:
        target = next((p for p, _ in versions if os.path.realpath(p) != live), None)
        if target is None:
            return "Nothing to restore — the only kept version is the live one."
    else:
        # Matched by base name against the ring, never taken as a path: the
        # page's version name arrives over the wire, and a caller must not be
        # able to name a directory the ring does not hold.
        target = next((p for p, _ in versions
                       if os.path.basename(p) == version), None)
        if target is None:
            return f"No kept version named {version}."
        if os.path.realpath(target) == live:
            return "That version is already the live one."

    with _publish_lock:
        if not os.path.isdir(target):
            return "That version was removed while you were deciding."
        flip = live_path + ".flip"
        if os.path.lexists(flip):
            os.remove(flip)
        os.symlink(target, flip)
        os.replace(flip, live_path)              # the restore: one atomic flip
        # The tree may date from a publish that extracted as root — the same
        # ownership repair as a publish, for the same reason.
        _chown_operator(os.path.realpath(live_path), strip_world=True)
    log.info("Restored content for %s to %s",
             site.domain or site.serve_dir, os.path.basename(target))
    return ""


def _version_line(row):
    """One kept version as a line for the terminal: when, how big, and
    whether it is the one being served."""
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(row["published"]))
    size = (f"{row['bytes'] / (1024 * 1024):.1f} MB" if row["bytes"] >= 1024 * 1024
            else f"{row['bytes'] / 1024:.0f} KB")
    files = f"{row['files']} file" + ("" if row["files"] == 1 else "s")
    return f"{when} — {files}, {size}" + ("  (live)" if row["live"] else "")


def cmd_restore_site(site):
    """Roll back to a kept version. One choice is a yes/no; several are a
    numbered list, newest first. Nothing is consumed — the version being
    rolled away stays in the ring, so this is undoable in its own terms."""
    rows = _site_versions(site)
    kept = [r for r in rows if not r["live"]]
    if not kept:
        # One line, and it says when that changes rather than explaining the
        # ring: "no kept versions yet" alone leaves a reader wondering what
        # would make one.
        print("  Nothing to restore — a kept version appears the first time")
        print("  new content replaces old.")
        return

    if len(kept) == 1:
        print(f"\n  Kept: {_version_line(kept[0])}")
        if not _prompt("Restore this content?"):
            print("  Restore cancelled.")
            return
        choice = kept[0]
    else:
        print()
        for n, row in enumerate(kept, 1):
            print(f"  {n}. {_version_line(row)}")
        raw = _input("\n  Restore which? [number, Enter = cancel]: ").strip()
        if not raw.isdigit() or not (1 <= int(raw) <= len(kept)):
            print("  Restore cancelled.")
            return
        choice = kept[int(raw) - 1]

    err = _restore_site(site, choice["name"])
    print(f"  {err}" if err else "  Site content restored.")

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
        # Judged at the one write door `set`, the page, and the prompt
        # share; the alternative was the authority refusing the account at
        # issuance time, far from the typo.
        err = _email_problem(value)
        if err:
            return err
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
                # Stored in the one canonical spelling (the redirect-source
                # precedent): the request path compares this against a
                # normalized socket address, and "2001:0DB8::1" typed here
                # would never equal the lowercase form the socket yields.
                value = str(ipaddress.ip_address(value))
            except ValueError:
                return "trusted_proxy must be an IP address (or empty to clear)"
        target.trusted_proxy = value
    elif key == "health_path":
        # The balancer fitting, terminal-only by ruling. The criteria are
        # the redirect source's — site-absolute, printable ASCII — plus one
        # of its own: /.well-known/ stays out of reach, or a health path
        # could shadow the connection test and the ACME challenges that
        # live there, for every visitor.
        if value:
            if (not value.startswith("/") or len(value) > _MAX_REDIRECT_CHARS
                    or any(not (0x20 <= ord(c) <= 0x7E) for c in value)):
                return ("a health path is a site-absolute printable-ASCII "
                        "path like /healthz (or empty to turn the check off)")
            if value.startswith("/.well-known/"):
                return ("/.well-known/ is reserved — the connection test and "
                        "ACME challenges live there")
        target.health_path = value
    elif key == "tls_min_version":
        if value not in ("1.2", "1.3"):
            return "tls_min_version is 1.2 or 1.3"
        target.tls_min_version = value
    elif key == "ciphers":
        if value:
            # Judged by the only arbiter there is — OpenSSL itself. A string
            # it refuses would otherwise be refused at the next server
            # start, which fails closed: the site down over a typo saved
            # months earlier.
            try:
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).set_ciphers(value)
            except ssl.SSLError:
                return ("not a cipher string OpenSSL accepts "
                        "(or empty for the system default)")
        target.ciphers = value
    elif key in ("csp", "permissions_policy"):
        # Sent verbatim as a header value on every response: a control or
        # non-ASCII character is header injection, refused at the door.
        # Empty disables the header.
        if any(not (0x20 <= ord(c) <= 0x7E) for c in value):
            return (f"{key} is a header value — printable ASCII only "
                    "(or empty to disable the header)")
        setattr(target, key, value)
    return ""


```

```python
# Site pairs
def _set_site_value(target, key, value):
    """Validate one per-site pair and apply it to target (the chosen site, or
    a scratch Site during the validation pass). Returns an error string,
    empty on success."""
    if key == "username":
        # A colon can never reach the server in a username: sign-in joins
        # user:password into one credential and _handle_request splits it at
        # the first colon, so a stored username containing one locks every
        # visitor out while the health row still reads private-and-healthy.
        # Refused here — the one write path — so `set`, the page, and the
        # interactive prompt judge it with the same sentence.
        if ":" in value:
            return "a username cannot contain a colon — sign-in splits user:password at the first one"
        # The load door refuses control characters in every text field, and
        # a door that saved one would be saving an answer the next restart
        # refuses — the same judgment at every door, or no principle at all.
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            return "a username cannot contain control characters"
        # Auth is one switch, not two half-states: a cleared username takes
        # the stored password with it, on every surface that writes settings
        # (`set`, the page, and the prompt alike, since all land here).
        had_login = bool(target.username)
        target.username = value
        if not value:
            target.password_hash = ""
            target.password_salt = ""
        if bool(value) != had_login:
            # Flipping access resets browser copies to that access's
            # default — here, the one write path, so every door resets
            # identically. Each surface announces the reset itself
            # (cmd_set's line, the prompt's line, the page's hint):
            # loudly, never as a side effect discovered later.
            target.cache = "no" if value else "yes"
    elif key == "redirect":
        # One rule per token: 'redirect=/path,/target' adds or replaces a
        # permanent (301) rule, a trailing ',temporary' makes it a 302, and
        # 'redirect=/path,' removes the rule from whichever table holds it.
        # The tables are mappings and `set` speaks in scalars, so commas are
        # where the two grammars meet — which prices a target literally
        # ending in ',temporary' out of this grammar (servette.toml still
        # spells it). Validation is _clean_redirects — the same function the
        # config load runs, so a redirect the file would refuse the command
        # refuses too.
        src, comma, rest = value.partition(",")
        if not comma:
            return ("a redirect is a pair: redirect=/path,/where-it-goes "
                    "(or /path, to remove; add ,temporary for a 302)")
        head, c2, tail = rest.rpartition(",")
        temp = False
        if c2 and head and tail.strip().lower() in ("temporary", "permanent"):
            temp, rest = tail.strip().lower() == "temporary", head
        src, dst = src.strip(), rest.strip()
        perm_table = dict(target.redirects)
        temp_table = dict(target.redirects_temp)
        if not dst:
            # The canonical spelling, because that is what the tables' keys
            # are stored in — the same rule the add path and the lookup
            # follow, so the page can hand back a stored key verbatim.
            norm = _canonical_source(src)
            if not (perm_table.pop(norm, None) or temp_table.pop(norm, None)):
                return f"no redirect from {src}"
        else:
            checked = _clean_redirects({src: dst})
            if not checked:
                return ("a redirect goes from a site path to a site path or an "
                        "http(s) URL, and may not point at itself")
            # Replacing a rule replaces its permanence with it: one source
            # lives in exactly one table.
            norm = next(iter(checked))
            perm_table.pop(norm, None)
            temp_table.pop(norm, None)
            (temp_table if temp else perm_table).update(checked)
            # Two refusals the pair only earns in company, judged here so
            # the operator gets a sentence at the door — written into the
            # file, either would make the strict load door refuse the whole
            # config at the next restart. The cap first, over the two
            # tables' sum:
            if len(perm_table) + len(temp_table) > _MAX_REDIRECTS:
                return (f"the redirect table is full ({_MAX_REDIRECTS} rules) "
                        "— remove one first")
            # And the ring, over both tables at once — a 302 hop bounces a
            # browser exactly as a 301 does, and each pair is valid alone
            # (/a→/b saved earlier, /b→/a now).
            merged = {**perm_table, **temp_table}
            if len(_clean_redirects(merged)) != len(merged):
                return ("that redirect closes a ring — the chain of rules "
                        "would send a visitor in a circle")
        target.redirects      = perm_table
        target.redirects_temp = temp_table
    elif key == "active":
        # The pause between serving and deleting: a deactivated site keeps
        # its config and files but is invisible to routing and TLS alike.
        v = value.strip().lower()
        if v not in ("yes", "no"):
            return "active must be yes or no"
        if v == "yes" and not target.active:
            # Reactivation makes the certificate load-bearing again: startup
            # skips a paused site's cert but fails closed on an active one,
            # so saving this flip over an unloadable pair would save an
            # answer the next restart refuses. Judged with the same load the
            # server itself performs, here — the one write path — so `set`,
            # the page, and the prompt refuse with the same sentence.
            try:
                _build_ssl_context(_resolve(target.cert_file),
                                   _resolve(target.key_file))
            except Exception:
                return (f"the certificate does not load "
                        f"({target.cert_file or 'none configured'}) — "
                        "run 'config cert' first")
        target.active = (v == "yes")
    elif key == "cache":
        # What visitors' browsers keep — the toggle the access flip above
        # resets. "yes": copies re-checked every visit. "no": no copies.
        v = value.strip().lower()
        if v not in ("yes", "no"):
            return 'cache is "yes" (copies, re-checked every visit) or "no" (no copies)'
        target.cache = v
    return ""


```

The vocabulary `set` accepts, and its usage line.

```python
# The set vocabulary
_SET_HOST_KEYS = ("port", "email", "rate_limit", "auth_rate_limit",
                  "cache_size_mb",
                  "trusted_proxy", "health_path", "tls_min_version",
                  "ciphers", "csp", "permissions_policy")
_SET_SITE_KEYS = ("username", "active", "cache", "redirect")


def _set_usage():
    print("  Usage: set [n] key=value ...")
    print(f"  Host keys: {', '.join(_SET_HOST_KEYS)}")
    print(f"  Site keys: {', '.join(_SET_SITE_KEYS)} (site index first, default 0)")
    print("  A redirect is a pair: redirect=/path,/where-it-goes — and")
    print("  redirect=/path, (nothing after the comma) removes it. A third")
    print("  token, redirect=/path,/target,temporary, answers a temporary")
    print("  302 instead of the permanent 301.")


```

The command itself; its docstring names the two deliberately absent keys.

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
    # The scratch site starts blank for every scalar — each is simply
    # overwritten — but the redirect table is edited rather than replaced,
    # so validating a removal against an empty table would refuse a
    # redirect that is really there.
    scratch_site.redirects      = dict(site.redirects)
    scratch_site.redirects_temp = dict(site.redirects_temp)
    # The active flip judges against the site's real state: reactivation
    # loads the certificate it would make load-bearing, so the scratch
    # carries the cert paths and the current value — a blank scratch would
    # run the check against no certificate at all, or skip it.
    scratch_site.active    = site.active
    scratch_site.cert_file = site.cert_file
    scratch_site.key_file  = site.key_file
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
    pre_login, pre_cache = bool(site.username), site.cache
    try:
        err = _apply_settings(site, pairs)
    except PermissionError:
        print("  Error: writing the config needs root, and sudo is unavailable — re-run as root.")
        return
    if err:
        print(f"  {err}")
        return
    print(f"  Saved {len(pairs)} setting{'s' if len(pairs) != 1 else ''}.")
    # The access flip's reset is announced, never discovered: the operator
    # who changed a username learns the cache toggle moved with it.
    if bool(site.username) != pre_login and site.cache != pre_cache:
        print("  Browser copies reset to "
              + ("'no' — a private site leaves no copies on visitors' machines"
                 if site.username else
                 "'yes' — a public site's copies are re-checked every visit")
              + " (change it with: set cache=yes|no).")


```

## Config sub-shell

The settings display: host-level rows once, then each site's own block.

```python
# The settings display
def _config_show():
    def val(v):
        return v if v else "(not set)"

    host_rows = [
        ("HTTPS port",         config.port),
        ("Email",              val(config.email)),
        ("Rate limit",         f"{config.rate_limit} req/min"),
        ("Auth rate limit",    f"{config.auth_rate_limit} fails/min"),
        ("Cache size",         f"{config.cache_size_mb} MB"),
        ("Trusted proxy",      val(config.trusted_proxy)),
        ("Health check path",  config.health_path or "(off)"),
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
            ("Username",    val(site.username)),
            ("Password",    "(set)" if site.password_hash else "(not set)"),
            ("Browser copies",
             "kept, re-checked each visit" if site.cache == "yes"
             else "none"),
        ]
        for label, value in site_rows:
            print(f"    {label:<{_PAD - 2}} {value}")
    print()


def _config_sites():
    _section("Sites")
    for i, site in enumerate(config.sites):
        auth = "private" if site.username else "public"
        state = "" if site.active else ", DEACTIVATED (set active=yes to serve)"
        print(f"  {i}: {site.domain or '(self-signed)'} — {site.serve_dir}, {auth}{state}")
    print()
    print("  Edit one with e.g. 'cert 1', 'username 1' (index defaults to 0).")
    print("  'add-site' adds one; 'remove-site <n>' removes one.\n")


```

The two predicates every serve_dir edit runs through: it must sit inside the data directory (the publish swap and the systemd sandbox both depend on that), and it must not be a folder that holds Servette's own secrets.

```python
# serve_dir containment
def _is_within_base_dir(path):
    """True if path (already resolved) is BASE_DIR itself or somewhere under
    it. What actually turns on this: the systemd unit's ReadWritePaths only
    grants write access under BASE_DIR, so a serve_dir outside it SERVES
    fine but cannot take a publish under the sandboxed service — a failure
    a manual, unsandboxed run never shows. (The atomic swap itself is
    indifferent to where serve_dir lives: staging and every kept version
    are its siblings, so they share its filesystem anywhere.) Containment
    is an implementation fact, not an enforced guarantee (#123, ruled):
    every folder Servette assigns satisfies it by construction, and a
    hand-edited config pointing outside is reported as a blocking health
    row rather than refused.

    Defers to _within so containment is decided in exactly one place: two
    implementations of the same security predicate can drift apart, and only
    one of them would be the one anybody reads."""
    return _within(os.path.realpath(BASE_DIR), os.path.realpath(path))


def _serve_dir_exposes_secrets(path):
    """True when serving `path` would hand out Servette's own secrets — the
    config (password hashes), the ACME account key, or the TLS private keys
    under certs/. BASE_DIR itself holds all three; the certs tree is the
    keys. Either would be served as plain file reads, so both are refused as
    a serve_dir wherever the value came from — the load door's security
    floor, fatal where containment is merely reported, because a config
    that would publish the keys must not run at all. Containment inside
    BASE_DIR is deliberately NOT assumed here: a hand-edited serve_dir may
    point anywhere, which is why this judges the resolved path alone."""
    real  = os.path.realpath(path)
    base  = os.path.realpath(BASE_DIR)
    certs = os.path.join(base, "certs")
    return real == base or real == certs or real.startswith(certs + os.sep)


```

Adding a site asks the same questions setup asks for the first one — and its inline comments carry the two traps this function is shaped around: certificate names that must not collide across remove/add sequences, and a fallback pair that must exist on disk before ACME is even attempted.

```python
# add-site
def _invent_site_dir():
    """Create and own an empty folder for a new site. Servette names it: the
    folder is where publishes land, not a question an operator answers
    ([the folder is not a setting](../DECISIONS.md#the-folder-is-not-a-setting-serve_dir-has-left-the-vocabulary)).
    Both doors — the page's add-card and the terminal's add-site — come
    here, so neither can invent a folder the other would not."""
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
    """Add a site — the same two questions cmd_setup asks for the very first
    one, domain and password. The folder is not among them: Servette names
    and creates it, the same way the page's add-card does."""
    print("\n  Adding a new site.\n")
    # Nothing is written into it and nothing is offered: a site with no
    # index.html answers its own domain with the embedded error page, which
    # says the server is up and that nothing is published yet. Setup still
    # never leaves a site with nothing to serve (#37) — it just no longer
    # needs to put a file in a folder to keep that promise.
    folder = _invent_site_dir()
    print(f"  Content will land in {_resolve(folder)} — Servette's to manage.")
    print("  Until you publish, the site answers with Servette's error page.")

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

    print(f"\n  Site {idx} added. Run 'publish {idx} <folder>' — or use the")
    print("  admin page — to put content on it.")
    if not reloaded and (_server_running() or _service_is_active()):
        _reload_server()


```

Removal deletes the server's copies — the published tree, its slots, and its backup — because keeping them silently was the trap: folders compounding with no way to reclaim them short of raw shell commands, which is not one of Servette's two surfaces. The pause that keeps everything is `active=no`, a setting like any other. Certificates stay (tiny, and re-adding the same domain skips re-issuance); a folder another site still points at stays too; the last site can't be removed.

```python
# remove-site
def _remove_site(idx):
    """Drop site `idx` and delete its server copies — the live tree, every
    kept version in its ring, a staged preview, and the shapes that predate
    the ring. The operator's originals live in their own local storage;
    everything here is a derived copy, which is what makes deletion the
    honest meaning of 'remove' (deactivation is the keep-everything
    alternative). The site's certificate files are kept, and a folder another
    site still points at is left alone. Returns an error sentence, empty on
    success. Shared by the terminal's remove-site and the page's cards."""
    if not (0 <= idx < len(config.sites)):
        return f"no site {idx}"
    if len(config.sites) == 1:
        return "can't remove the only site — a box needs at least one"
    victim = config.sites[idx]
    # rstrip, exactly as every derived-tree helper does: a hand-edited
    # trailing slash in serve_dir would otherwise aim the .bak/.new/base
    # deletions at names that do not exist and leave the trees behind.
    base   = _resolve(victim.serve_dir).rstrip(os.sep)
    del config.sites[idx]
    config.save()
    shared = any(os.path.realpath(_resolve(s.serve_dir)) == os.path.realpath(base)
                 for s in config.sites)
    if not shared and _is_within_base_dir(base):
        # Every derived tree, named by the same functions that create them
        # rather than by a prefix sweep over the directory: a sweep is
        # shorter and would also delete a neighbouring site whose folder
        # name happens to start with this one's. _version_dirs is the ring
        # (a filter, not a prefix match), _content_slots and .bak are the
        # pre-ring shapes a legacy site may still hold, .new is an
        # abandoned staging tree, and _preview_dir is an unpublished draft.
        doomed = [p for p, _stamp in _version_dirs(victim.serve_dir)]
        doomed += list(_content_slots(victim.serve_dir))
        doomed += [base + ".bak", base + ".new", _preview_dir(victim), base]
        for path in doomed:
            try:
                if os.path.islink(path):
                    os.unlink(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
            except OSError:
                pass  # a copy that resists deletion must not block the removal
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
    if not _prompt(f"Remove site {idx} ({label})? Its server copies are deleted — "
                   f"originals in your local storage are untouched "
                   f"('set {idx} active=no' deactivates without deleting)."):
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

    if domain:
        # The same syntax judgment the page's name door runs — refused here,
        # instantly, rather than by the authority after a network round trip
        # that could only ever fail.
        problem = _domain_problem(domain)
        if problem:
            print(f"  → {problem}, unchanged")
            return

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
    if new_value == current:
        print("  → unchanged")
        return
    # Through the shared validator, so the prompt refuses exactly what
    # `set` and the page refuse — clearing included: an emptied username
    # takes the stored password with it there, on every surface.
    err = _set_site_value(site, "username", new_value)
    if err:
        print(f"  → {err}")
        return
    config.save()
    print("  → auth disabled, password cleared" if new_value == ""
          else "  → saved")
    # Announce the reset the access flip carried (loudly, by ruling).
    if bool(new_value) != bool(current):
        print("  → browser copies reset to "
              + ("'no' (private default: none on visitors' machines)"
                 if new_value else
                 "'yes' (public default: re-checked every visit)"))


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

The `[n]` site-index convention, resolved in one place.

```python
# The site-index argument
def _config_site_arg(args):
    """Resolve cert/username/password/publish/restore-site's optional
    site-index argument to a Site, defaulting to site 0 — same [n]
    convention as the top-level 'log [n]'. Prints its own error and returns
    None if given but invalid, so callers can just no-op on None."""
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
        elif cmd in _SET_HOST_KEYS:
            # Every scalar knob has exactly one terminal door: `set`. The
            # prompt layer that wrapped it re-implemented the same
            # validations in a guided voice for an audience that has moved
            # to the admin page; the reader who remains knows key=value.
            print(f"  Scalars are set non-interactively: set {cmd}=<value>")
            print("  (from the main shell — 'back' first)")
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
                print("  Error: start needs root, and sudo is unavailable — re-run as root.")
            except FileNotFoundError:
                print("  Error: start requires a Linux server with systemd.")
            except subprocess.CalledProcessError as e:
                print(f"  Error starting service: {e}")
    else:
        start_server()
        if _server_running():
            # The macOS line carries only what the line above does not: there
            # is no service to install here, and tmux is the substitute. It
            # does not restate that quitting stops the server.
            print("  Running in session only — server will stop when you quit.")
            if _IS_MACOS:
                print("  A permanent service needs Linux; here, run it under tmux or screen.")
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
            print("  Service stopped.")
            log.info("Service stopped")
            stopped = True
        except PermissionError:
            print("  Error: stop needs root, and sudo is unavailable — re-run as root.")
        except FileNotFoundError:
            print("  Error: stop requires a Linux server with systemd.")
        except subprocess.CalledProcessError as e:
            print(f"  Error stopping service: {e}")

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
            print("  No journal on macOS — in session mode the log is this terminal's own output.")
        else:
            print("  journalctl not found. Is this a systemd system?")


```

Traffic is the journal re-read as counts: the server already logs every response, so the summary is pure reading — no collection, nothing new written, and no visitor identity in the result (IPs stay in the raw log for `log`; a dashboard has no business casually displaying them).

```python
# Traffic
def _traffic_lines(days=7):
    """The journal's lines for the window, timestamped (short-iso), oldest
    first; [] where no journal answers (macOS session mode, or a journal
    that needs privileges this shell doesn't hold)."""
    try:
        result = subprocess.run(
            ["journalctl", "-u", "servette", "-o", "short-iso",
             "--since", f"-{days}d", "--no-pager"],
            capture_output=True, text=True)
        return result.stdout.splitlines()
    except FileNotFoundError:
        return []


_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def _parse_traffic(lines, days=7, now=None):
    """Tally journal lines into the traffic summary: requests per day,
    status counts, top paths. Pure, so the suite can feed it real log
    lines (`now` pins the window's end for it; None means now). Every
    bucket in the window is present, zeroes included — the chart's x-axis
    is time, and a quiet day left out made two busy endpoints read as a
    steady week. Each line carries two prefixes — the journal's own
    ('<iso> <host> servette[pid]:') and then setup_logging's format
    ('<date> <time>  LEVEL  <message>') — so the level name is the anchor
    the message begins after. Anchoring on the unit token instead was the
    bug that made this count nothing at all: the Python timestamp sat
    where the status was expected. Only response lines count — every
    served response logs as '<status> <path> … to <ip>' (or 'from' on
    refusals) — and systemd's own lines, carrying no level, are skipped.
    Paths are tallied from content responses (200/206/304). IPs are never
    carried into the result."""
    per_day, statuses, paths = {}, {}, {}
    stamp = (lambda p: p[:13].replace("T", " ")) if days <= 2 else (lambda p: p[:10])
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or len(parts[0]) < 10 or parts[0][4:5] != "-":
            continue
        day = stamp(parts[0])
        lvl = next((i for i, p in enumerate(parts) if p in _LOG_LEVELS), None)
        if lvl is None:
            continue
        msg = parts[lvl + 1:]
        if not msg or len(msg[0]) != 3 or not msg[0].isdigit():
            continue
        statuses[msg[0]] = statuses.get(msg[0], 0) + 1
        per_day[day] = per_day.get(day, 0) + 1
        if msg[0] in ("200", "206", "304"):
            path = next((p for p in msg[1:] if p.startswith("/")), None)
            if path:
                paths[path] = paths.get(path, 0) + 1
    # The zero-fill: journalctl's -Nd window is N*24 hours ending now, so
    # it can touch N+1 calendar days — every bucket it covers gets a row.
    # Line-made buckets just outside the fill (clock skew, a test's fixed
    # dates) are kept: counted traffic is never dropped over its stamp.
    end  = now or datetime.datetime.now()
    step = datetime.timedelta(hours=1) if days <= 2 else datetime.timedelta(days=1)
    fmt  = "%Y-%m-%d %H" if days <= 2 else "%Y-%m-%d"
    for i in range((days * 24 if days <= 2 else days) + 1):
        per_day.setdefault((end - i * step).strftime(fmt), 0)
    top = sorted(paths.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    return {"days": sorted(per_day.items()), "statuses": dict(sorted(statuses.items())),
            "top_paths": top, "window_days": days,
            "bucket": "hour" if days <= 2 else "day",
            "total": sum(statuses.values())}


def _traffic_summary(days=7):
    return _parse_traffic(_traffic_lines(days), days)


def cmd_traffic():
    """`traffic` — requests, statuses, and top paths from the last 7 days,
    read from the journal. The page's Statistics tab renders this same
    summary; the raw log (IPs included) stays with `log`."""
    t = _traffic_summary()
    if not t["total"]:
        print("  No traffic in the window — or no readable journal on this host.")
        return
    _section("Traffic — last 7 days")
    print(f"  Requests: {sum(n for _, n in t['days'])}")
    for day, n in t["days"]:
        print(f"    {day}  {n}")
    print("  Statuses: " + ", ".join(f"{s} x{n}" for s, n in t["statuses"].items()))
    print("  Top paths:")
    for path, n in t["top_paths"]:
        print(f"    {n:>6}  {path}")
    print()


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
def _production_issues(running=None):
    """Return a list of strings describing conditions that prevent production
    readiness, across every configured site. Single-site installs (still the
    common case) see exactly today's unlabeled messages; a labeled site name
    is added only once there's more than one to tell apart. `running` rides
    to the swap check for a caller that already knows it (_status_data asks
    systemd once for the whole snapshot); None lets the check ask itself."""
    issues  = []
    labeled = len(config.sites) > 1
    for site in config.sites:
        tag = f" ({site.domain or site.serve_dir})" if labeled else ""
        if not site.serve_dir or not os.path.exists(_resolve(site.serve_dir)):
            issues.append(f"serve directory not configured{tag} — run 'config'")
        elif (os.path.exists(SERVICE_PATH)
                and not _is_within_base_dir(_resolve(site.serve_dir))):
            issues.append(f"serve directory outside {BASE_DIR}{tag} — the "
                          "sandboxed service cannot publish there")
        if not site.cert_file or not os.path.exists(_resolve(site.cert_file)):
            issues.append(f"certificate not configured{tag} — run 'config cert'")
        elif not site.domain:
            # Keyed on the configured domain rather than the certificate's
            # subject: a site with no domain is the catch-all whatever its cert
            # contains, gets no HSTS, and is not reachable by name — so 'add a
            # domain' is the advice that actually changes any of that.
            issues.append(f"self-signed certificate{tag} — run 'config cert' to add a domain")
        # A public site is deliberately not listed: public is a choice, not
        # a defect — most sites are public. The half-state IS a defect: a
        # username with nothing stored to check locks every visitor out.
        if site.username and not site.password_hash:
            issues.append(f"a username with no stored password{tag} — visitors are locked out; run 'config' to set one")
        # No colon-username line: every door refuses one, so it cannot
        # reach a running config.
    mem_kb, avail_kb, committed_kb = _meminfo()
    rec     = _swap_recommendation(mem_kb, committed_kb,
                                   _cache_headroom_mb(config.cache_size_mb, running))
    ours_mb, foreign_mb = _swap_sizes()
    offer   = _swap_offer(rec // (1024 * 1024) if rec else None,
                          os.path.exists(_SWAP_PATH), ours_mb, foreign_mb)
    if offer is not None:
        if ours_mb:
            # ours_mb, not SwapTotal: with a swap partition alongside, the
            # total printed a size the swapfile does not have.
            issues.append(f"swapfile {ours_mb} MB but {rec // (1024 * 1024)} MB "
                          "recommended — run 'enable' to resize")
        elif os.path.exists(_SWAP_PATH):
            # The file is on disk but not swapped on — "no swap" would be
            # untrue on this host, and the fix is activation, not creation.
            issues.append("swapfile present but inactive — run 'enable' to "
                          "re-activate it")
        else:
            issues.append(f"no swap ({mem_kb // 1024} MB RAM) — run 'enable' to add a swapfile")
    # Both surfaces say the same thing about disk: the page reads the health
    # row, the terminal reads this list, and neither may know something the
    # other does not.
    disk = _disk_snapshot()
    if _disk_is_low(disk):
        issues.append(f"only {disk['free_mb']:,.0f} MB free where content lands — "
                      "a publish may fail; remove what the box no longer needs")
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
                 "--property=ActiveEnterTimestampMonotonic,MemoryCurrent,"
                 "CPUUsageNSec,MainPID"],
                capture_output=True, text=True
            )
            props = dict(
                line.split("=", 1) for line in result.stdout.strip().splitlines() if "=" in line
            )
        except Exception:
            return rows
        elapsed = None
        mono = props.get("ActiveEnterTimestampMonotonic", "")
        if mono and mono != "0":
            try:
                with open("/proc/uptime") as f:
                    boot_elapsed = float(f.read().split()[0])
                elapsed = boot_elapsed - int(mono) / 1_000_000
                if elapsed >= 0:
                    rows.append(("Uptime", _format_uptime(elapsed)))
                else:
                    elapsed = None
            except Exception:
                elapsed = None
        mem = props.get("MemoryCurrent", "")
        if mem and mem.isdigit() and int(mem) > 0:
            rows.append(("Memory", f"{int(mem) / (1024 * 1024):.1f} MB"))
        # Average CPU for this run: systemd's cumulative CPU time over the
        # uptime just computed. Free — the same systemctl call already
        # answers it — and the honest reading on a static server, where
        # sustained CPU means something is wrong rather than popular. It is
        # an average, not a live meter: a spike that has passed is diluted
        # by every quiet second since.
        cpu = props.get("CPUUsageNSec", "")
        if elapsed and cpu.isdigit() and elapsed > 0:
            pct = (int(cpu) / 1_000_000_000) / elapsed * 100
            rows.append(("CPU", f"{pct:.1f}% average this run"))
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
        "active":    site.active,
        "serve_dir": site.serve_dir,
        "auth":      bool(site.username),
        "cert_days": _cert_days_remaining(_resolve(site.cert_file)),
    } for i, site in enumerate(config.sites)]


def _health_checks(service_active=None):
    """Every health fact as a row, green included — the admin page's Health
    checks card. The same ground _production_issues walks, saying what passes
    as plainly as what needs attention: ok True is healthy, False needs it.
    `key` is stable for consumers; `site` carries the index where the row is
    site-scoped, None where it is host-wide — the admin page splits its
    Settings cards (This site / This server) on exactly that.
    `service_active` lets _status_data hand in the one systemd probe it
    already ran; None asks here."""
    rows = []
    if service_active is None:
        service_active = _service_is_active()
    running = service_active or _server_running()
    # Labeled Mode, because that is what its three answers describe — and
    # the page prints no second Mode row beside it.
    rows.append({"key": "service", "site": None, "ok": running,
                 "blocking": not running, "label": "Mode",
                 "detail": "system service (survives reboots)" if service_active
                 else ("session only (stops when this terminal closes)" if running
                       else "stopped — 'start' brings it up")})
    if not _IS_MACOS:
        armed = os.path.exists(NETWATCH_PATH + ".timer")
        rows.append({"key": "netwatch", "site": None, "ok": armed,
                     "blocking": False, "label": "Network watchdog",
                     "detail": "armed (checks once per minute)" if armed
                     else "not installed — 'enable' provisions it"})
        mem_kb, _avail_kb, committed_kb = _meminfo()
        rec = _swap_recommendation(mem_kb, committed_kb,
                                   _cache_headroom_mb(config.cache_size_mb, running))
        ours_mb, foreign_mb = _swap_sizes()
        rec_mb = (rec // (1024 * 1024)) if rec else None
        offer  = _swap_offer(rec_mb, os.path.exists(_SWAP_PATH), ours_mb, foreign_mb)
        have   = (ours_mb or 0) + foreign_mb
        # The recommendation is named by the field that sets it, so this row
        # states the size and speaks up only when it falls short. `offer` is
        # a (description, hint) pair for the terminal's prompt — never a
        # number; do not interpolate it.
        if offer is None:
            detail = f"{have} MB active" if have else "not needed at this host's memory"
        elif have:
            detail = (f"{have} MB active, below the {rec_mb} MB recommendation"
                      if rec_mb else f"{have} MB active")
        elif os.path.exists(_SWAP_PATH):
            # On disk but not swapped on: "none" would be untrue, and the
            # fix is activation, not creation.
            detail = "swapfile present but inactive — 'enable' re-activates it"
        else:
            detail = f"none — {rec_mb} MB recommended" if rec_mb else "none"
        # `quiet` (this row only): warn amber where it lives — the Server
        # tab row and the terminal — but never as the cross-tab banner
        # (ruled: an undersized swap is worth its row's colour, not a
        # "This server" band over the site cards).
        rows.append({"key": "swap", "site": None, "ok": offer is None,
                     "quiet": True,
                     "blocking": False, "label": "Swap file", "detail": detail})
    # Disk is host-wide and platform-independent: a full disk is the outage
    # every other row assumes is not happening. A publish that cannot write
    # its tree fails in staging and leaves the live site alone, so this is a
    # warning rather than a fault — but an unread number prevents nothing,
    # which is why it is a row and not only a figure.
    disk = _disk_snapshot()
    if disk["free_mb"] is not None:
        low = _disk_is_low(disk)
        rows.append({"key": "disk", "site": None, "ok": not low,
                     "blocking": False, "label": "Disk",
                     "detail": f"{disk['free_mb']:,.0f} MB free of "
                               f"{disk['total_mb']:,.0f} MB"
                               + (" — publishing may fail" if low else "")})

    labeled = len(config.sites) > 1
    for i, site in enumerate(config.sites):
        tag = f"Site {i} · " if labeled else ""
        # The folder reports only when something is wrong. Where content
        # lives is Servette's business, not the operator's (the
        # folder-retirement ruling) — but a serve directory that has
        # vanished, or one a hand-edited config points outside the data
        # directory, is a defect the operator must hear about. Outside is
        # reported, not refused (#123, ruled), and only where the
        # consequence exists: the site serves from anywhere, and only the
        # systemd sandbox — ReadWritePaths under BASE_DIR — makes publishing
        # fail there, working in a manual run and dying under the service.
        # A session server (no unit) has no sandbox and no trap to name;
        # `enable`, which writes the unit, is where that box is warned.
        resolved_dir = _resolve(site.serve_dir)
        dir_ok = bool(site.serve_dir) and os.path.exists(resolved_dir)
        if not dir_ok:
            rows.append({"key": "dir", "site": i, "ok": False, "blocking": True,
                         "label": tag + "Folder",
                         "detail": "missing — publish to recreate it"})
        elif (os.path.exists(SERVICE_PATH)
                and not _is_within_base_dir(resolved_dir)):
            rows.append({"key": "dir", "site": i, "ok": False, "blocking": True,
                         "label": tag + "Folder",
                         "detail": f"outside {BASE_DIR} — the sandboxed "
                                   "service cannot publish here"})
        # One PEM load answers both certificate facts for the row.
        cert   = _load_cert(_resolve(site.cert_file)) if site.cert_file else None
        days   = _cert_days(cert)
        covers = _cert_covered_domain(cert)
        mismatched = bool(site.domain) and bool(covers) and covers != site.domain
        cert_ok = days is not None and days > 0 and bool(site.domain) and not mismatched
        # Severity turns on whether the site claims a public name. With a
        # domain set, an untrusted certificate is a full-page browser
        # interstitial for everyone who visits it — the site is unusable at
        # the name it advertises. Without one, self-signed is simply where
        # every site starts, and reporting it in the same red as a locked-out
        # site would cry wolf on the normal case.
        rows.append({"key": "cert", "site": i, "ok": cert_ok,
                     "blocking": bool(site.domain) and not cert_ok,
                     "label": tag + "Certificate",
                     "days": days,
                     "detail": (f"{days} days remaining (auto-renew enabled)" if cert_ok
                                else f"issued for {covers} — get one for this name" if mismatched
                                else "expired" if (days is not None and days <= 0)
                                else "self-signed" if days is not None
                                else "not configured")})
        # A public site is a choice, not a defect: no password is healthy.
        # What IS broken is the half-state — a username with nothing stored
        # to check against, which locks every visitor out.
        half_auth = bool(site.username) and not site.password_hash
        rows.append({"key": "password", "site": i,
                     "ok": not half_auth,
                     "blocking": half_auth, "label": tag + "Access",
                     "detail": ("a username with no stored password — set one below, or make the site public"
                                if half_auth
                                else "private — visitors sign in" if site.username
                                else "public — anyone can view it (the form below makes it private)")})
    return rows


def _load_snapshot(service_active=None):
    """Average CPU for this run and current memory, as numbers — the same
    facts _status_rows prints for the terminal, in the form the page
    renders. An average, not a live meter: cumulative CPU time over the
    time the server has been up, so a spike that has passed is diluted by
    every quiet second since. None for any figure that cannot be read.
    `service_active` lets _status_data hand in the one systemd probe it
    already ran; None asks here."""
    out = {"cpu_percent": None, "memory_mb": None, "uptime_s": None,
           "started_at": None, "cpu_ns": None, "sampled_at": time.time()}
    if service_active is None:
        service_active = _service_is_active()
    if service_active:
        try:
            result = subprocess.run(
                ["systemctl", "show", "servette",
                 "--property=ActiveEnterTimestampMonotonic,MemoryCurrent,CPUUsageNSec"],
                capture_output=True, text=True)
            props = dict(line.split("=", 1) for line in result.stdout.strip().splitlines()
                         if "=" in line)
            mono = props.get("ActiveEnterTimestampMonotonic", "")
            if mono.isdigit() and mono != "0":
                with open("/proc/uptime") as f:
                    elapsed = float(f.read().split()[0]) - int(mono) / 1_000_000
                if elapsed > 0:
                    out["uptime_s"] = elapsed
                    out["started_at"] = out["sampled_at"] - elapsed
                    cpu = props.get("CPUUsageNSec", "")
                    if cpu.isdigit():
                        # The raw counter travels too: successive readings
                        # are what let the page draw a live meter without
                        # anything being sampled or stored server-side.
                        out["cpu_ns"] = int(cpu)
                        out["cpu_percent"] = (int(cpu) / 1_000_000_000) / elapsed * 100
            mem = props.get("MemoryCurrent", "")
            if mem.isdigit() and int(mem) > 0:
                out["memory_mb"] = int(mem) / (1024 * 1024)
        except Exception:
            pass
    elif _server_running() and _server_start_time is not None:
        # Session mode: the server IS this process, so its own CPU clock
        # answers — no systemd to ask.
        elapsed = time.monotonic() - _server_start_time
        if elapsed > 0:
            times = os.times()
            out["uptime_s"] = elapsed
            out["started_at"] = out["sampled_at"] - elapsed
            out["cpu_ns"] = int((times[0] + times[1]) * 1_000_000_000)
            out["cpu_percent"] = (times[0] + times[1]) / elapsed * 100
    return out


_LATEST_CACHE = {"at": None, "version": None}


def _latest_release(ttl=21600):
    """The newest Servette on PyPI, or None when the question cannot be
    answered. Servette makes no outbound call on its own schedule: this one
    happens when the operator opens the admin page and asks, is cached for
    six hours, and fails silently — a box with no route out, or a PyPI
    having a bad day, must cost the page nothing but this row."""
    now = time.monotonic()
    if _LATEST_CACHE["at"] is not None and now - _LATEST_CACHE["at"] < ttl:
        return _LATEST_CACHE["version"]
    version = None
    try:
        with urllib.request.urlopen(
                "https://pypi.org/pypi/servette/json", timeout=4) as response:
            version = json.loads(response.read().decode("utf-8"))["info"]["version"]
    except Exception:
        version = None
    _LATEST_CACHE["at"], _LATEST_CACHE["version"] = now, version
    return version


def _version_parts(text):
    """A version as comparable integers, ignoring anything that is not one —
    Servette's own scheme is 0.<yy>.<doy>, and a suffix should never make a
    release look older than it is."""
    parts = []
    for chunk in str(text).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _upgrade_available():
    """The newer version's string when PyPI has one, else None. Telling is
    all Servette does here: installing is the package manager's job, and
    stays in the terminal (DECISIONS, 'pip install is the only installation
    path')."""
    latest = _latest_release()
    if latest and _version_parts(latest) > _version_parts(__version__):
        return latest
    return None


def _swap_snapshot(running=None):
    """Servette's own swapfile as numbers — what is allocated, what the
    kernel reports active, and what the sizing recommends. None on a host
    with no swap to speak of (macOS manages its own). `running` rides
    through to the headroom charge, for a caller that already knows it.

    The two sizes differ by design and the difference matters. /proc/swaps
    reports USABLE space, which is the file minus one page of header, so a
    1100 MB swapfile reads as 1099 MB active. A field showing the active
    number would invite an operator to type the recommended 1100, save, and
    watch it come back 1099 — a resize that looks broken while working
    perfectly. The field shows what was allocated; the status row keeps
    reporting what is active, which is the honest thing for a status row."""
    if _IS_MACOS:
        return {"allocated_mb": None, "active_mb": None, "recommended_mb": None}
    mem_kb, _avail_kb, committed_kb = _meminfo()
    rec = _swap_recommendation(mem_kb, committed_kb,
                               _cache_headroom_mb(config.cache_size_mb, running))
    ours_mb, _foreign = _swap_sizes()
    allocated = None
    try:
        allocated = os.path.getsize(_SWAP_PATH) // (1024 * 1024)
    except OSError:
        pass                      # no swapfile of ours on this host
    return {"allocated_mb": allocated, "active_mb": ours_mb,
            "recommended_mb": (rec // (1024 * 1024)) if rec else None}


def _disk_snapshot():
    """Free and total disk on the filesystem holding the data directory —
    where site content, the versions kept behind it, and the config live.
    That filesystem rather than '/' because it is the one a publish can
    fill. None for a figure the host will not answer."""
    try:
        total, _used, free = shutil.disk_usage(BASE_DIR)
    except OSError:
        return {"free_mb": None, "total_mb": None}
    return {"free_mb": free / (1024 * 1024), "total_mb": total / (1024 * 1024)}


def _disk_is_low(disk):
    """Whether free disk is low enough to say so. Two thresholds, because
    one does not fit both a 4 GB Pi card and a 200 GB VPS: an absolute
    floor that a publish plus its kept versions can exhaust, and a
    fraction that catches a large disk filling steadily."""
    if disk["free_mb"] is None:
        return False
    return (disk["free_mb"] < _DISK_LOW_MB
            or disk["free_mb"] < disk["total_mb"] * _DISK_LOW_FRACTION)


def _status_data():
    """The status snapshot as data — the shape `status --json` prints, for
    external tooling. cert_days is None when no certificate is readable;
    `checks` is the health-row form of the same facts, `load` the
    utilization figures, and `disk` the space left where content lands.

    The page's live meter polls this every few seconds, so the snapshot
    asks systemd exactly once and hands the answer to everything below —
    each subprocess spawn saved here is saved on every meter tick."""
    service_active = _service_is_active()
    running        = service_active or _server_running()
    return {
        "version":  __version__,
        "running":  running,
        "mode":     "service" if service_active else ("session" if running else None),
        "sites":    _site_rows(),
        "issues":   _production_issues(running),
        "warnings": _cache_warnings(),
        "checks":   _health_checks(service_active),
        "load":     _load_snapshot(service_active),
        "swap":     _swap_snapshot(running),
        "disk":     _disk_snapshot(),
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
            # Unreachable from any command: every folder Servette assigns is
            # under BASE_DIR. It takes a hand-edited servette.toml to get
            # here, so the sentence names the file rather than a command
            # that no longer exists.
            print(f"  serve_dir {serve_path} is outside {BASE_DIR}, where the publish")
            print(f"  swap and the service sandbox both need it — fix it in {Config.CONFIG_FILE}.")
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
    stale = _stale_units()
    # _stale_units answers empty when this environment can name no
    # interpreter to write into a unit — but an installed service in that
    # state is exactly the one whose pinned interpreter may have vanished
    # (a 203/EXEC crash-loop with only the journal as a symptom), so the
    # drift report is still owed a look.
    orphaned = (not stale and _service_file_exists()
                and not _unsafe_unit_path() and _unit_python_path() is None)
    if stale or orphaned:
        drift = _service_env_drift()
        if drift:
            print("  The enabled service was set up from a different environment:")
            for d in drift:
                print(f"    - {d}")
            print("  Leaving it untouched — run 'enable' to re-provision from this shell.")
        elif orphaned:
            pass   # nothing stale to rewrite and nothing drifted to report
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
                  "publish", "restore-site")

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

    The one notice goes to stderr: the child owns stdout, and `status --json`
    has to stay parseable through an elevation."""
    global _elevated_status
    if not shutil.which("sudo"):
        print(f"  '{cmd}' needs root, and sudo is not installed — re-run as root.",
              file=sys.stderr)
        _elevated_status = 1
        return True
    # Nothing is printed on the way in. sudo announces itself when it wants
    # a password, and says nothing when it does not — which is the right
    # amount either way. A line of ours ahead of it told an operator who
    # just typed an admin command something they already knew.
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
            print("  Usage: log [number]")
    elif cmd == "traffic":
        cmd_traffic()
    elif cmd == "admin":
        cmd_admin()
    elif cmd == "publish":
        cmd_publish(args)
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
            print("  Goodbye.")
            break
        elif not run_command(cmd, args):
            print(f"  Unknown command: {cmd}. Type 'help' for a list of commands.")


```
