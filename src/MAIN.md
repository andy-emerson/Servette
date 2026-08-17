# MAIN

*The program's entry point: the `config` singleton and the `if __name__ == "__main__"` dispatch. Built last, and it must be — these are statements that run on import, and every definition they call lives in the sections above.*

*Authored here. `servette.py` is generated from the Markdown sources in `src/` — by the package build itself ([`_literate_backend.py`](_literate_backend.py)), or by hand with [`build.py`](build.py). Edit the Markdown, never the module; the committed copy exists to be read, and `--check` holds it equal to the sources.*

One `Config` for the whole process, created here at the bottom of the file rather than beside its class.

> Config is a module-level singleton, instantiated here (not at its class
> definition, near the top) because migrating a pre-multi-site flat config
> calls _domain_from_cert() to backfill the migrated site's domain, and that
> function is defined much later, in Certificate management. Dependency
> injection (passing config into every function) is the textbook alternative,
> but the stdlib request handlers have fixed signatures and cannot accept
> extra arguments. In a single-file server that is always run as a process,
> the global is the right call.

```python

# The data directory must exist before the singleton loads from it. Unwritable
# (not root on a fresh host) is not fatal: config falls back to defaults and
# read-only commands still work — the first privileged command creates it.
try:
    os.makedirs(BASE_DIR, exist_ok=True)
except OSError:
    pass

# The config singleton
config = Config()

```

Three ways in. systemd runs `--serve`: refuse outright a config that exists but cannot be read (the shell's defaults-stand-in affordance would serve a password-protected site with no password), then serve until stopped, and exit nonzero if the server dies on its own, so systemd restarts the service. `servette <command>` runs one shell command and exits — the form external tooling drives (over SSH, which is the authentication), sharing the interactive shell's dispatcher so the two surfaces cannot drift; it exits 2 on an unknown command, passes on sudo's exit status when the command elevated, and deliberately skips the startup refresh so `status --json` output stays parseable. Bare `servette` is the interactive shell. (`python -m servette` is the same entry: a single module run with `-m` executes with `__name__` set to `__main__`, which is exactly the dispatch below.)

```python
# The entry point
def main():
    try:
        _main()
    except BrokenPipeError:
        # A consumer closed stdout mid-print — `servette status | head` is the
        # canonical case. That is the consumer's normal behavior, not a fault
        # here, so no traceback. stdout is re-pointed at devnull before exit so
        # the interpreter's shutdown flush cannot raise the same error again,
        # and the exit status is 141 (128+SIGPIPE): what the shell reports for
        # any tool that dies on a closed pipe, so pipelines see the convention
        # they already handle.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(141)


def _main():
    if sys.argv[1:2] == ["--serve"]:
        # Fail closed. Defaults standing in for an unreadable config is the
        # SHELL's affordance — it elevates and reads again as root. A service
        # has no second try, and the defaults carry no password: serving them
        # would open a protected site to the world because a file's ownership
        # broke. Exiting nonzero puts the truth in the journal instead.
        if config.unreadable:
            log.error("servette.toml exists but cannot be read — refusing to "
                      "serve defaults in its place. Fix its ownership: "
                      "chown servette:servette %s", config.CONFIG_FILE)
            sys.exit(1)
        start_server()
        try:
            _watch_server()
        except KeyboardInterrupt:
            stop_server()
        else:
            log.error("HTTPS server stopped unexpectedly — exiting so systemd restarts the service")
            sys.exit(1)
    elif len(sys.argv) > 1:
        cmd, args = sys.argv[1].lower(), sys.argv[2:]
        if not run_command(cmd, args):
            print(f"Unknown command: {cmd}. Run 'servette' for the interactive shell and its command list.")
            sys.exit(2)
        # The work may have happened in an elevated child. Exit with what sudo
        # made of it, so a refused password reads as a failure to whatever is
        # driving this over SSH instead of a silent success.
        if _elevated_status:
            sys.exit(_elevated_status)
    else:
        shell()


if __name__ == "__main__":
    main()
```
