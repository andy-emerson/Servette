# MAIN

*The program's entry point: the `config` singleton and the `if __name__ == "__main__"` dispatch. Built last, and it must be — these are statements that run on import, and every definition they call lives in the sections above.*

*Authored here. `servette.py` is built from the Markdown sources in `src/` by [`build.py`](build.py) — edit the Markdown, not the generated file.*

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

Three ways in. systemd runs `--serve`: serve until stopped, and exit nonzero if the server dies on its own, so systemd restarts the service. `servette <command>` runs one shell command and exits — the form external tooling drives (over SSH, which is the authentication), sharing the interactive shell's dispatcher so the two surfaces cannot drift; it exits 2 on an unknown command, and deliberately skips the startup refresh so `status --json` output stays parseable. Bare `servette` is the interactive shell. (`python -m servette` is the same entry through `__main__.py`.)

```python
# The entry point
def main():
    if "--serve" in sys.argv:
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
    else:
        shell()


if __name__ == "__main__":
    main()
```
