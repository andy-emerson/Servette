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

# The config singleton
config = Config()

```

Two ways in. systemd runs `--serve`: serve until stopped, and exit nonzero if the server dies on its own, so systemd restarts the service. A person just runs the file — and gets the shell.

```python
# The entry point
if __name__ == "__main__":
    _bootstrap()  # no-op if already in venv; otherwise re-execs into venv

    if "--serve" in sys.argv:
        start_server()
        try:
            _watch_server()
        except KeyboardInterrupt:
            stop_server()
        else:
            log.error("HTTPS server stopped unexpectedly — exiting so systemd restarts the service")
            sys.exit(1)
    else:
        shell()
```
