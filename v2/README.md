> Draft of the `servette` organization's profile README (the `README.md` in its `.github` repository, which GitHub shows on the organization's page). Nothing it describes beyond the server is built; the organization does not yet exist. It leaves this repository when the organization is created.

# Servette

**Simple and secure servers for things that are just a file.**

Python's standard library ships a web server that serves a folder in one command and warns, in its own documentation, that it is not for production. Servette is the production layer over that idea: a trusted certificate that renews itself, HTTPS only, security headers on every response, rate limiting, optional passwords, and a hardened service that survives reboots — in one module that one person can read in full.

The same idea extends to anything else that is just a file and needs a careful server in front of it. Each product in this organization is one such server, or a tool for using them, and each makes the same promise from its own side: **simple and secure**, for its purpose, and no more.

| Repository | What it is | For |
| - | - | - |
| [`servette`](https://github.com/servette/servette) | the server: serves static sites securely from one Python module, administered from its command line | the person who installs with a package manager and works in a terminal |
| [`servette-database`](https://github.com/servette/servette-database) | the first extension: the same server with `QUERY`, serving read-only embedded databases | the person with a SQLite or DuckDB file to publish as a queryable site |
| [`servette-admin`](https://github.com/servette/servette-admin) | the desktop application: add a box, click it, publish and configure from a window; it speaks to the server over your own SSH connection | the person who wants a familiar install and a GUI |
| [`servette-website`](https://github.com/servette/servette-website) | servette.org: the project site, served by Servette itself | everyone |

## The one principle

Every product derives its own rule from **simple and secure**, as strong as its purpose allows:

- The server never writes and never evaluates input at request time. Read and send, nothing more. Most of its security is what you get for free by never doing certain things.
- The database extension still never writes; it evaluates a query only inside an engine that cannot write, cannot reach outside its file, and cannot run past a budget. It is less secure than the static server by exactly that distance, and says so.
- The app holds no credential but the SSH key your system already keeps, adds nothing reachable from the network, and ships as a release you can verify.

Features that serve none of these are out of scope by definition, however useful. That is the design, not a limitation to work around.

## Start here

- To serve a site: [`servette`](https://github.com/servette/servette) — `pipx install servette`, then `servette`, then `setup`.
- To read the design and the reasons behind it: `DESIGN.md` and `DECISIONS.md` in the server's repository.
- To report a security issue: `SECURITY.md` in any repository.

MIT licensed throughout.
