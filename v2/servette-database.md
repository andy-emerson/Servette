> Draft of `servette/servette-database`'s README. Nothing it describes is built; the repository does not yet exist. Its design document is written before its code, ledger first — see "What this gives up" below, which is the ledger's outline.

# Servette Database

**The simple, secure server for databases that have no server of their own.**

SQLite, DuckDB, and their kind are a file and a library. They answer queries in-process and ship no way to answer them over a network — which is correct for what they are, and leaves anyone who wants to publish one reaching for a server that was built for something else. Servette Database is Servette with one more verb: `QUERY`. The same trusted certificate, HTTPS only, security headers, rate limiting, optional password, and hardened service, serving a read-only database instead of a folder.

It is a separate install because it is a separate promise. The static server never evaluates what a visitor sends; a database server must. This edition states exactly how much security that costs and how each piece is earned back.

```
pipx install servette-database
servette
```

Setup is the server's: a site is a database file instead of a folder, and `publish` lands a new file the way it lands a new site — staged, checked, swapped in atomically, with the previous versions kept.

## How a client asks

`QUERY` is the HTTP method the IETF HTTP working group is standardizing for exactly this: a safe, idempotent request that carries its query in the body because queries outgrow URLs. A request is query text plus an array of bound values, in the engine's own language, and the answer is rows as JSON. `OPTIONS` says which languages a database speaks (`Accept-Query`) and which origins may call from a browser. Nothing else is accepted: `GET` serves the connection test and nothing from the database, and `POST` is `405` as it always was.

## What this gives up, and how each piece is earned back

The static server's security is mostly what it gets for free by never writing and never evaluating input. Adding a verb that evaluates input gives some of that up. This is the ledger — what stopped being free, and what now earns it:

| No longer free | Earned by |
| - | - |
| Only reads happen | the engine's own read-only mode and, where it has one, its authorizer: the engine's parser decides what a statement is, never a second parser in the server |
| Nothing reaches outside the database file | the engine's external-access switches off and its configuration locked — no extensions, no reading other files |
| A request ends | a deadline the engine honors (interrupt or progress hook), with a refused query answering `503` and saying why |
| A response has a size | a row cap, enforced by fetching one row past it, and the server's existing body cap |
| What is visible is what you meant to publish | decided at publish time, as with a folder: a private column is a column you did not put in the file |

Everything not on this list is still free: the server never writes, the sandbox never widens, the closed-system miss and the per-site auth are the static server's own.

An engine is supported only if its adapter passes the same four refusals — write something, read a file outside the database, run forever, return the universe — and the supported list names the engine versions the battery ran against. An engine that cannot provide one of the four natively is listed as unsupported with the reason, not compensated for with inspection.

| Engine | Status |
| - | - |
| SQLite (standard library) | the first adapter |
| DuckDB | planned; its external-access switch and memory limit are the adapter's job |
| others | when they can meet the ledger |

## What it is not

Not a database server in the full sense — nothing is written, ever, through this door. Not an API layer — no row-level policy, no per-user views; publish a file that holds what you mean to serve. Not Datasette, which does this for SQLite with a platform around it; not PostgREST or Hasura, which are read-write fronts for one database engine. Servette Database is the read-only front for any engine that is just a file, from one module one person can read.

## How it relates to Servette

This is an edition of the same server: built from Servette's own literate sources plus the files in this repository, into one module. A security fix in Servette reaches this edition when it is rebuilt against the new release, and this edition's version names the Servette version it embeds, so the lag is visible rather than hidden. The server's design and decisions live in [`servette/servette`](https://github.com/servette/servette); this repository's `DESIGN.md` holds the ledger, the adapters, and the battery.

MIT licensed.
