> Draft of `servette/servette-website`'s README. The site exists today as the `servette.org/` directory of `andy-emerson/websites`; this repository is that directory moved to the organization. Describes the move, not new work.

# servette.org

**The project site — a Servette box serving itself.**

This repository is the content of [servette.org](https://servette.org): a static site, published to a Servette box with `servette publish`, exactly as any operator publishes theirs. The site is the program demonstrating itself — the security headers, the diagnosing error page, and the connection test at `/.well-known/servette-check` all come from Servette serving — which is why there is no mirror and no CDN in front of it: a copy served by something else would answer the closest inspection with someone else's server wearing the site's name.

## What is here

| Path | What it is |
| - | - |
| `/` | the front page: what Servette is, who it is for, how it compares |
| `/src/` | the source viewer: a read-only literate view of the server's `src/*.md`, fetched from GitHub at render time |
| `/.well-known/servette-check` | served by Servette, not by this repository — every Servette site has it |

## What is not here

- **Nothing that runs anywhere else.** The site holds no download. The desktop application's installers live in [`servette-admin`'s releases](https://github.com/servette/servette-admin/releases) with their checksums and provenance; the site links to them.
- **No scripts from third parties, no analytics.** The page demonstrates a self-hosted server and requests nothing from anyone else.
- **No admin tool.** The browser admin page that once rode the operator's SSH tunnel is replaced by [Servette Admin](https://github.com/servette/servette-admin); the publish tool that lived under `/pub/` goes with it.

## Working on it

The source viewer's end-to-end harness lives here and reads the server's `src/*.md`; run it with `SERVETTE_SRC` pointing at a checkout of [`servette/servette`](https://github.com/servette/servette). The site's exact per-section line counts are a measurement claim: `python3 src/build.py --counts` in the server's repository prints them, and whoever edits the page carries them over.

Publishing is the operator's own `servette publish` from a checkout, or Servette Admin pointed at the box. Nothing in this repository can deploy itself.

MIT licensed.
