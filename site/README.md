# site/ — the Servette website

This folder is the source of servette.org. It is also the default `serve_dir`, so a development checkout of this repository serves the project's own site — which is exactly how servette.org is hosted.

**Users don't copy this folder.** A user copies `servette.py` alone; setup fetches the demo page from the latest signed release and writes it into their own site folder as `index.html` (see [DESIGN.md](../DESIGN.md)).

## Layout

One rule shapes this folder: **one subdomain ↔ one self-contained directory, and every page is a directory holding an `index.html`.** What a page is for is said by its directory name, never its file name. Each directory carries its own assets — the server confines a site to its `serve_dir`, so a subdirectory served as its own subdomain cannot reach a sibling's files. (`404.html` at a serve_dir root is the standing exception to the naming rule; that name is the server's convention for the custom error page.)

| Path | Serves | What it is |
| - | - | - |
| `index.html` + `assets/` | servette.org | the project page: what Servette is, how it compares, how to use it, how it is built |
| `demo/index.html` | servette.org/demo/ and demo.servette.org | the self-test page — also the `demo.html` release asset every user's setup receives |

## The demo page

`demo/index.html` checks the live connection in the browser and reports it: a green **Verified encrypted** badge over HTTPS, or a red **Not encrypted** warning over plain HTTP. Over HTTPS, the green badge confirms the server, certificate, and HTTPS redirect are working end to end. (With a self-signed certificate the browser warns first; that's expected, and the badge still confirms encryption once you proceed.)

It ships with every GitHub release as the signed `demo.html` asset, and `servette.py` writes it into an empty site as `index.html` — the page a fresh Servette serves before its operator publishes anything. Its `servette:demo` marker comment is how updates tell the placeholder from an operator's own page; the marker's own text explains the rule.

Both pages are self-contained: no build step, and nothing to install.
