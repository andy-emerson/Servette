# site/ — the Servette website

This folder is the source of servette.org. It is also the default `serve_dir`, so a development checkout of this repository serves the project's own site — which is exactly how servette.org is hosted.

**Users don't copy this folder.** A user copies `servette.py` alone; setup fetches the demo page from the latest signed release and writes it into their own site folder as `index.html` (see [DESIGN.md](../DESIGN.md)).

## Layout

One rule shapes this folder: **one subdomain ↔ one self-contained directory, and every page is a directory holding an `index.html`.** What a page is for is said by its directory name, never its file name. Each directory carries its own assets — the server confines a site to its `serve_dir`, so a subdirectory served as its own subdomain cannot reach a sibling's files. (`404.html` at a serve_dir root is the standing exception to the naming rule; that name is the server's convention for the custom error page.)

| Path | Serves | What it is |
| - | - | - |
| `index.html` + `assets/` | servette.org | the project page: what Servette is, how it compares, how to use it, how it is built |
| `demo/index.html` | servette.org/demo/ and demo.servette.org | the self-test page — also the `demo.html` release asset every user's setup receives |
| `source/index.html` | servette.org/source/ and source.servette.org | a read-only literate view of `src/*.md`, with an optional in-browser AI reading assistant |
| `publish/` | nothing yet | reserved for the client-side publish tool planned in [#42](https://github.com/andy-emerson/Servette/issues/42) — see its own README |

## The demo page

`demo/index.html` checks the live connection in the browser and reports it: a green **Verified encrypted** badge over HTTPS, or a red **Not encrypted** warning over plain HTTP. Over HTTPS, the green badge confirms the server, certificate, and HTTPS redirect are working end to end. (With a self-signed certificate the browser warns first; that's expected, and the badge still confirms encryption once you proceed.)

It ships with every GitHub release as the signed `demo.html` asset, and `servette.py` writes it into an empty site as `index.html` — the page a fresh Servette serves before its operator publishes anything. Its `servette:demo` marker comment is how updates tell the placeholder from an operator's own page; the marker's own text explains the rule.

## The source viewer

`source/index.html` renders the authored `src/*.md` files as read-only notebook cells, fetched straight from GitHub at render time (`?ref=` picks a branch or tag; the parameter is validated and pinned to this repository). It began as the notebook interface Servette was written in — [andy-emerson/notebook](https://github.com/andy-emerson/notebook) — pared down by removing everything that edits, so what remains is the reading half of the real tool: file navigation and search, a rendered preview, a call map of the open file's functions, and an optional reading assistant. The assistant runs entirely in the visitor's browser (WebLLM over WebGPU), answers in the first person as Servette, and fetches the source documents each question needs; nothing typed there leaves the machine. The page remembers nothing about a visitor except a measured VRAM figure (a hardware fact, needed to size the model's context window) and that the welcome dialog was shown.

## Dependencies

No page has a build step. The front door and demo load nothing from third parties. The source viewer loads its libraries (markdown rendering, syntax highlighting, WebLLM) from CDNs and degrades gracefully without them. The reserved `publish/` page will be allowed no third-party code at all — it will handle a signing key; the reasoning is in its README.
