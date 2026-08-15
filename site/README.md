# site/ — the Servette website

This folder is the source of servette.org. It is also the default `serve_dir`, so a development checkout of this repository serves the project's own site — which is exactly how servette.org is hosted.

**Users don't receive this folder.** A user installs the servette package alone; setup writes the placeholder page embedded in the module itself into their own site folder as `index.html` (see [DESIGN.md](../DESIGN.md)).

## Layout

One rule shapes this folder: **one subdomain ↔ one self-contained directory, and every page is a directory holding an `index.html`.** What a page is for is said by its directory name, never its file name. Each directory carries its own assets — the server confines a site to its `serve_dir`, so a subdirectory served as its own subdomain cannot reach a sibling's files. (`404.html` at a serve_dir root is the standing exception to the naming rule; that name is the server's convention for the custom error page.)

| Path | Serves | What it is |
| - | - | - |
| `index.html` + `assets/` | servette.org | the project page: what Servette is, how it compares, how to use it, how it is built |
| `demo/index.html` | servette.org/demo/ and demo.servette.org | the self-test page — the live demo the home page links |
| `src/index.html` | servette.org/src/ and src.servette.org | a read-only literate view of `src/*.md` |
| `pub/index.html` | servette.org/pub/ and pub.servette.org | the client-side publish tool from [#42](https://github.com/andy-emerson/Servette/issues/42) — builds and signs content bundles in the browser |
| `pub/selftest/index.html` | servette.org/pub/selftest/ | the connection self-test as publishable content — the publish tool folds it into bundles at `/selftest/` |

## The demo page

`demo/index.html` checks the live connection in the browser and reports it: a green **Verified encrypted** badge over HTTPS, or a red **Not encrypted** warning over plain HTTP. Over HTTPS, the green badge confirms the server, certificate, and HTTPS redirect are working end to end. (With a self-signed certificate the browser warns first; that's expected, and the badge still confirms encryption once you proceed.)

It is the website's page alone — the live demo the home page links ([#70](https://github.com/andy-emerson/Servette/issues/70)). A fresh Servette seeds an empty site with the small placeholder embedded in the module, and the full self-test reaches an operator's site through the publish tool (`pub/selftest/`, whose checks deliberately duplicate this page's).

## The source viewer

`src/index.html` renders the authored `src/*.md` files as read-only notebook cells, fetched straight from GitHub at render time (`?ref=` picks a branch or tag; the parameter is validated and pinned to this repository). It began as the notebook interface Servette was written in — [andy-emerson/notebook](https://github.com/andy-emerson/notebook) — pared down by removing everything that edits, so what remains is the reading half of the real tool: file navigation and search, a rendered preview, and a call map of the open file's functions. (An in-browser AI reading assistant was tried and removed — it read the code poorly, and it was the one place the project's name attached to a persona rather than a program.) The page remembers nothing about a visitor except that the welcome dialog was shown.

## Dependencies

No page has a build step. The front door and demo load nothing from third parties. The source viewer loads its libraries (markdown rendering, syntax highlighting) from CDNs and degrades gracefully without them. The `pub/` page is allowed no third-party code at all — it handles a signing key; its only request is fetching its own `selftest/` page from this same site. The reasoning is in its README.
