# site/ — your site goes here

This is the folder Servette serves (`serve_dir` defaults to `site`). It ships with two pages so a fresh copy works immediately: copy `servette.py` and this folder to your server, start Servette, and you'll get a live site.

**Replace these files with your own site** when you're ready — drop your `index.html` and assets in here. Servette looks for `index.html` at the root and in any subdirectory.

## What ships here

`index.html` is the Servette project page: what it is, how it compares to the alternatives, how to use it, and how it is built. Its "How it Works" tab draws the architecture map from a description of the code held in the page's own source, so the map changes when that description does.

`demo.html` checks the live connection in the browser and reports it: a green **Verified encrypted** badge over HTTPS, or a red **Not encrypted** warning over plain HTTP. Over HTTPS, the green badge confirms the server, certificate, and HTTPS redirect are working end to end. (With a self-signed certificate the browser warns first; that's expected, and the badge still confirms encryption once you proceed.)

Both pages are self-contained: no build step, and nothing to install.
