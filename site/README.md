# site/ — your site goes here

This is the folder Servette serves (`serve_dir` defaults to `site`). It ships with a one-page placeholder demo so a fresh copy works immediately: copy `servette.py` and this folder to your server, start Servette, and you'll get a live page confirming HTTPS and the security headers are working.

**Replace these files with your own site** when you're ready — drop your `index.html` and assets in here. Servette looks for `index.html` at the root and in any subdirectory.

## The placeholder demo

`index.html` checks the live connection in the browser and reports it: a green **Verified encrypted** badge over HTTPS, or a red **Not encrypted** warning over plain HTTP. Over HTTPS, the green badge confirms the server, certificate, and HTTPS redirect are working end to end. (With a self-signed certificate the browser warns first; that's expected, and the badge still confirms encryption once you proceed.)
