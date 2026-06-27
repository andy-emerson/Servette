# Demo site

A one-page sample site for confirming that Servette is serving correctly before you put your own files in place.

`index.html` checks the connection in the browser and reports it: a green **Verified encrypted** badge over HTTPS, or a red **Not encrypted** warning over plain HTTP. Below that it lists the protections Servette adds on top of plain file serving — password protection, rate limiting, the HTTPS redirect, HSTS, security headers, and gzip/ETag.

## Using it

Servette serves the `site/` folder next to `servette.py` by default. To try the demo, either copy these files into `site/`, or point `serve_dir` at this `demo/` folder from the `config` shell.

Start Servette and open the site. Over HTTPS you should see the green **Verified encrypted** badge — confirmation that the server, the certificate, and the HTTPS redirect are all working end to end. (With a self-signed certificate your browser will warn first; that's expected, and the badge still confirms the connection is encrypted once you proceed.)
