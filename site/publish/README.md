# site/publish/ — reserved

The client-side publish app planned in
[#42](https://github.com/andy-emerson/Servette/issues/42): build and sign
content bundles in the browser, entirely client-side — Servette itself never
accepts instructions from the network.

Nothing is served from here yet, and nothing links here yet — per #42, no
link from the home page until the tool exists. Two constraints already
settled for whatever lands in this directory:

- **Dependency-free.** This page will handle the operator's private signing
  key, so it loads no third-party script — the pipeline needs none (WebCrypto
  Ed25519, `CompressionStream`, a hand-rolled ustar writer). The CDN
  allowance that applies to the other subdomain pages deliberately does not
  apply here; the reasoning is recorded in #42.
- **Signing only.** If a capability cannot be expressed as "produce a signed
  artifact the operator chooses to pull," it does not belong here.
