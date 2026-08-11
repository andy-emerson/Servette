# site/publish/ — the publish tool

The client-side publish app from
[#42](https://github.com/andy-emerson/Servette/issues/42): `index.html`
builds and signs content bundles entirely in the browser. The operator
generates or loads an Ed25519 key, picks their site folder, and downloads a
signed `.tar.gz` + `.sig` pair plus the `publish_key` hex for
`config > publish`; hosting the pair and running `pull` stay with the
operator — Servette itself never accepts instructions from the network.

Constraints the page is built to, all load-bearing:

- **Dependency-free.** The page handles the operator's private signing key,
  so it loads no third-party script — the pipeline needs none (WebCrypto
  Ed25519, `CompressionStream`, a hand-rolled ustar writer). The CDN
  allowance that applies to the other subdomain pages deliberately does not
  apply here; the reasoning is recorded in #42.
- **Signing only.** If a capability cannot be expressed as "produce a signed
  artifact the operator chooses to pull," it does not belong here.
- **Nothing stored.** The key is supplied per session — generated in the tab
  or read from a PKCS#8 PEM file — and lives only in memory, as a
  non-extractable `CryptoKey`. Clearing the browser loses nothing; an XSS
  here has nothing durable to steal.

Not linked from the home page yet — per #42, no link until the tool is
deployed where the link would point.
