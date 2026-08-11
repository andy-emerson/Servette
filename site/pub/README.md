# site/publish/ — the publish tool

The client-side publish app from
[#42](https://github.com/andy-emerson/Servette/issues/42): `index.html`
builds and signs content bundles entirely in the browser. The operator
generates or loads an Ed25519 key, picks their site folder — or starts with
the demo site if they have no content yet — and downloads a signed
`.tar.gz` + `.sig` pair plus the `publish_key` hex for `config > publish`;
hosting the pair and running `pull` stay with the operator — Servette
itself never accepts instructions from the network.

`selftest/` is the connection self-test as publishable content, the ruling
that closed #42's post-publish-verification fork: a page on
`publish.servette.org` cannot read what it probes on the operator's domain
(cross-origin), so instead the tool folds this page into bundles at
`/selftest/` — on the operator's own origin it runs the full checks the
demo page runs, after every `pull`. It carries no `servette:demo` marker
(published, it is the operator's content; `update` must never touch it),
and its checks duplicate `site/demo/index.html`'s — there is no build step
to share them, so a change to either page's checks belongs in both.

Constraints the page is built to, all load-bearing:

- **Dependency-free.** The page handles the operator's private signing key,
  so it loads no third-party script — the pipeline needs none (WebCrypto
  Ed25519, `CompressionStream`, a hand-rolled ustar writer). The CDN
  allowance that applies to the other subdomain pages deliberately does not
  apply here; the reasoning is recorded in #42.
- **Signing only.** If a capability cannot be expressed as "produce a signed
  artifact the operator chooses to pull," it does not belong here.
- **Nothing extractable stored.** The key is supplied per session —
  generated in the tab or read from a PKCS#8 PEM file — and held as a
  non-extractable `CryptoKey`. By default it lives only in memory; the
  operator can opt in to remembering it in IndexedDB, where the stored
  handle can sign but can never be read out, by any script on the origin
  (ruled on #42; the accepted residual is that a compromised page could
  misuse a remembered key while open, never steal it). Either way the key
  file is the only durable copy — clearing the browser never loses the
  ability to publish.

Not linked from the home page yet — per #42, no link until the tool is
deployed where the link would point.
