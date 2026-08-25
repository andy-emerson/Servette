# Security Policy

Servette serves real sites on the public internet, so the threat model is
the open web. Report security issues **privately**, never in a public
issue, via GitHub's private vulnerability reporting:

> **Security → Report a vulnerability**
> https://github.com/andy-emerson/servette/security/advisories/new

Include enough to reproduce: the affected behavior, how to trigger it, and
the impact you see. Expect an acknowledgement, an honest assessment of
scope and severity, and a fix in a new release with credit if you'd like
it — best-effort from a single maintainer, so please allow a reasonable
window before disclosing publicly. Only the latest release receives
security fixes; stay current with `pipx upgrade servette`.

## Scope

Servette implements its own auth, TLS configuration, rate limiting, path
resolution, certificate lifecycle, and publish-bundle extraction from a
small trusted base. Reports against any of those are in scope, for example:

- Path traversal or any way to read files outside the served directory.
- Authentication or rate-limiting bypass.
- TLS misconfiguration that weakens the connection.
- Flaws in publish-bundle extraction — a bundle that escapes the site
  tree, a decompression bomb, or an entry type that should be refused.

Out of scope: the deliberate design choices documented under
[Scope & non-goals](DESIGN.md#scope--non-goals), and issues that require an
attacker who already has local or root access to the host.
