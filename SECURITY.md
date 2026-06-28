# Security Policy

Security is central to what Servette is for — it serves a real site on the
public internet, so the threat model is the open web. This document covers how
to report a vulnerability and what to expect in return.

## Supported versions

Servette is pre-1.0 and ships as a single file that updates itself to the
latest **signed** GitHub Release (the trust model is described in
[`design.md`](design.md#how-it-works)). Only the latest release receives
security fixes — run `update` from the Servette shell to stay current.

## Reporting a vulnerability

Please report security issues **privately**, not in a public issue.

Use GitHub's private vulnerability reporting:

> **Security → Report a vulnerability**
> https://github.com/andy-emerson/servette/security/advisories/new

Include enough to reproduce: the affected behavior, steps to trigger it, and
the impact you see. Proof-of-concept code is welcome but not required.

What to expect:

- An acknowledgement that the report was received.
- An honest assessment of whether it's in scope (see below) and how serious it is.
- A fix released as a new signed version, with credit to you if you'd like it.

This is a small, single-maintainer project, so responses are best-effort rather
than bound to a formal SLA. Please allow a reasonable window to address an issue
before disclosing it publicly.

## What's in scope

Servette implements its own auth, TLS configuration, rate limiting, path
resolution, and certificate lifecycle from a small trusted base. Reports
against any of those are in scope, for example:

- Path traversal or any way to read files outside the served directory.
- Authentication or rate-limiting bypass.
- TLS misconfiguration that weakens the connection.
- Flaws in update signature verification.

Out of scope: the deliberate design choices documented under
[Scope & non-goals](design.md#scope--non-goals) (e.g. binding to all interfaces,
which a public server requires), and issues that depend on an attacker who
already has local/root access to the host.
