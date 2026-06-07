# Servette TODO

## Implementation Plan

| # | Step | Area | Difficulty |
|---|------|------|------------|
| 1 | Bootstrapping: virtualenv creation, Hypercorn install, re-exec | Transport | Medium |
| M1 | **Test:** virtualenv created, Hypercorn importable inside it | — | — |
| 2 | Hypercorn migration: rewrite HTTP handling layer as ASGI app | Transport | Hard |
| 2b | Rate limiter: convert to async, `time.monotonic()`, IPv6 normalization, stale entry eviction, `X-Forwarded-For` support | Rate Limiting | Easy |
| 2c | Logging: switch to `RotatingFileHandler`, unify Hypercorn access log, replace `tail` subprocess with Python file reading | Logging | Easy |
| 2a | Rewrite test.py to work with new Hypercorn-based architecture | Testing | Medium |
| M2 | **Test:** server starts, serves over HTTP/2 and HTTP/3 | — | — |
| M2 | **Merge to main** | — | — |
| 3 | Auto self-signed cert generation when no domain provided (use `cryptography` lib, no openssl subprocess) | Certificates | Easy |
| 4 | Simplify cert wizard to one question, invisible everything else | Certificates | Medium |
| 4a | Replace certbot/snap chain with pure Python `acme` + `josepy` library | Certificates | Medium |
| M3 | **Test:** no-domain path, self-signed cert generated automatically | — | — |
| 5 | Auto cert swap when domain added later | Certificates | Medium |
| M4 | **Test:** domain added, cert swaps automatically, server restarts | — | — |
| M4 | **Merge to main** | — | — |
| 6 | Single-folder serving with MIME types and index.html fallback | Serving | Medium |
| M5 | **Test:** Hugo/Jekyll site loads correctly from folder | — | — |
| 7 | 403 path traversal protection | Serving | Easy |
| 8 | 404 with optional 404.html fallback, inline default | Serving | Easy |
| 9 | 500 catch-all for unhandled exceptions | Serving | Easy |
| M6 | **Test:** path traversal blocked, 404 fallback, 500 catch-all | — | — |
| M6 | **Merge to main** | — | — |

## Dependencies
| Package | Replaces | Benefit |
|---------|----------|---------|
| `hypercorn` | Hand-rolled HTTP/1.1 server, threading, SSL | HTTP/2 + HTTP/3, modern TLS defaults, async concurrency |
| `cryptography` | openssl subprocess calls | Pure Python cert generation, no CLI dependency |
| `acme` + `josepy` | certbot/snap chain | Faster, reliable on Pi OS Lite, programmatic cert lifecycle |

## Platform
- Target Raspberry Pi 4+ (ARM64, Raspberry Pi OS) — no backward compatibility with older Pis
- Note: `snap` may not be present on Pi OS Lite — certbot/snap path replaced by `acme` library
- All dependencies have ARM64 wheels on PyPI
