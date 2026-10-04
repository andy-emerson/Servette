> Draft of `servette/servette-admin`'s README. Nothing it describes is built; the repository does not yet exist. Its technology and first packaging are an open decision in the server repository's `DESIGN-V2.md`.

# Servette Admin

**Your Servette boxes, in a window, over your own SSH key.**

Servette is administered from its command line over SSH. Servette Admin is that command line with a face: a desktop application for your own computer that keeps the list of your boxes, opens the SSH connection for you, and shows each box's sites, settings, history, and traffic — one card per site, publish by dropping a folder, roll back in one click.

It adds nothing to your server. There is no agent to install, no port to open, no login to set up: the app runs the same commands you would type, over the same connection, and your server never knows the difference.

## Install

Download the installer for your platform from the [releases](https://github.com/servette/servette-admin/releases), where each one carries its checksum and build provenance and is signed for the platforms that check. servette.org links to the same releases and hosts nothing itself.

Then add a box: its address, your user, and the key you already use to `ssh` in. The app stores those three things and nothing else.

## What it does

| On a box | How |
| - | - |
| Shows every site, its health, certificate, access and history | `servette status --json`, `sites --json` |
| Publishes a folder from your computer | builds the bundle locally, sends it over SSH, `servette publish` lands it |
| Previews a folder before you publish it | serves the folder on your own computer — nothing is staged on the box |
| Changes settings, names a site, orders a certificate | the same `set` and `config` commands, run for you |
| Rolls back | `servette restore-site` |
| Reads traffic | `servette traffic --json`, charted |

Works against any Servette 2.x box, with or without the [database extension](https://github.com/servette/servette-database).

## What it never does

- **Hold a secret.** The SSH key stays with your system's `ssh` and its agent; the app only knows which one to use. There is no passcode, no pairing, no token of the app's own on any box.
- **Listen on the network.** The window is a browser page served on your computer's own loopback, reachable only by you, with a per-launch token so other local programs and sites cannot drive it.
- **Change your server's attack surface.** Everything the app does is a command the terminal could run. A box that never meets the app loses nothing.

## The trust you are extending

Installing this application means trusting its release the way you trust any installed software: whoever could alter it could act on your computer and, through your SSH key, on your boxes. That is why it is built in public CI from a tagged commit, published with its checksum and provenance, and signed — and why servette.org links to the release rather than serving the binary from a single box. Operators who prefer not to extend that trust use the terminal, which is complete.

## Related

- [`servette`](https://github.com/servette/servette) — the server, and the command-line contract this app drives.
- [servette.org](https://servette.org) — the project site.

MIT licensed.
