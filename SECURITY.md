# Security policy

OpenWarp runs a root daemon that changes routes and DNS and stores device credentials, so security reports are
taken seriously.

## Supported versions

Only the latest release (and `main`) receives security fixes while the project is pre-1.0.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** Report it privately through GitHub:
**Security → Report a vulnerability** on this repository
(<https://github.com/ImanMontajabi/OpenWarp/security/advisories/new>).

Include what you found, how to reproduce it, the affected version or commit, and the impact you expect. You can
expect an acknowledgement within a week. Once a fix is ready it is released and the advisory is published with
credit, unless you prefer to stay anonymous.

Never include real registration tokens, private keys or license keys in a report; redact them.

## Scope

In scope: the `openwarp` daemon and CLI (privilege handling, the control socket, state file permissions,
route/DNS changes, credential handling) and the OpenWarp app.

Out of scope: Cloudflare's own service and the official WARP client (report those to
[Cloudflare](https://www.cloudflare.com/disclosure/)), and problems that need an attacker who already has root.

## What automated checks do and do not cover

CI runs `govulncheck`, CodeQL, a secret scan and Dependabot. These catch known vulnerable dependencies and
common mistakes; they do not prove the software is secure.
