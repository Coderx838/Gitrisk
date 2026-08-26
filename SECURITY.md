# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a Vulnerability

If you discover a security vulnerability in GitRisk itself, **please do not open a public GitHub Issue.**

Instead:

1. Open a [GitHub Security Advisory](https://github.com/gitrisk/gitrisk/security/advisories/new) (preferred).
2. Or email the maintainers directly (contact info in the GitHub profile).

We aim to respond within **72 hours** and provide a fix within **14 days** for critical issues.

## Privacy Guarantee

GitRisk is designed to be privacy-first:

- **No code is ever uploaded.** All scanning runs locally.
- **No account required.** The CLI works without authentication.
- **Internet access is optional.** Only `gitrisk db update` makes network requests — and only to download public vulnerability data.
- **The `db update` command never transmits your repository contents, package names, file paths, or scan results.**

## Scope

In scope for security reports:
- Any code path that could cause GitRisk to transmit repository data
- Vulnerabilities in GitRisk's own dependencies
- Privilege escalation or path traversal issues in the scanner
- False negatives in secret detection that could endanger users
