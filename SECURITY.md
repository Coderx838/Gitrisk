# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.3.x   | ✅ Active Support |
| 0.2.x   | ⚠️ Security fixes only |
| < 0.2.0 | ❌ Unsupported |

## Reporting a Vulnerability

If you discover a security vulnerability in GitRisk itself, **please do not open a public GitHub Issue.**

Instead:

1. Open a private [GitHub Security Advisory](https://github.com/Coderx838/Gitrisk/security/advisories/new) (preferred).
2. Or contact the maintainers directly via GitHub.

We aim to acknowledge reports within **48 hours** and provide a patched release within **7 days** for critical issues.

## Privacy & Local Execution Guarantee

GitRisk is engineered from the ground up to be **privacy-first and local-first**:

- **Zero Code Transmission:** Your code, file names, commit history, and scan results are processed 100% locally in memory and never leave your machine.
- **Zero Telemetry / Tracking:** No usage metrics, error telemetry, or tracking pings are embedded in GitRisk.
- **No Account Required:** The CLI operates fully without authentication, tokens, or cloud services.
- **Offline Capable:** Internet access is strictly optional and only utilized when running `gitrisk db update` to pull public OSV vulnerability records directly into your local SQLite cache.
- **Safe Advisory Updates:** The `db update` command downloads public advisory datasets without sending any information about your repositories, installed packages, or local environment.

## Scope

In scope for security reports:
- Any code path that could cause GitRisk to transmit repository or environment data
- Vulnerabilities or supply chain risks in GitRisk's own dependencies
- Path traversal or execution escalation issues in the scanner engine or fixer subsystem
- False negatives or bypasses in secret detection that could endanger users
