# GitRisk 🔍

> **Find the risks in your repo.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

GitRisk is a **privacy-first, local-first, offline-capable** security and repository-health scanner for Git repositories.

> ⚠️ **Early Development** — GitRisk is in active development (v0.1). APIs and scanners may change.

## Philosophy

- **No server.** All scanning runs on your machine.
- **No account.** No registration required.
- **No code upload.** Your code never leaves your system.
- **Local scanning.** Fast, zero-config, terminal-native.
- **Optional updates.** Internet is only used when you choose to update the local vulnerability database.

## Quick Start

```bash
# Install
pip install gitrisk

# Scan the current directory
gitrisk scan .

# Scan a specific project
gitrisk scan ./my-project

# Update local vulnerability database
gitrisk db update

# Get help
gitrisk --help
```

## What GitRisk Scans

| # | Scanner | Detects |
|---|---------|--------|
| 1 | **Secrets** | API keys, tokens, private keys, passwords |
| 2 | **Dependencies** | Known vulnerable packages (via local OSV DB) |
| 3 | **.env tracked** | Environment files committed to Git |
| 4 | **GitHub Actions** | Excessive workflow permissions |
| 5 | **Missing .gitignore** | No or weak ignore rules |
| 6 | **Sensitive files** | Private keys, certs, dumps, credential files |
| 7 | **Git configuration** | Risky repository configuration |
| 8 | **Outdated dependencies** | Packages significantly behind current versions |
| 9 | **Missing SECURITY.md** | No vulnerability disclosure policy |
| 10 | **Suspicious hardcoding** | Passwords, connection strings, embedded tokens |

## Example Output

```
GitRisk v0.1.0
Repository: my-project
Files scanned: 247

GITRISK SCORE: 72/100
  Security      81/100
  Dependencies  64/100
  Git           92/100
  Secrets       58/100
  Configuration 76/100

🔴 HIGH  Hardcoded API key detected            api/client.py:42
🔴 HIGH  Dependency has known vulnerability    requirements.txt:7
🟡 MED   .env file is tracked by Git           .env
🟡 MED   GitHub Action has excessive perms     .github/workflows/ci.yml:3
🟢 LOW   Missing SECURITY.md                   /

5 risks found · 1 critical action recommended
```

## Remediation Types

GitRisk classifies each fix so you know what level of review is needed:

- **SAFE** — Automatic, deterministic fixes (e.g., adding `.env` to `.gitignore`)
- **REVIEW** — GitRisk generates a patch, you review before applying
- **MANUAL** — Security incidents requiring human judgment (e.g., secret rotation)

## Installation

### From PyPI (when available)

```bash
pip install gitrisk
```

### From Source

```bash
git clone https://github.com/gitrisk/gitrisk.git
cd gitrisk
pip install -e .[dev]
```

## Commands

| Command | Description |
|---------|-------------|
| `gitrisk scan [PATH]` | Scan a repository |
| `gitrisk scan --format json` | Output findings as JSON |
| `gitrisk scan --format sarif` | Output findings as SARIF |
| `gitrisk scan --severity HIGH` | Filter by severity |
| `gitrisk db update` | Update local vulnerability database |
| `gitrisk db status` | Show local DB info |
| `gitrisk fix` | Interactive remediation |
| `gitrisk report` | Generate HTML/JSON report |
| `gitrisk --version` | Show version |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and how to report vulnerabilities.

## License
 
GNU General Public License v3.0 — see [LICENSE](LICENSE).
