# GitRisk 🔍

> **Find the risks in your repo.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version: v0.4.0](https://img.shields.io/badge/version-0.4.0-green.svg)](https://github.com/Coderx838/Gitrisk)

GitRisk is a **privacy-first, local-first, offline-capable** security and repository-health scanner for Git repositories, powered by the **GitRisk SEI (Secret Intelligence Engine)**.

---

## 🌟 What's New in v0.4.0 — The SEI Engine

- **🧠 GitRisk SEI (Secret Intelligence Engine):** Completely replaces naive regex scanning with a hybrid evidential model that evaluates *why* a token exists, where it is located, and how likely it is to be a real credential.
- **🗺️ Content Topology & Media Disambiguation:** Maps files into topological regions (Source Code, Comments, Config, Base64 Payloads, SVG Nodes, Lockfiles) to completely eliminate false positives from embedded raster image data.
- **🧩 Token Reconstruction Engine:** Reassembles fragmented and split-string credentials (e.g. `"AIzaSy" + "..."` or template interpolations) before evaluation.
- **🧪 Magic Byte Payload Inspector:** Decodes Base64 payloads to distinguish binary media headers (`\x89PNG`, `GIF`, `WOFF`) from genuine JWTs and encoded tokens.
- **⚖️ Multi-Signal Evidence Scoring:** Uses signed positive and negative weights across Shannon entropy, syntactic context, variable bindings, and delimiters to compute a weighted confidence index [0 - 100].
- **🔒 One-Way Secret Fingerprinting:** Generates non-reversible HMAC-SHA256 digests for cross-file and historical lifecycle correlation without ever storing plaintext secrets.

---

## 🔒 Philosophy

- **No server.** All scanning runs entirely on your local machine.
- **No account.** No registration or API keys required to scan.
- **No code upload.** Your code and repository data never leave your system.
- **Local vulnerability database.** Queries a fast local SQLite DB populated from OSV.dev.
- **Zero-config & fast.** Scans repositories with thousands of files in seconds.

---

## 🚀 Quick Start

```bash
# Install directly from GitHub
pip install git+https://github.com/Coderx838/Gitrisk.git

# Update local vulnerability database
gitrisk db update

# Scan the current directory
gitrisk scan .

# Automatically apply safe fixes
gitrisk fix .
```

---

## 🛠️ CLI Commands & Usage

| Command | Description |
|---|---|
| `gitrisk scan [PATH]` | Scan a repository for vulnerabilities, secrets, and misconfigurations |
| `gitrisk scan --format json` | Output structured findings as JSON |
| `gitrisk scan --format sarif` | Output findings in standard SARIF format (for GitHub code scanning) |
| `gitrisk scan --severity HIGH` | Filter findings by minimum severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| `gitrisk fix [PATH]` | Interactively preview and apply safe automated fixes |
| `gitrisk fix [PATH] --dry-run` | Preview diffs and patches without modifying files |
| `gitrisk fix [PATH] --yes` | Apply all safe fixes without prompting (ideal for CI/CD pipelines) |
| `gitrisk db update` | Download or refresh local OSV vulnerability database |
| `gitrisk db status` | Check status and record count of the local vulnerability DB |
| `gitrisk report [PATH]` | Generate a full JSON or SARIF report file |
| `gitrisk --version` | Display version and ASCII banner |

---

## 🔍 What GitRisk Scans

| # | Scanner | Detects |
|---|---|---|
| 1 | **Secrets Scanner** | High-entropy API keys, tokens, private keys, passwords (with string literal + entropy validation) |
| 2 | **Git History Scanner** | Deleted or leaked secrets in commit history |
| 3 | **Dependencies Scanner** | Known CVEs/GHSAs in `requirements.txt` & `pyproject.toml` via local OSV DB |
| 4 | **Outdated Dependencies** | Pinned dependencies significantly lagging behind current releases |
| 5 | **.env & Config Exposure** | Unprotected `.env` files tracked by Git or missing from `.gitignore` |
| 6 | **GitHub Actions Scanner** | Overly permissive workflows, unpinned action hashes, dangerous script injections |
| 7 | **GitIgnore Scanner** | Missing security ignores (`.env`, `*.pem`, `*.key`, credential caches) |
| 8 | **Sensitive Files Scanner** | Committed certificates, database dumps, SSH keys, configuration archives |
| 9 | **Git Config Scanner** | Risky local Git settings (`fileMode`, unsafe remotes, compromised hooks) |
| 10 | **Security Policy Scanner** | Missing `SECURITY.md`, `README.md`, or Dependabot configuration |
| 11 | **Hardcoding Scanner** | Hardcoded connection strings, database URLs, and exposed internal endpoints |

---

## 💻 Example Output

```text
╭────────────── >> GitRisk Scan ──────────────╮
│ GitRisk v0.3.2                              │
│ Repository: my-project                      │
│ Path:       C:\my-project                   │
│ Files:      124 scanned                     │
│ Scanned:    2026-08-28 14:30                │
╰─────────────────────────────────────────────╯

╭────────┬────────────┬───────────────────────────────────────────────────────────┬──────────────────┬──────────╮
│ Sev    │ ID         │ Finding                                                   │ Location         │ Fix      │
├────────┼────────────┼───────────────────────────────────────────────────────────┼──────────────────┼──────────┤
│ CRIT   │ SEC-001    │ AWS Access Key ID detected                                │ app.py:12        │ MANUAL   │
│ CRIT   │ HIST-001   │ Secret exposed in Git history (commit 01d18f8)            │ keys.txt         │ MANUAL   │
│ HIGH   │ DEP-001    │ Vulnerable dependency: requests (8 vulnerabilities)       │ requirements.txt │ ASSISTED │
│ LOW    │ GIT-002    │ .gitignore is missing critical security patterns          │ .gitignore       │ AUTO     │
│ LOW    │ POL-001    │ No SECURITY.md found                                      │ -                │ AUTO     │
╰────────┴────────────┴───────────────────────────────────────────────────────────┴──────────────────┴──────────╯

╭─────────────────── 📊 Score ───────────────────╮
│ GITRISK SCORE: 78/100                          │
│                                                │
│   Configuration  100/100  ████████████████████ │
│   Dependencies    65/100  █████████████░░░░░░░ │
│   General        100/100  ████████████████████ │
│   Git             90/100  ██████████████████░░ │
│   Policy          95/100  ███████████████████░ │
│   Secrets         60/100  ████████████░░░░░░░░ │
╰────────────────────────────────────────────────╯

  5 finding(s): 2 critical · 1 high · 2 low
  3 fix(es) can be applied automatically — run gitrisk fix .
```

---

## 🔧 4-Tier Remediation System

GitRisk categorizes every finding with a remediation tier so you immediately know what action is required:

- **`AUTO`** — 100% deterministic, zero-risk fixes (e.g. creating `SECURITY.md`, appending missing security ignore rules).
- **`ASSISTED`** — Automated dependency upgrade to a verified minimum-safe version computed against the local OSV DB.
- **`REVIEW`** — Patch generated for review (e.g. updating outdated major packages, configuration adjustments).
- **`MANUAL`** — Human action mandatory (e.g. revoking exposed API tokens, rotating leaked database credentials, purging git history via `git-filter-repo`).

---

## 📦 Installation

### From GitHub

```bash
pip install --upgrade git+https://github.com/Coderx838/Gitrisk.git
```

### From Source (Development)

```bash
git clone https://github.com/Coderx838/Gitrisk.git
cd Gitrisk
pip install -e .[dev]
pytest -q
```

---

## 🤝 Contributing

Contributions are welcome! Please check out [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new scanners and test cases.

---

## 🛡️ Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

---

## 📄 License

GNU General Public License v3.0 — see [LICENSE](LICENSE).
