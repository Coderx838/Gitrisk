import json

rules = [
    # SEC-001 to SEC-020
    {"id": "SEC-001", "title": "AWS Access Key ID", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-002", "title": "AWS Secret Access Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-003", "title": "GitHub Token", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-522"], "owasp": ["A07:2021"]},
    {"id": "SEC-004", "title": "GitHub Fine-Grained Token", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-522"], "owasp": ["A07:2021"]},
    {"id": "SEC-005", "title": "Slack Token", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-522"], "owasp": ["A07:2021"]},
    {"id": "SEC-006", "title": "Stripe Secret Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-007", "title": "SendGrid API Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-008", "title": "Google API Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-009", "title": "Twilio Auth Token", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-010", "title": "RSA Private Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-321"], "owasp": ["A07:2021"]},
    {"id": "SEC-011", "title": "OpenSSH Private Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-321"], "owasp": ["A07:2021"]},
    {"id": "SEC-012", "title": "Generic PEM Private Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-321"], "owasp": ["A07:2021"]},
    {"id": "SEC-013", "title": "NPM Auth Token", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-522"], "owasp": ["A07:2021"]},
    {"id": "SEC-014", "title": "Mailchimp API Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-015", "title": "Mailgun API Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-016", "title": "Telegram Bot Token", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-017", "title": "Heroku API Key", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-018", "title": "PyPI Token", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    {"id": "SEC-019", "title": "Basic Auth in URL", "cat": "Secrets", "sev": "CRITICAL", "cwe": ["CWE-522"], "owasp": ["A07:2021"]},
    {"id": "SEC-020", "title": "Generic Secret Assignment", "cat": "Secrets", "sev": "HIGH", "cwe": ["CWE-798"], "owasp": ["A07:2021"]},
    
    # Dependencies
    {"id": "DEP-001", "title": "Vulnerable dependency", "cat": "Dependencies", "sev": "HIGH", "cwe": ["CWE-937"], "owasp": ["A06:2021"]},
    {"id": "DEP-002", "title": "Vulnerable dependency (requests)", "cat": "Dependencies", "sev": "HIGH", "cwe": ["CWE-937"], "owasp": ["A06:2021"]},
    {"id": "DEP-003", "title": "Vulnerable dependency (pytest)", "cat": "Dependencies", "sev": "HIGH", "cwe": ["CWE-937"], "owasp": ["A06:2021"]},
    
    # Environment
    {"id": "ENV-001", "title": ".env file tracked by Git", "cat": "Environment", "sev": "CRITICAL", "cwe": ["CWE-200"], "owasp": ["A02:2021"]},
    
    # GitHub Actions
    {"id": "GHA-001", "title": "Workflow permissions not restricted", "cat": "GitHub Actions", "sev": "MEDIUM", "cwe": ["CWE-250"], "owasp": []},
    {"id": "GHA-002", "title": "Elevated write permission in workflow", "cat": "GitHub Actions", "sev": "HIGH", "cwe": ["CWE-250"], "owasp": ["A01:2021"]},
    {"id": "GHA-003", "title": "Use of pull_request_target trigger", "cat": "GitHub Actions", "sev": "HIGH", "cwe": ["CWE-250"], "owasp": []},
    
    # Git Configuration
    {"id": "GIT-001", "title": "Large binary file committed", "cat": "Git Configuration", "sev": "MEDIUM", "cwe": ["CWE-400"], "owasp": []},
    {"id": "GIT-002", "title": ".gitignore missing critical security patterns", "cat": "Git Configuration", "sev": "HIGH", "cwe": ["CWE-200"], "owasp": []},
    {"id": "GIT-010", "title": "Not a Git repository", "cat": "Git Configuration", "sev": "INFO", "cwe": [], "owasp": []},
    {"id": "GIT-011", "title": "fileMode disabled", "cat": "Git Configuration", "sev": "INFO", "cwe": [], "owasp": []},
    {"id": "GIT-012", "title": "Shared repository mode enabled", "cat": "Git Configuration", "sev": "MEDIUM", "cwe": ["CWE-284"], "owasp": []},
    {"id": "GIT-013", "title": "SSL verification disabled", "cat": "Git Configuration", "sev": "HIGH", "cwe": ["CWE-295"], "owasp": []},
    {"id": "GIT-014", "title": "Git credential helper stores plaintext", "cat": "Git Configuration", "sev": "HIGH", "cwe": ["CWE-522"], "owasp": []},
    
    # Hardcoding
    {"id": "HRD-001", "title": "Hardcoded database connection string", "cat": "Hardcoding", "sev": "CRITICAL", "cwe": ["CWE-259"], "owasp": ["A02:2021"]},
    {"id": "HRD-002", "title": "Hardcoded password", "cat": "Hardcoding", "sev": "CRITICAL", "cwe": ["CWE-259"], "owasp": ["A07:2021"]},
    {"id": "HRD-003", "title": "Hardcoded private IP address", "cat": "Hardcoding", "sev": "MEDIUM", "cwe": ["CWE-200"], "owasp": []},
    {"id": "HRD-004", "title": "Hardcoded internal IP address", "cat": "Hardcoding", "sev": "MEDIUM", "cwe": ["CWE-200"], "owasp": []},
    {"id": "HRD-005", "title": "Hardcoded port number", "cat": "Hardcoding", "sev": "LOW", "cwe": ["CWE-200"], "owasp": []},
    {"id": "HRD-006", "title": "Hardcoded service endpoint", "cat": "Hardcoding", "sev": "LOW", "cwe": ["CWE-200"], "owasp": []},
    
    # Policy
    {"id": "POL-001", "title": "No SECURITY.md found", "cat": "Policy", "sev": "LOW", "cwe": [], "owasp": []},
    {"id": "POL-002", "title": "No README.md found", "cat": "Policy", "sev": "INFO", "cwe": [], "owasp": []},
    {"id": "POL-003", "title": "No CONTRIBUTING.md found", "cat": "Policy", "sev": "INFO", "cwe": [], "owasp": []},
]

with open("C:/Coder/Sector16/Gitrisk/src/gitrisk/rulebook/rules.py", "w") as f:
    f.write('"""GitRisk rule database."""\n\n')
    f.write('from dataclasses import dataclass\n')
    f.write('from typing import Dict, List\n\n')
    f.write('@dataclass\n')
    f.write('class RuleDoc:\n')
    f.write('    rule_id: str\n')
    f.write('    title: str\n')
    f.write('    category: str\n')
    f.write('    severity: str\n')
    f.write('    cwe: List[str]\n')
    f.write('    owasp: List[str]\n')
    f.write('    description: str\n')
    f.write('    impact: str\n')
    f.write('    remediation: List[str]\n')
    f.write('    examples: Dict[str, str]\n')
    f.write('    references: List[str]\n')
    f.write('    tags: List[str]\n\n')
    f.write('RULES: Dict[str, RuleDoc] = {\n')
    
    for r in rules:
        f.write(f'    "{r["id"]}": RuleDoc(\n')
        f.write(f'        rule_id="{r["id"]}",\n')
        f.write(f'        title="{r["title"]}",\n')
        f.write(f'        category="{r["cat"]}",\n')
        f.write(f'        severity="{r["sev"]}",\n')
        f.write(f'        cwe={json.dumps(r.get("cwe", []))},\n')
        f.write(f'        owasp={json.dumps(r.get("owasp", []))},\n')
        f.write(f'        description="Found {r["title"]}. This exposes sensitive information or configurations.",\n')
        f.write(f'        impact="Could lead to unauthorized access, data breach, or service disruption.",\n')
        f.write(f'        remediation=["Remove the hardcoded secret or configuration.", "Use environment variables or a secret manager.", "Rotate compromised credentials immediately."],\n')
        f.write(f'        examples={{"bad": "{r["id"]} = \'secret\'", "good": "{r["id"]} = os.getenv(\'SECRET\')"}},\n')
        f.write(f'        references=["https://cwe.mitre.org/", "https://owasp.org/"],\n')
        f.write(f'        tags=["{r["cat"].lower()}", "security"]\n')
        f.write('    ),\n')
        
    f.write('}\n')

