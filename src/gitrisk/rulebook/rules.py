"""GitRisk Rule Knowledge Base — complete database of all finding codes with
industry-standard security guidance, real CWE/OWASP classifications, and
actionable remediation steps.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class RuleDoc:
    """Structured documentation for a single GitRisk finding rule."""
    rule_id: str
    title: str
    category: str
    severity: str                      # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cwe: List[str]                     # e.g. ["CWE-798", "CWE-259"]
    owasp: List[str]                   # e.g. ["A02:2021", "A07:2021"]
    description: str                   # Full explanation of the risk
    impact: str                        # What can go wrong if exploited
    remediation: List[str]             # Ordered steps to fix
    examples: Dict[str, str]           # {"bad": "...", "good": "..."}
    references: List[str]              # Real URLs
    tags: List[str]                    # Searchable keywords


# ---------------------------------------------------------------------------
# HELPER — keeps RULES dict readable
# ---------------------------------------------------------------------------
def _r(**kwargs) -> RuleDoc:
    kwargs.setdefault("examples", {})
    kwargs.setdefault("tags", [])
    return RuleDoc(**kwargs)


RULES: Dict[str, RuleDoc] = {

    # =========================================================================
    # SEC — Secrets & Credentials
    # =========================================================================

    "SEC-001": _r(
        rule_id="SEC-001",
        title="AWS Access Key ID",
        category="Secrets",
        severity="CRITICAL",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "An AWS Access Key ID (AKIA… / ASIA… / AROA…) was found hardcoded in source code. "
            "AWS Access Key IDs, when paired with their Secret Access Key, grant programmatic "
            "access to AWS services. Hardcoded credentials are frequently harvested by automated "
            "scanners that index public repositories within minutes of a push, leading to rapid "
            "exploitation — resource hijacking, S3 data exfiltration, EC2 cryptomining, and "
            "massive unexpected billing are all well-documented outcomes."
        ),
        impact=(
            "Full programmatic access to all AWS services allowed by the associated IAM policy. "
            "This can include reading/writing S3 buckets, launching EC2 instances, accessing "
            "RDS databases, invoking Lambda functions, and exfiltrating any data stored in AWS. "
            "In worst-case scenarios, attackers pivot to delete infrastructure or move laterally "
            "to other cloud accounts."
        ),
        remediation=[
            "Immediately revoke the exposed key via IAM → Security Credentials in the AWS Console.",
            "Check AWS CloudTrail for unauthorized activity in the last 90 days.",
            "Generate a new key pair and store it in AWS Secrets Manager or as an environment variable.",
            "Remove the hardcoded key from the source file and clean Git history with git-filter-repo.",
            "Enforce least-privilege IAM policies: the new key should only have permissions it needs.",
            "Enable AWS GuardDuty and CloudTrail alerts for anomalous API calls going forward.",
        ],
        examples={
            "bad": (
                "# aws_client.py\n"
                "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n"
                "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
                "s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, ...)"
            ),
            "good": (
                "# aws_client.py — load from environment or IAM instance role\n"
                "import os\n"
                "# boto3 automatically uses AWS_ACCESS_KEY_ID env var, or EC2 instance profile\n"
                "s3 = boto3.client('s3')  # No credentials in source code"
            ),
        },
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials",
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://trufflesecurity.com/blog/oops-i-committed-a-secret",
        ],
        tags=["aws", "cloud", "iam", "credentials", "secrets"],
    ),

    "SEC-002": _r(
        rule_id="SEC-002",
        title="AWS Secret Access Key",
        category="Secrets",
        severity="CRITICAL",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "An AWS Secret Access Key was found assigned to a variable (aws_secret_access_key / "
            "AWS_SECRET_ACCESS_KEY). This 40-character random string is the password-equivalent "
            "for the paired AWS Access Key ID. Unlike Access Key IDs, Secret Access Keys cannot "
            "be retrieved once lost and are the key piece needed to sign all AWS API requests."
        ),
        impact=(
            "Combined with an AWS Access Key ID, this credential provides full authenticated "
            "access to all AWS services in scope. Exposure results in immediate risk of resource "
            "hijacking, data exfiltration, and denial of service to the owning AWS account."
        ),
        remediation=[
            "Immediately revoke the key in the AWS IAM Console.",
            "Audit CloudTrail for any API calls made with this key in the last 90 days.",
            "Replace with environment variable AWS_SECRET_ACCESS_KEY or use IAM role-based auth.",
            "Remove from source code and purge from Git history using git-filter-repo.",
        ],
        examples={
            "bad": "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
            "good": (
                "# Use environment variables\n"
                "# export AWS_SECRET_ACCESS_KEY='your_key'\n"
                "# boto3 reads it automatically from the environment"
            ),
        },
        references=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["aws", "cloud", "iam", "secret", "credentials"],
    ),

    "SEC-003": _r(
        rule_id="SEC-003",
        title="GitHub Personal Access Token",
        category="Secrets",
        severity="CRITICAL",
        cwe=["CWE-522"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A GitHub Personal Access Token (classic: ghp_… / ghx_…, OAuth: gho_…, "
            "user-to-server: ghu_…, server-to-server: ghs_…, refresh: ghr_…) was found "
            "in source code. GitHub PATs authenticate as the owning user and can grant "
            "read/write access to repositories, packages, secrets, org settings, and more "
            "depending on the scopes assigned. GitHub scans public repositories for these "
            "tokens and will immediately revoke them if detected — but private exposure is "
            "equally dangerous."
        ),
        impact=(
            "An attacker with this token can clone private repos, read GitHub Actions secrets, "
            "push malicious code, delete repositories, access GitHub Projects data, and "
            "impersonate the owning user across GitHub's API."
        ),
        remediation=[
            "Immediately revoke the token at github.com → Settings → Developer Settings → Personal Access Tokens.",
            "Review GitHub audit logs at github.com/settings/security-log for unauthorized activity.",
            "Generate a new fine-grained token with the minimum required scopes.",
            "Store the token in a GitHub Actions secret or an environment variable — never in code.",
            "Remove the token from source and clean Git history with git-filter-repo.",
        ],
        examples={
            "bad": "GITHUB_TOKEN = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'",
            "good": (
                "import os\n"
                "GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')  # Set via CI secret or local .env"
            ),
        },
        references=[
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
            "https://cwe.mitre.org/data/definitions/522.html",
        ],
        tags=["github", "token", "vcs", "credentials", "oauth"],
    ),

    "SEC-004": _r(
        rule_id="SEC-004",
        title="GitHub Fine-Grained Personal Access Token",
        category="Secrets",
        severity="CRITICAL",
        cwe=["CWE-522"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A GitHub Fine-Grained Personal Access Token (github_pat_…) was found in source code. "
            "Fine-grained PATs are the newer, more restrictive token type that can be scoped to "
            "specific repositories and permissions. Despite their improved least-privilege design, "
            "exposure of a fine-grained token still allows attackers to perform all actions the "
            "token's granted permissions allow."
        ),
        impact=(
            "Depending on the token's scope, an attacker can read or write to specific private "
            "repositories, manage issues/PRs, or access repository secrets within the permitted scope."
        ),
        remediation=[
            "Immediately revoke the token at github.com → Settings → Developer Settings → Fine-grained Tokens.",
            "Review access logs for suspicious activity.",
            "Re-create the token with the absolute minimum required permissions.",
            "Store in an environment variable or CI/CD secrets manager.",
        ],
        examples={
            "bad": "token = 'github_pat_11AAAAAAA0AbcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEFGHIJKLMN0PQR'",
            "good": "token = os.getenv('GITHUB_FINE_GRAINED_TOKEN')",
        },
        references=[
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token",
            "https://cwe.mitre.org/data/definitions/522.html",
        ],
        tags=["github", "token", "fine-grained", "credentials"],
    ),

    "SEC-005": _r(
        rule_id="SEC-005",
        title="Slack Bot / User Token",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-522"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A Slack API token (xoxb- bot token, xoxp- user token, xoxa- app token, "
            "xoxr- refresh token, xoxs- workspace session token) was found in source code. "
            "These tokens authenticate Slack apps and bots to the Slack API and grant access "
            "to workspace data, messaging, channels, and user information."
        ),
        impact=(
            "An exposed Slack bot token allows an attacker to read all messages in channels the "
            "bot has access to, post messages impersonating the bot, access user profiles and "
            "emails, download files, and potentially join private channels."
        ),
        remediation=[
            "Immediately revoke the token at api.slack.com/apps → Your App → OAuth & Permissions → Revoke.",
            "Review Slack audit logs (available for Business+ workspaces) for suspicious activity.",
            "Re-install the Slack app to generate a new token and store it in an environment variable.",
        ],
        examples={
            "bad": "SLACK_BOT_TOKEN = 'xoxb-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX'  # real token — do not hardcode",
            "good": "SLACK_BOT_TOKEN = os.getenv('SLACK_BOT_TOKEN')",
        },
        references=[
            "https://api.slack.com/authentication/token-types",
            "https://api.slack.com/authentication/best-practices",
            "https://cwe.mitre.org/data/definitions/522.html",
        ],
        tags=["slack", "bot", "workspace", "messaging", "api"],
    ),

    "SEC-006": _r(
        rule_id="SEC-006",
        title="Stripe Secret Key",
        category="Secrets",
        severity="CRITICAL",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A Stripe secret API key (sk_live_… for production, sk_test_… for test mode) was found "
            "in source code. Stripe secret keys grant full programmatic access to the Stripe account — "
            "creating charges, refunds, managing subscriptions, and accessing customer payment data "
            "including card last-four and billing details."
        ),
        impact=(
            "An exposed live Stripe secret key allows an attacker to charge stored payment methods, "
            "issue unauthorized refunds to their own accounts, access customer PII and billing history, "
            "create/modify webhook endpoints to intercept future payment events, and destroy subscription "
            "plans — all constituting a PCI-DSS breach."
        ),
        remediation=[
            "Immediately roll the key in the Stripe Dashboard → Developers → API Keys.",
            "Review Stripe Dashboard logs for unauthorized API calls.",
            "Store the key in an environment variable (STRIPE_SECRET_KEY) and never hardcode.",
            "Use Stripe's restricted API keys for services that don't need full account access.",
        ],
        examples={
            "bad": "stripe.api_key = 'sk_live_<YOUR_STRIPE_KEY_HERE>'  # never hardcode — use env var",
            "good": (
                "import os\n"
                "stripe.api_key = os.getenv('STRIPE_SECRET_KEY')"
            ),
        },
        references=[
            "https://stripe.com/docs/keys",
            "https://stripe.com/docs/security",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["stripe", "payments", "pci", "billing", "api-key"],
    ),

    "SEC-007": _r(
        rule_id="SEC-007",
        title="SendGrid API Key",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A SendGrid API key (SG.…) was found in source code. SendGrid API keys authenticate "
            "requests to SendGrid's email delivery API. Depending on the key's permissions, they "
            "can send email on behalf of your domain, manage sender identities, access email "
            "statistics, and in some cases modify account settings."
        ),
        impact=(
            "Exposure allows an attacker to send phishing emails at scale from your domain, burning "
            "your domain's email reputation, sending spam campaigns, accessing email delivery logs, "
            "and in some configurations managing contact lists."
        ),
        remediation=[
            "Immediately revoke the key in the SendGrid console → Settings → API Keys.",
            "Monitor SendGrid activity logs for unusual send volume or new sender identities.",
            "Re-create the key with the minimum required permissions (e.g., Mail Send only).",
            "Store in environment variable SENDGRID_API_KEY.",
        ],
        examples={
            "bad": "SENDGRID_API_KEY = 'SG.abcdefgh.1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ'",
            "good": "SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')",
        },
        references=[
            "https://docs.sendgrid.com/ui/account-and-settings/api-keys",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["sendgrid", "email", "api-key", "smtp"],
    ),

    "SEC-008": _r(
        rule_id="SEC-008",
        title="Google API Key",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A Google API key (AIzaSy… — exactly 39 characters) was found in source code. "
            "Google API keys grant access to Google Cloud and Google services APIs including "
            "Maps, Places, Gemini AI, YouTube Data, Gmail, and more. While keys can be "
            "restricted by HTTP referrer or IP, hardcoded keys are commonly found without "
            "these restrictions, or the restrictions may not cover all abuse vectors."
        ),
        impact=(
            "An attacker can use an unrestricted Google API key to rack up billing charges against "
            "your Google Cloud account (Maps/Places queries are expensive at scale), access the "
            "Gemini AI API at your cost, read YouTube data, or enumerate GCP resources. "
            "Google provides no refunds for fraudulent API usage."
        ),
        remediation=[
            "Immediately restrict or delete the key in the Google Cloud Console → APIs & Services → Credentials.",
            "Check the GCP billing dashboard and usage metrics for anomalous spikes.",
            "Re-create the key with API restrictions (specific APIs only) and application restrictions (HTTP referrers / IP).",
            "For server-side use, switch to Service Account authentication (JSON key file or Workload Identity).",
            "Store the key in an environment variable and never commit it.",
        ],
        examples={
            "bad": "GOOGLE_API_KEY = 'AIzaSyB8n9X0abcdefghijklmnopqrstuvwxyz1'",
            "good": (
                "import os\n"
                "GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')"
            ),
        },
        references=[
            "https://cloud.google.com/docs/authentication/api-keys",
            "https://cloud.google.com/docs/authentication/best-practices-applications",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["google", "gcp", "gemini", "maps", "api-key", "cloud"],
    ),

    "SEC-009": _r(
        rule_id="SEC-009",
        title="Twilio Auth Token",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A Twilio Auth Token was found in source code. Twilio Auth Tokens authenticate all "
            "REST API requests to Twilio's communication platform. Combined with the Account SID, "
            "they allow complete control over SMS/voice messaging, phone number management, and "
            "account configuration."
        ),
        impact=(
            "An attacker with the Auth Token and Account SID can send thousands of SMS messages "
            "or make phone calls at the account's expense, access call/message logs containing "
            "customer phone numbers, modify or delete phone numbers, and access Twilio Verify "
            "or Authy configurations potentially bypassing 2FA implementations."
        ),
        remediation=[
            "Immediately reset the Auth Token in the Twilio Console → Account → General Settings.",
            "Note: Resetting the token invalidates all existing API integrations — update them with the new token.",
            "Store the token in environment variable TWILIO_AUTH_TOKEN.",
            "Use Twilio API Keys (sub-credentials) instead of the primary Auth Token for application code.",
        ],
        examples={
            "bad": (
                "TWILIO_ACCOUNT_SID = 'ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'\n"
                "TWILIO_AUTH_TOKEN = '1234567890abcdef1234567890abcdef'"
            ),
            "good": (
                "import os\n"
                "TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')\n"
                "TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')"
            ),
        },
        references=[
            "https://help.twilio.com/articles/223136227-What-is-an-Account-SID",
            "https://www.twilio.com/docs/iam/api-keys",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["twilio", "sms", "voice", "api-key", "communication"],
    ),

    "SEC-010": _r(
        rule_id="SEC-010",
        title="RSA Private Key",
        category="Secrets",
        severity="CRITICAL",
        cwe=["CWE-321"],
        owasp=["A02:2021 – Cryptographic Failures"],
        description=(
            "An RSA private key (-----BEGIN RSA PRIVATE KEY-----) was found in the repository. "
            "RSA private keys are used for SSH authentication, TLS certificate signing, JWT signing, "
            "code signing, and encrypted communication. The private key must remain secret — "
            "only the corresponding public key should be shared. Any repository (even private) "
            "that has ever contained a private key should be treated as compromised."
        ),
        impact=(
            "An attacker with access to an RSA private key can: authenticate as the key's owner to any "
            "SSH server or service that trusts it, sign TLS certificates or JWTs as the legitimate issuer, "
            "decrypt messages encrypted with the corresponding public key, and impersonate the identity "
            "bound to the key (code signing, client authentication)."
        ),
        remediation=[
            "Immediately revoke the key everywhere it's registered (GitHub SSH keys, server authorized_keys, TLS cert authorities).",
            "Generate a new RSA key pair: ssh-keygen -t rsa -b 4096 -C 'your@email.com'",
            "Register only the new PUBLIC key (.pub file) in remote services.",
            "Store private keys on disk only, never commit them. Add *.pem, *.key, id_rsa to .gitignore.",
            "Remove the key from Git history: git filter-repo --path <file> --invert-paths",
            "Consider switching to hardware security keys (FIDO2/YubiKey) for critical infrastructure.",
        ],
        examples={
            "bad": (
                "# deploy_key.pem — committed to repository\n"
                "-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAEBRMEnpnMKwJhAEMLCv..."
            ),
            "good": (
                "# .gitignore\n"
                "*.pem\n"
                "*.key\n"
                "id_rsa\n"
                "id_ed25519\n\n"
                "# Store key path in config, not the key itself\n"
                "SSH_KEY_PATH = os.getenv('SSH_KEY_PATH', '~/.ssh/deploy_key')"
            ),
        },
        references=[
            "https://cwe.mitre.org/data/definitions/321.html",
            "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
        tags=["rsa", "private-key", "ssh", "tls", "cryptography", "pem"],
    ),

    "SEC-011": _r(
        rule_id="SEC-011",
        title="OpenSSH Private Key",
        category="Secrets",
        severity="CRITICAL",
        cwe=["CWE-321"],
        owasp=["A02:2021 – Cryptographic Failures"],
        description=(
            "An OpenSSH private key (-----BEGIN OPENSSH PRIVATE KEY-----) was found in the repository. "
            "This is the modern OpenSSH key format used for ed25519, ecdsa, and newer rsa keys. "
            "These keys are used for SSH authentication to servers, GitHub/GitLab, and other "
            "services. Even passphrase-protected keys should not be committed — the passphrase "
            "can be brute-forced offline."
        ),
        impact=(
            "Allows SSH authentication as the key owner to any server or service with the matching "
            "public key registered. This typically means full shell access to production servers, "
            "ability to clone all private repositories, or impersonation in CI/CD pipelines."
        ),
        remediation=[
            "Immediately remove the key from ~/.ssh/authorized_keys on all servers.",
            "Remove it from GitHub/GitLab SSH key settings.",
            "Generate a new key: ssh-keygen -t ed25519 -C 'your@email.com'",
            "Add id_ed25519, id_rsa, *.pem to .gitignore immediately.",
            "Clean Git history with git-filter-repo.",
        ],
        examples={
            "bad": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA...",
            "good": (
                "# .gitignore\n"
                "id_rsa\nid_ed25519\nid_ecdsa\n*.pem\n*.key"
            ),
        },
        references=[
            "https://man.openbsd.org/ssh-keygen",
            "https://cwe.mitre.org/data/definitions/321.html",
            "https://docs.github.com/en/authentication/connecting-to-github-with-ssh",
        ],
        tags=["openssh", "ssh", "ed25519", "ecdsa", "private-key"],
    ),

    "SEC-012": _r(
        rule_id="SEC-012",
        title="Generic PEM Private Key",
        category="Secrets",
        severity="CRITICAL",
        cwe=["CWE-321"],
        owasp=["A02:2021 – Cryptographic Failures"],
        description=(
            "A PEM-encoded private key block (BEGIN PRIVATE KEY, BEGIN EC PRIVATE KEY, "
            "BEGIN ENCRYPTED PRIVATE KEY, etc.) was found in the repository. PEM is the "
            "standard format for storing cryptographic private keys for TLS certificates, "
            "PKCS#8 keys, and many other purposes. Committing TLS private keys is especially "
            "dangerous as it completely invalidates the security guarantee of HTTPS."
        ),
        impact=(
            "Depending on key usage: TLS private key exposure enables man-in-the-middle attacks "
            "on HTTPS traffic and allows decrypting captured TLS sessions. EC/PKCS8 key exposure "
            "can compromise code signing, JWT signing, or encrypted data stores."
        ),
        remediation=[
            "Revoke any certificates signed by this key immediately.",
            "Request a new TLS certificate from your CA (Let's Encrypt, DigiCert, etc.).",
            "Store private keys in a secrets manager (Vault, AWS Secrets Manager) — never on disk in repos.",
            "For TLS: configure your web server to load keys from a path outside the repository.",
        ],
        examples={
            "bad": "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...",
            "good": (
                "# server.py — load certificate from path, not embedded\n"
                "ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
                "ssl_ctx.load_cert_chain(certfile='/etc/ssl/cert.pem', keyfile='/etc/ssl/key.pem')"
            ),
        },
        references=[
            "https://cwe.mitre.org/data/definitions/321.html",
            "https://letsencrypt.org/docs/revoking/",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
        tags=["pem", "tls", "ssl", "certificate", "private-key", "ec", "pkcs8"],
    ),

    "SEC-013": _r(
        rule_id="SEC-013",
        title="NPM Authentication Token",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-522"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "An NPM authentication token (npm_…) was found in source code or .npmrc file. "
            "NPM tokens authenticate publish and download operations against the npm registry. "
            "They are commonly found hardcoded in CI configuration files or .npmrc files that "
            "are accidentally committed. A leaked publish token allows attackers to publish "
            "malicious versions of your npm packages — a form of supply-chain attack."
        ),
        impact=(
            "An attacker with an npm publish token can publish malicious versions of your packages, "
            "potentially injecting backdoors into thousands of downstream projects that depend on them "
            "(software supply chain attack). Read tokens leak private package contents."
        ),
        remediation=[
            "Immediately revoke the token at npmjs.com → Account Settings → Access Tokens.",
            "Check your package's publish history for any unauthorized versions.",
            "Add .npmrc to .gitignore and regenerate the token.",
            "Use CICD-scoped tokens with the minimum required permissions (publish vs. read-only).",
        ],
        examples={
            "bad": (
                "# .npmrc — accidentally committed\n"
                "//registry.npmjs.org/:_authToken=npm_1234567890abcdefghijklmnopqrstuvwxyz"
            ),
            "good": (
                "# .npmrc — reference environment variable\n"
                "//registry.npmjs.org/:_authToken=${NPM_TOKEN}"
            ),
        },
        references=[
            "https://docs.npmjs.com/creating-and-viewing-access-tokens",
            "https://docs.npmjs.com/using-private-packages-in-a-ci-cd-workflow",
            "https://cwe.mitre.org/data/definitions/522.html",
        ],
        tags=["npm", "node", "registry", "supply-chain", "token"],
    ),

    "SEC-014": _r(
        rule_id="SEC-014",
        title="Mailchimp API Key",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A Mailchimp API key (format: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-us1) was found. "
            "Mailchimp API keys provide full access to your Mailchimp account including email "
            "campaigns, contact lists, automated workflows, and account settings."
        ),
        impact=(
            "An attacker can export your entire contact database (names, emails, demographics), "
            "send campaigns impersonating your brand, delete lists, modify automations, and "
            "access analytics."
        ),
        remediation=[
            "Revoke the key at mailchimp.com → Account → Extras → API Keys.",
            "Audit recent campaign and list activity for unauthorized changes.",
            "Generate a new key and store as MAILCHIMP_API_KEY environment variable.",
        ],
        examples={
            "bad": "MAILCHIMP_API_KEY = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-us14'  # real key — do not hardcode",
            "good": "MAILCHIMP_API_KEY = os.getenv('MAILCHIMP_API_KEY')",
        },
        references=[
            "https://mailchimp.com/developer/marketing/docs/fundamentals/#authentication",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["mailchimp", "email-marketing", "api-key"],
    ),

    "SEC-015": _r(
        rule_id="SEC-015",
        title="Mailgun API Key",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A Mailgun API key (key-… or pubkey-…) was found in source code. Mailgun is an "
            "email delivery API service. Exposed private keys allow sending emails from your "
            "verified domains and accessing email logs."
        ),
        impact=(
            "Attackers can send phishing emails appearing to originate from your domain, "
            "consuming your Mailgun quota, damaging your domain's sender reputation, and "
            "accessing stored email logs."
        ),
        remediation=[
            "Revoke the key in the Mailgun Control Panel → Account Security.",
            "Monitor sending activity for unauthorized usage.",
            "Store as MAILGUN_API_KEY environment variable.",
        ],
        examples={
            "bad": "MAILGUN_API_KEY = 'key-3ax6xnjp29jd6fds4gc373sgvjxteol0'",
            "good": "MAILGUN_API_KEY = os.getenv('MAILGUN_API_KEY')",
        },
        references=[
            "https://documentation.mailgun.com/docs/mailgun/api-reference/authentication/",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["mailgun", "email", "api-key", "smtp"],
    ),

    "SEC-016": _r(
        rule_id="SEC-016",
        title="Telegram Bot Token",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A Telegram Bot API token (format: 123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ) was found. "
            "Telegram bot tokens authenticate bots to the Telegram Bot API, granting full control "
            "of the bot — sending and receiving messages, managing groups/channels, and accessing "
            "all data the bot can see."
        ),
        impact=(
            "An attacker can hijack your Telegram bot entirely, read all messages the bot has "
            "received, send messages to all users who have interacted with the bot, modify bot "
            "commands and webhooks, and delete the bot's data."
        ),
        remediation=[
            "Immediately generate a new token by messaging @BotFather on Telegram: /revoke",
            "Update all services using the old token with the new one.",
            "Store as TELEGRAM_BOT_TOKEN environment variable.",
        ],
        examples={
            "bad": "BOT_TOKEN = '1234567890:ABCDefGhIJKlmNoPQRsTUVwxyz01234567'",
            "good": "BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')",
        },
        references=[
            "https://core.telegram.org/bots/api#authorizing-your-bot",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["telegram", "bot", "messaging", "api-key"],
    ),

    "SEC-017": _r(
        rule_id="SEC-017",
        title="Heroku API Key",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A Heroku API key (UUID format) was found in source code. Heroku API keys grant "
            "full access to your Heroku account — deploying apps, managing config vars, scaling "
            "dynos, and accessing add-on credentials."
        ),
        impact=(
            "Full Heroku account access including deploying malicious code to production apps, "
            "reading all config vars (which often contain other secrets), scaling resources to "
            "incur costs, and accessing databases through add-on credentials."
        ),
        remediation=[
            "Regenerate the key in the Heroku Dashboard → Account Settings.",
            "Audit recent Heroku activity logs.",
            "Store as HEROKU_API_KEY environment variable in CI/CD.",
        ],
        examples={
            "bad": "HEROKU_API_KEY = '12345678-1234-1234-1234-1234567890ab'",
            "good": "HEROKU_API_KEY = os.getenv('HEROKU_API_KEY')",
        },
        references=[
            "https://devcenter.heroku.com/articles/authentication",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["heroku", "paas", "cloud", "api-key", "deployment"],
    ),

    "SEC-018": _r(
        rule_id="SEC-018",
        title="PyPI Upload Token",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-798"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A PyPI API token (pypi-…) was found in source code. PyPI tokens authenticate "
            "uploads to the Python Package Index. A leaked publish token enables supply-chain "
            "attacks — uploading malicious versions of your Python packages that could then "
            "be installed by millions of users."
        ),
        impact=(
            "A compromised PyPI token allows an attacker to publish malicious package versions, "
            "injecting backdoors into your Python packages that propagate to all downstream "
            "users running pip install."
        ),
        remediation=[
            "Immediately revoke the token at pypi.org → Account Settings → API Tokens.",
            "Check your package's release history for unauthorized versions.",
            "Use scoped tokens limited to specific packages.",
            "Use Trusted Publishers (GitHub Actions OIDC) instead of long-lived tokens.",
        ],
        examples={
            "bad": "PYPI_TOKEN = 'pypi-AgEIcHlwaS5vcmcCJDdlMWQ2NjBiLTkyMzEtNDM2OS04MWUwLTAzZjliZDE3MmVhZA'",
            "good": (
                "# Use GitHub Actions Trusted Publisher (OIDC) in pyproject.toml\n"
                "# or: store as PYPI_API_TOKEN CI secret"
            ),
        },
        references=[
            "https://pypi.org/help/#apitoken",
            "https://docs.pypi.org/trusted-publishers/",
            "https://cwe.mitre.org/data/definitions/798.html",
        ],
        tags=["pypi", "python", "supply-chain", "package", "token"],
    ),

    "SEC-019": _r(
        rule_id="SEC-019",
        title="Credentials Embedded in URL",
        category="Secrets",
        severity="HIGH",
        cwe=["CWE-522"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A URL containing embedded credentials in the format "
            "https://username:password@host/... was found in source code. Embedding credentials "
            "in URLs is a serious security practice: they appear in server access logs, browser "
            "history, referrer headers, and any proxy or CDN layer. This pattern is common in "
            "database connection strings and Git remote URLs."
        ),
        impact=(
            "Any system that logs HTTP requests (web servers, proxies, CDNs, load balancers) will "
            "store the credentials in plaintext log files. These logs are often retained for months "
            "and may be accessible to many team members or systems."
        ),
        remediation=[
            "Remove credentials from the URL immediately.",
            "Use separate authentication mechanisms (auth headers, environment variables).",
            "For database URLs: use a DSN environment variable that parses separately.",
            "For Git remotes: use SSH key auth or credential managers instead of HTTPS with password.",
        ],
        examples={
            "bad": "DATABASE_URL = 'postgresql://admin:s3cr3tP@ssw0rd@db.example.com:5432/mydb'",
            "good": (
                "import os\n"
                "DB_USER = os.getenv('DB_USER')\n"
                "DB_PASS = os.getenv('DB_PASSWORD')\n"
                "DB_HOST = os.getenv('DB_HOST')\n"
                "DATABASE_URL = f'postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}/mydb'"
            ),
        },
        references=[
            "https://cwe.mitre.org/data/definitions/522.html",
            "https://owasp.org/www-community/vulnerabilities/Cleartext_Transmission_of_Sensitive_Information",
        ],
        tags=["url", "credentials", "database", "basic-auth", "connection-string"],
    ),

    "SEC-020": _r(
        rule_id="SEC-020",
        title="Generic Secret Assignment",
        category="Secrets",
        severity="MEDIUM",
        cwe=["CWE-798", "CWE-259"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A variable with a sensitive name (secret, password, api_key, auth_token, "
            "access_token, private_key) was found assigned a hardcoded quoted string value. "
            "This is a generic catch-all rule that fires when a specific service provider "
            "cannot be identified, but the pattern strongly suggests a credential is being "
            "hardcoded in source code."
        ),
        impact=(
            "Hardcoded credentials in source code are permanently embedded in Git history and "
            "visible to anyone with repository access. If the repo is ever made public, or if "
            "an internal threat actor exists, these credentials are immediately exploitable."
        ),
        remediation=[
            "Replace the hardcoded value with an environment variable lookup.",
            "Move the actual credential to a .env file (ensure .env is in .gitignore).",
            "For production: use a secrets manager (AWS Secrets Manager, Vault, GCP Secret Manager).",
            "Rotate the credential if it was ever committed to a repository.",
        ],
        examples={
            "bad": (
                "API_KEY = 'my-super-secret-key-12345'\n"
                "password = 'Tr0ub4dor&3'"
            ),
            "good": (
                "import os\n"
                "API_KEY = os.getenv('API_KEY')        # loaded from .env or CI secret\n"
                "password = os.getenv('DB_PASSWORD')   # never hardcoded"
            ),
        },
        references=[
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://cwe.mitre.org/data/definitions/259.html",
            "https://12factor.net/config",
        ],
        tags=["hardcoded", "secret", "password", "credentials", "config"],
    ),

    # =========================================================================
    # DEP — Dependencies
    # =========================================================================

    "DEP-001": _r(
        rule_id="DEP-001",
        title="Dependency with Known Vulnerabilities",
        category="Dependencies",
        severity="HIGH",
        cwe=["CWE-1395"],
        owasp=["A06:2021 – Vulnerable and Outdated Components"],
        description=(
            "A project dependency was found to have one or more publicly disclosed CVEs in the "
            "OSV (Open Source Vulnerabilities) database. GitRisk checks installed package versions "
            "against the local OSV database to detect components with known, exploitable security "
            "vulnerabilities. This is one of the most common and underestimated attack surfaces."
        ),
        impact=(
            "Depending on the CVE: remote code execution via deserialization flaws, SSRF, path "
            "traversal, authentication bypass, denial of service, or information disclosure. "
            "Supply-chain attacks through transitive dependencies are a growing concern."
        ),
        remediation=[
            "Run `gitrisk fix .` to automatically update the package to the first safe version.",
            "Review the CVE description and assess if your code uses the affected functionality.",
            "Update the dependency in requirements.txt/pyproject.toml to a patched version.",
            "Run `pip audit` regularly and integrate it into CI/CD pipelines.",
            "Consider using Dependabot to receive automated pull requests for vulnerable dependencies.",
        ],
        examples={
            "bad": (
                "# requirements.txt\n"
                "requests==2.18.0  # CVE-2018-18074: SSRF via crafted redirect"
            ),
            "good": (
                "# requirements.txt\n"
                "requests>=2.32.0  # patched version"
            ),
        },
        references=[
            "https://osv.dev/",
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
            "https://cwe.mitre.org/data/definitions/1395.html",
            "https://pip.pypa.io/en/stable/cli/pip_audit/",
        ],
        tags=["dependencies", "cve", "osv", "supply-chain", "packages"],
    ),

    "DEP-002": _r(
        rule_id="DEP-002",
        title="Vulnerable requests Package",
        category="Dependencies",
        severity="HIGH",
        cwe=["CWE-1395"],
        owasp=["A06:2021 – Vulnerable and Outdated Components"],
        description=(
            "The `requests` HTTP library has a version with known CVEs. Older requests versions "
            "have had SSRF vulnerabilities (CVE-2018-18074), header injection issues, and "
            "certificate verification bypasses. The requests library is one of the most "
            "widely-used Python packages and is a prime target for vulnerability research."
        ),
        impact=(
            "Depending on the specific CVE: Server-Side Request Forgery (SSRF) allows attackers "
            "to make the server issue HTTP requests to internal services, bypassing firewalls. "
            "Header injection can lead to response splitting or credential theft."
        ),
        remediation=[
            "Update requests to the latest stable version: pip install --upgrade requests",
            "In requirements.txt: requests>=2.32.0",
        ],
        examples={
            "bad": "requests==2.18.0",
            "good": "requests>=2.32.0",
        },
        references=[
            "https://pypi.org/project/requests/#history",
            "https://osv.dev/list?ecosystem=PyPI&q=requests",
        ],
        tags=["requests", "http", "ssrf", "python", "dependency"],
    ),

    "DEP-003": _r(
        rule_id="DEP-003",
        title="Vulnerable pytest Package",
        category="Dependencies",
        severity="MEDIUM",
        cwe=["CWE-1395"],
        owasp=["A06:2021 – Vulnerable and Outdated Components"],
        description=(
            "The `pytest` testing framework has a version with known security issues. "
            "While pytest vulnerabilities are often lower severity (since the package typically "
            "only runs in development/CI environments), keeping testing tools updated is still "
            "important as they may be used in security-sensitive CI pipelines or in production "
            "by mistake."
        ),
        impact=(
            "Low direct impact in most cases. However, vulnerable test frameworks can be "
            "exploited in CI/CD environments where tests run against production data or "
            "infrastructure credentials."
        ),
        remediation=[
            "Update pytest: pip install --upgrade pytest",
            "In pyproject.toml or requirements-dev.txt: pytest>=8.3.0",
        ],
        examples={
            "bad": "pytest==6.0.0",
            "good": "pytest>=8.3.0",
        },
        references=[
            "https://pypi.org/project/pytest/#history",
            "https://osv.dev/list?ecosystem=PyPI&q=pytest",
        ],
        tags=["pytest", "testing", "dev-dependency", "ci"],
    ),

    # =========================================================================
    # ENV — Environment File Tracking
    # =========================================================================

    "ENV-001": _r(
        rule_id="ENV-001",
        title=".env File Tracked by Git",
        category="Environment",
        severity="HIGH",
        cwe=["CWE-200", "CWE-312"],
        owasp=["A02:2021 – Cryptographic Failures"],
        description=(
            "A .env file is being tracked by Git (it is not listed in .gitignore and appears "
            "in the Git index). .env files are the standard mechanism for storing local "
            "environment configuration — database URLs, API keys, secret keys, SMTP passwords, "
            "and other sensitive values. These files should NEVER be committed to version control "
            "as they expose all contained secrets to every person with repository access, and "
            "permanently into Git history."
        ),
        impact=(
            "All secrets contained in the .env file are exposed to anyone with repository read access. "
            "If the repository is public or becomes public in the future, all secrets are immediately "
            "exposed to the entire internet and automated scanning tools."
        ),
        remediation=[
            "Run: git rm --cached .env  (removes from tracking but keeps local file)",
            "Add .env to .gitignore immediately: echo '.env' >> .gitignore",
            "Rotate every credential that appeared in the .env file.",
            "Create a .env.example file with placeholder values to document required config.",
            "Check Git history for other commits that may have contained .env contents.",
        ],
        examples={
            "bad": (
                "# .env — this file was committed!\n"
                "DATABASE_URL=postgresql://user:secretpass@localhost/prod\n"
                "STRIPE_SECRET_KEY=sk_live_abc123\n"
                "SECRET_KEY=my-very-secret-django-key"
            ),
            "good": (
                "# .env.example — only this template file is committed\n"
                "DATABASE_URL=postgresql://user:password@localhost/dbname\n"
                "STRIPE_SECRET_KEY=sk_live_YOUR_KEY_HERE\n"
                "SECRET_KEY=generate-a-random-secret-key\n\n"
                "# .gitignore\n"
                ".env\n"
                ".env.*\n"
                "!.env.example"
            ),
        },
        references=[
            "https://12factor.net/config",
            "https://cwe.mitre.org/data/definitions/200.html",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
        tags=["env", "dotenv", "gitignore", "config", "secrets"],
    ),

    # =========================================================================
    # GHA — GitHub Actions
    # =========================================================================

    "GHA-001": _r(
        rule_id="GHA-001",
        title="Workflow Permissions Not Explicitly Set",
        category="GitHub Actions",
        severity="MEDIUM",
        cwe=["CWE-250"],
        owasp=["A01:2021 – Broken Access Control"],
        description=(
            "A GitHub Actions workflow does not explicitly define the `permissions` key at the "
            "top level. When permissions are not explicitly set and the repository's default is "
            "`read-all` or `write-all`, workflows may have broader access than required. "
            "Following least-privilege principles, all workflows should explicitly declare "
            "the minimal permissions they need."
        ),
        impact=(
            "Over-permissioned workflow tokens can be exploited via script injection in PR titles, "
            "issue bodies, or commit messages to write to the repository, trigger releases, or "
            "access other resources — a common GitHub Actions attack vector."
        ),
        remediation=[
            "Add a top-level `permissions: read-all` or `permissions: {}` to the workflow.",
            "Then grant only specific permissions needed by individual jobs.",
            "Set the repository default to 'restricted' in Settings → Actions → General.",
        ],
        examples={
            "bad": (
                "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4"
            ),
            "good": (
                "on: [push]\npermissions: read-all  # deny all write by default\njobs:\n  build:\n    permissions:\n      contents: read\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4"
            ),
        },
        references=[
            "https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
            "https://cwe.mitre.org/data/definitions/250.html",
            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        ],
        tags=["github-actions", "workflow", "permissions", "ci-cd"],
    ),

    "GHA-002": _r(
        rule_id="GHA-002",
        title="Elevated Write Permission in Workflow",
        category="GitHub Actions",
        severity="MEDIUM",
        cwe=["CWE-250"],
        owasp=["A01:2021 – Broken Access Control"],
        description=(
            "A GitHub Actions workflow grants `write` permissions to a sensitive resource "
            "(e.g. contents: write, pull-requests: write, packages: write). While these "
            "permissions may be intentional for deployment or release workflows, they significantly "
            "increase the blast radius if the workflow is compromised through a script injection "
            "or malicious pull request."
        ),
        impact=(
            "A workflow with `contents: write` can push commits or tags, enabling a compromised "
            "workflow to backdoor the repository. `packages: write` can push malicious container "
            "images. Script injection through pull_request events with write permissions is a "
            "well-documented GitHub Actions attack vector."
        ),
        remediation=[
            "Review if write permissions are truly necessary for the workflow's purpose.",
            "If needed, limit write permissions to only the specific jobs/steps that require them.",
            "Avoid using pull_request_target trigger with write permissions and untrusted code.",
            "Ensure no user-controlled input is used directly in shell commands (script injection).",
        ],
        examples={
            "bad": (
                "permissions:\n  contents: write  # allows pushing commits\n  pull-requests: write"
            ),
            "good": (
                "permissions:\n  contents: read\n  pull-requests: read\n# Only grant write in jobs that deploy:"
                "\njobs:\n  deploy:\n    permissions:\n      contents: write"
            ),
        },
        references=[
            "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
            "https://cwe.mitre.org/data/definitions/250.html",
        ],
        tags=["github-actions", "permissions", "write", "ci-cd", "injection"],
    ),

    "GHA-003": _r(
        rule_id="GHA-003",
        title="Use of pull_request_target Trigger",
        category="GitHub Actions",
        severity="HIGH",
        cwe=["CWE-250"],
        owasp=["A01:2021 – Broken Access Control"],
        description=(
            "The workflow uses the `pull_request_target` trigger, which runs in the context of "
            "the base repository rather than the fork. This trigger has access to repository "
            "secrets and a write-permissions GITHUB_TOKEN by default. If the workflow checks out "
            "or uses code from the fork alongside secret access, it is vulnerable to compromise "
            "by malicious pull requests — sometimes called a 'pwn request'."
        ),
        impact=(
            "A malicious PR can modify workflow files or scripts that are later executed with "
            "the base repository's secrets, exfiltrating all GitHub Actions secrets, AWS keys, "
            "deployment credentials, or any other secrets stored in the repository."
        ),
        remediation=[
            "Avoid using pull_request_target unless absolutely required.",
            "If used: do NOT checkout or execute code from the pull request's fork.",
            "Use pull_request (no _target) for workflows that build/test fork code.",
            "If you need secrets in PR workflows, use environments with required reviewers.",
        ],
        examples={
            "bad": (
                "on: pull_request_target\njobs:\n  build:\n    steps:\n"
                "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}"
            ),
            "good": (
                "on: pull_request  # safer: runs in fork context, no secret access\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4"
            ),
        },
        references=[
            "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
            "https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target",
            "https://cwe.mitre.org/data/definitions/250.html",
        ],
        tags=["github-actions", "pull-request", "fork", "secrets", "pwn-request"],
    ),

    # =========================================================================
    # GIT — Git Configuration
    # =========================================================================

    "GIT-001": _r(
        rule_id="GIT-001",
        title="Large Binary File Committed",
        category="Git",
        severity="LOW",
        cwe=["CWE-400"],
        owasp=[],
        description=(
            "A large binary file (>1MB) was detected in the Git repository. Binary files "
            "(images, datasets, model weights, archives, databases) bloat repository size "
            "significantly because Git stores full copies of each version. Large repos cause "
            "slow clones, high storage costs, and can harbor malicious payloads embedded in "
            "binary formats."
        ),
        impact=(
            "Repository becomes slow to clone, consuming CI/CD time and developer bandwidth. "
            "Sensitive data embedded in binary files (e.g., database exports with customer records) "
            "is harder to detect and remove."
        ),
        remediation=[
            "Use Git LFS (Large File Storage) for legitimate large binary assets.",
            "For datasets and model weights: use DVC (Data Version Control) instead.",
            "Remove binary files from history using git-filter-repo if they were committed accidentally.",
        ],
        examples={},
        references=[
            "https://git-lfs.com/",
            "https://dvc.org/",
        ],
        tags=["binary", "file-size", "lfs", "performance"],
    ),

    "GIT-002": _r(
        rule_id="GIT-002",
        title=".gitignore Missing Critical Security Patterns",
        category="Git",
        severity="LOW",
        cwe=["CWE-200"],
        owasp=["A02:2021 – Cryptographic Failures"],
        description=(
            "The repository's .gitignore file is missing one or more critical security patterns. "
            "Common security-sensitive files that should always be ignored include: .env, .env.*, "
            "*.pem, *.key, *.p12, *.pfx, id_rsa, id_ed25519, *.secrets, credentials.json, "
            "secrets.yml, and similar files. Without these patterns, a single mistake can "
            "accidentally commit sensitive credentials."
        ),
        impact=(
            "A missing .gitignore entry for credential files means any developer running "
            "`git add .` could accidentally commit secrets to the repository."
        ),
        remediation=[
            "Run `gitrisk fix .` to automatically add missing security patterns to .gitignore.",
            "Use github.com/github/gitignore as a reference for language-specific ignore patterns.",
            "Consider adding a pre-commit hook using detect-secrets or gitleaks to catch secrets before commit.",
        ],
        examples={
            "bad": (
                "# .gitignore — missing security patterns\n"
                "__pycache__/\n*.pyc\ndist/"
            ),
            "good": (
                "# .gitignore — with security patterns\n"
                "__pycache__/\n*.pyc\ndist/\n\n# Security\n.env\n.env.*\n!.env.example\n*.pem\n*.key\nid_rsa\nid_ed25519\ncredentials.json"
            ),
        },
        references=[
            "https://github.com/github/gitignore",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        tags=["gitignore", "configuration", "prevention", "secrets"],
    ),

    "GIT-010": _r(
        rule_id="GIT-010",
        title="Not a Git Repository",
        category="Git",
        severity="INFO",
        cwe=[],
        owasp=[],
        description=(
            "GitRisk could not find a .git directory in the scanned path. GitRisk is designed "
            "to scan Git repositories and some checks (Git history, .gitignore, tracked files) "
            "require a Git repository to function properly."
        ),
        impact="Informational only — no security risk. Git history checks are skipped.",
        remediation=[
            "Run `git init` to initialize a Git repository if you intend to use one.",
            "Ensure you are pointing GitRisk at the correct directory.",
        ],
        examples={},
        references=["https://git-scm.com/docs/git-init"],
        tags=["git", "setup", "informational"],
    ),

    "GIT-011": _r(
        rule_id="GIT-011",
        title="fileMode Disabled in Git Config",
        category="Git",
        severity="INFO",
        cwe=[],
        owasp=[],
        description=(
            "The local Git repository has core.fileMode = false set in .git/config. "
            "This disables tracking of POSIX file permission changes (chmod +x). "
            "On Windows (NTFS), this setting is the default because Windows filesystems do not "
            "support executable permission bits — this is expected behavior and not a security "
            "issue on Windows. On Linux/macOS, this setting could mask accidentally making "
            "sensitive files world-executable."
        ),
        impact=(
            "On Linux/macOS only: permission changes (e.g., making a private key file executable) "
            "may not be tracked by Git, reducing auditability."
        ),
        remediation=[
            "On Linux/macOS: run `git config core.fileMode true` if you want to track permission changes.",
            "On Windows: this is the expected default and requires no action.",
        ],
        examples={},
        references=["https://git-scm.com/docs/git-config#Documentation/git-config.txt-corefileMode"],
        tags=["git", "config", "permissions", "filemode"],
    ),

    "GIT-012": _r(
        rule_id="GIT-012",
        title="Shared Repository Mode Enabled",
        category="Git",
        severity="MEDIUM",
        cwe=["CWE-284"],
        owasp=["A01:2021 – Broken Access Control"],
        description=(
            "Git is configured with `sharedRepository` mode enabled. This setting grants "
            "multiple UNIX users on the same system shared read/write access to the repository "
            "objects. This is designed for centralized bare repositories on a single server, "
            "and is rarely appropriate for regular working repositories."
        ),
        impact=(
            "Other users on the same system can read and potentially modify Git objects, "
            "history, and repository configuration — violating least-privilege access control."
        ),
        remediation=[
            "Verify whether shared mode is intentional for your server setup.",
            "To disable: `git config core.sharedRepository false`",
            "Review file permissions on .git/ directory: ls -la .git/",
        ],
        examples={},
        references=["https://git-scm.com/docs/git-config#Documentation/git-config.txt-coresharedRepository"],
        tags=["git", "config", "access-control", "permissions"],
    ),

    "GIT-013": _r(
        rule_id="GIT-013",
        title="SSL Certificate Verification Disabled",
        category="Git",
        severity="HIGH",
        cwe=["CWE-295"],
        owasp=["A02:2021 – Cryptographic Failures"],
        description=(
            "Git's http.sslVerify is set to false in the repository or global configuration. "
            "This disables TLS certificate verification for all Git remote operations (fetch, "
            "push, pull) over HTTPS. This is a critical security setting — without certificate "
            "verification, Git connections are vulnerable to man-in-the-middle attacks."
        ),
        impact=(
            "An attacker on the network path between the developer and the remote (MITM) can "
            "intercept Git traffic to read credentials, inject malicious code into clones, or "
            "redirect pushes to a rogue server — all without any warning to the user."
        ),
        remediation=[
            "Re-enable SSL verification: `git config --global http.sslVerify true`",
            "If using a corporate CA, install its certificate system-wide rather than disabling verification.",
            "For self-signed certs: `git config http.sslCAInfo /path/to/ca.crt`",
        ],
        examples={
            "bad": "git config --global http.sslVerify false  # NEVER do this",
            "good": (
                "# For custom CA certificates:\n"
                "git config --global http.sslCAInfo /etc/ssl/certs/company-ca.crt"
            ),
        },
        references=[
            "https://git-scm.com/docs/git-config#Documentation/git-config.txt-httpsslVerify",
            "https://cwe.mitre.org/data/definitions/295.html",
        ],
        tags=["git", "ssl", "tls", "mitm", "certificate"],
    ),

    "GIT-014": _r(
        rule_id="GIT-014",
        title="Git Credential Helper Stores in Plaintext",
        category="Git",
        severity="MEDIUM",
        cwe=["CWE-522", "CWE-312"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "Git is configured to use `credential.helper=store`, which saves credentials in "
            "plaintext to the file ~/.git-credentials. This file is readable by any process "
            "running as the same user and contains the full username and password/token for "
            "all Git remotes the user has authenticated with."
        ),
        impact=(
            "Any malware or unauthorized process running as the same user account can "
            "read all stored Git credentials — GitHub/GitLab tokens, SSH passwords, "
            "or HTTP passwords — in plaintext from ~/.git-credentials."
        ),
        remediation=[
            "Switch to a secure credential helper:",
            "  macOS: git config --global credential.helper osxkeychain",
            "  Windows: git config --global credential.helper manager",
            "  Linux: git config --global credential.helper /usr/share/doc/git/contrib/credential/gnome-keyring/...",
            "Delete the existing plaintext credentials file: rm ~/.git-credentials",
        ],
        examples={
            "bad": (
                "# ~/.gitconfig\n"
                "[credential]\n"
                "    helper = store  # stores passwords in plaintext"
            ),
            "good": (
                "# macOS\n"
                "[credential]\n"
                "    helper = osxkeychain\n\n"
                "# Windows\n"
                "[credential]\n"
                "    helper = manager"
            ),
        },
        references=[
            "https://git-scm.com/docs/git-credential-store",
            "https://git-scm.com/doc/credential-helpers",
            "https://cwe.mitre.org/data/definitions/522.html",
        ],
        tags=["git", "credentials", "keychain", "plaintext", "config"],
    ),

    # =========================================================================
    # HRD — Hardcoding
    # =========================================================================

    "HRD-001": _r(
        rule_id="HRD-001",
        title="Hardcoded Database Connection String",
        category="Hardcoding",
        severity="CRITICAL",
        cwe=["CWE-259", "CWE-798"],
        owasp=["A02:2021 – Cryptographic Failures", "A07:2021 – Identification and Authentication Failures"],
        description=(
            "A database connection string or URL containing embedded credentials was found "
            "hardcoded in source code. Connection strings in the format "
            "postgresql://user:password@host:port/dbname, mysql://user:pass@host/db, or "
            "mongodb://user:pass@host/db expose both the database host and credentials. "
            "This is one of the most frequent causes of database breaches — exposed connection "
            "strings give attackers direct access to production databases."
        ),
        impact=(
            "Direct unauthorized access to the database, including reading all records (customer PII, "
            "financial data, credentials), writing or deleting data, and depending on DB user "
            "permissions, executing OS-level commands. This constitutes a data breach requiring "
            "regulatory notification in many jurisdictions (GDPR, CCPA, HIPAA)."
        ),
        remediation=[
            "Move the connection string to an environment variable: DATABASE_URL=... in .env",
            "Load it in code: import os; db_url = os.getenv('DATABASE_URL')",
            "Add .env to .gitignore and never commit it.",
            "Rotate the database password immediately.",
            "Restrict database user permissions to only what the application needs (not superuser).",
            "Consider using a secrets manager for production (AWS Secrets Manager, Vault).",
        ],
        examples={
            "bad": (
                "# db.py\n"
                "DATABASE_URL = 'postgresql://admin:Sup3rS3cr3t@db.prod.example.com:5432/customers'\n"
                "engine = create_engine(DATABASE_URL)"
            ),
            "good": (
                "# db.py\n"
                "import os\n"
                "DATABASE_URL = os.getenv('DATABASE_URL')  # set in .env or CI secrets\n"
                "if not DATABASE_URL:\n"
                "    raise ValueError('DATABASE_URL environment variable is required')\n"
                "engine = create_engine(DATABASE_URL)"
            ),
        },
        references=[
            "https://cwe.mitre.org/data/definitions/259.html",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "https://12factor.net/config",
            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
        ],
        tags=["database", "connection-string", "password", "postgresql", "mysql", "mongodb"],
    ),

    "HRD-002": _r(
        rule_id="HRD-002",
        title="Hardcoded Password",
        category="Hardcoding",
        severity="HIGH",
        cwe=["CWE-259"],
        owasp=["A07:2021 – Identification and Authentication Failures"],
        description=(
            "A hardcoded password literal was found assigned to a variable named `password`, "
            "`passwd`, `pass`, or similar. Hardcoding passwords in source code is a perennial "
            "security anti-pattern that permanently embeds credentials in the codebase and "
            "Git history, making them visible to every developer, CI system, and anyone who "
            "ever gains access to the repository."
        ),
        impact=(
            "The hardcoded password may be used to authenticate to databases, APIs, admin panels, "
            "SSH servers, or other services. Exposure leads to unauthorized access to all services "
            "using that password, including if the same password is reused elsewhere."
        ),
        remediation=[
            "Never hardcode passwords in source code.",
            "Use environment variables: password = os.getenv('SERVICE_PASSWORD')",
            "For interactive scripts: use getpass.getpass() to prompt at runtime.",
            "Rotate the hardcoded password immediately.",
            "Scan Git history for the password: git log -S 'your-password' --all",
        ],
        examples={
            "bad": (
                "# auth.py\n"
                "PASSWORD = 'Tr0ub4dor&3'\n"
                "conn = smtp.login('user@example.com', PASSWORD)"
            ),
            "good": (
                "# auth.py\n"
                "import os\n"
                "import getpass\n"
                "PASSWORD = os.getenv('SMTP_PASSWORD') or getpass.getpass('SMTP password: ')\n"
                "conn = smtp.login('user@example.com', PASSWORD)"
            ),
        },
        references=[
            "https://cwe.mitre.org/data/definitions/259.html",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
        ],
        tags=["password", "hardcoded", "credentials", "authentication"],
    ),

    "HRD-003": _r(
        rule_id="HRD-003",
        title="Hardcoded Private IP Address",
        category="Hardcoding",
        severity="LOW",
        cwe=["CWE-200"],
        owasp=["A05:2021 – Security Misconfiguration"],
        description=(
            "A private IP address (10.x.x.x, 192.168.x.x, 172.16-31.x.x) was found hardcoded "
            "in source code. Hardcoded internal IP addresses expose network topology information "
            "and create brittle configurations — if the target server's IP changes, the "
            "application breaks without any obvious error."
        ),
        impact=(
            "Information disclosure of internal network topology. If the repository becomes "
            "public, attackers learn the structure of your internal network. Also causes "
            "reliability issues when internal IPs change."
        ),
        remediation=[
            "Replace hardcoded IPs with environment variables or DNS hostnames.",
            "Use service discovery (Consul, Kubernetes DNS) in microservice environments.",
            "Example: DB_HOST = os.getenv('DB_HOST', 'db.internal.example.com')",
        ],
        examples={
            "bad": "DB_HOST = '192.168.1.100'  # hardcoded internal IP",
            "good": "DB_HOST = os.getenv('DB_HOST', 'db.internal.example.com')",
        },
        references=[
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        tags=["ip-address", "network", "topology", "hardcoded"],
    ),

    "HRD-004": _r(
        rule_id="HRD-004",
        title="Hardcoded Internal IP Address",
        category="Hardcoding",
        severity="LOW",
        cwe=["CWE-200"],
        owasp=["A05:2021 – Security Misconfiguration"],
        description=(
            "An internal or link-local IP address was found hardcoded in source code. "
            "This includes RFC 1918 private ranges and RFC 3927 link-local addresses. "
            "Similar to HRD-003, this leaks internal network topology and creates rigid "
            "infrastructure coupling."
        ),
        impact=(
            "Information disclosure about internal network infrastructure. Creates hard "
            "dependencies that break when infrastructure changes."
        ),
        remediation=[
            "Use environment variables or configuration files for host addresses.",
            "Use internal DNS names rather than IP addresses.",
            "For cloud environments: use service discovery or instance metadata.",
        ],
        examples={
            "bad": "INTERNAL_SERVICE = 'http://10.0.1.42:8080/api'",
            "good": "INTERNAL_SERVICE = os.getenv('INTERNAL_SERVICE_URL', 'http://service.internal:8080/api')",
        },
        references=["https://cwe.mitre.org/data/definitions/200.html"],
        tags=["ip-address", "network", "internal", "hardcoded"],
    ),

    "HRD-005": _r(
        rule_id="HRD-005",
        title="Hardcoded Port Number",
        category="Hardcoding",
        severity="INFO",
        cwe=["CWE-200"],
        owasp=[],
        description=(
            "A hardcoded port number was found in source code. While not always a security "
            "issue, hardcoded ports can reveal internal service architecture, create inflexible "
            "configurations, and in some cases expose information about which services are "
            "running internally."
        ),
        impact="Low direct security impact. Creates brittle configurations and leaks service topology.",
        remediation=[
            "Use environment variables for port configuration: PORT = int(os.getenv('PORT', '8080'))",
            "Follow the twelve-factor app methodology for configuration.",
        ],
        examples={
            "bad": "app.run(host='0.0.0.0', port=5432)  # hardcoded port",
            "good": "app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5432')))",
        },
        references=["https://12factor.net/config"],
        tags=["port", "hardcoded", "config", "network"],
    ),

    "HRD-006": _r(
        rule_id="HRD-006",
        title="Hardcoded Service Endpoint",
        category="Hardcoding",
        severity="INFO",
        cwe=["CWE-200"],
        owasp=[],
        description=(
            "A hardcoded external service URL or endpoint was found in source code. "
            "Hardcoded service URLs create rigid configurations, expose the dependency graph "
            "of the application, and make it difficult to switch between environments "
            "(development, staging, production) without code changes."
        ),
        impact=(
            "Low direct security risk. May expose internal service topology. "
            "Creates environment-coupling problems that can lead to accidentally calling "
            "production services from development code."
        ),
        remediation=[
            "Move service URLs to environment variables.",
            "Use configuration files per environment (config/dev.yml, config/prod.yml).",
            "Consider a service mesh or API gateway for service-to-service communication.",
        ],
        examples={
            "bad": "API_BASE = 'https://api.internal.example.com/v2'",
            "good": "API_BASE = os.getenv('API_BASE_URL', 'https://api.example.com/v2')",
        },
        references=["https://12factor.net/backing-services"],
        tags=["endpoint", "url", "service", "hardcoded", "config"],
    ),

    # =========================================================================
    # POL — Policy / Documentation
    # =========================================================================

    "POL-001": _r(
        rule_id="POL-001",
        title="No SECURITY.md Found",
        category="Policy",
        severity="LOW",
        cwe=[],
        owasp=["A05:2021 – Security Misconfiguration"],
        description=(
            "The repository does not have a SECURITY.md file. A SECURITY.md (or "
            ".github/SECURITY.md) is the standard location for a project's security policy. "
            "It documents how to responsibly disclose vulnerabilities to the project, the "
            "supported versions, and the expected response timeline. GitHub prominently links "
            "to this file in the repository's Security tab."
        ),
        impact=(
            "Without a SECURITY.md, security researchers and users don't know how to report "
            "vulnerabilities privately. This increases the risk of public zero-day disclosure "
            "before patches are available."
        ),
        remediation=[
            "Run `gitrisk fix .` to automatically generate a SECURITY.md template.",
            "Or create SECURITY.md manually with: supported versions, disclosure process, and contact info.",
            "Consider enabling GitHub's Private Security Advisories for coordinated disclosure.",
        ],
        examples={
            "good": (
                "# SECURITY.md\n\n"
                "## Supported Versions\n| Version | Supported |\n|---------|----------|\n| 1.x | ✅ |\n\n"
                "## Reporting Vulnerabilities\nPlease report security issues privately via GitHub Security Advisories\n"
                "or email security@example.com. Do not file public issues for security bugs."
            ),
        },
        references=[
            "https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository",
            "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html",
        ],
        tags=["policy", "security-disclosure", "documentation", "github"],
    ),

    "POL-002": _r(
        rule_id="POL-002",
        title="No README.md Found",
        category="Policy",
        severity="INFO",
        cwe=[],
        owasp=[],
        description=(
            "The repository does not have a README.md file. A README is fundamental "
            "documentation that describes what the project does, how to install it, and how "
            "to use it. While not a security issue per se, a missing README suggests low "
            "project maturity and makes it harder for contributors to understand security "
            "requirements and safe usage patterns."
        ),
        impact="Informational. Low developer experience quality; harder for users to understand secure usage.",
        remediation=[
            "Create a README.md with at minimum: project description, installation, basic usage.",
            "Include a Security section pointing to SECURITY.md.",
        ],
        examples={},
        references=["https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes"],
        tags=["documentation", "readme", "developer-experience"],
    ),

    "POL-003": _r(
        rule_id="POL-003",
        title="No CONTRIBUTING.md Found",
        category="Policy",
        severity="INFO",
        cwe=[],
        owasp=[],
        description=(
            "The repository does not have a CONTRIBUTING.md file. A contribution guide "
            "documents the development workflow, coding standards, and importantly — "
            "security expectations for contributors (e.g., 'do not commit credentials', "
            "'run security tests before submitting a PR'). Its absence can lead to "
            "contributors accidentally introducing security issues."
        ),
        impact="Low. Increased risk of security anti-patterns from contributors unfamiliar with project standards.",
        remediation=[
            "Create CONTRIBUTING.md with development setup, code style, and security guidelines.",
            "Include a note about running `gitrisk scan .` before submitting pull requests.",
        ],
        examples={},
        references=["https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/setting-guidelines-for-repository-contributors"],
        tags=["documentation", "contributing", "community"],
    ),
}
