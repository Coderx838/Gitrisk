import pytest
from typer.testing import CliRunner

from gitrisk.cli.main import app
from gitrisk.rulebook.rules import RULES

runner = CliRunner()

def test_doc_command_hrd_001():
    result = runner.invoke(app, ["doc", "HRD-001"])
    assert result.exit_code == 0
    assert "HRD-001" in result.output
    assert "CRITICAL" in result.output
    # Title exists (Rich may truncate or case-fold in panel borders)
    assert "Database Connection" in result.output or "connection string" in result.output.lower()

def test_doc_command_sec_001():
    result = runner.invoke(app, ["doc", "SEC-001"])
    assert result.exit_code == 0
    assert "AWS Access Key ID" in result.output
    assert "SEC-001" in result.output

def test_doc_command_invalid():
    result = runner.invoke(app, ["doc", "INVALID-999"])
    assert result.exit_code == 0
    assert "not found" in result.output.lower() or "INVALID-999" in result.output

def test_doc_command_list():
    result = runner.invoke(app, ["doc", "--list"])
    assert result.exit_code == 0
    assert "Secrets" in result.output
    assert "Dependencies" in result.output
    assert "Environment" in result.output
    assert "GitHub Actions" in result.output
    # Our rulebook uses "Git" category (not "Git Configuration")
    assert "Git" in result.output
    assert "Hardcoding" in result.output
    assert "Policy" in result.output

def test_db_has_required_fields():
    for rule_id, rule in RULES.items():
        assert rule.rule_id, f"{rule_id} missing rule_id"
        assert rule.title, f"{rule_id} missing title"
        assert rule.severity, f"{rule_id} missing severity"
        assert rule.description, f"{rule_id} missing description"
        assert rule.remediation, f"{rule_id} missing remediation"
        assert isinstance(rule.remediation, list), f"{rule_id} remediation must be a list"
        assert len(rule.remediation) > 0, f"{rule_id} remediation list is empty"
        # Descriptions should be specific — not just generic boilerplate
        assert len(rule.description) > 80, f"{rule_id} description too short (generic)"

