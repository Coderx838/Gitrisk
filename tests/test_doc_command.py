import pytest
from typer.testing import CliRunner

from gitrisk.cli.main import app
from gitrisk.rulebook.rules import RULES

runner = CliRunner()

def test_doc_command_hrd_001():
    result = runner.invoke(app, ["doc", "HRD-001"])
    assert result.exit_code == 0
    assert "Hardcoded database connection string" in result.output
    assert "HRD-001" in result.output
    assert "CRITICAL" in result.output

def test_doc_command_sec_001():
    result = runner.invoke(app, ["doc", "SEC-001"])
    assert result.exit_code == 0
    assert "AWS Access Key ID" in result.output
    assert "SEC-001" in result.output

def test_doc_command_invalid():
    result = runner.invoke(app, ["doc", "INVALID-999"])
    assert result.exit_code == 0
    assert "Rule 'INVALID-999' not found" in result.output

def test_doc_command_list():
    result = runner.invoke(app, ["doc", "--list"])
    assert result.exit_code == 0
    assert "Secrets" in result.output
    assert "Dependencies" in result.output
    assert "Environment" in result.output
    assert "GitHub Actions" in result.output
    assert "Git Configuration" in result.output
    assert "Hardcoding" in result.output
    assert "Policy" in result.output

def test_db_has_required_fields():
    for rule_id, rule in RULES.items():
        assert rule.rule_id
        assert rule.title
        assert rule.severity
        assert rule.description
        assert rule.remediation
        assert isinstance(rule.remediation, list)
        assert len(rule.remediation) > 0
