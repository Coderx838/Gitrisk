"""Tests for GitRisk SEI (Secret Intelligence Engine)."""
from pathlib import Path
from gitrisk.sei.engine import SecretIntelligenceEngine
from gitrisk.sei.payload import inspect_payload_bytes
from gitrisk.sei.reconstructor import reconstruct_tokens
from gitrisk.sei.topology import analyze_file_topology, RegionType


def test_sei_suppresses_svg_base64_image():
    sei = SecretIntelligenceEngine()
    # Emulate an SVG file with embedded Base64 raster data that randomly contains 'AIza...'
    svg_line = '<image xlink:href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIzaSy1234567890abcdefghijklmnopqrstuvwxyz"/>'
    findings = sei.evaluate_line(
        line=svg_line,
        line_number=10,
        filepath=Path("banner.svg"),
    )
    # Must be 0 findings because topology marks it as media and magic bytes detect PNG header
    assert len(findings) == 0


def test_sei_detects_real_google_key_in_code():
    sei = SecretIntelligenceEngine()
    code_line = 'GOOGLE_API_KEY = "AIzaSyB8n9X0abcdefghijklmnopqrstuvwxyz1"'
    findings = sei.evaluate_line(
        line=code_line,
        line_number=5,
        filepath=Path("config.py"),
    )
    assert len(findings) == 1
    assert findings[0].id == "SEC-008"


def test_sei_reconstructs_split_tokens():
    sei = SecretIntelligenceEngine()
    split_line = 'API_KEY = "AIzaSyB8n9X0abcdef" + "ghijklmnopqrstuvwxyz1"'
    findings = sei.evaluate_line(
        line=split_line,
        line_number=15,
        filepath=Path("app.py"),
    )
    assert len(findings) == 1
    assert findings[0].id == "SEC-008"


def test_sei_suppresses_unquoted_code_variables():
    sei = SecretIntelligenceEngine()
    cases = [
        "self.gemini_api_key = gemini_api_key",
        "self.brain = LLMBrain(api_key=gemini_api_key)",
        "api_key = api_key.strip()",
        "self.api_key = gemini_api_key or load_api_key()",
    ]
    for line in cases:
        findings = sei.evaluate_line(
            line=line,
            line_number=1,
            filepath=Path("controller.py"),
        )
        assert len(findings) == 0, f"Expected 0 findings for '{line}', got {findings}"


def test_sei_inspects_payload_magic_bytes():
    # PNG header in base64: iVBORw0KGgo=
    res = inspect_payload_bytes("iVBORw0KGgoAAAANSUhEUgAA")
    assert res.is_media_or_binary is True
    assert res.mime_type == "image/png"

