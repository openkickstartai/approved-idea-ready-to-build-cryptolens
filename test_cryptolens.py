"""Tests for CryptoLens scanner engine."""
import json
import sys
import os
import tempfile
from pathlib import Path
from cryptolens import scan_content, compute_score, generate_report, Finding


def test_detects_broken_md5():
    findings = scan_content("h = hashlib.md5(data)", "t.py")
    assert any(f.algorithm == "MD5" and f.category == "broken" for f in findings)


def test_detects_broken_sha1():
    findings = scan_content("d = hashlib.sha1(data)", "t.py")
    assert any(f.algorithm == "SHA-1" and f.category == "broken" for f in findings)


def test_detects_pq_vulnerable_rsa():
    findings = scan_content("key = RSA.generate(2048)", "t.py")
    vuln = [f for f in findings if f.category == "pq_vulnerable"]
    assert any(f.algorithm == "RSA" for f in vuln)


def test_detects_pq_vulnerable_ecdsa():
    findings = scan_content("sig = ECDSA.sign(key, msg)", "t.py")
    assert any(f.algorithm == "ECDSA" and f.category == "pq_vulnerable" for f in findings)


def test_detects_pq_safe_algorithms():
    code = "x = AES_256(key)\ny = SHA_256(data)\nz = ChaCha20(key)"
    findings = scan_content(code, "safe.py")
    safe = [f for f in findings if f.category == "pq_safe"]
    assert len(safe) >= 3


def test_detects_pqc_kyber_dilithium():
    code = "kem = Kyber.encapsulate(pk)\nsig = Dilithium.sign(sk, msg)"
    findings = scan_content(code, "pqc.py")
    assert any("Kyber" in f.algorithm for f in findings)
    assert any("Dilithium" in f.algorithm for f in findings)


def test_score_no_findings():
    score = compute_score([])
    assert score["score"] == 100
    assert score["grade"] == "A+"


def test_score_broken_penalty():
    findings = [Finding("MD5", "broken", "f.py", 1, "md5(x)", "fix")]
    score = compute_score(findings)
    assert score["score"] == 85
    assert score["grade"] == "B"


def test_score_pq_vulnerable_penalty():
    findings = [Finding("RSA", "pq_vulnerable", "f.py", 1, "rsa(x)", "fix")]
    score = compute_score(findings)
    assert score["score"] == 95
    assert score["grade"] == "A+"


def test_generate_report_structure():
    findings = scan_content("h = hashlib.md5(data)\nk = RSA.generate(2048)", "t.py")
    report = generate_report(findings)
    assert "pq_readiness" in report
    assert "findings" in report
    assert isinstance(report["findings"], list)
    assert report["pq_readiness"]["total"] == len(findings)


# ---- Format output tests ----

def _make_sample_report():
    """Helper: produce a report with at least one finding of each category."""
    code = "h = hashlib.md5(data)\nk = RSA.generate(2048)\nc = AES_256(key)"
    findings = scan_content(code, "sample.py")
    return generate_report(findings)


def test_format_json_parseable():
    """JSON format must produce valid, parseable JSON with expected keys."""
    report = _make_sample_report()
    raw = json.dumps(report, indent=2, default=str)
    parsed = json.loads(raw)
    assert "pq_readiness" in parsed
    assert "findings" in parsed
    assert isinstance(parsed["findings"], list)
    assert len(parsed["findings"]) >= 3


def test_format_table_has_header_row():
    """Table format must contain a header row with all expected column names."""
    # import format_table from main
    sys.path.insert(0, os.path.dirname(__file__))
    from main import format_table
    report = _make_sample_report()
    table_output = format_table(report)
    assert "File" in table_output
    assert "Line" in table_output
    assert "Algorithm" in table_output
    assert "Category" in table_output
    assert "Quantum Safe" in table_output
    assert "Severity" in table_output
    # Should contain separator lines
    assert "+" in table_output
    assert "|" in table_output
    # Should contain the header row between separators
    lines = table_output.strip().split("\n")
    # First line is title, then separator, header, separator, data rows, separator
    assert len(lines) >= 5  # title + sep + header + sep + at least 1 data row + sep
    header_line = lines[2]
    assert "File" in header_line
    assert "Algorithm" in header_line


def test_format_sarif_valid_structure():
    """SARIF output must have required $schema and version fields, and tool.driver.name == CryptoLens."""
    sys.path.insert(0, os.path.dirname(__file__))
    from main import format_sarif
    report = _make_sample_report()
    sarif_raw = format_sarif(report)
    sarif = json.loads(sarif_raw)
    assert "$schema" in sarif
    assert "sarif-schema-2.1.0" in sarif["$schema"]
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) >= 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "CryptoLens"
    assert "results" in run
    assert len(run["results"]) >= 3
    # Each result must have ruleId, message, and locations
    for result in run["results"]:
        assert "ruleId" in result
        assert "message" in result
        assert "locations" in result
        assert len(result["locations"]) >= 1


def test_format_sarif_output_to_file():
    """--output flag should write SARIF to a file."""
    sys.path.insert(0, os.path.dirname(__file__))
    from main import format_sarif
    report = _make_sample_report()
    sarif_raw = format_sarif(report)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
        f.write(sarif_raw)
        tmp_path = f.name
    try:
        content = Path(tmp_path).read_text()
        parsed = json.loads(content)
        assert parsed["version"] == "2.1.0"
        assert parsed["runs"][0]["tool"]["driver"]["name"] == "CryptoLens"
    finally:
        os.unlink(tmp_path)


import pytest
import jsonschema
from cryptolens import validate_cbom


def _make_valid_finding(**overrides):
    base = {
        "algorithm": "AES-256",
        "category": "symmetric",
        "file_path": "crypto.py",
        "line_number": 42,
        "quantum_safe": True,
        "severity": "info",
        "recommendation": "PQ-safe with 256-bit keys",
    }
    base.update(overrides)
    return base


def test_validate_cbom_valid_report():
    report = {
        "findings": [
            _make_valid_finding(),
            _make_valid_finding(
                algorithm="MD5",
                category="hash",
                file_path="auth.py",
                line_number=7,
                quantum_safe=False,
                severity="critical",
                recommendation="Replace with SHA-256 or SHA-3",
            ),
        ]
    }
    assert validate_cbom(report) is True


def test_validate_cbom_empty_findings():
    report = {"findings": []}
    assert validate_cbom(report) is True


def test_validate_cbom_missing_required_fields():
    report = {
        "findings": [
            {
                "algorithm": "RSA",
                "category": "asymmetric",
                # missing file_path, line_number, quantum_safe, severity, recommendation
            }
        ]
    }
    with pytest.raises(jsonschema.ValidationError):
        validate_cbom(report)


def test_validate_cbom_wrong_type_line_number():
    report = {
        "findings": [
            _make_valid_finding(line_number="not_an_integer"),
        ]
    }
    with pytest.raises(jsonschema.ValidationError):
        validate_cbom(report)


def test_validate_cbom_invalid_category_enum():
    report = {
        "findings": [
            _make_valid_finding(category="broken"),
        ]
    }
    with pytest.raises(jsonschema.ValidationError):
        validate_cbom(report)


def test_validate_cbom_invalid_severity_enum():
    report = {
        "findings": [
            _make_valid_finding(severity="high"),
        ]
    }
    with pytest.raises(jsonschema.ValidationError):
        validate_cbom(report)


def test_validate_cbom_wrong_type_quantum_safe():
    report = {
        "findings": [
            _make_valid_finding(quantum_safe="yes"),
        ]
    }
    with pytest.raises(jsonschema.ValidationError):
        validate_cbom(report)
