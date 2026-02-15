"""Tests for CryptoLens scanner engine."""
from cryptolens import scan_content, compute_score, generate_report, Finding, calculate_pq_readiness



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
    findings = [Finding("RSA", "pq_vulnerable", "f.py", 1, "RSA()", "migrate")]
    score = compute_score(findings)
    assert score["score"] == 95
    assert score["grade"] == "A"


def test_score_mixed_findings():
    findings = [
        Finding("MD5", "broken", "f.py", 1, "md5", "fix"),
        Finding("RSA", "pq_vulnerable", "f.py", 2, "rsa", "migrate"),
        Finding("AES-256", "pq_safe", "f.py", 3, "aes", "ok"),
    ]
    score = compute_score(findings)
    assert score["score"] == 80
    assert score["grade"] == "B"


def test_report_structure():
    findings = scan_content("h = MD5(data)\nk = RSA.gen(2048)", "t.py")
    report = generate_report(findings)
    assert "version" in report
    assert "pq_readiness" in report
    assert "algorithms" in report
    assert "findings" in report
    assert report["pq_readiness"]["total"] >= 2


def test_empty_content_returns_nothing():
    assert scan_content("", "empty.py") == []
    score = compute_score([])
    assert score["score"] == 100


def test_snippet_truncated_to_120_chars():
    line = "x = MD5(" + "a" * 200 + ")"
    findings = scan_content(line, "t.py")
    assert len(findings) > 0
    assert len(findings[0].snippet) <= 120


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


# === Tests for calculate_pq_readiness ===

def test_pq_readiness_empty_input():
    """Empty findings should return perfect score of 100."""
    result = calculate_pq_readiness([])
    assert result["score"] == 100
    assert result["total_findings"] == 0
    assert result["quantum_safe_count"] == 0
    assert result["quantum_unsafe_count"] == 0
    assert result["critical_items"] == []


def test_pq_readiness_all_safe():
    """All quantum-safe findings should yield score=100."""
    findings = [
        {"algorithm": "AES-256", "category": "symmetric", "quantum_safe": True},
        {"algorithm": "SHA-256", "category": "hash", "quantum_safe": True},
        {"algorithm": "ML-KEM/Kyber", "category": "asymmetric", "quantum_safe": True},
    ]
    result = calculate_pq_readiness(findings)
    assert result["score"] == 100
    assert result["quantum_safe_count"] == 3
    assert result["quantum_unsafe_count"] == 0
    assert result["critical_items"] == []


def test_pq_readiness_all_unsafe_asymmetric():
    """All unsafe asymmetric findings: score should floor at 0."""
    findings = [
        {"algorithm": "RSA", "category": "asymmetric", "quantum_safe": False},
        {"algorithm": "ECDSA", "category": "asymmetric", "quantum_safe": False},
    ]
    result = calculate_pq_readiness(findings)
    # round(0/2 * 100) = 0, then -10*2 = -20, floor at 0
    assert result["score"] == 0
    assert result["quantum_safe_count"] == 0
    assert result["quantum_unsafe_count"] == 2
    assert len(result["critical_items"]) == 2


def test_pq_readiness_mixed_input():
    """Mixed safe/unsafe with one critical asymmetric item."""
    findings = [
        {"algorithm": "AES-256", "category": "symmetric", "quantum_safe": True},
        {"algorithm": "RSA", "category": "asymmetric", "quantum_safe": False},
        {"algorithm": "SHA-256", "category": "hash", "quantum_safe": True},
    ]
    result = calculate_pq_readiness(findings)
    # round(2/3 * 100) = 67, then -10*1 = 57
    assert result["score"] == 57
    assert result["total_findings"] == 3
    assert result["quantum_safe_count"] == 2
    assert result["quantum_unsafe_count"] == 1
    assert len(result["critical_items"]) == 1
    assert result["critical_items"][0]["algorithm"] == "RSA"


def test_pq_readiness_single_safe_finding():
    """Single safe finding should yield score=100."""
    findings = [{"algorithm": "AES-256", "category": "symmetric", "quantum_safe": True}]
    result = calculate_pq_readiness(findings)
    assert result["score"] == 100
    assert result["total_findings"] == 1
    assert result["quantum_safe_count"] == 1
    assert result["quantum_unsafe_count"] == 0


def test_pq_readiness_single_unsafe_asymmetric():
    """Single unsafe asymmetric finding: score floors at 0."""
    findings = [{"algorithm": "RSA", "category": "asymmetric", "quantum_safe": False}]
    result = calculate_pq_readiness(findings)
    # round(0/1 * 100) = 0, then -10*1 = -10, floor at 0
    assert result["score"] == 0
    assert len(result["critical_items"]) == 1


def test_pq_readiness_critical_items_only_asymmetric():
    """critical_items must only contain asymmetric findings, not hash/symmetric."""
    findings = [
        {"algorithm": "MD5", "category": "hash", "quantum_safe": False},
        {"algorithm": "3DES", "category": "symmetric", "quantum_safe": False},
        {"algorithm": "RSA", "category": "asymmetric", "quantum_safe": False},
        {"algorithm": "AES-256", "category": "symmetric", "quantum_safe": True},
    ]
    result = calculate_pq_readiness(findings)
    assert len(result["critical_items"]) == 1
    assert result["critical_items"][0]["algorithm"] == "RSA"
    assert result["quantum_unsafe_count"] == 3


def test_pq_readiness_unsafe_non_asymmetric_no_extra_penalty():
    """Unsafe non-asymmetric findings reduce base score but no extra -10 penalty."""
    findings = [
        {"algorithm": "MD5", "category": "hash", "quantum_safe": False},
    ]
    result = calculate_pq_readiness(findings)
    # round(0/1 * 100) = 0, no critical items so no extra penalty
    assert result["score"] == 0
    assert result["critical_items"] == []


def test_pq_readiness_summary_message():
    """Summary string should contain the count of critical asymmetric items."""
    findings = [
        {"algorithm": "RSA", "category": "asymmetric", "quantum_safe": False},
        {"algorithm": "ECDSA", "category": "asymmetric", "quantum_safe": False},
        {"algorithm": "ECDH", "category": "asymmetric", "quantum_safe": False},
    ]
    result = calculate_pq_readiness(findings)
    assert "3 quantum-unsafe asymmetric usages that require migration" in result["summary"]
