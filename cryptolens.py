"""CryptoLens — core scanning engine for cryptographic usage detection."""
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict



@dataclass
class Finding:
    algorithm: str
    category: str
    file: str
    line: int
    snippet: str
    recommendation: str


PATTERNS = [
    (r"\bmd5\b", "broken", "MD5", "Replace with SHA-256 or SHA-3"),
    (r"\bsha[-_]?1\b", "broken", "SHA-1", "Replace with SHA-256 or SHA-3"),
    (r"\b(3des|triple.?des|desede)\b", "broken", "3DES", "Replace with AES-256"),
    (r"\brc4\b", "broken", "RC4", "Replace with AES-256-GCM"),
    (r"\bblowfish\b", "broken", "Blowfish", "Replace with AES-256"),
    (r"\brsa\b", "pq_vulnerable", "RSA", "Migrate to ML-KEM (Kyber) / ML-DSA (Dilithium)"),
    (r"\becdsa\b", "pq_vulnerable", "ECDSA", "Migrate to ML-DSA (Dilithium)"),
    (r"\becdh\b", "pq_vulnerable", "ECDH", "Migrate to ML-KEM (Kyber)"),
    (r"\bed25519\b", "pq_vulnerable", "Ed25519", "Migrate to ML-DSA (Dilithium)"),
    (r"\bdiffie.?hellman\b", "pq_vulnerable", "DH", "Migrate to ML-KEM (Kyber)"),
    (r"\baes[-_]?256\b", "pq_safe", "AES-256", "PQ-safe with 256-bit keys"),
    (r"\bsha[-_]?256\b", "pq_safe", "SHA-256", "PQ-safe"),
    (r"\bsha[-_]?384\b", "pq_safe", "SHA-384", "PQ-safe"),
    (r"\bsha[-_]?512\b", "pq_safe", "SHA-512", "PQ-safe"),
    (r"\bchacha20\b", "pq_safe", "ChaCha20", "PQ-safe"),
    (r"\bargon2\b", "pq_safe", "Argon2", "PQ-safe"),
    (r"\bkyber\b", "pq_safe", "ML-KEM/Kyber", "PQ-safe, NIST standardized"),
    (r"\bdilithium\b", "pq_safe", "ML-DSA/Dilithium", "PQ-safe, NIST standardized"),
]

EXTENSIONS = {
    ".py", ".rs", ".go", ".java", ".js", ".ts", ".c", ".cpp",
    ".h", ".rb", ".cs", ".toml", ".yml", ".yaml", ".xml", ".cfg",
}
def scan_content(content: str, filepath: str) -> List[Finding]:
    """Scan source code content for cryptographic algorithm usage."""
    findings = []
    lines = content.split("\n")
    for line_num, line_text in enumerate(lines, start=1):
        lower = line_text.lower()
        for pattern, category, algo_name, recommendation in PATTERNS:
            if re.search(pattern, lower):
                findings.append(Finding(
                    algorithm=algo_name,
                    category=category,
                    file=filepath,
                    line=line_num,
                    snippet=line_text.strip(),
                    recommendation=recommendation,
                ))
    return findings


def scan_path(target: str) -> List[Finding]:
    """Scan a file or directory tree for cryptographic usage."""
    findings = []
    p = Path(target)
    if p.is_file():
        if p.suffix in EXTENSIONS:
            findings.extend(scan_content(p.read_text(errors="ignore"), str(p)))
    elif p.is_dir():
        for child in sorted(p.rglob("*")):
            if child.is_file() and child.suffix in EXTENSIONS:
                findings.extend(scan_content(child.read_text(errors="ignore"), str(child)))
    return findings


CATEGORY_WEIGHTS = {"broken": -15, "pq_vulnerable": -10, "pq_safe": 0}
GRADE_THRESHOLDS = [(97, "A+"), (90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def _grade(score: int) -> str:
    """Map numeric score to letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def compute_score(findings: List[Finding]) -> Dict:
    """Compute PQ readiness score from a list of Finding objects."""
    total = len(findings)
    broken = sum(1 for f in findings if f.category == "broken")
    pq_vulnerable = sum(1 for f in findings if f.category == "pq_vulnerable")
    pq_safe = sum(1 for f in findings if f.category == "pq_safe")

    if total == 0:
        score = 100
    else:
        score = 100
        for f in findings:
            score += CATEGORY_WEIGHTS.get(f.category, 0)
        score = max(0, min(100, score))

    grade = _grade(score)
    return {
        "score": score,
        "grade": grade,
        "total": total,
        "broken": broken,
        "pq_vulnerable": pq_vulnerable,
        "pq_safe": pq_safe,
    }


def generate_report(findings: List[Finding]) -> Dict:
    """Generate a full scan report including PQ readiness assessment."""
    pq = compute_score(findings)
    return {
        "pq_readiness": pq,
        "findings": [asdict(f) for f in findings],
    }


def calculate_pq_readiness(findings: list[dict]) -> dict:
    """Calculate post-quantum migration readiness score from crypto findings.

    Args:
        findings: List of dicts, each with at least 'quantum_safe' (bool)
                  and 'category' (str, e.g. 'asymmetric', 'symmetric', 'hash').

    Returns:
        Dict with score (0-100), total_findings, quantum_safe_count,
        quantum_unsafe_count, critical_items, and summary.
    """
    total_findings = len(findings)
    quantum_safe_count = sum(1 for f in findings if f.get("quantum_safe", False))
    quantum_unsafe_count = total_findings - quantum_safe_count

    critical_items = [
        f for f in findings
        if not f.get("quantum_safe", False) and f.get("category") == "asymmetric"
    ]

    if total_findings == 0:
        score = 100
    else:
        score = round((quantum_safe_count / total_findings) * 100)
        score -= 10 * len(critical_items)
        score = max(0, score)

    summary = (
        f"Your codebase has {len(critical_items)} quantum-unsafe asymmetric "
        f"usages that require migration"
    )

    return {
        "score": score,
        "total_findings": total_findings,
        "quantum_safe_count": quantum_safe_count,
        "quantum_unsafe_count": quantum_unsafe_count,
        "critical_items": critical_items,
        "summary": summary,
    }

    }


def validate_cbom(report: dict) -> bool:
    """Validate a CBOM report dict against the CBOM JSON schema.

    Returns True if valid. Raises jsonschema.ValidationError if malformed.
    """
    import jsonschema

    schema_path = Path(__file__).parent / "cbom_schema.json"
    with open(schema_path, "r") as f:
        schema = json.load(f)
    jsonschema.validate(instance=report, schema=schema)
    return True
