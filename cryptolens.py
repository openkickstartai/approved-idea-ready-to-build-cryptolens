"""CryptoLens — core scanning engine for cryptographic usage detection."""
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
    findings = []
    for i, line in enumerate(content.split("\n"), 1):
        for regex, cat, algo, rec in PATTERNS:
            if re.search(regex, line, re.IGNORECASE):
                findings.append(Finding(algo, cat, filepath, i, line.strip()[:120], rec))
    return findings


def scan_path(target: str) -> List[Finding]:
    p = Path(target)
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = [f for f in p.rglob("*") if f.suffix in EXTENSIONS and f.is_file()]
    else:
        return []
    results = []
    for f in files:
        try:
            results.extend(scan_content(f.read_text(errors="ignore"), str(f)))
        except (OSError, PermissionError):
            continue
    return results


def compute_score(findings: List[Finding]) -> Dict:
    if not findings:
        return {"score": 100, "grade": "A+", "broken": 0, "pq_vulnerable": 0, "pq_safe": 0, "total": 0}
    b = sum(1 for f in findings if f.category == "broken")
    v = sum(1 for f in findings if f.category == "pq_vulnerable")
    s = sum(1 for f in findings if f.category == "pq_safe")
    score = max(0, min(100, 100 - b * 15 - v * 5))
    grade = next(g for t, g in [(90, "A"), (70, "B"), (50, "C"), (30, "D"), (0, "F")] if score >= t)
    return {"score": score, "grade": grade, "broken": b, "pq_vulnerable": v, "pq_safe": s, "total": len(findings)}


def generate_report(findings: List[Finding]) -> Dict:
    algos = {}
    for f in findings:
        if f.algorithm not in algos:
            algos[f.algorithm] = {"category": f.category, "count": 0, "files": set(), "recommendation": f.recommendation}
        algos[f.algorithm]["count"] += 1
        algos[f.algorithm]["files"].add(f.file)
    for v in algos.values():
        v["files"] = sorted(v["files"])
    return {
        "version": "0.1.0",
        "pq_readiness": compute_score(findings),
        "algorithms": algos,
        "findings": [asdict(f) for f in findings],
    }
