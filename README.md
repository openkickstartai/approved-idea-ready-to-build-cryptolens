# 🔬 CryptoLens

**Cryptographic Usage Scanner & Post-Quantum Migration Readiness Assessor**

CryptoLens scans your codebase for cryptographic algorithm usage, classifies each finding
by post-quantum security status, and produces a migration readiness score.

## Features

- Pattern-based scanning of 18+ crypto algorithms across Python, Rust, Go, Java, C/C++, JS/TS
- Three-tier classification: **Broken**, **PQ-Vulnerable**, **PQ-Safe**
- PQ Readiness Score (0–100) with letter grade
- CBOM-style JSON reports for CI/CD integration
- `--fail-under` threshold for pipeline gates

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Scan a directory
python main.py ./src

# JSON report
python main.py ./src --json

# CI gate: fail if score < 70
python main.py ./src --fail-under 70

# Disable colors
python main.py ./src --no-color
```

## Example Output

```
🔬 CryptoLens Scan Report
==================================================
  PQ Readiness Score: 80/100 (Grade: B)
  Total findings: 3 | Broken: 1 | PQ-Vulnerable: 1 | PQ-Safe: 1
==================================================
  [BROKEN] src/auth.py:12 MD5 — h = hashlib.md5(password)
  [PQ-VULN] src/tls.py:8 RSA — key = RSA.generate(2048)
  [PQ-SAFE] src/enc.py:5 AES-256 — cipher = AES_256_GCM(key)

  Recommendations:
    ⚠  MD5: Replace with SHA-256 or SHA-3
    ⚠  RSA: Migrate to ML-KEM (Kyber) / ML-DSA (Dilithium)
```

## Detected Algorithms

| Category | Algorithms |
|---|---|
| **Broken** | MD5, SHA-1, 3DES, RC4, Blowfish |
| **PQ-Vulnerable** | RSA, ECDSA, ECDH, Ed25519, Diffie-Hellman |
| **PQ-Safe** | AES-256, SHA-256/384/512, ChaCha20, Argon2, Kyber, Dilithium |

## Testing

```bash
pytest test_cryptolens.py -v
```

## License

MIT
