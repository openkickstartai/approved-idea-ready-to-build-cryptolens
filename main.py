#!/usr/bin/env python3
"""CryptoLens CLI — scan code for cryptographic usage & PQ migration readiness."""
import argparse
import json
import sys
from pathlib import Path
from cryptolens import scan_path, generate_report

COLORS = {"broken": "\033[91m", "pq_vulnerable": "\033[93m", "pq_safe": "\033[92m", "end": "\033[0m"}
LABELS = {"broken": "BROKEN", "pq_vulnerable": "PQ-VULN", "pq_safe": "PQ-SAFE"}


def fmt_tag(category, no_color=False):
    label = f"[{LABELS.get(category, category)}]"
    if no_color:
        return label
    return f"{COLORS.get(category, '')}{label}{COLORS['end']}"


def main():
    parser = argparse.ArgumentParser(prog="cryptolens", description="CryptoLens: crypto scanner & PQ readiness assessor")
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Output JSON report")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--fail-under", type=int, default=0, help="Exit 1 if score below threshold")
    args = parser.parse_args()

    target = Path(args.target)
    if not target.exists():
        print(f"Error: path '{args.target}' not found.", file=sys.stderr)
        sys.exit(2)

    findings = scan_path(args.target)
    report = generate_report(findings)
    pq = report["pq_readiness"]

    if args.as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"\n\U0001f52c CryptoLens Scan Report")
        print("=" * 50)
        print(f"  PQ Readiness Score: {pq['score']}/100 (Grade: {pq['grade']})")
        print(f"  Total: {pq['total']} | Broken: {pq['broken']} | PQ-Vulnerable: {pq['pq_vulnerable']} | PQ-Safe: {pq['pq_safe']}")
        print("=" * 50)
        if findings:
            for f in findings:
                print(f"  {fmt_tag(f.category, args.no_color)} {f.file}:{f.line} {f.algorithm} \u2014 {f.snippet}")
            seen = set()
            recs = [(f.algorithm, f.recommendation) for f in findings if f.category != "pq_safe"]
            print("\n  Recommendations:")
            for algo, rec in recs:
                if algo not in seen:
                    seen.add(algo)
                    print(f"    \u26a0  {algo}: {rec}")
        else:
            print("  \u2705 No cryptographic usage detected.")
        print()

    if pq["score"] < args.fail_under:
        sys.exit(1)


if __name__ == "__main__":
    main()
