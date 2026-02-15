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


def format_table(report):
    """Format report as a human-readable ASCII table using only stdlib."""
    findings = report["findings"]
    pq = report["pq_readiness"]

    headers = ["File", "Line", "Algorithm", "Category", "Quantum Safe", "Severity"]

    severity_map = {"broken": "HIGH", "pq_vulnerable": "MEDIUM", "pq_safe": "LOW"}
    quantum_safe_map = {"broken": "No", "pq_vulnerable": "No", "pq_safe": "Yes"}

    rows = []
    for f in findings:
        rows.append([
            f["file"],
            str(f["line"]),
            f["algorithm"],
            f["category"],
            quantum_safe_map.get(f["category"], "Unknown"),
            severity_map.get(f["category"], "Unknown"),
        ])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    def format_row(cells):
        return "| " + " | ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(cells)) + " |"

    separator = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"

    lines = []
    lines.append(f"CryptoLens Scan Report \u2014 Score: {pq['score']}/100 (Grade: {pq['grade']})")
    lines.append(separator)
    lines.append(format_row(headers))
    lines.append(separator)
    for row in rows:
        lines.append(format_row(row))
    lines.append(separator)

    return "\n".join(lines)


def format_sarif(report):
    """Format report as SARIF v2.1.0 JSON for GitHub Code Scanning."""
    findings = report["findings"]

    severity_map = {"broken": "error", "pq_vulnerable": "warning", "pq_safe": "note"}

    results = []
    rules = {}
    for f in findings:
        rule_id = "crypto-" + f["algorithm"].lower().replace("/", "-").replace(" ", "-")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f"{f['algorithm']} usage detected"},
                "helpUri": "https://github.com/cryptolens/cryptolens",
            }

        result = {
            "ruleId": rule_id,
            "level": severity_map.get(f["category"], "note"),
            "message": {
                "text": f"{f['algorithm']} ({f['category']}): {f['recommendation']}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": f["line"]},
                    }
                }
            ],
        }
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CryptoLens",
                        "version": "1.0.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def main():
    parser = argparse.ArgumentParser(
        prog="cryptolens",
        description="CryptoLens: crypto scanner & PQ readiness assessor",
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument(
        "--format", "-f",
        choices=["json", "table", "sarif"],
        default="json",
        help="Output format: json (CBOM JSON, default), table (ASCII table), sarif (SARIF v2.1.0)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write output to file instead of stdout",
    )
    parser.add_argument("--json", dest="as_json", action="store_true", help="Output JSON report (legacy, same as --format json)")
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

    fmt = args.format
    if args.as_json:
        fmt = "json"

    if fmt == "json":
        output_text = json.dumps(report, indent=2, default=str)
    elif fmt == "table":
        output_text = format_table(report)
    elif fmt == "sarif":
        output_text = format_sarif(report)
    else:
        output_text = json.dumps(report, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(output_text + "\n")
    else:
        print(output_text)

    if args.fail_under and pq["score"] < args.fail_under:
        sys.exit(1)


if __name__ == "__main__":
    main()
