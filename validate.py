#!/usr/bin/env python3
"""
Validate generated Sigma rules using sigma-cli.

Usage:
    python validate.py [--output-dir ./output] [--verbose]
"""

import subprocess
import sys
import os
import argparse
import json
from collections import Counter


def main():
    parser = argparse.ArgumentParser(description="Validate generated Sigma rules")
    parser.add_argument("--output-dir", default="./output", help="Sigma rules directory")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not os.path.isdir(args.output_dir):
        print(f"ERROR: Output directory not found: {args.output_dir}")
        sys.exit(1)

    # Measure total rules
    total = 0
    for root, dirs, files in os.walk(args.output_dir):
        for f in files:
            if f.endswith(".yml"):
                total += 1

    print(f"Validating {total} Sigma rules in {args.output_dir}...")

    # Run sigma check
    result = subprocess.run(
        ["sigma", "check", args.output_dir, "-E", "-I"],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        print(f"FATAL: sigma check returned code {result.returncode}")
        print(result.stderr)
        sys.exit(1)

    # Parse issues
    issue_counts = Counter()
    issue_details = {}
    parse_errors = 0
    parse_fails = []

    for line in result.stdout.strip().split("\n"):
        if not line.startswith("issue="):
            if "Parsing Sigma rules" in line or "Checking Sigma rules" in line:
                continue
            continue

        # Parse: issue=Type severity=X description=... rule=... ...
        parts = {}
        for part in line.split():
            if "=" in part:
                key, val = part.split("=", 1)
                parts[key] = val

        issue_type = parts.get("issue", "unknown")
        severity = parts.get("severity", "unknown")
        rule = parts.get("rule", "")

        issue_counts[(issue_type, severity)] += 1

        if issue_type not in issue_details:
            issue_details[issue_type] = {
                "count": 0,
                "severity": severity,
                "example_rule": rule,
                "example_full": line[:300],
            }
        issue_details[issue_type]["count"] += 1

    # Summary
    print(f"\n{'='*60}")
    print(f"VALIDATION RESULTS")
    print(f"{'='*60}")
    print(f"  Rules checked:  {total}")
    print(f"  Parse errors:   {parse_errors}")
    print(f"  Issues found:   {sum(issue_counts.values())}")

    if issue_counts:
        print(f"\n  Issues by type:")
        for (issue_type, severity), count in issue_counts.most_common():
            pct = count / max(total, 1) * 100
            print(f"    [{severity}] {issue_type}: {count} ({pct:.1f}%)")

        # Show examples
        if args.verbose:
            print(f"\n  Issue examples:")
            for itype, detail in sorted(issue_details.items()):
                print(f"\n  --- {itype} ({detail['count']}x) ---")
                print(f"    Example: {os.path.basename(detail['example_rule'])}")
                print(f"    {detail['example_full'][:200]}")

    # Determine pass/fail
    high_issues = sum(c for (t, s), c in issue_counts.items() if s == "high")
    med_issues = sum(c for (t, s), c in issue_counts.items() if s == "medium")

    if high_issues > 0:
        print(f"\n  RESULT: FAIL ({high_issues} high-severity issues)")
        sys.exit(1)
    elif med_issues > 0:
        print(f"\n  RESULT: PASS with warnings ({med_issues} medium-severity issues)")
    else:
        print(f"\n  RESULT: PASS (no issues)")

    # Write detailed report
    report = {
        "total_rules": total,
        "parse_errors": parse_errors,
        "parse_fails": parse_fails,
        "issues": {str(k): v for k, v in issue_counts.items()},
    }
    with open("validation_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"  Report: validation_report.json")


if __name__ == "__main__":
    main()
