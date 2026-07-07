#!/usr/bin/env python3
"""
Splunk Security Content → Sigma Rule Converter

Reads detection rules from the Splunk security_content repository,
parses their SPL search expressions, and converts applicable rules
to Sigma format.

Usage:
    python main.py [--input-dir DIR] [--output-dir DIR] [--limit N]
"""

import os
import sys
import json
import glob
import argparse
import traceback
import yaml

from spl_parser import parse_spl
from macro_resolver import MacroResolver
from classifier import classify_detection
from sigma_generator import SigmaGenerator


def main():
    parser = argparse.ArgumentParser(
        description="Convert Splunk security_content detections to Sigma rules"
    )
    parser.add_argument(
        "--input-dir",
        default="/tmp/security_content/detections",
        help="Path to security_content/detections directory",
    )
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Output directory for Sigma rules",
    )
    parser.add_argument(
        "--macro-dir",
        default="/tmp/security_content/macros",
        help="Path to security_content/macros directory",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit processing to N detections (0 = all)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    args = parser.parse_args()

    # Verify input directory exists
    if not os.path.isdir(args.input_dir):
        print(f"ERROR: Input directory not found: {args.input_dir}")
        print("Clone the repo first: git clone https://github.com/splunk/security_content.git /tmp/security_content")
        sys.exit(1)

    # Load macros
    print(f"Loading macros from {args.macro_dir}...")
    macro_resolver = MacroResolver(args.macro_dir)
    print(f"  Loaded {len(macro_resolver.macros)} macros")

    # Initialize Sigma generator
    generator = SigmaGenerator(macro_resolver)

    # Find all detection YAML files
    print(f"Finding detection files in {args.input_dir}...")
    detection_files = sorted(glob.glob(
        os.path.join(args.input_dir, "**/*.yml"), recursive=True
    ))
    print(f"  Found {len(detection_files)} detection files")

    if args.limit > 0:
        detection_files = detection_files[:args.limit]
        print(f"  Limited to {args.limit} files")

    # Process detections
    stats = {
        "total": 0,
        "converted": 0,
        "skipped": 0,
        "errors": 0,
        "skipped_reasons": {},
        "converted_files": [],
        "error_files": [],
    }

    for i, filepath in enumerate(detection_files):
        stats["total"] += 1
        relative_path = os.path.relpath(filepath, args.input_dir)
        rule_name = os.path.splitext(os.path.basename(filepath))[0]

        if i % 100 == 0:
            print(f"  Progress: {i}/{len(detection_files)} ({stats['converted']} converted, {stats['skipped']} skipped, {stats['errors']} errors)")

        try:
            # Load detection YAML
            with open(filepath) as f:
                detection = yaml.safe_load(f)

            if not detection or "search" not in detection:
                stats["skipped"] += 1
                _inc_reason(stats, "No search field")
                continue

            search_str = detection["search"]
            if not search_str or not search_str.strip():
                stats["skipped"] += 1
                _inc_reason(stats, "Empty search")
                continue

            # Parse the SPL
            try:
                ast = parse_spl(search_str)
            except Exception as e:
                if args.verbose:
                    print(f"  SKIP {rule_name}: SPL parse error: {e}")
                stats["skipped"] += 1
                _inc_reason(stats, f"SPL parse error: {str(e)[:80]}")
                continue

            # Classify
            is_convertible, reason, info = classify_detection(ast, macro_resolver)

            if not is_convertible:
                if args.verbose:
                    print(f"  SKIP {rule_name}: {reason}")
                stats["skipped"] += 1
                _inc_reason(stats, reason)
                continue

            # Generate Sigma rule
            output_path = generator.generate(
                detection, ast, info, args.output_dir
            )

            if output_path:
                stats["converted"] += 1
                stats["converted_files"].append({
                    "source": relative_path,
                    "output": os.path.relpath(output_path, args.output_dir),
                    "title": detection.get("name", ""),
                })
                if args.verbose:
                    print(f"  CONV {rule_name} -> {os.path.relpath(output_path, args.output_dir)}")
            else:
                stats["skipped"] += 1
                _inc_reason(stats, "No conditions extracted")

        except Exception as e:
            if args.verbose:
                print(f"  ERROR {rule_name}: {e}")
                traceback.print_exc()
            stats["errors"] += 1
            stats["error_files"].append({
                "source": relative_path,
                "error": str(e),
            })

    # Write skipped/error report
    _write_report(stats, args.output_dir)

    # Print summary
    print(f"\n{'='*60}")
    print(f"CONVERSION SUMMARY")
    print(f"{'='*60}")
    print(f"  Total detections:     {stats['total']}")
    print(f"  Converted to Sigma:   {stats['converted']} ({_pct(stats['converted'], stats['total'])})")
    print(f"  Skipped (not suitable): {stats['skipped']} ({_pct(stats['skipped'], stats['total'])})")
    print(f"  Errors:               {stats['errors']} ({_pct(stats['errors'], stats['total'])})")

    print(f"\n  Skip reasons (top 10):")
    for reason, count in sorted(stats["skipped_reasons"].items(),
                                 key=lambda x: -x[1])[:10]:
        print(f"    {reason}: {count}")

    print(f"\n  Output directory: {args.output_dir}")
    print(f"  Converted rules: {len(stats['converted_files'])}")


def _inc_reason(stats: dict, reason: str):
    """Increment a skip reason counter."""
    if reason not in stats["skipped_reasons"]:
        stats["skipped_reasons"][reason] = 0
    stats["skipped_reasons"][reason] += 1


def _pct(part: int, total: int) -> str:
    """Calculate percentage."""
    if total == 0:
        return "0.0%"
    return f"{part / total * 100:.1f}%"


def _write_report(stats: dict, output_dir: str):
    """Write the conversion report as JSON (to project root, not output dir)."""
    report_path = "conversion_report.json"
    report = {
        "summary": {
            "total": stats["total"],
            "converted": stats["converted"],
            "skipped": stats["skipped"],
            "errors": stats["errors"],
            "conversion_rate": _pct(stats["converted"], stats["total"]),
        },
        "skip_reasons": dict(sorted(
            stats["skipped_reasons"].items(), key=lambda x: -x[1]
        )),
        "converted": stats["converted_files"][:500],  # truncate for readability
        "errors": stats["error_files"][:100],
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  Report written to: {report_path}")


if __name__ == "__main__":
    main()
