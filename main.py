#!/usr/bin/env python3
"""
Splunk Security Content → Sigma Rule Converter.

Reads detection rules one at a time from disk, parses SPL, and converts
applicable rules to Sigma format. Uses streaming I/O — never loads all
files into memory at once.

Usage:
    python main.py [--input-dir DIR] [--output-dir DIR] [--limit N]
"""

import os
import sys
import gc
import json
import argparse
import traceback

import yaml

from spl_parser import parse_spl
from macro_resolver import MacroResolver
from classifier import classify_detection
from sigma_generator import SigmaGenerator


def _walk_yml_files(root_dir: str, limit: int = 0):
    """Generator: yield YAML file paths one at a time. Never builds a full list."""
    count = 0
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in sorted(filenames):
            if fn.endswith(".yml"):
                yield os.path.join(dirpath, fn)
                count += 1
                if limit > 0 and count >= limit:
                    return


def main():
    p = argparse.ArgumentParser(
        description="Convert Splunk security_content detections to Sigma rules"
    )
    p.add_argument("--input-dir", default="/tmp/security_content/detections",
                   help="Path to security_content/detections directory")
    p.add_argument("--output-dir", default="./output",
                   help="Output directory for Sigma rules")
    p.add_argument("--macro-dir", default="/tmp/security_content/macros",
                   help="Path to security_content/macros directory")
    p.add_argument("--limit", type=int, default=0,
                   help="Limit processing to N detections (0 = all)")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    if not os.path.isdir(args.input_dir):
        print(f"ERROR: Input directory not found: {args.input_dir}")
        print("Clone: git clone https://github.com/splunk/security_content.git /tmp/security_content")
        sys.exit(1)

    # Load macros once (small, ~170 entries)
    print(f"Loading macros from {args.macro_dir}...")
    macro_resolver = MacroResolver(args.macro_dir)
    print(f"  Loaded {len(macro_resolver.macros)} macros")

    generator = SigmaGenerator(macro_resolver)

    # Count files first (fast directory walk)
    total = sum(1 for _ in _walk_yml_files(args.input_dir))
    if args.limit > 0:
        total = min(total, args.limit)
    print(f"Processing {total} detection files...")

    stats = {"total": 0, "converted": 0, "skipped": 0, "errors": 0,
             "skipped_reasons": {}, "converted_files": [], "error_files": []}

    # Stream through files one at a time
    for filepath in _walk_yml_files(args.input_dir, args.limit):
        stats["total"] += 1
        rel = os.path.relpath(filepath, args.input_dir)
        name = os.path.splitext(os.path.basename(filepath))[0]

        if stats["total"] % 200 == 0:
            pct = stats["total"] * 100 // total
            print(f"  [{pct}%] {stats['total']}/{total}  "
                  f"converted={stats['converted']} skipped={stats['skipped']} errors={stats['errors']}")
            gc.collect()  # force GC periodically to keep memory low

        try:
            with open(filepath) as f:
                detection = yaml.safe_load(f)

            if not detection or "search" not in detection:
                stats["skipped"] += 1
                _inc(stats, "No search field")
                continue

            search_str = detection.get("search", "")
            if not search_str or not search_str.strip():
                stats["skipped"] += 1
                _inc(stats, "Empty search")
                continue

            # Parse SPL
            try:
                ast = parse_spl(search_str)
            except Exception as e:
                if args.verbose:
                    print(f"  SKIP {name}: SPL parse error: {e}")
                stats["skipped"] += 1
                _inc(stats, f"SPL parse error: {str(e)[:80]}")
                continue

            # Classify
            is_convertible, reason, info = classify_detection(ast, macro_resolver)
            if not is_convertible:
                if args.verbose:
                    print(f"  SKIP {name}: {reason}")
                stats["skipped"] += 1
                _inc(stats, reason)
                continue

            # Generate Sigma rule
            out = generator.generate(detection, ast, info, args.output_dir)
            if out:
                stats["converted"] += 1
                stats["converted_files"].append({
                    "source": rel,
                    "output": os.path.relpath(out, args.output_dir),
                    "title": detection.get("name", ""),
                })
                if args.verbose:
                    print(f"  CONV {name} -> {os.path.relpath(out, args.output_dir)}")
            else:
                stats["skipped"] += 1
                _inc(stats, "No conditions extracted")

        except Exception as e:
            if args.verbose:
                print(f"  ERROR {name}: {e}")
                traceback.print_exc()
            stats["errors"] += 1
            stats["error_files"].append({"source": rel, "error": str(e)})

    # Write report
    _write_report(stats)

    # Summary
    print(f"\n{'='*60}")
    print("CONVERSION SUMMARY")
    print(f"{'='*60}")
    print(f"  Total detections:     {stats['total']}")
    print(f"  Converted to Sigma:   {stats['converted']} ({_pct(stats['converted'], stats['total'])})")
    print(f"  Skipped:              {stats['skipped']} ({_pct(stats['skipped'], stats['total'])})")
    print(f"  Errors:               {stats['errors']}")

    print(f"\n  Skip reasons (top 10):")
    for reason, count in sorted(stats["skipped_reasons"].items(), key=lambda x: -x[1])[:10]:
        print(f"    {reason}: {count}")

    print(f"\n  Output directory: {args.output_dir}")
    print(f"  Sigma rules: {stats['converted']}")


def _inc(stats, reason):
    d = stats["skipped_reasons"]
    d[reason] = d.get(reason, 0) + 1


def _pct(part, total):
    if total == 0:
        return "0.0%"
    return f"{part / total * 100:.1f}%"


def _write_report(stats):
    report = {
        "summary": {
            "total": stats["total"],
            "converted": stats["converted"],
            "skipped": stats["skipped"],
            "errors": stats["errors"],
            "conversion_rate": _pct(stats["converted"], stats["total"]),
        },
        "skip_reasons": dict(sorted(stats["skipped_reasons"].items(), key=lambda x: -x[1])),
        "converted": stats["converted_files"][:500],
        "errors": stats["error_files"][:100],
    }
    with open("conversion_report.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  Report: conversion_report.json")


if __name__ == "__main__":
    main()
