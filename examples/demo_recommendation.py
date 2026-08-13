"""
examples/demo_recommendation.py
-----------------------------------
Demo CLI for the risk-detection path: osv_client + recommendation.
No assertions here - the unit tests are in tests/test_recommendation.py.

Pipeline:
  1) parse the package name and version
  2) look up CVEs with osv_client.query_vulnerabilities()
  3) merge them via RecommendationEngine.analyze_package(cve_issues=...)
  4) pretty-print the resulting {issues, alternatives} JSON

Usage:
    python examples/demo_recommendation.py
    python examples/demo_recommendation.py requests==2.28.0 reqeusts==1.0.0
    python examples/demo_recommendation.py nonexistent-ai-pkg==0.1.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional


# Runnable straight from a clone, without installing the package first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aibom_guard.osv_client import query_vulnerabilities  # noqa: E402
from aibom_guard.recommendation import RecommendationEngine  # noqa: E402

DEFAULT_CASES = (
    "requests==2.28.0",
    "reqeusts==1.0.0",
    "nonexistent-ai-pkg==0.1.0",
)

_PIN_RE = re.compile(
    r"^([A-Za-z0-9_\-.]+)\s*==\s*([A-Za-z0-9_.+\-]+)\s*$"
)


def parse_pin(spec: str) -> tuple[str, str]:
    """Parse 'name==version' into (name, version)."""
    match = _PIN_RE.match(spec.strip())
    if not match:
        raise ValueError(
            f"Invalid package spec '{spec}'. Expected format: name==version"
        )
    return match.group(1), match.group(2)


def run_case(
    engine: RecommendationEngine,
    package_name: str,
    version: str,
    *,
    ecosystem: str = "PyPI",
) -> dict:
    """
    Run one package through osv_client, then recommendation.

    Returns:
      {"package", "version", "issues", "alternatives"}
    """
    print(f"  [1/2] OSV CVE lookup: {package_name}=={version} ({ecosystem})")
    cve_issues = query_vulnerabilities(package_name, version, ecosystem=ecosystem)
    print(f"        -> {len(cve_issues)} CVE issue(s)")

    print("  [2/2] RecommendationEngine.analyze_package(...)")
    result = engine.analyze_package(
        package_name,
        version,
        cve_issues=cve_issues,
    )

    # Attach identity fields for readable test output (core schema unchanged)
    return {
        "package": package_name,
        "version": version,
        "issues": result.get("issues", []),
        "alternatives": result.get("alternatives", []),
    }


def summarize(report: dict) -> str:
    """One-line human summary for the terminal header."""
    issues = report.get("issues") or []
    alts = report.get("alternatives") or []
    counts: dict[str, int] = {}
    for issue in issues:
        t = str(issue.get("type", "unknown"))
        counts[t] = counts.get(t, 0) + 1
    type_part = ", ".join(f"{k}×{v}" for k, v in sorted(counts.items())) or "none"
    return f"issues={len(issues)} [{type_part}] | alternatives={len(alts)}"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Demo: osv_client + recommendation on one package"
    )
    parser.add_argument(
        "packages",
        nargs="*",
        help="Package pins to test, e.g. requests==2.28.0 (default: demo set)",
    )
    parser.add_argument(
        "--ecosystem",
        default="PyPI",
        help="OSV ecosystem (default: PyPI)",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print compact JSON (no indent)",
    )
    args = parser.parse_args(argv)

    specs = args.packages or list(DEFAULT_CASES)

    print("=" * 72)
    print("AIBOM-Guard - osv_client + recommendation demo")
    print("  osv_client.query_vulnerabilities → RecommendationEngine.analyze_package")
    print("=" * 72)

    engine = RecommendationEngine()
    reports: list[dict] = []
    failures = 0

    for idx, spec in enumerate(specs, start=1):
        print(f"\n[{idx}/{len(specs)}] Case: {spec}")
        print("-" * 72)
        try:
            name, version = parse_pin(spec)
        except ValueError as exc:
            print(f"  [ERROR] {exc}")
            failures += 1
            continue

        try:
            report = run_case(
                engine, name, version, ecosystem=args.ecosystem
            )
        except Exception as exc:  # noqa: BLE001 - surface any integration failure
            print(f"  [ERROR] Integration failed: {exc}")
            failures += 1
            continue

        reports.append(report)
        print(f"  Summary: {summarize(report)}")
        print("  JSON:")
        indent = None if args.compact else 2
        print(json.dumps(report, indent=indent, ensure_ascii=False))

    print("\n" + "=" * 72)
    print(f"Done. {len(reports)} passed, {failures} failed (of {len(specs)}).")
    print("=" * 72)

    # Also emit a combined array for easy copy/paste into other modules
    if reports and not args.compact:
        print("\n# Combined results (array)")
        print(json.dumps(reports, indent=2, ensure_ascii=False))

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
