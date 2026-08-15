"""
examples/demo_scenarios.py
-----------------------------------
One-shot demo of the three presentation scenarios:

  1) Normal (clean) model          — safetensors / no pickle risk
  2) Malicious pickle model        — picklescan-style dangerous globals
  3) Typosquatting package         — reqeusts ≈ requests
  4) Hallucinated package          — name that does not exist on PyPI

Default mode is fully offline (synthetic model reports + mocked PyPI).
Pass ``--live`` to query real PyPI for the package scenarios.

Usage:
    python examples/demo_scenarios.py
    python examples/demo_scenarios.py --live
    python examples/demo_scenarios.py --compact
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional
from unittest.mock import patch

# Runnable straight from a clone, without installing the package first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aibom_guard.model_checker import collect_issues  # noqa: E402
from aibom_guard.recommendation import (  # noqa: E402
    PyPIPackageInfo,
    RecommendationEngine,
)
from aibom_guard.scanner import _model_issues  # noqa: E402
from aibom_guard.score_engine import calculate_trust_score  # noqa: E402


def _base_model_report(**overrides: Any) -> dict:
    """Minimal model_checker-shaped report (same skeleton as unit tests)."""
    base = {
        "model_id": "demo/fixture-model",
        "license": "apache-2.0",
        "license_name": "apache-2.0",
        "gated": False,
        "trust_remote_code": False,
        "auto_map": {},
        "tokenizer_auto_map": {},
        "external_code_repos": [],
        "commit_sha": "a" * 40,
        "config_errors": [],
        "missing_model_card_fields": [],
        "model_card": {
            "present": True,
            "is_unedited_template": False,
            "placeholder_count": 0,
        },
        "file_formats": {
            "pickle": [],
            "pickle_only": False,
            "python_files": [],
        },
        "pickle_scan": {
            "status": "NOT_APPLICABLE",
            "malicious": [],
            "suspicious": [],
            "skipped": [],
            "detail": "",
        },
    }
    base.update(overrides)
    return base


def score_model_fixture(label: str, report: dict) -> dict:
    """
    Replay model_checker → scanner mapping → score_engine, offline.

    Mirrors ``scanner.scan_model`` without Hub network I/O.
    """
    report = dict(report)
    report["issues"] = collect_issues(report)
    model_context = {k: v for k, v in report.items() if k != "issues"}
    score = calculate_trust_score({
        "type": "model",
        "license_status": "ALLOWED",
        "issues": _model_issues(report),
        "model_info": model_context,
        "repository_info": None,
    })
    return {
        "scenario": label,
        "kind": "model",
        "model_id": report.get("model_id"),
        "raw_issues": report["issues"],
        "trust_score": score["trust_score"],
        "verdict": score["verdict"],
        "hard_block": score["hard_block"],
        "hard_block_reasons": score["hard_block_reasons"],
        "confidence": score["confidence"],
        "issue_types": sorted({
            str(i.get("type")) for i in (report["issues"] or []) if i.get("type")
        }),
    }


def score_package(
    engine: RecommendationEngine,
    label: str,
    name: str,
    version: str,
    *,
    skip_pypi: bool = False,
) -> dict:
    result = engine.analyze_package(name, version, skip_pypi=skip_pypi)
    issues = result.get("issues") or []
    score = calculate_trust_score({
        "type": "library",
        "license_status": "ALLOWED",
        "issues": issues,
        "model_info": None,
        "repository_info": None,
    })
    return {
        "scenario": label,
        "kind": "package",
        "package": name,
        "version": version,
        "raw_issues": issues,
        "alternatives": result.get("alternatives") or [],
        "trust_score": score["trust_score"],
        "verdict": score["verdict"],
        "hard_block": score["hard_block"],
        "hard_block_reasons": score["hard_block_reasons"],
        "confidence": score["confidence"],
        "issue_types": sorted({
            str(i.get("type")) for i in issues if i.get("type")
        }),
    }


def run_offline() -> list[dict]:
    """Deterministic demo — no Hub / PyPI / OSV."""
    engine = RecommendationEngine()

    clean = score_model_fixture(
        "1_normal_model",
        _base_model_report(model_id="demo/clean-safetensors"),
    )

    malicious = score_model_fixture(
        "2_malicious_pickle_model",
        _base_model_report(
            model_id="demo/evil-pickle",
            file_formats={
                "pickle": [{"path": "pytorch_model.bin", "risk": "HIGH"}],
                "pickle_only": True,
                "python_files": [],
            },
            pickle_scan={
                "status": "OK",
                "skipped": [],
                "suspicious": [],
                "detail": "fixture replay",
                "malicious": [{
                    "file": "pytorch_model.bin",
                    "module": "builtins",
                    "name": "eval",
                }],
            },
        ),
    )

    # Typosquat needs no network when skip_pypi=True.
    typosquat = score_package(
        engine, "3_typosquat_package", "reqeusts", "1.0.0", skip_pypi=True,
    )

    # Confirmed hallucination: 404-shaped PyPI response (exists=False, no error).
    missing = PyPIPackageInfo(name="nonexistent-ai-pkg", exists=False)
    with patch.object(engine.pypi, "get_package", return_value=missing):
        hallucination = score_package(
            engine, "4_hallucinated_package",
            "nonexistent-ai-pkg", "0.1.0", skip_pypi=False,
        )

    return [clean, malicious, typosquat, hallucination]


def run_live() -> list[dict]:
    """
    Package scenarios hit real PyPI; model scenarios stay fixture-based
    (Hub download is too heavy for a slide deck).
    """
    reports = run_offline()
    # Replace package rows with live lookups.
    engine = RecommendationEngine()
    reports[2] = score_package(
        engine, "3_typosquat_package", "reqeusts", "1.0.0", skip_pypi=False,
    )
    reports[3] = score_package(
        engine, "4_hallucinated_package",
        "nonexistent-ai-pkg", "0.1.0", skip_pypi=False,
    )
    return reports


def print_banner(row: dict) -> None:
    types = ", ".join(row.get("issue_types") or []) or "(none)"
    target = row.get("model_id") or f"{row.get('package')}=={row.get('version')}"
    print(
        f"\n=== {row['scenario']} ({row['kind']}: {target}) ===\n"
        f"  verdict={row['verdict']}  trust_score={row['trust_score']}  "
        f"hard_block={row['hard_block']}\n"
        f"  issue_types=[{types}]"
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Demo: clean model / malicious pickle / typosquat / hallucination",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Query real PyPI for package scenarios (models stay fixtures)",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Print compact JSON (no indent)",
    )
    args = parser.parse_args(argv)

    mode = "live" if args.live else "offline"
    print(f"AIBOM-Guard threat scenarios ({mode})")
    rows = run_live() if args.live else run_offline()

    for row in rows:
        print_banner(row)

    payload = {"mode": mode, "scenarios": rows}
    print("\n--- JSON ---")
    if args.compact:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    # Soft self-check so a broken demo fails loudly during rehearsal.
    by_id = {r["scenario"]: r for r in rows}
    assert by_id["1_normal_model"]["verdict"] in ("ALLOW", "WARNING")
    assert by_id["2_malicious_pickle_model"]["verdict"] == "BLOCK"
    assert "malicious" in by_id["2_malicious_pickle_model"]["issue_types"]
    assert "typosquatting" in by_id["3_typosquat_package"]["issue_types"]
    assert "hallucination" in by_id["4_hallucinated_package"]["issue_types"]
    print("\n[ok] scenario assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
