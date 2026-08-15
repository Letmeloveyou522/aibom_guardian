"""
Hugging Face model scan + score_engine integration for the CLI.

``scan_model`` wraps ``model_checker.check_model`` and translates findings into
the shared issue protocol before calling ``calculate_trust_score``.
"""

import logging

from .license_checker import classify_license_detailed
from .score_engine import calculate_trust_score

logger = logging.getLogger("aibom_guardian.scanner")


def _model_issues(report: dict) -> list:
    """
    Translate model_checker's findings into score_engine issue categories.

    The mapping is explicit so an unmapped finding type surfaces as
    ``unrecognised`` instead of vanishing from the score. ``remote_code`` maps
    to ``provenance`` (not ``malicious``) because ``trust_remote_code`` is a
    policy/origin signal — the repo code may be benign — whereas picklescan
    ``malicious`` globals are the only model path that hard-blocks outright.
    """
    type_map = {
        "malicious": "malicious",
        "suspicious": "malicious",
        "pickle_only": "provenance",
        "pickle_file": "provenance",
        "remote_code": "provenance",
        "external_code": "provenance",
        "python_files": "provenance",
        "no_model_card": "provenance",
        "template_model_card": "provenance",
        "incomplete_model_card": "provenance",
        "no_license": "license",
        "gated": "license",
        "unverified": "provenance",
    }
    severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

    issues = []
    for issue in report.get("issues") or []:
        issues.append({
            "type": type_map.get(issue.get("type"), issue.get("type")),
            "id": issue.get("type"),
            "severity": severity_map.get(issue.get("severity"), "unknown"),
            "detail": issue.get("message"),
            "summary": issue.get("message"),
        })
    return issues


def scan_model(model_ref: str, max_pickle_size_mb: int = 0) -> dict | None:
    """
    Run model_checker over one Hugging Face model and score it.

    Returns the model_checker report with verdict fields folded in, or None when
    the model could not be read. Logs to the module logger (not stdout) because
    ``mcp_server.check_model`` shares this path and stdout is JSON-RPC there.
    """
    from aibom_guardian import scanner as sc

    if not sc.HAS_MODEL_CHECKER:
        logger.warning("model_checker unavailable - model scan skipped for %s",
                       model_ref)
        return None

    try:
        report = sc.check_model(model_ref, max_pickle_size_mb=max_pickle_size_mb)
    except Exception as exc:  # noqa: BLE001 - a bad model must not end the run
        logger.error("could not read model '%s': %s", model_ref, exc)
        return None

    license_text = report.get("license_name") or report.get("license")
    detail = classify_license_detailed(license_text)
    report["license_status"] = detail["status"]
    report["license_family"] = detail["family"]
    report["license_reason"] = detail["reason"]

    model_context = {k: v for k, v in report.items() if k != "issues"}

    score_result = calculate_trust_score({
        "type": "model",
        "license_status": detail["status"],
        "issues": _model_issues(report),
        "model_info": model_context,
        "repository_info": None,
    })
    report["risk_score"] = score_result["trust_score"]
    report["verdict"] = score_result["verdict"]
    report["hard_block"] = score_result["hard_block"]
    report["hard_block_reasons"] = score_result["hard_block_reasons"]
    report["score_breakdown"] = score_result["breakdown"]
    report["confidence"] = score_result["confidence"]
    return report
