"""
Shapes collector output into score_engine's input schema.

scanner.py (CLI) and mcp_server.py (MCP) both go through here, so their
verdicts cannot drift apart.

None vs []:
    []      OSV answered; no known vulnerabilities.
    None    OSV did not answer; unknown.

Never coerce None to [] - score_engine keys on it to lower confidence.
Doing so reports a clean verdict for a package nobody checked.
"""

from __future__ import annotations

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


def _vulns_to_issues(vulns: list | None) -> list | None:
    """
    Convert OSV records into score_engine's ``issues`` shape. None in, None out.

    cvss_score and aliases must survive: score_engine falls back to the CVSS
    score when a severity label is missing, and merges aliases so a finding
    reported as both GHSA and PYSEC is not counted twice.
    """
    if vulns is None:
        return None

    issues = []
    for vuln in vulns:
        severity = str(vuln.get("severity", "unknown")).lower()
        if severity not in VALID_SEVERITIES:
            severity = "unknown"
        issue = {
            "type": "cve",
            "id": vuln.get("id"),
            "severity": severity,
            "summary": vuln.get("summary") or vuln.get("detail"),
            "detail": vuln.get("detail") or vuln.get("summary"),
        }
        if vuln.get("cvss_score") is not None:
            issue["cvss_score"] = vuln["cvss_score"]
        if vuln.get("aliases"):
            issue["aliases"] = vuln["aliases"]
        issues.append(issue)
    return issues


def _build_check_result(
    license_status: str,
    issues: list | None,
    repository_info: dict | None = None,
    model_info: dict | None = None,
) -> dict:
    """
    Assemble the input for score_engine.calculate_trust_score().

    ``issues`` is the merged list from every producer. ``repository_info`` is
    repository_checker's whole result; score_engine reads its trust_score and
    issues from there.
    """
    return {
        "type": "library",
        "license_status": license_status,
        "issues": issues,
        "model_info": model_info,
        "repository_info": repository_info,
    }
