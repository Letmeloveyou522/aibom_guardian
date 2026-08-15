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

# Same contract as OSV unverified: a license read from something other than
# the pinned release describes a version nobody asked about. severity
# "unknown" is what score_engine._confidence keys on, so this lowers
# confidence rather than passing off another version's terms as the answer.
LICENSE_UNVERIFIED_ISSUE = {
    "type": "unverified",
    "severity": "unknown",
    "detail": "License could not be read from the pinned release.",
}


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


def attach_license_unverified(
    issues: list | None,
    lic: dict | None,
    *,
    detail: str | None = None,
) -> list | None:
    """
    Append a license-unverified issue when the license was not read from
    the pinned release.

    Never coerces ``None`` → ``[]``. When OSV already failed (``issues is
    None``), score_engine already treats the package as unverified; adding a
    one-item list here would hide that and look like a successful empty CVE
    scan plus one soft finding.
    """
    if not isinstance(lic, dict) or not lic.get("unverified"):
        return issues
    if issues is None:
        return None

    issue = dict(LICENSE_UNVERIFIED_ISSUE)
    if detail:
        issue["detail"] = detail
    return list(issues) + [issue]


def _build_check_result(
    license_status: str,
    issues: list | None,
    repository_info: dict | None = None,
    model_info: dict | None = None,
) -> dict:
    """
    Assemble the input for ``score_engine.calculate_trust_score()``.

    Centralised here (not duplicated in ``scanner.run_scan`` and
    ``mcp_server.check_package``) so CLI and MCP cannot drift to different
    shapes. ``type`` defaults to ``library`` because package checks are the
    common path; ``scan_model`` passes ``type: model`` with ``model_info`` set.

    ``issues`` is the merged list from every producer. ``repository_info`` is
    repository_checker's whole result; score_engine reads its trust_score and
    issues from there. ``None`` must survive intact — it means "never looked",
    which is how unverified OSV results become WARNING instead of ALLOW.
    """
    return {
        "type": "library",
        "license_status": license_status,
        "issues": issues,
        "model_info": model_info,
        "repository_info": repository_info,
    }
