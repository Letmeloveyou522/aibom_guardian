"""
SARIF 2.1.0 output, for GitHub code scanning.

Uploading this with `github/codeql-action/upload-sarif` puts each finding on
the requirements.txt line that caused it, as a PR annotation, instead of
leaving it in a log nobody opens.

Transitive packages have no line of their own, so they are anchored to line 1
and name the package in the message.
"""

from __future__ import annotations

import json

from . import __version__

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Letmeloveyou522/aibom_guardian"

# SARIF has three levels. BLOCK is the only one that should fail a merge.
_VERDICT_LEVEL = {"BLOCK": "error", "WARNING": "warning", "ALLOW": "note"}

_SEVERITY_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "unknown": "warning",
}

_RULES = {
    "cve": ("Known vulnerability",
            "A published vulnerability affects this version."),
    "license": ("License restriction",
                "The license restricts use or imposes obligations."),
    "typosquatting": ("Possible typosquat",
                      "The name is confusingly close to a popular package."),
    "hallucination": ("Package not on PyPI",
                      "No such package is published; the name can be claimed."),
    "malicious": ("Malicious code",
                  "Dangerous code was detected in the artifact."),
    "provenance": ("Provenance concern",
                   "The origin of this artifact could not be established."),
    "pii": ("Sensitive data", "Sensitive data may be exposed."),
    "unverified": ("Check did not run",
                   "A check could not complete, so this is unverified."),
}


def _rule_id(issue_type: str) -> str:
    return f"aibom-guardian/{issue_type or 'unknown'}"


def _level(issue: dict) -> str:
    return _SEVERITY_LEVEL.get(str(issue.get("severity", "")).lower(), "warning")


def _location(uri: str, line: int) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": max(1, line)},
        }
    }


def _message(package: dict, issue: dict) -> str:
    name = f"{package['package']}=={package['version']}"
    detail = issue.get("detail") or issue.get("summary") or issue.get("id") or ""
    if not package.get("direct", True):
        name += "  (pulled in, not listed)"
    identifier = issue.get("id")
    prefix = f"{identifier}: " if identifier and identifier not in detail else ""
    return f"{name} — {prefix}{detail}".strip()


def build_sarif(scan_report: list[dict], requirements_path: str) -> dict:
    """
    Turn a scan report into a SARIF document.

    One result per issue. Packages with nothing to say produce no results -
    a clean SARIF run is how "we looked and found nothing" is expressed.
    """
    used: dict[str, tuple] = {}
    results = []

    for package in scan_report:
        line = package.get("line") or 1
        for issue in package.get("issues") or []:
            issue_type = str(issue.get("type") or "unknown")
            rule_id = _rule_id(issue_type)
            if issue_type in _RULES:
                used[rule_id] = _RULES[issue_type]
            results.append({
                "ruleId": rule_id,
                "level": _level(issue),
                "message": {"text": _message(package, issue)},
                "locations": [_location(requirements_path, line)],
                "partialFingerprints": {
                    "aibomGuard/v1": f"{package['package']}@{package['version']}"
                                     f"/{issue_type}/{issue.get('id') or ''}",
                },
            })

    rules = [
        {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": name},
            "fullDescription": {"text": description},
            "helpUri": INFORMATION_URI,
        }
        for rule_id, (name, description) in sorted(used.items())
    ]

    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AIBOM-Guardian",
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def write_sarif(scan_report: list[dict], requirements_path: str,
                output_path: str) -> dict:
    document = build_sarif(scan_report, requirements_path)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2)
    return document
