"""
osv_client.py
-----------------------------------
Queries the OSV (Open Source Vulnerabilities) API with a package name
and version to check for known vulnerabilities (CVEs, etc.).

OSV is a free, open vulnerability database run by Google.
No API key is needed - just send an HTTP POST request.
Docs: https://osv.dev/docs/

Severity note:
  OSV often returns CVSS *vector strings* in severity[].score
  (e.g. "CVSS:3.1/AV:N/AC:H/..."), not numeric scores or labels.
  This module parses those vectors into Base Score + severity.
"""

from __future__ import annotations

import math
import re
from typing import Any, Optional

import requests

OSV_API_URL = "https://api.osv.dev/v1/query"

# CVSS v3 / v3.1 qualitative severity (NVD / FIRST)
_SEVERITY_BY_SCORE = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "none"),
)

_LABEL_ALIASES = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "MODERATE": "medium",
    "LOW": "low",
    "NONE": "none",
    "UNKNOWN": "unknown",
}


def _roundup_1(value: float) -> float:
    """CVSS Roundup: round up to 1 decimal place."""
    return math.ceil(value * 10) / 10.0


def parse_cvss_v3_vector(vector: str) -> Optional[dict[str, Any]]:
    """
    Parse a CVSS v3 / v3.1 vector string and compute Base Score + severity.

    Example:
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        -> {"cvss_score": 8.1, "severity": "high", "version": "3.1"}
    """
    if not vector or not isinstance(vector, str):
        return None

    vector = vector.strip()
    if not vector.upper().startswith("CVSS:3"):
        return None

    metrics = dict(re.findall(r"/([A-Z]+):([A-Z])", f"/{vector.split('/', 1)[-1]}"))
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(metrics):
        return None

    version_match = re.match(r"CVSS:(3(?:\.\d+)?)", vector, re.IGNORECASE)
    version = version_match.group(1) if version_match else "3.x"

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics["AV"])
    ac = {"L": 0.77, "H": 0.44}.get(metrics["AC"])
    ui = {"N": 0.85, "R": 0.62}.get(metrics["UI"])
    c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics["C"])
    i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics["I"])
    a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics["A"])
    scope = metrics["S"]

    if None in (av, ac, ui, c, i, a) or scope not in ("U", "C"):
        return None

    if scope == "U":
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics["PR"])
    else:
        pr = {"N": 0.85, "L": 0.68, "H": 0.50}.get(metrics["PR"])
    if pr is None:
        return None

    isc_base = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup_1(min(impact + exploitability, 10.0))
    else:
        score = _roundup_1(min(1.08 * (impact + exploitability), 10.0))

    return {
        "cvss_score": score,
        "severity": severity_from_score(score),
        "version": version,
    }


def severity_from_score(score: float) -> str:
    """Map a CVSS Base Score to critical / high / medium / low / none."""
    for threshold, label in _SEVERITY_BY_SCORE:
        if score >= threshold:
            return label
    return "unknown"


def normalize_severity_label(raw: Any) -> Optional[str]:
    """Normalize free-text labels like MODERATE / High → medium / high."""
    if raw is None:
        return None
    text = str(raw).strip().upper()
    if text in _LABEL_ALIASES:
        return _LABEL_ALIASES[text]
    # Sometimes people embed labels inside longer strings
    for key, label in _LABEL_ALIASES.items():
        if key in text and key != "UNKNOWN":
            return label
    return None


def _extract_severity(vuln: dict) -> tuple[str, Optional[float], Optional[str]]:
    """
    Resolve (severity_label, cvss_score, vector_or_None) from one OSV vuln.

    Priority:
      1) severity[] CVSS v3/v3.1 vector → compute Base Score
      2) severity[] numeric score
      3) database_specific.severity label (e.g. MODERATE)
      4) unknown
    """
    best_score: Optional[float] = None
    best_label: Optional[str] = None
    best_vector: Optional[str] = None

    for entry in vuln.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        score_field = entry.get("score")
        entry_type = str(entry.get("type", "")).upper()

        if isinstance(score_field, str) and score_field.upper().startswith("CVSS:3"):
            parsed = parse_cvss_v3_vector(score_field)
            if parsed and (best_score is None or parsed["cvss_score"] > best_score):
                best_score = parsed["cvss_score"]
                best_label = parsed["severity"]
                best_vector = score_field
            continue

        # Numeric score already provided
        if isinstance(score_field, (int, float)):
            numeric = float(score_field)
            if best_score is None or numeric > best_score:
                best_score = numeric
                best_label = severity_from_score(numeric)
            continue

        if isinstance(score_field, str):
            try:
                numeric = float(score_field)
                if best_score is None or numeric > best_score:
                    best_score = numeric
                    best_label = severity_from_score(numeric)
                continue
            except ValueError:
                pass

        # Rare: type says CVSS but score is missing; ignore
        _ = entry_type

    if best_label is not None:
        return best_label, best_score, best_vector

    db_label = normalize_severity_label(
        (vuln.get("database_specific") or {}).get("severity")
    )
    if db_label:
        return db_label, None, None

    return "unknown", None, None


def query_vulnerabilities(
    package_name: str, version: str, ecosystem: str = "PyPI"
) -> list[dict]:
    """
    Query the OSV API for known vulnerabilities affecting a specific
    package name + version.

    Returns a list of issue-shaped dicts (team Data Protocol):
      {
        "type": "cve",
        "id": "GHSA-...",
        "severity": "high",          # critical|high|medium|low|none|unknown
        "cvss_score": 8.1,           # optional float
        "detail": "...",
        # backward-compat aliases used by scanner / sbom_generator / mcp:
        "summary": "...",
      }
    """
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
        "version": version,
    }

    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        # Don't crash the whole scan if the network call fails
        print(f"[WARNING] Failed to query vulnerabilities for {package_name}: {e}")
        return []

    data = response.json()
    vulns = data.get("vulns", [])

    results = []
    for vuln in vulns:
        severity, cvss_score, _vector = _extract_severity(vuln)
        summary = vuln.get("summary") or vuln.get("details") or "No description"
        # Keep detail short for JSON reports / AI prompts
        detail = summary if len(summary) <= 240 else summary[:237] + "..."

        item = {
            "type": "cve",
            "id": vuln.get("id", "UNKNOWN-ID"),
            "severity": severity,
            "detail": detail,
            "summary": detail,  # backward compatible with existing callers
        }
        if cvss_score is not None:
            item["cvss_score"] = cvss_score
        results.append(item)

    return results


if __name__ == "__main__":
    import json

    # Vector unit checks (no network)
    samples = [
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1, "high"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3, "medium"),
    ]
    for vector, expected_score, expected_sev in samples:
        parsed = parse_cvss_v3_vector(vector)
        assert parsed is not None, vector
        assert parsed["cvss_score"] == expected_score, (vector, parsed)
        assert parsed["severity"] == expected_sev, (vector, parsed)
    print("CVSS parse self-check: OK")

    # Live smoke test: requests 2.28.0 has known CVEs
    result = query_vulnerabilities("requests", "2.28.0")
    print(json.dumps(result, indent=2, ensure_ascii=False))
