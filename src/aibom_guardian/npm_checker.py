"""
npm_checker.py
-----------------------------------
Minimal npm ecosystem support: scan ``package.json`` ``dependencies`` and
``devDependencies`` only (no transitive expansion).

License strings come from the npm registry; verdicts reuse
``license_checker.classify_license_detailed``. CVEs reuse
``osv_client.query_vulnerabilities(..., ecosystem=\"npm\")``. Trust Score
reuses ``score_engine.calculate_trust_score`` via ``_adapters._build_check_result``.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from typing import NamedTuple

from ._adapters import (
    LICENSE_UNVERIFIED_ISSUE,
    _build_check_result,
    _vulns_to_issues,
    attach_license_unverified,
)
from ._cli_report import print_report, print_unscanned_lines, save_report
from .license_checker import classify_license_detailed, set_offline
from .osv_client import query_vulnerabilities
from .score_engine import calculate_trust_score
from ._scanner_collect import _display_issues

logger = logging.getLogger(__name__)

NPM_REGISTRY_URL = "https://registry.npmjs.org/{package}"
NPM_REGISTRY_VERSION_URL = "https://registry.npmjs.org/{package}/{version}"
NPM_TIMEOUT_SEC = 10.0
OSV_ECOSYSTEM = "npm"

_REGISTRY_CACHE: dict = {}
_NPM_SESSION = None
_THREAD_LOCAL = threading.local()

# Semver-ish token after stripping a leading range operator.
_VERSION_TOKEN = re.compile(
    r"^(\d+\.\d+\.\d+(?:[-+][\w.-]+)?|\d+\.\d+(?:[-+][\w.-]+)?|\d+(?:[-+][\w.-]+)?)$"
)


class NpmPackage(NamedTuple):
    """One dependency line from package.json, normalized for OSV lookup."""

    name: str
    version: str          # normalized version sent to OSV / registry
    spec: str             # original range string from package.json
    section: str          # "dependencies" or "devDependencies"
    exact: bool           # True when spec is an exact pin, not a range prefix


def _npm_session():
    global _NPM_SESSION
    if _NPM_SESSION is not None:
        return _NPM_SESSION
    session = getattr(_THREAD_LOCAL, "npm", None)
    if session is None:
        import requests

        session = requests.Session()
        _THREAD_LOCAL.npm = session
    return session


def normalize_npm_version(spec: str) -> tuple[str, bool] | None:
    """
    Turn an npm version range into a concrete version for OSV / registry lookup.

    Exact pins (``4.18.2``) are trusted. Common prefixes (``^``, ``~``, ``>=``)
    strip to the stated version — a best-effort lookup, not a lockfile resolve.
    Wildcards (``*``, ``latest``) and compound ranges (``||``) return ``None``.
    """
    text = str(spec or "").strip()
    if not text or text in ("*", "latest"):
        return None
    if "||" in text or " - " in text:
        return None

    token = text.split()[0]
    exact = not token.startswith(("^", "~", ">", "<", "="))
    stripped = re.sub(r"^[\^~<>=v]+", "", token)
    if _VERSION_TOKEN.match(stripped):
        return stripped, exact and stripped == token
    return None


def parse_package_json(path: str) -> tuple[list[NpmPackage], list[str]]:
    """
    Read ``dependencies`` and ``devDependencies`` from a ``package.json`` file.

    Returns ``(packages, unscanned)`` where ``unscanned`` lists entries that
    could not be turned into a concrete ``name@version`` pair (same role as
    ``parse_requirements``'s unscanned lines).
    """
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"{path}: root must be a JSON object")

    packages: list[NpmPackage] = []
    unscanned: list[str] = []

    for section in ("dependencies", "devDependencies"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            unscanned.append(f"{section}: expected an object")
            continue
        for name, spec in block.items():
            if not isinstance(name, str) or not name.strip():
                continue
            spec_text = str(spec).strip() if spec is not None else ""
            normalized = normalize_npm_version(spec_text)
            if normalized is None:
                unscanned.append(f"{section}.{name}: {spec_text!r}")
                continue
            version, exact = normalized
            packages.append(
                NpmPackage(
                    name=name.strip(),
                    version=version,
                    spec=spec_text,
                    section=section,
                    exact=exact,
                )
            )

    return packages, unscanned


def _license_string(raw) -> str:
    """Normalize npm manifest license fields to a single string."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw.strip()
    if isinstance(raw, dict):
        return str(raw.get("type") or raw.get("name") or "").strip()
    if isinstance(raw, list):
        parts = []
        for entry in raw:
            if isinstance(entry, str):
                parts.append(entry)
            elif isinstance(entry, dict):
                parts.append(str(entry.get("type") or entry.get("name") or ""))
        return " AND ".join(p for p in parts if p)
    return str(raw).strip()


def fetch_npm_license(package_name: str, version: str, *, offline: bool = False) -> dict:
    """
    Read the license for one npm package version from the registry.

    Returns the same dict shape as ``scanner.resolve_license`` so downstream
    scoring and report fields stay consistent.
    """
    if offline:
        return {
            "license": "UNKNOWN",
            "source": "none",
            "version": None,
            "unverified": True,
            "error": "offline",
        }

    cache_key = (package_name.lower(), version)
    if cache_key in _REGISTRY_CACHE:
        return _REGISTRY_CACHE[cache_key]

    try:
        from urllib.parse import quote

        url = NPM_REGISTRY_VERSION_URL.format(
            package=quote(package_name, safe=""),
            version=quote(version, safe=""),
        )
        response = _npm_session().get(url, timeout=NPM_TIMEOUT_SEC)
    except Exception as exc:  # noqa: BLE001 - network
        result = {
            "license": "UNKNOWN",
            "source": "none",
            "version": None,
            "unverified": True,
            "error": f"network: {exc}",
        }
        _REGISTRY_CACHE[cache_key] = result
        return result

    if response.status_code == 404:
        result = {
            "license": "NOT_INSTALLED",
            "source": "none",
            "version": None,
            "unverified": True,
            "error": f"release {package_name}@{version} not found on npm",
        }
        _REGISTRY_CACHE[cache_key] = result
        return result

    if response.status_code != 200:
        result = {
            "license": "UNKNOWN",
            "source": "none",
            "version": None,
            "unverified": True,
            "error": f"http {response.status_code}",
        }
        _REGISTRY_CACHE[cache_key] = result
        return result

    try:
        manifest = response.json()
    except ValueError as exc:
        result = {
            "license": "UNKNOWN",
            "source": "none",
            "version": None,
            "unverified": True,
            "error": f"invalid json: {exc}",
        }
        _REGISTRY_CACHE[cache_key] = result
        return result

    raw = _license_string(manifest.get("license"))
    if not raw:
        licenses = manifest.get("licenses")
        if isinstance(licenses, list) and licenses:
            raw = _license_string(licenses[0])

    if raw:
        result = {
            "license": raw,
            "source": "npm:registry",
            "version": version,
            "unverified": False,
            "error": None,
        }
    else:
        result = {
            "license": "UNKNOWN",
            "source": "npm:registry",
            "version": version,
            "unverified": True,
            "error": f"{package_name}@{version} declares no license",
        }

    _REGISTRY_CACHE[cache_key] = result
    return result


def _scan_one_package(entry: NpmPackage, *, offline: bool) -> dict:
    """Collect license + OSV data for one npm package."""
    lic = fetch_npm_license(entry.name, entry.version, offline=offline)
    lic_raw = lic["license"]
    lic_detail = classify_license_detailed(lic_raw)
    lic_status = lic_detail["status"]

    license_issue = None
    if lic["unverified"]:
        if lic["source"] == "none":
            detail = (
                f"No license could be read for {entry.name}@{entry.version}: "
                f"{lic['error']}."
            )
        elif not entry.exact:
            detail = (
                f"License for {entry.name}@{entry.version} was read from "
                f"{lic['source']} for the normalized version {entry.version} "
                f"(package.json spec {entry.spec!r}). npm ranges are not "
                f"lockfile-resolved here, so terms may not match what installs."
            )
        else:
            detail = (
                f"License for {entry.name}@{entry.version} could not be "
                f"confirmed: {lic['error']}."
            )
        license_issue = dict(LICENSE_UNVERIFIED_ISSUE, detail=detail)

    if offline:
        vulns, issues = [], None
    else:
        vulns = query_vulnerabilities(entry.name, entry.version, OSV_ECOSYSTEM)
        issues = _vulns_to_issues(vulns)

    osv_unverified = not offline and vulns is None
    scored_issues = attach_license_unverified(
        issues,
        lic,
        detail=license_issue.get("detail") if license_issue else None,
    )

    score_result = calculate_trust_score(
        _build_check_result(lic_status, scored_issues, repository_info=None)
    )

    return {
        "package": entry.name,
        "version": entry.version,
        "requirement": entry.spec,
        "version_resolved": not entry.exact,
        "direct": True,
        "depth": 0,
        "line": 0,
        "ecosystem": "npm",
        "section": entry.section,
        "license_raw": lic_raw,
        "license_status": lic_status,
        "license_spdx_id": lic_detail["spdx_id"],
        "license_family": lic_detail["family"],
        "license_obligations": lic_detail["obligations"],
        "license_source": lic["source"],
        "license_version": lic["version"],
        "license_unverified": lic["unverified"],
        "vulnerabilities": vulns,
        "issues": _display_issues(
            issues,
            osv_unverified=osv_unverified,
            extra=[license_issue] if license_issue else None,
        ),
        "osv_unverified": osv_unverified,
        "scanned": issues is not None,
        "alternatives": [],
        "trust_score": score_result["trust_score"],
        "verdict": score_result["verdict"],
        "hard_block": score_result["hard_block"],
        "hard_block_reasons": score_result["hard_block_reasons"],
        "score_breakdown": score_result["breakdown"],
        "confidence": score_result["confidence"],
        "_license_warning": license_issue,
        "_osv_unverified": osv_unverified,
    }


def run_npm_scan(
    package_json_path: str,
    *,
    offline: bool = False,
    explain: bool = False,
    report_path: str = "scan_report.json",
    verbose: bool = False,
) -> list:
    """
    Scan npm ``dependencies`` / ``devDependencies`` from ``package_json_path``.

    Returns a list of per-package report rows (same shape as ``run_scan``).
    """
    from .scanner import ScanReport, explain_results

    packages, unscanned_lines = parse_package_json(package_json_path)
    if not packages:
        print("No npm packages found to scan. Check your package.json.")
        if unscanned_lines:
            print(f"[INFO] {len(unscanned_lines)} entr(y/ies) could not be parsed.")
        return []

    set_offline(offline)
    if offline:
        print("[INFO] Offline mode: OSV and npm registry lookups are skipped.")

    report = []
    for entry in packages:
        print(f"[Scanning npm] {entry.name}@{entry.version} "
              f"({entry.section}, spec {entry.spec!r}) ...")
        row = _scan_one_package(entry, offline=offline)

        if row.get("_license_warning"):
            print(f"  [WARNING] {row['_license_warning']['detail']}")
        if row.get("_osv_unverified"):
            print(f"  [WARNING] OSV lookup failed for {entry.name}@{entry.version} — "
                  f"CVE status unverified (not treated as clean).")

        row.pop("_license_warning", None)
        row.pop("_osv_unverified", None)
        report.append(row)

    print_report(report, verbose=verbose)
    if unscanned_lines:
        print_unscanned_lines(unscanned_lines)

    document = {"packages": report, "models": [], "unscanned": unscanned_lines}
    save_report(document, report_path)

    if explain:
        print("\n===== AI Explanation (local model via Ollama) =====\n")
        print(explain_results(document))

    result = ScanReport(report)
    result.unscanned = unscanned_lines
    return result
