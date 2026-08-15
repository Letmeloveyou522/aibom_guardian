"""
scanner.py
-----------------------------------
AIBOM-Guard - main CLI.

Takes a requirements.txt file and, for each pinned package:

  1) classifies the license                  license_checker
  2) queries OSV for known vulnerabilities   osv_client
  3) detects typosquatting / hallucinated /
     deprecated packages and suggests fixes  recommendation
  4) optionally checks supply-chain trust    repository_checker
  5) scores everything into one verdict      score_engine
  6) writes scan_report.json + CycloneDX sbom.json
  7) optionally explains the result locally  ai_explainer

Usage:
    aibom-guard examples/sample-requirements.txt
    aibom-guard reqs.txt --supply-chain      # add supply-chain checks
    aibom-guard reqs.txt --offline           # no PyPI/OSV lookups
    aibom-guard reqs.txt --no-explain --json out.json

``python -m aibom_guard`` is equivalent to the console script.

Layout (P2 split):
    ``_requirements.py``  — parse_requirements / transitive expand / Pinned
    ``_cli_report.py``    — print_report / save_report / terminal tables
    ``scanner.py``        — run_scan orchestration, license resolve, CLI main

Public names are still re-exported here so
``from aibom_guard.scanner import parse_requirements, print_report`` keeps working.

Exit codes (so this can gate CI):
    0  every package is ALLOW and every requirement line was scanned
    1  bad input - unreadable file, bad arguments, nothing to scan
    2  at least one package or model is BLOCK
    3  no hard block, but a WARNING or an unscanned line - see --fail-on
"""

import argparse
import logging
import sys
import threading
__all__ = [
    "HAS_PRETTYTABLE",
    "_MAX_VULNS_SHOWN",
    "_SEVERITY_ORDER",
    "_VULN_SUMMARY_CHARS",
    "_first_sentence",
    "_print_vulnerabilities",
    "_vuln_count_label",
    "Pinned",
    "TRANSITIVE_MAX_DEPTH",
    "_DIRECTIVE_PREFIXES",
    "_PYPI_SESSION",
    "_normalize_name",
    "_pypi_versions",
    "_requires_dist",
    "_resolve_specifier",
    "run_scan",
    "main",
]
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version as installed_version, PackageNotFoundError, metadata

from . import __version__
from ._adapters import (
    LICENSE_UNVERIFIED_ISSUE,
    _build_check_result,
    _vulns_to_issues,
    attach_license_unverified,
)
from ._cli_report import (
    HAS_PRETTYTABLE,
    _MAX_VULNS_SHOWN,
    _SEVERITY_ORDER,
    _VULN_SUMMARY_CHARS,
    _first_sentence,
    _print_vulnerabilities,
    _vuln_count_label,
    print_model_report,
    print_report,
    print_unscanned_lines,
    save_report,
)
from ._requirements import (  # noqa: F401 - re-export for scanner.* callers/tests
    PYPI_TIMEOUT_SEC,
    Pinned,
    TRANSITIVE_MAX_DEPTH,
    _DIRECTIVE_PREFIXES,
    _PYPI_SESSION,
    _RELEASE_CACHE,
    _normalize_name,
    _pypi_session,
    _pypi_versions,
    _requires_dist,
    _resolve_specifier,
    expand_transitive,
    parse_requirements,
)
from .osv_client import query_vulnerabilities
from .license_checker import classify_license_detailed, set_offline
from .sarif import write_sarif
from .sbom_generator import build_final_sbom
from .ai_explainer import explain_results
from .score_engine import calculate_trust_score

logger = logging.getLogger(__name__)

# Modules 2 and 3 are optional at import time so a partial checkout, or a
# missing transitive dependency, degrades to the core scan instead of
# preventing the CLI from starting at all.
try:
    from .recommendation import RecommendationEngine
    HAS_RECOMMENDATION = True
except ImportError:
    HAS_RECOMMENDATION = False

try:
    from .repository_checker import check_repository
    HAS_REPOSITORY_CHECKER = True
except ImportError:
    HAS_REPOSITORY_CHECKER = False

try:
    from .model_checker import check_model
    HAS_MODEL_CHECKER = True
except ImportError:
    HAS_MODEL_CHECKER = False


class ScanReport(list):
    """
    The package rows, plus the requirement lines that could not be scanned.

    A plain list keeps every existing caller working; `unscanned` rides along
    because the exit code has to see it. Coverage is part of the result: a
    scan that skipped six of seven lines is not the same answer as one that
    read them all.
    """

    def __init__(self, rows=()):
        super().__init__(rows)
        self.unscanned: list = []


# Requirements parsing / transitive resolution live in _requirements.py.
# Pinned, parse_requirements, expand_transitive, and the shared PyPI session
# + _RELEASE_CACHE are imported above so ``scanner.Pinned`` etc. keep working.

PYPI_RELEASE_URL = "https://pypi.org/pypi/{package}/{version}/json"


def _license_candidates(fields: dict) -> list:
    """
    License strings a distribution offers, best-structured first.

    PEP 639's `License-Expression` is authoritative when present. Below it the
    order matters less than it looks, because `_best_candidate` re-ranks by
    what actually resolves - a short free-text `License` beats a classifier
    only when it names a real identifier.
    """
    candidates = []

    expression = (fields.get("license_expression") or "").strip()
    if expression and expression.upper() != "UNKNOWN":
        candidates.append((expression, "license_expression"))

    lic = (fields.get("license") or "").strip()
    # A short, single-line License field is almost always an identifier
    # (MIT, BSD-3-Clause, Apache-2.0), not the full text.
    if lic and lic.upper() != "UNKNOWN" and len(lic) < 300 and lic.count("\n") <= 3:
        candidates.append((lic, "license"))

    for classifier in fields.get("classifiers") or []:
        if classifier.startswith("License ::"):
            candidates.append((classifier, "classifier"))

    # The full text last: it is the least ambiguous evidence but the most
    # expensive to read, and numpy ships 47 KB of it with third-party terms
    # appended.
    if lic and lic.upper() != "UNKNOWN" and (lic, "license") not in candidates:
        candidates.append((lic, "license_text"))

    return candidates


def _best_candidate(candidates: list) -> tuple:
    """
    Pick the license string that identifies the license most precisely.

    psycopg2 publishes `License: "LGPL with exceptions"` alongside the trove
    classifier "GNU Library or Lesser General Public License (LGPL)". Taking
    the first field in a fixed order throws away whichever one happens to be
    the resolvable one, so each candidate is graded and the one that resolves
    to an SPDX identifier wins.
    """
    graded = [(raw, field, classify_license_detailed(raw))
              for raw, field in candidates]

    for raw, field, detail in graded:
        if detail["spdx_id"]:
            return raw, field
    for raw, field, detail in graded:
        if detail["status"] != "UNKNOWN":
            return raw, field
    if graded:
        raw, field, _ = graded[0]
        return raw, field
    return "", ""


def _installed_license(package_name: str) -> tuple:
    """Read the license of the copy installed in this environment."""
    try:
        meta = metadata(package_name)
    except PackageNotFoundError:
        return "NOT_INSTALLED", "", None

    fields = {
        "license_expression": meta.get("License-Expression") or "",
        "license": meta.get("License") or "",
        "classifiers": meta.get_all("Classifier") or [],
    }
    raw, field = _best_candidate(_license_candidates(fields))
    try:
        found_version = installed_version(package_name)
    except PackageNotFoundError:
        found_version = None
    return (raw or "UNKNOWN"), field, found_version


def _pypi_release_license(package_name: str, version: str) -> tuple:
    """
    Read the license PyPI records for one exact release.

    Returns (raw, field, error). `error` is a string when the release could
    not be read, so the caller can record *why* it fell back rather than
    silently reporting the wrong version's terms.
    """
    key = (package_name.lower(), version)
    if key in _RELEASE_CACHE:
        return _RELEASE_CACHE[key]

    try:
        from urllib.parse import quote
    except ImportError as exc:                      # pragma: no cover
        return "", "", f"requests unavailable: {exc}"

    url = PYPI_RELEASE_URL.format(package=quote(package_name, safe=""),
                                  version=quote(version, safe=""))
    try:
        response = _pypi_session().get(url, timeout=PYPI_TIMEOUT_SEC)
    except Exception as exc:                        # noqa: BLE001 - network
        result = ("", "", f"network: {exc}")
        _RELEASE_CACHE[key] = result
        return result

    if response.status_code == 404:
        result = ("", "", f"release {package_name}=={version} not found on PyPI")
        _RELEASE_CACHE[key] = result
        return result
    if response.status_code != 200:
        result = ("", "", f"http {response.status_code}")
        _RELEASE_CACHE[key] = result
        return result

    try:
        info = response.json().get("info") or {}
    except ValueError as exc:
        result = ("", "", f"invalid json: {exc}")
        _RELEASE_CACHE[key] = result
        return result

    raw, field = _best_candidate(_license_candidates(info))
    result = (raw, field, None) if raw else (
        "", "", f"{package_name}=={version} declares no license")
    _RELEASE_CACHE[key] = result
    return result


def resolve_license(package_name: str, version: str = None,
                    offline: bool = False) -> dict:
    """
    Resolve the license of the *requested* version of a package.

    Reading the installed copy is not good enough, and the gap is not
    theoretical: chardet 5.2.0 is LGPL-2.1 and chardet 7.5.1 is 0BSD. A
    requirements file pinning 5.2.0 while the environment holds 7.5.1 would be
    reported as permissive, and the copyleft obligation would be missed
    entirely. Packages that are not installed at all reported NOT_INSTALLED
    and were graded UNKNOWN.

    So the pinned release on PyPI is the source of record, and the installed
    copy is the fallback - marked as such, because it describes a different
    version.

    Returns:
        license        the raw string to classify
        source         pypi:<field> / installed:<field> / none
        version        the version the license was read from, when known
        unverified     True when the license does not come from the pinned
                       release; score_engine lowers confidence on it rather
                       than trusting a version that was never checked
        error          why PyPI was not used, when it was not
    """
    if version and not offline:
        raw, field, error = _pypi_release_license(package_name, version)
        if raw:
            return {"license": raw, "source": f"pypi:{field}",
                    "version": version, "unverified": False, "error": None}
    else:
        error = "offline" if offline else "no version pinned"

    raw, field, found_version = _installed_license(package_name)
    source = f"installed:{field}" if field else "none"
    # The installed copy only describes the pinned version when it *is* the
    # pinned version.
    matches_pin = bool(version) and found_version == version
    return {
        "license": raw,
        "source": source if raw != "NOT_INSTALLED" else "none",
        "version": found_version,
        "unverified": not matches_pin,
        "error": error,
    }


OSV_UNVERIFIED_ISSUE = {
    "type": "unverified",
    "severity": "unknown",
    "detail": (
        "OSV vulnerability lookup failed (network/API error). "
        "CVE status is unverified — not the same as 'no known vulnerabilities'."
    ),
}

# LICENSE_UNVERIFIED_ISSUE lives in _adapters so CLI and MCP share one object.


def analyze_package_risks(
    engine,
    name: str,
    version: str,
    vulns: list | None,
    min_release_age: int = 0,
) -> tuple[list | None, list]:
    """
    Run recommendation over one package and return (issues, alternatives).

    RecommendationEngine.analyze_package() merges the OSV findings we hand
    it into its own issue list, so its return value is the complete set -
    adding `vulns` again here would double-count every CVE.

    When ``vulns`` is ``None`` (OSV lookup failed), return ``(None, [])`` so
    the caller can pass ``issues=None`` into score_engine — meaning
    "unverified", not "clean".

    A failure downgrades to the OSV issues alone rather than aborting the
    scan; the caller records the reason.
    """
    if vulns is None:
        return None, []
    if engine is None:
        return _vulns_to_issues(vulns), []
    try:
        result = engine.analyze_package(name, version,
                                        cve_issues=_vulns_to_issues(vulns),
                                        min_release_age=min_release_age)
    except Exception as exc:  # noqa: BLE001 - network/parse errors must not stop a scan
        logger.warning("recommendation engine failed for %s: %s", name, exc)
        return _vulns_to_issues(vulns), []
    return result.get("issues") or [], result.get("alternatives") or []


def _display_issues(issues: list | None, *, osv_unverified: bool,
                    extra: list | None = None) -> list:
    """Issues shown in the report/terminal (may include the unverified markers)."""
    shown: list = []
    if osv_unverified:
        shown.append(dict(OSV_UNVERIFIED_ISSUE))
    if extra:
        shown.extend(extra)
    if issues:
        shown.extend(issues)
    return shown


def scan_model(model_ref: str, max_pickle_size_mb: int = 0) -> dict | None:
    """
    Run model_checker over one Hugging Face model and score it.

    Returns the model_checker report with the AIBOM-Guard verdict folded in,
    or None when the model could not be read at all.

    `max_pickle_size_mb` defaults to 0 (metadata only). Downloading weights
    to scan pickle contents is opt-in because a single model can be tens of
    gigabytes; --model-pickle-scan raises it.
    """
    # Logged, not printed: mcp_server.check_model calls this, and stdout is
    # the JSON-RPC channel there. _configure_cli_logging shows it on the CLI.
    if not HAS_MODEL_CHECKER:
        logger.warning("model_checker unavailable - model scan skipped for %s",
                       model_ref)
        return None

    try:
        report = check_model(model_ref, max_pickle_size_mb=max_pickle_size_mb)
    except Exception as exc:  # noqa: BLE001 - a bad model must not end the run
        logger.error("could not read model '%s': %s", model_ref, exc)
        return None

    # Grade the declared license. This is the whole point of an AIBOM:
    # llama3.1, gemma and the RAIL family are not OSI-approved, and the
    # generic package path would never see them.
    license_text = report.get("license_name") or report.get("license")
    detail = classify_license_detailed(license_text)
    report["license_status"] = detail["status"]
    report["license_family"] = detail["family"]
    report["license_reason"] = detail["reason"]

    # score_engine also harvests issues out of `model_info`, so the raw
    # model_checker findings are removed from the copy handed to it - they
    # are already present, translated, in the top-level `issues` list.
    # Leaving both in counted every model finding twice.
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


def _model_issues(report: dict) -> list:
    """
    Translate model_checker's findings into score_engine's issue categories.

    model_checker grades its own findings as HIGH/MEDIUM/LOW with its own
    issue types; score_engine works in the six protocol categories. The
    mapping is explicit rather than implicit so an unmapped finding type
    shows up as `unrecognised` instead of vanishing.
    """
    type_map = {
        "malicious": "malicious",          # dangerous pickle global
        "suspicious": "malicious",
        "pickle_only": "provenance",
        "pickle_file": "provenance",
        "remote_code": "provenance",       # trust_remote_code/auto_map — needs review, not confirmed malware
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


def check_supply_chain(name: str, version: str) -> dict | None:
    """
    Run repository_checker over one package. None when it could not run.

    Kept behind --supply-chain because it costs several network round trips
    per package (PyPI, GitHub, OpenSSF) and needs GITHUB_TOKEN to avoid
    rate limits.
    """
    if not HAS_REPOSITORY_CHECKER:
        return None
    try:
        return check_repository(f"{name}=={version}", target_type="pypi")
    except Exception as exc:  # noqa: BLE001
        logger.warning("supply-chain check failed for %s: %s", name, exc)
        return None


DEFAULT_JOBS = 8


def _gather(entry, *, engine_for_thread, offline, supply_chain, min_release_age):
    """Every network lookup for one package. Runs on a worker thread."""
    name, version = entry.name, entry.version
    lic = resolve_license(name, version, offline=offline)

    if offline:
        vulns, issues, alternatives = [], None, []
    else:
        vulns = query_vulnerabilities(name, version)
        if vulns is None:
            issues, alternatives = None, []
        else:
            issues, alternatives = analyze_package_risks(
                engine_for_thread(), name, version, vulns, min_release_age)

    repository_info = None
    if supply_chain and not offline:
        repository_info = check_supply_chain(name, version)

    return {
        "license": lic,
        "vulns": vulns,
        "issues": issues,
        "alternatives": alternatives,
        "repository_info": repository_info,
    }


def _prefetch(packages, *, engine_factory, offline, supply_chain, jobs,
              min_release_age=0):
    """
    Look everything up concurrently, keyed by package.

    These are network waits, not CPU work, so threads are the right tool and
    the GIL is not in the way. The reporting loop still walks `packages` in
    order, so output does not depend on which lookup finished first.
    """
    local = threading.local()

    def engine_for_thread():
        engine = getattr(local, "engine", None)
        if engine is None:
            engine = engine_factory()
            local.engine = engine
        return engine

    def work(entry):
        return _gather(entry, engine_for_thread=engine_for_thread,
                       offline=offline, supply_chain=supply_chain,
                       min_release_age=min_release_age)

    if jobs <= 1 or len(packages) <= 1:
        return {id(e): work(e) for e in packages}

    with ThreadPoolExecutor(max_workers=min(jobs, len(packages))) as pool:
        return dict(zip((id(e) for e in packages), pool.map(work, packages)))


def run_scan(
    requirements_path: str,
    supply_chain: bool = False,
    offline: bool = False,
    explain: bool = True,
    report_path: str = "scan_report.json",
    sbom_path: str = "sbom.json",
    models: list | None = None,
    model_pickle_size_mb: int = 0,
    verbose: bool = False,
    transitive: bool = True,
    jobs: int = DEFAULT_JOBS,
    min_release_age: int = 0,
    sarif_path: str | None = None,
) -> list[dict]:
    """
    Scan every package `requirements_path` will install.

    Args:
        supply_chain: also run repository_checker per package (slow; needs
            and ideally GITHUB_TOKEN).
        offline: skip every network lookup - OSV, PyPI and supply chain.
            The license check still runs against installed metadata.
        explain: run the local Ollama explanation at the end.
        transitive: also scan what the listed packages pull in. Off means
            scanning the file rather than the install.
        jobs: concurrent lookups. 1 disables threading.
        min_release_age: days a release must have been public. 0 disables.

    Returns the report list, so tests and other callers can assert on it
    without parsing stdout.
    """
    packages, unscanned_lines = parse_requirements(requirements_path,
                                                   offline=offline)
    if not packages:
        print("No packages found to scan. Check your requirements.txt format.")
        if unscanned_lines:
            print(f"[INFO] {len(unscanned_lines)} line(s) were not in name==version format.")
        return []

    if transitive and not offline:
        direct_count = len(packages)
        packages, unresolved_deps = expand_transitive(packages)
        unscanned_lines = list(unscanned_lines) + unresolved_deps
        pulled_in = len(packages) - direct_count
        if pulled_in:
            print(f"[INFO] {direct_count} direct + {pulled_in} transitive "
                  f"= {len(packages)} packages to scan.")
        if unresolved_deps:
            print(f"[WARNING] {len(unresolved_deps)} dependency requirement(s) "
                  f"could not be resolved; reported as unscanned.")

    # The license registries are downloaded and cached on first use; offline
    # means "use whatever is already cached, never fetch".
    set_offline(offline)

    engine = None
    if offline:
        print("[INFO] Offline mode: OSV, PyPI and supply-chain lookups are skipped.")
    elif not HAS_RECOMMENDATION:
        print("[WARNING] recommendation.py unavailable - typosquatting, "
              "hallucination and deprecation checks will NOT run.")
    else:
        engine = RecommendationEngine()

    if supply_chain and not HAS_REPOSITORY_CHECKER:
        print("[WARNING] repository_checker.py unavailable - supply-chain "
              "checks will NOT run.")

    report = []
    fetched = _prefetch(
        packages,
        engine_factory=lambda: engine,
        offline=offline,
        supply_chain=supply_chain,
        jobs=jobs,
        min_release_age=min_release_age,
    )

    for entry in packages:
        name, version = entry.name, entry.version
        origin = f"  (resolved from {entry.spec})" if entry.resolved else ""
        print(f"[Scanning] {name}=={version} ...{origin}")

        found = fetched[id(entry)]
        lic = found["license"]
        lic_raw = lic["license"]
        lic_detail = classify_license_detailed(lic_raw)
        lic_status = lic_detail["status"]

        license_issue = None
        if lic["unverified"]:
            if lic["source"] == "none":
                # Nothing to read anywhere - a typo, a hallucinated name, or a
                # private package. "The terms may differ" would be nonsense
                # here; there are no terms.
                detail = (f"No license could be read for {name}=={version}: "
                          f"{lic['error']}, and it is not installed locally.")
                warning = f"no license found — {lic['error']}"
            else:
                seen = f" (version {lic['version']})" if lic["version"] else ""
                detail = (f"License for {name}=={version} was read from "
                          f"{lic['source']}{seen} because {lic['error']}. A "
                          f"package can change license between releases, so "
                          f"these terms may not be the pinned release's.")
                warning = (f"license read from {lic['source']}{seen} — "
                           f"{lic['error']}. Terms may differ from "
                           f"{name}=={version}.")
            license_issue = dict(LICENSE_UNVERIFIED_ISSUE, detail=detail)
            print(f"  [WARNING] {warning}")

        # Surfaced here because a cooldown hit rarely moves a package out of
        # ALLOW, and the detail list only shows packages needing attention -
        # so a check the user switched on would otherwise be invisible.
        for issue in found["issues"] or []:
            if "release_age_days" in issue:
                print(f"  [COOLDOWN] {name}=={version} published "
                      f"{issue['release_age_days']} day(s) ago "
                      f"(threshold {issue['min_release_age_days']}).")

        # None, not [] - an empty list means "we looked and found nothing";
        # None means "we never looked", which score_engine turns into low
        # confidence and a WARNING instead of a clean ALLOW.
        vulns = found["vulns"]
        issues = found["issues"]
        alternatives = found["alternatives"]
        osv_unverified = not offline and vulns is None
        if osv_unverified:
            print(f"  [WARNING] OSV lookup failed for {name}=={version} — "
                  f"CVE status unverified (not treated as clean).")

        repository_info = found["repository_info"]

        # `issues is None` means OSV never ran; keep it None so score_engine
        # still sees "never looked" rather than a one-item list.
        # attach_license_unverified shares that contract with MCP.
        scored_issues = attach_license_unverified(
            issues,
            lic,
            detail=license_issue.get("detail") if license_issue else None,
        )

        score_result = calculate_trust_score(
            _build_check_result(lic_status, scored_issues, repository_info)
        )

        entry = {
            "package": name,
            "version": version,
            # The requirement as written, not as resolved. A bare "flask"
            # must not read back as "==3.1.3" - that would claim the file
            # pinned a version it never named.
            "requirement": entry.spec or "(any)",
            "version_resolved": entry.resolved,
            "direct": entry.direct,
            "depth": entry.depth,
            "line": entry.line,
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
                issues, osv_unverified=osv_unverified,
                extra=[license_issue] if license_issue else None),
            "osv_unverified": osv_unverified,
            "scanned": issues is not None,
            "alternatives": alternatives,
            "trust_score": score_result["trust_score"],
            "verdict": score_result["verdict"],
            "hard_block": score_result["hard_block"],
            "hard_block_reasons": score_result["hard_block_reasons"],
            "score_breakdown": score_result["breakdown"],
            "confidence": score_result["confidence"],
        }
        if repository_info is not None:
            # Keep the summary, not the full 20-key payload, so scan_report
            # stays readable. The MCP check_repo_trust tool returns the rest.
            entry["supply_chain"] = {
                "trust_score": repository_info.get("trust_score"),
                "verdict": repository_info.get("verdict"),
                "openssf_score": repository_info.get("openssf_score"),
                "repository": repository_info.get("github_repository"),
                "github_star": repository_info.get("github_star"),
                "last_commit": repository_info.get("last_commit"),
                "signature": repository_info.get("signature"),
                "provenance": repository_info.get("provenance"),
                "issues": repository_info.get("issues") or [],
            }

        report.append(entry)

    # -- AI models ------------------------------------------------------
    model_reports = []
    for model_ref in (models or []):
        if offline:
            print(f"[INFO] Offline: skipping model {model_ref}")
            continue
        print(f"[Scanning model] {model_ref} ...")
        model_report = scan_model(model_ref, model_pickle_size_mb)
        if model_report:
            model_reports.append(model_report)

    print_report(report, verbose=verbose)
    if model_reports:
        print_model_report(model_reports)
    if unscanned_lines:
        print_unscanned_lines(unscanned_lines)

    report_document = {
        "packages": report,
        "models": model_reports,
        "unscanned": unscanned_lines,
    }
    save_report(report_document, report_path)
    build_final_sbom(requirements_path, report, sbom_path, model_reports)

    if sarif_path:
        write_sarif(report, requirements_path, sarif_path)
        print(f"[Saved] SARIF -> {sarif_path}")

    if explain:
        print("\n===== AI Explanation (local model via Ollama) =====\n")
        print(explain_results(report_document))

    # Models participate in the exit code: a BLOCK model must fail CI just
    # like a BLOCK package.
    report_with_models = ScanReport(report)
    for model_report in model_reports:
        report_with_models.append({
            "package": model_report.get("model_id"),
            "verdict": model_report.get("verdict", "WARNING"),
            "_is_model": True,
        })
    report_with_models.unscanned = unscanned_lines
    return report_with_models


class _Parser(argparse.ArgumentParser):
    """
    argparse exits 2 on a usage error, and 2 is our "a package is BLOCKED".
    A CI job cannot tell a typo in the command line from a blocked dependency,
    and the two call for opposite reactions. Usage errors are input errors, so
    they exit 1 like every other unusable input.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_INPUT_ERROR)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="aibom-guard",
        description="Scan a requirements.txt for vulnerability, license and "
                    "supply-chain risk, and emit a CycloneDX SBOM.",
    )
    # Same __version__ pyproject packages, so it cannot disagree with the wheel.
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("requirements", help="path to a requirements.txt")
    parser.add_argument("--supply-chain", action="store_true",
                        help="also run repository/supply-chain trust checks. "
                             "Slow: several network calls per package; set "
                             "GITHUB_TOKEN to avoid rate limits.")
    parser.add_argument("--sarif", dest="sarif_path", metavar="PATH",
                        help="also write SARIF 2.1.0, for GitHub code "
                             "scanning (upload-sarif).")
    parser.add_argument("--min-release-age", type=int, default=0, metavar="DAYS",
                        help="warn about versions published fewer than DAYS "
                             "ago. Compromised releases are usually pulled "
                             "within hours. Default 0 (off).")
    parser.add_argument("-j", "--jobs", type=int, default=DEFAULT_JOBS,
                        metavar="N",
                        help=f"concurrent lookups (default {DEFAULT_JOBS}). "
                             f"1 scans one package at a time.")
    parser.add_argument("--direct-only", action="store_true",
                        help="scan only the packages the file lists, not what "
                             "they pull in. Faster, but a dependency's CVE is "
                             "still your CVE.")
    parser.add_argument("--offline", action="store_true",
                        help="skip all network lookups (OSV, PyPI, GitHub)")
    parser.add_argument("--no-explain", action="store_true",
                        help="skip the local Ollama explanation")
    parser.add_argument("--json", dest="report_path", default="scan_report.json",
                        help="where to write the JSON report "
                             "(default: scan_report.json)")
    parser.add_argument("--sbom", dest="sbom_path", default="sbom.json",
                        help="where to write the CycloneDX SBOM "
                             "(default: sbom.json)")
    parser.add_argument("--model", dest="models", action="append", metavar="REF",
                        help="a Hugging Face model to include in the AIBOM "
                             "(URL or owner/name). Repeatable. The SBOM "
                             "becomes an ML-BOM when this is used.")
    parser.add_argument("--model-pickle-scan", type=int, default=0,
                        metavar="MB",
                        help="download and picklescan model weight files up "
                             "to this size in MB (default: 0 = metadata only)")
    parser.add_argument("--verbose", action="store_true",
                        help="print every vulnerability instead of the worst "
                             "few per package")
    parser.add_argument("--fail-on", choices=("block", "warning", "never"),
                        default="warning",
                        help="what makes the exit code non-zero. "
                             "'warning' (default) also fails on WARNING and "
                             "on requirements lines that could not be "
                             "scanned; 'block' fails only on BLOCK; 'never' "
                             "always exits 0 unless the input is unusable.")
    return parser


# Exit codes. 1 is reserved for "the input could not be scanned at all", so a
# broken invocation is never mistaken for a clean result.
EXIT_CLEAN = 0
EXIT_INPUT_ERROR = 1
EXIT_BLOCK = 2
EXIT_NOT_CLEAN = 3


def decide_exit_code(report: list, unscanned: list, fail_on: str = "warning") -> int:
    """
    Turn a scan into a CI verdict.

    The old rule was `2 if any BLOCK else 0`, which quietly disagreed with the
    documented contract ("0 means everything is ALLOW"). Everything short of a
    hard block passed: a failed OSV lookup, a package that does not exist, a
    license nobody could read, six requirements lines that were never parsed.
    That is the opposite of this project's rule that unexamined things do not
    get a pass, and it is the failure mode that matters most, because a gate
    that reports success while checking nothing is worse than no gate.
    """
    if any(item.get("verdict") == "BLOCK" for item in report):
        return EXIT_BLOCK
    if fail_on in ("block", "never"):
        return EXIT_CLEAN
    if unscanned:
        return EXIT_NOT_CLEAN
    if any(item.get("verdict") != "ALLOW" for item in report):
        return EXIT_NOT_CLEAN
    return EXIT_CLEAN


def _configure_cli_logging(verbose: bool) -> None:
    """
    Route library warnings to stderr for CLI runs.

    The scanning modules log rather than print, because mcp_server imports the
    same functions and stdout is the JSON-RPC channel there. Without a handler
    the CLI would show nothing; stderr keeps the report on stdout pipeable.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="  [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _configure_cli_logging(args.verbose)

    try:
        report = run_scan(
            args.requirements,
            supply_chain=args.supply_chain,
            offline=args.offline,
            explain=not args.no_explain,
            report_path=args.report_path,
            sbom_path=args.sbom_path,
            models=args.models,
            model_pickle_size_mb=args.model_pickle_scan,
            verbose=args.verbose,
            transitive=not args.direct_only,
            jobs=args.jobs,
            min_release_age=args.min_release_age,
            sarif_path=args.sarif_path,
        )
    except FileNotFoundError:
        print(f"[ERROR] No such file: {args.requirements}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    if not report:
        return EXIT_INPUT_ERROR

    code = decide_exit_code(report, getattr(report, "unscanned", []),
                            fail_on=args.fail_on)
    if code == EXIT_NOT_CLEAN:
        print("\n[EXIT 3] Nothing is hard-blocked, but this scan is not clean "
              "- see the WARNING rows and any unscanned lines above. "
              "Use --fail-on block to gate only on BLOCK.")
    return code


if __name__ == "__main__":
    sys.exit(main())
