"""
Concurrent package evidence collection for the CLI scan loop.

Runs OSV, recommendation, and optional repository_checker lookups per package.
``scanner.run_scan`` consumes the returned dicts; nothing here prints or scores.
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from ._adapters import _vulns_to_issues
from .osv_client import query_vulnerabilities

logger = logging.getLogger(__name__)

OSV_UNVERIFIED_ISSUE = {
    "type": "unverified",
    "severity": "unknown",
    "detail": (
        "OSV vulnerability lookup failed (network/API error). "
        "CVE status is unverified — not the same as 'no known vulnerabilities'."
    ),
}

DEFAULT_JOBS = 8


def analyze_package_risks(
    engine,
    name: str,
    version: str,
    vulns: list | None,
    min_release_age: int = 0,
) -> tuple[list | None, list]:
    """
    Run recommendation over one package and return ``(issues, alternatives)``.

    When ``vulns`` is ``None`` (OSV lookup failed), return ``(None, [])`` so the
    caller passes ``issues=None`` into score_engine — meaning unverified, not clean.
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
    """Issues shown in the report/terminal (may include unverified markers)."""
    shown: list = []
    if osv_unverified:
        shown.append(dict(OSV_UNVERIFIED_ISSUE))
    if extra:
        shown.extend(extra)
    if issues:
        shown.extend(issues)
    return shown


def check_supply_chain(name: str, version: str) -> dict | None:
    """
    Run repository_checker over one package. None when it could not run.

    Kept behind ``--supply-chain`` because it costs several network round trips
    per package and needs ``GITHUB_TOKEN`` to avoid rate limits.
    """
    from aibom_guardian import scanner as sc

    if not sc.HAS_REPOSITORY_CHECKER:
        return None
    try:
        return sc.check_repository(f"{name}=={version}", target_type="pypi")
    except Exception as exc:  # noqa: BLE001
        logger.warning("supply-chain check failed for %s: %s", name, exc)
        return None


def _gather(entry, *, engine_for_thread, offline, supply_chain, min_release_age):
    """Every network lookup for one package. Runs on a worker thread."""
    # Import at call time so tests can monkeypatch scanner.resolve_license et al.
    from aibom_guardian import scanner as sc

    name, version = entry.name, entry.version
    lic = sc.resolve_license(name, version, offline=offline)

    if offline:
        vulns, issues, alternatives = [], None, []
    else:
        vulns = sc.query_vulnerabilities(name, version)
        if vulns is None:
            issues, alternatives = None, []
        else:
            issues, alternatives = sc.analyze_package_risks(
                engine_for_thread(), name, version, vulns, min_release_age)

    repository_info = None
    if supply_chain and not offline:
        repository_info = sc.check_supply_chain(name, version)

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
    Look everything up concurrently, keyed by package id(entry).

    These are network waits, not CPU work, so threads are appropriate. The
    reporting loop still walks ``packages`` in file order so output does not
    depend on which lookup finished first.
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
