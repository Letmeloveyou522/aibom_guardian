"""
npm_checker.py
-----------------------------------
npm ecosystem support: scan ``package.json`` ``dependencies`` and
``devDependencies``, then walk registry ``dependencies`` the same way
``_requirements.expand_transitive`` walks PyPI ``requires_dist``.

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
NPM_TRANSITIVE_MAX_DEPTH = 12

_REGISTRY_CACHE: dict = {}
_NPM_SESSION = None
_THREAD_LOCAL = threading.local()

# Semver-ish token after stripping a leading range operator.
_VERSION_TOKEN = re.compile(
    r"^(\d+\.\d+\.\d+(?:[-+][\w.-]+)?|\d+\.\d+(?:[-+][\w.-]+)?|\d+(?:[-+][\w.-]+)?)$"
)
# python-semver (and packaging) do not speak npm's ^ / ~ / || grammar, and
# neither is a project dependency, so range matching stays local and small.
_SEMVER_RE = re.compile(
    r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


class _Semver(NamedTuple):
    major: int
    minor: int
    patch: int
    prerelease: tuple
    precision: int  # 1, 2, or 3 components written in the spec


class NpmPackage(NamedTuple):
    """One dependency line from package.json, normalized for OSV lookup."""

    name: str
    version: str          # normalized version sent to OSV / registry
    spec: str             # original range string from package.json
    section: str          # "dependencies" or "devDependencies"
    exact: bool           # True when spec is an exact pin, not a range prefix
    direct: bool = True   # False when pulled in by another package
    depth: int = 0        # 0 = named in package.json


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


def _normalize_npm_name(name: str) -> str:
    """Registry names are case-insensitive; keep scope slashes intact."""
    return str(name or "").strip().lower()


def _parse_semver(text: str) -> _Semver | None:
    """Parse a version or range base into comparable parts. None if not semver."""
    raw = str(text or "").strip()
    match = _SEMVER_RE.match(raw)
    if not match:
        return None
    major = int(match.group(1))
    minor_s, patch_s, pre_s = match.group(2), match.group(3), match.group(4)
    precision = 1 + int(minor_s is not None) + int(patch_s is not None)
    minor = int(minor_s) if minor_s is not None else 0
    patch = int(patch_s) if patch_s is not None else 0
    prerelease = tuple(pre_s.split(".")) if pre_s else ()
    return _Semver(major, minor, patch, prerelease, precision)


def _pre_sort_key(parts: tuple) -> tuple:
    key = []
    for part in parts:
        if str(part).isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, str(part)))
    return tuple(key)


def _semver_sort_key(version: _Semver) -> tuple:
    # A release ranks above any prerelease of the same triple, matching semver.
    return (version.major, version.minor, version.patch,
            not version.prerelease, _pre_sort_key(version.prerelease))


def _npm_versions(package_name: str) -> list:
    """
    Published versions of an npm package.

    Cached per process: a tree walk asks for the same package's version list
    from many parents, and registry.npmjs.org should not be asked twice.
    """
    key = ("__versions__", _normalize_npm_name(package_name))
    if key in _REGISTRY_CACHE:
        return _REGISTRY_CACHE[key]

    try:
        from urllib.parse import quote
    except ImportError:                              # pragma: no cover
        return []

    url = NPM_REGISTRY_URL.format(package=quote(package_name, safe=""))
    try:
        response = _npm_session().get(url, timeout=NPM_TIMEOUT_SEC)
        response.raise_for_status()
        versions = list((response.json().get("versions") or {}).keys())
    except Exception:                                # noqa: BLE001 - network
        _REGISTRY_CACHE[key] = []
        return []

    _REGISTRY_CACHE[key] = versions
    return list(versions)


def _npm_spec_matches(spec: str, version: str) -> bool:
    """
    True when ``version`` satisfies a simple npm range.

    Supports exact pins, ``^``, ``~``, and ``||`` unions of those. Compound
    comparators (``>=`` / ``<`` hyphen ranges, wildcards) are out of scope.
    """
    text = str(spec or "").strip()
    if not text or text in ("*", "latest"):
        return False
    if "||" in text:
        return any(_npm_spec_matches(part, version) for part in text.split("||"))
    if " - " in text:
        return False

    parsed = _parse_semver(version)
    if parsed is None:
        return False

    if text.startswith((">=", "<=", ">", "<")):
        return False

    if text.startswith("^"):
        base = _parse_semver(text[1:].strip())
        return base is not None and _caret_allows(base, parsed)
    if text.startswith("~"):
        base = _parse_semver(text[1:].strip())
        return base is not None and _tilde_allows(base, parsed)

    if text.startswith("="):
        text = text[1:].strip()
    base = _parse_semver(text)
    if base is None:
        return False
    return (parsed.major, parsed.minor, parsed.patch) == (
        base.major, base.minor, base.patch
    ) and parsed.prerelease == base.prerelease


def _caret_allows(base: _Semver, version: _Semver) -> bool:
    if _semver_sort_key(version) < _semver_sort_key(base):
        return False
    if base.major != 0:
        return version.major == base.major
    if base.minor != 0:
        return version.major == 0 and version.minor == base.minor
    if base.precision >= 3:
        return (version.major == 0 and version.minor == 0
                and version.patch == base.patch)
    if base.precision == 2:
        return version.major == 0 and version.minor == 0
    return version.major == 0


def _tilde_allows(base: _Semver, version: _Semver) -> bool:
    if _semver_sort_key(version) < _semver_sort_key(base):
        return False
    if base.precision <= 1:
        return version.major == base.major
    return version.major == base.major and version.minor == base.minor


def _resolve_npm_range(name: str, spec: str) -> str | None:
    """
    Pick the version a range would install: the newest release that satisfies
    it. Returns None when the registry cannot be reached or nothing matches.
    """
    candidates = _npm_versions(name)
    if not candidates:
        return None

    parsed = []
    for raw in candidates:
        version = _parse_semver(raw)
        if version is None:
            continue
        parsed.append((raw, version))

    spec_has_pre = False
    for part in str(spec or "").split("||"):
        token = _parse_semver(part.strip().lstrip("^~="))
        if token is not None and token.prerelease:
            spec_has_pre = True
            break

    def matching(allow_prerelease: bool) -> list:
        found = []
        for raw, version in parsed:
            if version.prerelease and not allow_prerelease:
                continue
            if _npm_spec_matches(spec, raw):
                found.append((raw, version))
        return found

    allowed = matching(spec_has_pre)
    if not allowed:
        allowed = matching(True)
    if not allowed:
        return None
    return max(allowed, key=lambda item: _semver_sort_key(item[1]))[0]


def _npm_dependencies(name: str, version: str) -> dict:
    """
    Runtime ``dependencies`` the registry records for one exact release.

    Per-version, not per-project: a package's dependency list changes between
    releases. Same role as PyPI ``requires_dist``.
    """
    key = ("__deps__", _normalize_npm_name(name), version)
    if key in _REGISTRY_CACHE:
        return _REGISTRY_CACHE[key]

    try:
        from urllib.parse import quote
    except ImportError:                              # pragma: no cover
        return {}

    url = NPM_REGISTRY_VERSION_URL.format(
        package=quote(name, safe=""),
        version=quote(version, safe=""),
    )
    try:
        response = _npm_session().get(url, timeout=NPM_TIMEOUT_SEC)
        response.raise_for_status()
        deps = response.json().get("dependencies") or {}
    except Exception:                                # noqa: BLE001 - network
        _REGISTRY_CACHE[key] = {}
        return {}

    if not isinstance(deps, dict):
        deps = {}
    cleaned = {}
    for dep_name, dep_spec in deps.items():
        if not isinstance(dep_name, str) or not dep_name.strip():
            continue
        cleaned[dep_name.strip()] = (
            str(dep_spec).strip() if dep_spec is not None else ""
        )
    _REGISTRY_CACHE[key] = cleaned
    return dict(cleaned)


def _spec_is_exact(spec: str) -> bool:
    normalized = normalize_npm_version(spec)
    return bool(normalized and normalized[1])


def expand_npm_transitive(
    pinned: list,
    *,
    offline: bool = False,
    max_depth: int = NPM_TRANSITIVE_MAX_DEPTH,
) -> tuple[list, list]:
    """
    Walk the npm dependency tree and return every package that will be installed.

    Returns (packages, unresolved). Resolved from registry ``dependencies``, so
    nothing needs to be installed.

    First occurrence of a name wins, so a direct pin is not replaced by a
    dependency's range. Cycles stop at the seen set, not the depth cap.
    """
    if offline:
        return list(pinned), []

    packages = list(pinned)
    unresolved: list = []
    seen = {_normalize_npm_name(p.name) for p in pinned}
    frontier = list(pinned)

    for depth in range(1, max_depth + 1):
        discovered = []
        for parent in frontier:
            deps = _npm_dependencies(parent.name, parent.version)
            for req_name, req_spec in deps.items():
                key = _normalize_npm_name(req_name)
                if key in seen:
                    continue
                seen.add(key)

                version = _resolve_npm_range(req_name, req_spec)
                if version is None:
                    unresolved.append(
                        f"{req_name}@{req_spec}  (required by {parent.name})"
                    )
                    continue

                child = NpmPackage(
                    req_name,
                    version,
                    req_spec,
                    parent.section,
                    _spec_is_exact(req_spec),
                    direct=False,
                    depth=depth,
                )
                packages.append(child)
                discovered.append(child)

        if not discovered:
            break
        frontier = discovered

    return packages, unresolved


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
        # None, not [] — offline never queried OSV (same contract as scanner).
        vulns, issues = None, None
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
        "direct": entry.direct,
        "depth": entry.depth,
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
    transitive: bool = True,
) -> list:
    """
    Scan npm ``dependencies`` / ``devDependencies`` from ``package_json_path``.

    Returns a list of per-package report rows (same shape as ``run_scan``).
    ``transitive`` also scans what those packages pull in from the registry.
    """
    from .scanner import ScanReport, explain_results

    packages, unscanned_lines = parse_package_json(package_json_path)
    if not packages:
        print("No npm packages found to scan. Check your package.json.")
        if unscanned_lines:
            print(f"[INFO] {len(unscanned_lines)} entr(y/ies) could not be parsed.")
        return []

    if transitive and not offline:
        direct_count = len(packages)
        packages, unresolved_deps = expand_npm_transitive(packages)
        unscanned_lines = list(unscanned_lines) + unresolved_deps
        pulled_in = len(packages) - direct_count
        if pulled_in:
            print(f"[INFO] {direct_count} direct + {pulled_in} transitive "
                  f"= {len(packages)} packages to scan.")
        if unresolved_deps:
            print(f"[WARNING] {len(unresolved_deps)} dependency requirement(s) "
                  f"could not be resolved; reported as unscanned.")

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
