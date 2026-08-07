"""
scanner.py
-----------------------------------
AIBOM-Guard - main CLI.

Takes a requirements.txt file and, for each pinned package:

  1) classifies the license                  license_checker.py
  2) queries OSV for known vulnerabilities   osv_client.py        (3)
  3) detects typosquatting / hallucinated /
     deprecated packages and suggests fixes  recommendation.py    (3)
  4) optionally checks supply-chain trust    repository_checker.py (2)
  5) scores everything into one verdict      score_engine.py      (4)
  6) writes scan_report.json + CycloneDX sbom.json                (5)
  7) optionally explains the result locally  ai_explainer.py

Usage:
    python3 scanner.py examples/sample-requirements.txt
    python3 scanner.py reqs.txt --supply-chain      # add module 2 checks
    python3 scanner.py reqs.txt --offline           # no PyPI/OSV lookups
    python3 scanner.py reqs.txt --no-explain --json out.json

Exit codes (so this can gate CI):
    0  every package is ALLOW
    1  bad input / nothing to scan
    2  at least one package is BLOCK
"""

import argparse
import json
import re
import sys
from typing import NamedTuple
from importlib.metadata import version as installed_version, PackageNotFoundError, metadata

from osv_client import query_vulnerabilities
from license_checker import classify_license_detailed, set_offline
from sbom_generator import build_final_sbom
from ai_explainer import explain_results
from score_engine import calculate_trust_score

try:
    from prettytable import PrettyTable
    HAS_PRETTYTABLE = True
except ImportError:
    HAS_PRETTYTABLE = False

# Modules 2 and 3 are optional at import time so a partial checkout, or a
# missing transitive dependency, degrades to the core scan instead of
# preventing the CLI from starting at all.
try:
    from recommendation import RecommendationEngine
    HAS_RECOMMENDATION = True
except ImportError:
    HAS_RECOMMENDATION = False

try:
    from repository_checker import check_repository
    HAS_REPOSITORY_CHECKER = True
except ImportError:
    HAS_REPOSITORY_CHECKER = False

try:
    from model_checker import check_model
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


class Pinned(NamedTuple):
    """
    One requirement resolved to the single version that will be installed.

    `resolved` is False when the file named the version outright and True when
    a range was narrowed down here, because those are different claims: an
    exact pin is what the project ships, a resolved range is what it would get
    if installed today.
    """

    name: str
    version: str
    spec: str
    resolved: bool


# Lines that are directives rather than requirements. Following them would
# mean fetching or building something, which a scanner has no business doing.
_DIRECTIVE_PREFIXES = ("-r", "--requirement", "-c", "--constraint",
                       "-e", "--editable", "-f", "--find-links", "-i",
                       "--index-url", "--extra-index-url", "--no-binary",
                       "--only-binary", "--hash", "--pre", "--trusted-host")


def _pypi_versions(package_name: str) -> list:
    """
    Versions of a package this interpreter could actually install.

    Releases whose `requires_python` excludes the running interpreter are left
    out, because resolving a range to a version pip would refuse means
    scanning something the project will never get. pytest 9 needs Python 3.10;
    on 3.9 the honest answer to `pytest>=8.0` is pytest 8, not pytest 9.
    """
    global _PYPI_SESSION

    key = ("__versions__", package_name.lower())
    if key in _RELEASE_CACHE:
        return _RELEASE_CACHE[key]

    try:
        import requests
        from urllib.parse import quote
    except ImportError:                              # pragma: no cover
        return []

    if _PYPI_SESSION is None:
        _PYPI_SESSION = requests.Session()

    url = f"https://pypi.org/pypi/{quote(package_name, safe='')}/json"
    try:
        response = _PYPI_SESSION.get(url, timeout=PYPI_TIMEOUT_SEC)
        response.raise_for_status()
        releases = response.json().get("releases") or {}
    except Exception:                                # noqa: BLE001 - network
        _RELEASE_CACHE[key] = []
        return []

    try:
        from packaging.specifiers import SpecifierSet
        python_version = ".".join(str(n) for n in sys.version_info[:3])
    except ImportError:                              # pragma: no cover
        SpecifierSet = None

    usable = []
    for version, files in releases.items():
        # No files means the release was never actually published; a fully
        # yanked one should not be what a range resolves to.
        if not files or all(f.get("yanked") for f in files):
            continue
        if SpecifierSet is not None:
            requires = next((f.get("requires_python") for f in files
                             if f.get("requires_python")), None)
            if requires:
                try:
                    if python_version not in SpecifierSet(requires):
                        continue
                except Exception:                    # noqa: BLE001 - bad spec
                    pass
        usable.append(version)

    _RELEASE_CACHE[key] = usable
    return usable


def _resolve_specifier(name: str, spec: str) -> str | None:
    """
    Pick the version a range would install: the newest release that satisfies
    it. Returns None when PyPI cannot be reached or nothing matches.
    """
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import InvalidVersion, Version
    except ImportError:                              # pragma: no cover
        return None

    candidates = _pypi_versions(name)
    if not candidates:
        return None

    parsed = []
    for raw in candidates:
        try:
            parsed.append(Version(raw))
        except InvalidVersion:
            continue

    try:
        allowed = list(SpecifierSet(spec or "").filter(parsed))
    except Exception:                                # noqa: BLE001 - bad spec
        return None
    if not allowed:
        # Every match was a pre-release; take those rather than give up.
        try:
            allowed = list(SpecifierSet(spec or "").filter(parsed, prereleases=True))
        except Exception:                            # noqa: BLE001
            return None
    if not allowed:
        return None
    return str(max(allowed))


def parse_requirements(path: str, offline: bool = False) -> tuple[list, list]:
    """
    Parse a requirements file into the exact versions to scan.

    Returns (packages, unscanned_lines).

    Real requirements files are not all exact pins. Only accepting
    ``name==version`` meant this project's own requirements.txt scanned one
    line out of seven and still exited 0 - a gate that checks almost nothing
    and reports success. So a range is resolved against PyPI to the version it
    would actually install, and the report records that the version was chosen
    here rather than pinned by the file.

    Anything genuinely unscannable - a ``-r`` include, a VCS or URL
    requirement, a range that could not be resolved offline - goes into
    `unscanned_lines` and is reported, never dropped.
    """
    try:
        from packaging.requirements import InvalidRequirement, Requirement
        from packaging.markers import UndefinedEnvironmentName
        has_packaging = True
    except ImportError:                              # pragma: no cover
        has_packaging = False

    packages: list = []
    unscanned: list[str] = []
    seen: dict = {}

    def skip(line: str, reason: str) -> None:
        unscanned.append(line)
        print(f"[INFO] Not scanned ({reason}): {line}")

    def add(name: str, version: str, spec: str, resolved: bool) -> None:
        # PEP 503: names differing only in case or in -/_/. are one project.
        # Reporting Django and django as two rows would double every finding.
        key = (re.sub(r"[-_.]+", "-", name).lower(), version)
        if key in seen:
            return
        seen[key] = True
        packages.append(Pinned(name, version, spec, resolved))

    # utf-8-sig, not utf-8: a requirements.txt saved by Notepad or exported
    # from Windows tooling starts with a BOM, and it would otherwise glue
    # itself to the first requirement and make that line unparseable.
    with open(path, "r", encoding="utf-8-sig") as f:
        for raw_line in f:
            line = raw_line.split(" #")[0].split("\t#")[0].strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith(_DIRECTIVE_PREFIXES):
                skip(line, "pip directive, not a requirement")
                continue
            if "://" in line:
                skip(line, "URL or VCS requirement")
                continue

            if not has_packaging:
                match = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)$",
                                 line)
                if match:
                    add(match.group(1), match.group(2),
                        "==" + match.group(2), False)
                else:
                    skip(line, "packaging not installed; only name==version parsed")
                continue

            try:
                requirement = Requirement(line)
            except InvalidRequirement as exc:
                skip(line, f"not a valid requirement: {exc}")
                continue

            # An environment marker that is false here describes a dependency
            # this platform never installs.
            if requirement.marker is not None:
                try:
                    if not requirement.marker.evaluate():
                        print(f"[INFO] Skipped (marker does not apply here): {line}")
                        continue
                except UndefinedEnvironmentName:
                    pass          # extras-only markers; scan the package

            spec = str(requirement.specifier)
            exact = [s for s in requirement.specifier if s.operator in ("==", "===")]
            if len(exact) == 1 and "*" not in exact[0].version:
                add(requirement.name, exact[0].version, spec, False)
                continue

            if offline:
                skip(line, "offline: a version range cannot be resolved")
                continue

            version = _resolve_specifier(requirement.name, spec)
            if version is None:
                skip(line, "no published version satisfies this range")
                continue

            print(f"[INFO] Resolved {line} -> {requirement.name}=={version}")
            add(requirement.name, version, spec, True)

    return packages, unscanned


PYPI_RELEASE_URL = "https://pypi.org/pypi/{package}/{version}/json"
PYPI_TIMEOUT_SEC = 8.0

# One session and one cache per process: a requirements file repeats packages
# across transitive pins, and pypi.org should not be asked twice for the same
# release.
_PYPI_SESSION = None
_RELEASE_CACHE: dict = {}


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
    global _PYPI_SESSION

    key = (package_name.lower(), version)
    if key in _RELEASE_CACHE:
        return _RELEASE_CACHE[key]

    try:
        import requests
        from urllib.parse import quote
    except ImportError as exc:                      # pragma: no cover
        return "", "", f"requests unavailable: {exc}"

    if _PYPI_SESSION is None:
        _PYPI_SESSION = requests.Session()

    url = PYPI_RELEASE_URL.format(package=quote(package_name, safe=""),
                                  version=quote(version, safe=""))
    try:
        response = _PYPI_SESSION.get(url, timeout=PYPI_TIMEOUT_SEC)
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


def _vulns_to_issues(vulns: list) -> list:
    """
    OSV 취약점 목록을 score_engine이 기대하는 issues 형식으로 변환.

    cvss_score is carried through deliberately: score_engine falls back to
    the CVSS base score when a severity label is missing, and dropping the
    field here would disable that path.
    """
    issues = []
    for v in vulns:
        sev = str(v.get("severity", "unknown")).lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "unknown"
        issue = {
            "type": "cve",
            "id": v.get("id"),
            "severity": sev,
            "summary": v.get("summary") or v.get("detail"),
            "detail": v.get("detail") or v.get("summary"),
        }
        if v.get("cvss_score") is not None:
            issue["cvss_score"] = v["cvss_score"]
        if v.get("aliases"):
            issue["aliases"] = v["aliases"]
        issues.append(issue)
    return issues


OSV_UNVERIFIED_ISSUE = {
    "type": "unverified",
    "severity": "unknown",
    "detail": (
        "OSV vulnerability lookup failed (network/API error). "
        "CVE status is unverified — not the same as 'no known vulnerabilities'."
    ),
}

# Same contract as above: a license read from something other than the pinned
# release describes a version nobody asked about. severity "unknown" is what
# score_engine._confidence keys on, so this lowers confidence rather than
# passing off another version's terms as the answer.
LICENSE_UNVERIFIED_ISSUE = {
    "type": "unverified",
    "severity": "unknown",
    "detail": "License could not be read from the pinned release.",
}


def _build_check_result(
    license_status: str,
    issues: list | None,
    repository_info: dict | None = None,
    model_info: dict | None = None,
) -> dict:
    """
    score_engine.calculate_trust_score() 입력 스키마에 맞게 조립.

    `issues` is the merged list from every producer - OSV plus whatever
    module 3 found - already in the team Data Protocol shape. Module 2's
    full result goes into `repository_info`; score_engine reads its
    trust_score and folds in its issues.
    """
    return {
        "type": "library",
        "license_status": license_status,
        "issues": issues,
        "model_info": model_info,
        "repository_info": repository_info,
    }


def analyze_package_risks(
    engine,
    name: str,
    version: str,
    vulns: list | None,
) -> tuple[list | None, list]:
    """
    Run module 3 over one package and return (issues, alternatives).

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
        result = engine.analyze_package(name, version, cve_issues=_vulns_to_issues(vulns))
    except Exception as exc:  # noqa: BLE001 - network/parse errors must not stop a scan
        print(f"  [WARNING] recommendation engine failed for {name}: {exc}")
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


def _vuln_count_label(vulns: list | None) -> str:
    if vulns is None:
        return "?"
    return str(len(vulns))


def scan_model(model_ref: str, max_pickle_size_mb: int = 0) -> dict | None:
    """
    Run module 1 over one Hugging Face model and score it.

    Returns the model_checker report with the AIBOM-Guard verdict folded in,
    or None when the model could not be read at all.

    `max_pickle_size_mb` defaults to 0 (metadata only). Downloading weights
    to scan pickle contents is opt-in because a single model can be tens of
    gigabytes; --model-pickle-scan raises it.
    """
    if not HAS_MODEL_CHECKER:
        print("  [WARNING] model_checker.py unavailable - model scan skipped.")
        return None

    try:
        report = check_model(model_ref, max_pickle_size_mb=max_pickle_size_mb)
    except Exception as exc:  # noqa: BLE001 - a bad model must not end the run
        print(f"  [ERROR] could not read model '{model_ref}': {exc}")
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
    Translate model_checker's findings into team Data Protocol issues.

    model_checker grades its own findings as HIGH/MEDIUM/LOW with its own
    issue types; score_engine works in the seven protocol categories. The
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
    Run module 2 over one package. Returns None when it could not run.

    Kept behind --supply-chain because it costs several network round trips
    per package (PyPI, GitHub, OpenSSF) and needs GITHUB_TOKEN to avoid
    rate limits.
    """
    if not HAS_REPOSITORY_CHECKER:
        return None
    try:
        return check_repository(f"{name}=={version}", target_type="pypi")
    except Exception as exc:  # noqa: BLE001
        print(f"  [WARNING] supply-chain check failed for {name}: {exc}")
        return None


def run_scan(
    requirements_path: str,
    supply_chain: bool = False,
    offline: bool = False,
    explain: bool = True,
    report_path: str = "scan_report.json",
    sbom_path: str = "sbom.json",
    models: list | None = None,
    model_pickle_size_mb: int = 0,
) -> list[dict]:
    """
    Scan every pinned package in `requirements_path`.

    Args:
        supply_chain: also run module 2 per package (slow; needs network
            and ideally GITHUB_TOKEN).
        offline: skip every network lookup - OSV, PyPI and supply chain.
            The license check still runs against installed metadata.
        explain: run the local Ollama explanation at the end.

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

    for entry in packages:
        name, version = entry.name, entry.version
        origin = f"  (resolved from {entry.spec})" if entry.resolved else ""
        print(f"[Scanning] {name}=={version} ...{origin}")

        lic = resolve_license(name, version, offline=offline)
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
                found = f" (version {lic['version']})" if lic["version"] else ""
                detail = (f"License for {name}=={version} was read from "
                          f"{lic['source']}{found} because {lic['error']}. A "
                          f"package can change license between releases, so "
                          f"these terms may not be the pinned release's.")
                warning = (f"license read from {lic['source']}{found} — "
                           f"{lic['error']}. Terms may differ from "
                           f"{name}=={version}.")
            license_issue = dict(LICENSE_UNVERIFIED_ISSUE, detail=detail)
            print(f"  [WARNING] {warning}")

        if offline:
            # None, not [] - the distinction matters. An empty list means
            # "we looked and found nothing"; None means "we never looked",
            # which score_engine turns into low confidence and a
            # WARNING verdict instead of a clean ALLOW.
            vulns, issues, alternatives = [], None, []
            osv_unverified = False
        else:
            vulns = query_vulnerabilities(name, version)
            osv_unverified = vulns is None
            if osv_unverified:
                print(f"  [WARNING] OSV lookup failed for {name}=={version} — "
                      f"CVE status unverified (not treated as clean).")
                issues, alternatives = None, []
            else:
                issues, alternatives = analyze_package_risks(engine, name, version, vulns)

        repository_info = None
        if supply_chain and not offline:
            repository_info = check_supply_chain(name, version)

        # `issues is None` means OSV never ran; keep it None so score_engine
        # still sees "never looked" rather than a one-item list.
        scored_issues = issues
        if license_issue is not None and issues is not None:
            scored_issues = issues + [license_issue]

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

    # -- AI models (module 1) ------------------------------------------------
    model_reports = []
    for model_ref in (models or []):
        if offline:
            print(f"[INFO] Offline: skipping model {model_ref}")
            continue
        print(f"[Scanning model] {model_ref} ...")
        model_report = scan_model(model_ref, model_pickle_size_mb)
        if model_report:
            model_reports.append(model_report)

    print_report(report)
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


def print_report(report: list[dict]):
    print("\n===== AIBOM-Guard Scan Results =====\n")

    # Only widen the table when supply-chain data was actually collected;
    # three empty columns on a normal scan is just noise.
    has_supply = any(item.get("supply_chain") for item in report)

    if HAS_PRETTYTABLE:
        table = PrettyTable()
        columns = ["Package", "Version", "License Status", "Vulns"]
        if has_supply:
            columns += ["OpenSSF", "Signed"]
        columns += ["Trust Score", "Verdict"]
        table.field_names = columns

        for item in report:
            row = [
                item["package"],
                item["version"],
                item["license_status"],
                _vuln_count_label(item["vulnerabilities"]),
            ]
            if has_supply:
                supply = item.get("supply_chain") or {}
                openssf = supply.get("openssf_score")
                signed = supply.get("signature")
                row += [
                    openssf if openssf is not None else "-",
                    ("yes" if signed else "no") if signed is not None else "-",
                ]
            row += [item["trust_score"], item["verdict"]]
            table.add_row(row)
        print(table)
    else:
        for item in report:
            print(f"{item['package']}=={item['version']} | license:{item['license_status']} | "
                  f"vulns:{_vuln_count_label(item['vulnerabilities'])} | "
                  f"score:{item['trust_score']} | {item['verdict']}")

    unverified = [i for i in report if i.get("osv_unverified")]
    if unverified:
        print("\n[OSV lookup failed — CVE status unverified]")
        for item in unverified:
            print(f"- {item['package']}=={item['version']}: "
                  f"OSV query failed; not treated as vulnerability-free")

    # Show details for anything that isn't a clean ALLOW
    risky = [i for i in report if i["verdict"] != "ALLOW"]
    if risky:
        print("\n[Packages needing attention]")
        for item in risky:
            print(f"- {item['package']}=={item['version']} "
                  f"({item['verdict']}, score {item['trust_score']})")

            for reason in item.get("hard_block_reasons") or []:
                print(f"    [HARD BLOCK] {reason}")

            if item.get("osv_unverified"):
                print(f"    [unverified] {OSV_UNVERIFIED_ISSUE['detail']}")

            if item["license_status"] in ("REVIEW", "BLOCKED", "UNKNOWN"):
                license_text = str(item["license_raw"])
                if len(license_text) > 80:      # full license texts are huge
                    license_text = license_text[:77].replace("\n", " ") + "..."
                print(f"    License: {license_text} -> {item['license_status']}")

            # Non-CVE findings first: a typosquat or a hallucinated package is
            # a different kind of problem from a known vulnerability, and it
            # is what module 3 exists to surface.
            for issue in item.get("issues") or []:
                if issue.get("type") == "cve":
                    continue
                print(f"    [{issue.get('type')}] {issue.get('detail') or issue.get('summary')}")

            for issue in item.get("issues") or []:
                if issue.get("type") != "cve":
                    continue
                extra = ""
                if issue.get("cvss_score") is not None:
                    extra = f", CVSS {issue['cvss_score']}"
                if issue.get("aliases"):
                    extra += f", aka {', '.join(issue['aliases'])}"
                print(f"    Vuln {issue.get('id')} "
                      f"(severity {issue.get('severity')}{extra}): "
                      f"{issue.get('summary') or issue.get('detail')}")

            supply = item.get("supply_chain")
            if supply:
                print(f"    Supply chain: {supply.get('verdict')} "
                      f"(trust {supply.get('trust_score')}, "
                      f"OpenSSF {supply.get('openssf_score')})")
                for issue in supply.get("issues") or []:
                    print(f"      - [{issue.get('severity')}] {issue.get('detail')}")

            for alt in item.get("alternatives") or []:
                print(f"    -> suggested: {alt.get('target')} "
                      f"({alt.get('confidence')}) - {alt.get('reason')}")


def print_model_report(model_reports: list[dict]):
    """Terminal summary for the AI models in this scan."""
    print("\n===== AI Models =====\n")

    if HAS_PRETTYTABLE:
        table = PrettyTable()
        table.field_names = ["Model", "License", "Family", "Weights",
                             "Remote code", "Card", "Score", "Verdict"]
        for model in model_reports:
            formats = model.get("file_formats") or {}
            weights = "safetensors" if formats.get("has_safetensors") else "-"
            if formats.get("pickle_only"):
                weights = "PICKLE ONLY"
            elif formats.get("pickle"):
                weights += " + pickle"
            table.add_row([
                model.get("model_id"),
                model.get("license") or "NOT DECLARED",
                model.get("license_family", "-"),
                weights,
                "YES" if model.get("trust_remote_code") else "no",
                f"{(model.get('model_card') or {}).get('completeness', 0)}/100",
                model.get("risk_score"),
                model.get("verdict"),
            ])
        print(table)
    else:
        for model in model_reports:
            print(f"{model.get('model_id')} | license:{model.get('license')} "
                  f"| score:{model.get('risk_score')} | {model.get('verdict')}")

    for model in model_reports:
        if model.get("verdict") == "ALLOW":
            continue
        print(f"\n- {model.get('model_id')} ({model.get('verdict')}, "
              f"score {model.get('risk_score')})")
        if model.get("license_family") in ("ai-community", "ai-behavioural"):
            print(f"    License: {model.get('license')} "
                  f"[{model['license_family']}] - {model.get('license_reason')}")
        for reason in model.get("hard_block_reasons") or []:
            print(f"    [HARD BLOCK] {reason}")
        for issue in model.get("issues") or []:
            # Hub errors arrive as multi-line HTTP dumps; keep the report
            # readable and leave the full text in scan_report.json.
            message = " ".join(str(issue.get("message") or "").split())
            if len(message) > 160:
                message = message[:157] + "..."
            print(f"    [{issue.get('severity')}] {issue.get('type')}: {message}")


def print_unscanned_lines(unscanned_lines: list[str]):
    """Report requirements.txt lines that were not in name==version format."""
    print("\n[Unscanned requirements lines]")
    for line in unscanned_lines:
        print(f"- {line}")


def save_report(report_document: dict, out_path: str):
    payload = {
        "packages": report_document.get("packages") or [],
        "models": report_document.get("models") or [],
        "unscanned": report_document.get("unscanned") or [],
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"\n[Saved] {out_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Scan a requirements.txt for vulnerability, license and "
                    "supply-chain risk, and emit a CycloneDX SBOM.",
    )
    parser.add_argument("requirements", help="path to a requirements.txt")
    parser.add_argument("--supply-chain", action="store_true",
                        help="also run repository/supply-chain trust checks "
                             "(module 2). Slow: several network calls per "
                             "package; set GITHUB_TOKEN to avoid rate limits.")
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


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

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
