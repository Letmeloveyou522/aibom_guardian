"""
License resolution for pinned package versions.

PyPI release metadata is the source of record; the locally installed copy is
only a fallback and is marked ``unverified`` when it does not match the pin.
Shared with ``scanner.run_scan`` and tests via ``aibom_guardian.scanner`` re-exports.
"""

from importlib.metadata import PackageNotFoundError, metadata, version as installed_version

from ._requirements import PYPI_TIMEOUT_SEC, _RELEASE_CACHE, _pypi_session
from .license_checker import classify_license_detailed

PYPI_RELEASE_URL = "https://pypi.org/pypi/{package}/{version}/json"


def _license_candidates(fields: dict) -> list:
    """
    License strings a distribution offers, best-structured first.

    PEP 639's ``License-Expression`` is authoritative when present. Below it the
    order matters less than it looks, because ``_best_candidate`` re-ranks by
    what actually resolves - a short free-text ``License`` beats a classifier
    only when it names a real identifier.
    """
    candidates = []

    expression = (fields.get("license_expression") or "").strip()
    if expression and expression.upper() != "UNKNOWN":
        candidates.append((expression, "license_expression"))

    lic = (fields.get("license") or "").strip()
    if lic and lic.upper() != "UNKNOWN" and len(lic) < 300 and lic.count("\n") <= 3:
        candidates.append((lic, "license"))

    for classifier in fields.get("classifiers") or []:
        if classifier.startswith("License ::"):
            candidates.append((classifier, "classifier"))

    if lic and lic.upper() != "UNKNOWN" and (lic, "license") not in candidates:
        candidates.append((lic, "license_text"))

    return candidates


def _best_candidate(candidates: list) -> tuple:
    """
    Pick the license string that identifies the license most precisely.

    psycopg2 publishes ``License: "LGPL with exceptions"`` alongside the trove
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

    Returns ``(raw, field, error)``. ``error`` is a string when the release could
    not be read, so the caller can record *why* it fell back rather than
    silently reporting the wrong version's terms. Results are memoised in
    ``_RELEASE_CACHE`` so transitive scans do not re-fetch the same release.
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

    Reading the installed copy is not good enough: chardet 5.2.0 is LGPL-2.1 and
    chardet 7.5.1 is 0BSD. A requirements file pinning 5.2.0 while the environment
    holds 7.5.1 would be reported as permissive if we only looked locally.

    Returns a dict with ``license``, ``source``, ``version``, ``unverified``,
    and ``error``. ``unverified=True`` tells score_engine to lower confidence
    rather than treat an unchecked version as compliant.
    """
    if version and not offline:
        from aibom_guardian import scanner as sc

        raw, field, error = sc._pypi_release_license(package_name, version)
        if raw:
            return {"license": raw, "source": f"pypi:{field}",
                    "version": version, "unverified": False, "error": None}
    else:
        error = "offline" if offline else "no version pinned"

    from aibom_guardian import scanner as sc

    raw, field, found_version = sc._installed_license(package_name)
    source = f"installed:{field}" if field else "none"
    matches_pin = bool(version) and found_version == version
    return {
        "license": raw,
        "source": source if raw != "NOT_INSTALLED" else "none",
        "version": found_version,
        "unverified": not matches_pin,
        "error": error,
    }
