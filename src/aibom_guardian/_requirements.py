"""
Requirements parsing and transitive dependency resolution.

Reads a requirements.txt into exact versions to scan, and walks PyPI
``requires_dist`` so transitive packages are included without installing.
Shared PyPI session / release cache live here so license lookups in
scanner.py reuse the same process memo without a circular import.
"""

from __future__ import annotations

import re
import sys
import threading
from typing import NamedTuple

PYPI_TIMEOUT_SEC = 8.0

# One cache per process: a requirements file repeats packages across
# transitive pins, and pypi.org should not be asked twice for the same release.
# License resolution in scanner.py shares this dict (same keys never collide:
# deps/versions use "__deps__" / "__versions__" prefixes).
_RELEASE_CACHE: dict = {}

# Set only by tests, to inject a fake. Production uses a session per thread,
# because requests.Session is not safe to share across the scan workers.
_PYPI_SESSION = None
_THREAD_LOCAL = threading.local()


def _pypi_session():
    if _PYPI_SESSION is not None:
        return _PYPI_SESSION
    session = getattr(_THREAD_LOCAL, "pypi", None)
    if session is None:
        import requests
        session = requests.Session()
        _THREAD_LOCAL.pypi = session
    return session


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
    direct: bool = True   # False when pulled in by another package
    depth: int = 0        # 0 = named in the file
    line: int = 0         # line in the requirements file, 0 when transitive


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
    key = ("__versions__", package_name.lower())
    if key in _RELEASE_CACHE:
        return _RELEASE_CACHE[key]

    try:
        from urllib.parse import quote
    except ImportError:                              # pragma: no cover
        return []

    url = f"https://pypi.org/pypi/{quote(package_name, safe='')}/json"
    try:
        response = _pypi_session().get(url, timeout=PYPI_TIMEOUT_SEC)
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


TRANSITIVE_MAX_DEPTH = 12


def _normalize_name(name: str) -> str:
    """PEP 503 normalization, so Jinja2 and jinja-2 are one package."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _requires_dist(name: str, version: str) -> list:
    """
    Dependencies PyPI records for one exact release.

    Per-version, not per-project: a package's dependency list changes between
    releases.
    """
    key = ("__deps__", _normalize_name(name), version)
    if key in _RELEASE_CACHE:
        return _RELEASE_CACHE[key]

    try:
        from urllib.parse import quote
    except ImportError:                              # pragma: no cover
        return []

    url = (f"https://pypi.org/pypi/{quote(name, safe='')}"
           f"/{quote(version, safe='')}/json")
    try:
        response = _pypi_session().get(url, timeout=PYPI_TIMEOUT_SEC)
        response.raise_for_status()
        requires = response.json().get("info", {}).get("requires_dist") or []
    except Exception:                                # noqa: BLE001 - network
        _RELEASE_CACHE[key] = []
        return []

    _RELEASE_CACHE[key] = list(requires)
    return list(requires)


def expand_transitive(
    pinned: list,
    *,
    offline: bool = False,
    max_depth: int = TRANSITIVE_MAX_DEPTH,
) -> tuple[list, list]:
    """
    Walk the dependency tree and return every package that will be installed.

    Returns (packages, unresolved). Resolved from PyPI ``requires_dist``, so
    nothing needs to be installed.

    Markers are evaluated against this interpreter with an empty ``extra``,
    matching an install that requested no extras. First occurrence of a name
    wins, so a direct pin is not replaced by a dependency's range.
    """
    if offline:
        return list(pinned), []

    try:
        from packaging.requirements import InvalidRequirement, Requirement
    except ImportError:                              # pragma: no cover
        return list(pinned), []

    packages = list(pinned)
    unresolved: list = []
    seen = {_normalize_name(p.name) for p in pinned}
    frontier = list(pinned)

    for depth in range(1, max_depth + 1):
        discovered = []
        for parent in frontier:
            for raw in _requires_dist(parent.name, parent.version):
                try:
                    req = Requirement(raw)
                except InvalidRequirement:
                    continue

                if req.marker is not None:
                    try:
                        if not req.marker.evaluate({"extra": ""}):
                            continue
                    except Exception:                # noqa: BLE001 - odd marker
                        continue

                key = _normalize_name(req.name)
                if key in seen:
                    continue
                seen.add(key)

                version = _resolve_specifier(req.name, str(req.specifier))
                if version is None:
                    unresolved.append(f"{raw}  (required by {parent.name})")
                    continue

                child = Pinned(req.name, version, raw, True,
                               direct=False, depth=depth)
                packages.append(child)
                discovered.append(child)

        if not discovered:
            break
        frontier = discovered

    return packages, unresolved


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
        packages.append(Pinned(name, version, spec, resolved, line=lineno[0]))

    lineno = [0]

    # utf-8-sig, not utf-8: a requirements.txt saved by Notepad or exported
    # from Windows tooling starts with a BOM, and it would otherwise glue
    # itself to the first requirement and make that line unparseable.
    with open(path, "r", encoding="utf-8-sig") as f:
        for number, raw_line in enumerate(f, start=1):
            lineno[0] = number
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
