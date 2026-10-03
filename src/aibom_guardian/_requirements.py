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
    One pinned or independently resolved requirement selected for inspection.

    `resolved` is False when the file named the version outright and True when
    a range was narrowed down here, because those are different claims: an
    exact pin is the user's input, while a range produces a candidate version.
    Neither proves that pip can install the complete set together.
    """

    name: str
    version: str
    spec: str
    resolved: bool
    direct: bool = True   # False when pulled in by another package
    depth: int = 0        # 0 = named in the file
    line: int = 0         # line in the requirements file, 0 when transitive
    extras: tuple[str, ...] = ()


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


def _requires_dist(name: str, version: str) -> list | None:
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
        info = response.json()['info']
        requires = info.get("requires_dist")
        if requires is None:
            requires = []
        if not isinstance(requires, list) or any(not isinstance(r, str) for r in requires):
            return None
    except Exception:                                # noqa: BLE001 - network
        return None

    _RELEASE_CACHE[key] = list(requires)
    return list(requires)


def expand_transitive(
    pinned: list,
    *,
    offline: bool = False,
    max_depth: int = TRANSITIVE_MAX_DEPTH,
) -> tuple[list, list]:
    """
    Walk PyPI dependencies to produce a candidate inventory, not a pip solution.

    Returns (packages, unresolved). Resolved from PyPI ``requires_dist``, so
    nothing needs to be installed.

    Markers are evaluated for the base package and requested extras. First occurrence of a name
    wins, so a direct pin is not replaced by a dependency's range. Conflicting
    constraints and incomplete expansion are reported, never silently ignored.
    """
    if offline:
        return list(pinned), []

    try:
        from packaging.requirements import InvalidRequirement, Requirement
    except ImportError:                              # pragma: no cover
        return list(pinned), []

    packages = list(pinned)
    unresolved: list = []
    selected = {_normalize_name(p.name): p for p in pinned}
    extras = {}
    for p in pinned:
        extras.setdefault(_normalize_name(p.name), set()).update(p.extras)
    for p in pinned:
        other = selected[_normalize_name(p.name)]
        if p.version != other.version:
            unresolved.append(f'{p.name}: conflicting input pins {p.version} and {other.version}')
    frontier = list(pinned)

    for depth in range(1, max_depth + 2):
        discovered = []
        for parent in frontier:
            requirements = _requires_dist(parent.name, parent.version)
            if requirements is None:
                unresolved.append(f'{parent.name}=={parent.version}: dependency metadata lookup failed')
                continue
            for raw in requirements:
                try:
                    req = Requirement(raw)
                except InvalidRequirement:
                    unresolved.append(f'{raw} (invalid dependency required by {parent.name})')
                    continue

                if req.marker is not None:
                    try:
                        contexts = {"", *extras.get(_normalize_name(parent.name), ())}
                        if not any(req.marker.evaluate({"extra": extra}) for extra in contexts):
                            continue
                    except Exception:                # noqa: BLE001 - odd marker
                        unresolved.append(f'{raw} (marker evaluation failed; required by {parent.name})')
                        continue

                key = _normalize_name(req.name)
                if req.url:
                    unresolved.append(f'{raw} (unsupported URL dependency; required by {parent.name})')
                    continue
                if key in selected:
                    existing = selected[key]
                    if not req.specifier.contains(existing.version, prereleases=True):
                        unresolved.append(
                            f'{raw} (dependency conflict: selected {existing.name}=={existing.version}; '
                            f'required by {parent.name}=={parent.version})')
                    new_extras = {_normalize_name(e) for e in req.extras} - extras.get(key, set())
                    if new_extras:
                        if depth >= max_depth:
                            unresolved.append(f'{raw} (extras expansion depth limit {max_depth}; required by {parent.name})')
                        else:
                            extras.setdefault(key, set()).update(new_extras)
                            if existing not in discovered:
                                discovered.append(existing)
                    continue
                if depth > max_depth:
                    unresolved.append(f'{raw} (depth limit {max_depth}; required by {parent.name})')
                    continue

                version = _resolve_specifier(req.name, str(req.specifier))
                if version is None:
                    unresolved.append(f"{raw}  (required by {parent.name})")
                    continue

                child = Pinned(req.name, version, raw, True,
                               direct=False, depth=depth)
                packages.append(child)
                selected[key] = child
                extras[key] = {_normalize_name(e) for e in req.extras}
                discovered.append(child)

        if not discovered:
            break
        frontier = discovered

    return [p._replace(extras=tuple(sorted(extras.get(_normalize_name(p.name), ()))))
            for p in packages], list(dict.fromkeys(unresolved))


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

    def add(name: str, version: str, spec: str, resolved: bool, extras=()) -> None:
        # PEP 503: names differing only in case or in -/_/. are one project.
        # Reporting Django and django as two rows would double every finding.
        key = (re.sub(r"[-_.]+", "-", name).lower(), version)
        requested = {_normalize_name(e) for e in extras}
        if key in seen:
            index = seen[key]
            packages[index] = packages[index]._replace(
                extras=tuple(sorted(set(packages[index].extras) | requested)))
            return
        seen[key] = len(packages)
        packages.append(Pinned(name, version, spec, resolved, line=lineno[0],
                               extras=tuple(sorted(requested))))

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
                add(requirement.name, exact[0].version, spec, False, requirement.extras)
                continue

            if offline:
                skip(line, "offline: a version range cannot be resolved")
                continue

            version = _resolve_specifier(requirement.name, spec)
            if version is None:
                skip(line, "no published version satisfies this range")
                continue

            print(f"[INFO] Resolved {line} -> {requirement.name}=={version}")
            add(requirement.name, version, spec, True, requirement.extras)

    return packages, unscanned
