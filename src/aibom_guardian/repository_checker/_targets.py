"""
Works out what a caller pointed at: GitHub repo, HF model or dataset, PyPI
requirement, or local path. Also reports whether the reference is pinned,
since a branch can move between one call and the next.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ._constants import GITHUB_OWNER_REPO_RE, PYPI_SPEC_RE
from ._helpers import _issue, _normalize_pypi_name
from ._http import SSRFError, validate_public_url


def detect_target_type(target: str, target_type: str = "auto") -> dict:
    """
    Detect and normalize the input target.

    Returns a dict with keys:
        type, normalized, owner, name, revision, version, version_pinned,
        ambiguous, issues, raw
    """
    raw = (target or "").strip()
    result = {
        "type": None,
        "normalized": None,
        "owner": None,
        "name": None,
        "revision": None,
        "version": None,
        "version_pinned": False,
        "ambiguous": False,
        "issues": [],
        "raw": raw,
        "repo_type": None,  # for HF: model|dataset
    }

    if not raw:
        result["issues"].append(_issue(
            "repository", "critical", "empty target",
            recommendation="provide a GitHub, Hugging Face, or PyPI target",
        ))
        return result

    requested = (target_type or "auto").lower().strip()
    if requested not in ("auto", "github", "hf_model", "hf_dataset", "pypi", "local"):
        result["issues"].append(_issue(
            "repository", "high", f"unknown target_type: {target_type}",
            recommendation="use auto, github, hf_model, hf_dataset, pypi, or local",
        ))
        requested = "auto"

    if requested == "local":
        result["type"] = "local"
        result["normalized"] = raw
        return result

    # Explicit git+ URL with optional revision
    git_plus = re.match(
        r"^git\+https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/@]+?)(?:\.git)?(?:@(?P<rev>[^/]+))?$",
        raw,
        re.IGNORECASE,
    )
    if git_plus and requested in ("auto", "github"):
        result["type"] = "github"
        result["owner"] = git_plus.group("owner")
        result["name"] = git_plus.group("repo").removesuffix(".git")
        result["normalized"] = f"{result['owner']}/{result['name']}"
        result["revision"] = git_plus.group("rev")
        return result

    # Full / host-based URLs
    lowered = raw.lower()
    if "://" in raw or lowered.startswith("github.com/") or lowered.startswith("www.github.com/"):
        url = raw if "://" in raw else f"https://{raw}"
        try:
            # SSRF check for non-file schemes; may raise
            if urlparse(url).scheme in ("http", "https"):
                if urlparse(url).scheme == "http":
                    result["issues"].append(_issue(
                        "repository", "critical", "HTTP URLs are not allowed",
                        evidence=url, recommendation="use HTTPS",
                    ))
                    result["type"] = "invalid"
                    return result
                validate_public_url(url)
        except SSRFError as exc:
            result["issues"].append(_issue(
                "repository", "critical", f"blocked URL: {exc}",
                evidence=url, recommendation="use an allowlisted public host over HTTPS",
            ))
            result["type"] = "invalid"
            return result

        parsed = urlparse(url if "://" in url else f"https://{raw}")
        host = (parsed.hostname or "").lower()
        parts = [p for p in parsed.path.split("/") if p]

        if host in ("github.com", "www.github.com") and requested in ("auto", "github"):
            if len(parts) >= 2:
                owner, repo = parts[0], parts[1].removesuffix(".git")
                result["type"] = "github"
                result["owner"] = owner
                result["name"] = repo
                result["normalized"] = f"{owner}/{repo}"
                if len(parts) >= 4 and parts[2] == "commit":
                    result["revision"] = parts[3]
                return result

        if host == "huggingface.co" and requested in ("auto", "hf_model", "hf_dataset"):
            if parts and parts[0] == "datasets" and len(parts) >= 3:
                result["type"] = "hf_dataset"
                result["repo_type"] = "dataset"
                result["owner"] = parts[1]
                result["name"] = parts[2]
                result["normalized"] = f"{parts[1]}/{parts[2]}"
                if "revision" in parts:
                    idx = parts.index("revision")
                    if idx + 1 < len(parts):
                        result["revision"] = parts[idx + 1]
                return result
            if len(parts) >= 2 and parts[0] != "datasets":
                if requested == "hf_dataset":
                    result["type"] = "hf_dataset"
                    result["repo_type"] = "dataset"
                else:
                    result["type"] = "hf_model"
                    result["repo_type"] = "model"
                result["owner"] = parts[0]
                result["name"] = parts[1]
                result["normalized"] = f"{parts[0]}/{parts[1]}"
                if "revision" in parts:
                    idx = parts.index("revision")
                    if idx + 1 < len(parts):
                        result["revision"] = parts[idx + 1]
                return result

        result["issues"].append(_issue(
            "repository", "high", "unsupported URL host or path",
            evidence=url,
        ))
        result["type"] = "invalid"
        return result

    # Explicit type overrides for shorthand
    if requested == "github":
        m = GITHUB_OWNER_REPO_RE.fullmatch(raw)
        if m:
            result["type"] = "github"
            result["owner"] = m.group("owner")
            result["name"] = m.group("repo")
            result["normalized"] = f"{result['owner']}/{result['name']}"
            return result
        result["issues"].append(_issue("repository", "high", "invalid GitHub owner/repo", evidence=raw))
        result["type"] = "invalid"
        return result

    if requested == "hf_model":
        m = GITHUB_OWNER_REPO_RE.fullmatch(raw)
        if m:
            result["type"] = "hf_model"
            result["repo_type"] = "model"
            result["owner"] = m.group("owner")
            result["name"] = m.group("repo")
            result["normalized"] = f"{result['owner']}/{result['name']}"
            return result

    if requested == "hf_dataset":
        # allow datasets/ns/name or ns/name
        cleaned = raw
        if cleaned.startswith("datasets/"):
            cleaned = cleaned[len("datasets/"):]
        m = GITHUB_OWNER_REPO_RE.fullmatch(cleaned)
        if m:
            result["type"] = "hf_dataset"
            result["repo_type"] = "dataset"
            result["owner"] = m.group("owner")
            result["name"] = m.group("repo")
            result["normalized"] = f"{result['owner']}/{result['name']}"
            return result

    if requested == "pypi":
        return _parse_pypi_target(raw, result)

    # auto: PyPI package expression?
    pypi_match = PYPI_SPEC_RE.fullmatch(raw)
    if pypi_match and "==" in raw:
        return _parse_pypi_target(raw, result)

    # auto: owner/repo — ambiguous between GitHub and HF
    owner_repo = GITHUB_OWNER_REPO_RE.fullmatch(raw)
    if owner_repo:
        result["ambiguous"] = True
        result["type"] = "ambiguous"
        result["owner"] = owner_repo.group("owner")
        result["name"] = owner_repo.group("repo")
        result["normalized"] = f"{result['owner']}/{result['name']}"
        result["issues"].append(_issue(
            "repository", "medium",
            "ambiguous_target: owner/repo could be GitHub or Hugging Face",
            evidence=raw,
            recommendation="set target_type to github, hf_model, or hf_dataset",
        ))
        return result

    # bare package name without ==
    if pypi_match:
        return _parse_pypi_target(raw, result)

    result["issues"].append(_issue(
        "repository", "high", "unable to detect target type",
        evidence=raw,
        recommendation="provide a full URL or set --type explicitly",
    ))
    result["type"] = "invalid"
    return result


def _parse_pypi_target(raw: str, result: dict) -> dict:
    m = PYPI_SPEC_RE.fullmatch(raw.strip())
    if not m:
        result["issues"].append(_issue("repository", "high", "invalid PyPI package spec", evidence=raw))
        result["type"] = "invalid"
        return result
    name, version = m.group(1), m.group(2)
    result["type"] = "pypi"
    result["name"] = name
    result["normalized"] = _normalize_pypi_name(name)
    result["version"] = version
    result["version_pinned"] = version is not None
    return result
