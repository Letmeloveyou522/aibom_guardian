"""
Artifact-level evidence: file hashes, signature detection, CODEOWNERS and
contributor parsing, and pulling GitHub URLs out of free-form metadata.

All of it answers "who produced this and can that be checked", which is what
the provenance category scores.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from ._constants import (
    BOT_LOGINS,
    CODEOWNERS_OWNER_RE,
    CONTRIBUTOR_MAX_MAINTAINERS,
    CONTRIBUTOR_MIN_COMMITS,
    GITHUB_URL_RE,
    HEX64_RE,
    SIGNATURE_FILENAMES,
    SIGNATURE_SUFFIXES,
)
from ._helpers import _safe_path_for_log

# ---------------------------------------------------------------------------
# Hash / signature / provenance
# ---------------------------------------------------------------------------

def calculate_sha256(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """Compute SHA-256 of a local file in chunks."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"file not found: {_safe_path_for_log(file_path)}")
    if file_path.is_symlink():
        # Resolve once; still require a regular file after resolve
        file_path = file_path.resolve()
    if not file_path.is_file():
        raise ValueError(f"not a regular file: {_safe_path_for_log(file_path)}")
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"file not readable: {_safe_path_for_log(file_path)}")

    digest = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text[7:]
    if not HEX64_RE.fullmatch(text):
        return None
    return text


def _looks_like_signature(name: str) -> bool:
    lower = name.lower()
    if lower in SIGNATURE_FILENAMES:
        return True
    return any(lower.endswith(suffix) for suffix in SIGNATURE_SUFFIXES)


def _redact_sensitive(text: str) -> str:
    if not text:
        return text
    redacted = re.sub(
        r"(?i)(authorization|token|bearer|key|secret)\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        text,
    )
    redacted = re.sub(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----",
                      "[REDACTED CERT/KEY]", redacted, flags=re.DOTALL)
    return redacted[:500]


# ---------------------------------------------------------------------------
# CODEOWNERS / contributors
# ---------------------------------------------------------------------------

def parse_codeowners(content: str) -> list[str]:
    owners: list[str] = []
    seen = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for match in CODEOWNERS_OWNER_RE.findall(line):
            if match not in seen:
                seen.add(match)
                owners.append(match)
    return owners


def estimate_maintainers_from_contributors(contributors: list[dict]) -> tuple[int | None, str]:
    """
    Estimate maintainers from contributor stats.
    Excludes bots/anonymous. Returns (count, method).
    """
    meaningful = []
    for c in contributors:
        if not isinstance(c, dict):
            continue
        login = (c.get("login") or "").strip()
        if not login:
            continue
        lower = login.lower()
        if lower.endswith("[bot]") or lower in BOT_LOGINS or "bot" == lower:
            continue
        if c.get("type") == "Anonymous" or login == "ghost":
            continue
        contributions = int(c.get("contributions") or 0)
        if contributions >= CONTRIBUTOR_MIN_COMMITS:
            meaningful.append((login, contributions))

    if not meaningful:
        return None, "unknown"

    meaningful.sort(key=lambda x: x[1], reverse=True)
    # Keep top contributors with at least half of the top contributor's count,
    # capped to avoid counting the whole community.
    top = meaningful[0][1]
    threshold = max(CONTRIBUTOR_MIN_COMMITS, top // 5)
    selected = [m for m in meaningful if m[1] >= threshold][:CONTRIBUTOR_MAX_MAINTAINERS]
    if not selected:
        return None, "unknown"
    return len(selected), "contributors_estimate"


# ---------------------------------------------------------------------------
# GitHub URL extraction from text/metadata
# ---------------------------------------------------------------------------

def _normalize_repo_name(repo: str) -> str:
    """
    Clean a repo name matched out of free text.

    GITHUB_URL_RE has to allow dots (requests/requests.oauthlib is real), so a
    URL at the end of a sentence matches as "repo." and then 404s. GitHub
    rejects names ending in a dot, so stripping them loses nothing.
    """
    return repo.removesuffix(".git").rstrip(".")


def extract_github_candidates(
    metadata_urls: dict | None = None,
    readme_text: str | None = None,
) -> tuple[str | None, list[str]]:
    """
    Return (chosen_owner_repo or None, candidate list).
    """
    candidates: list[str] = []
    seen = set()

    def _add(owner: str, repo: str) -> None:
        repo = _normalize_repo_name(repo)
        if not repo:
            return
        key = f"{owner}/{repo}".lower()
        if key not in seen:
            seen.add(key)
            candidates.append(f"{owner}/{repo}")

    preferred_keys = (
        "repository", "source_code", "source", "code", "github",
        "Source", "Source Code", "Repository", "Code", "GitHub",
        "Homepage",
    )

    meta_hits: list[str] = []
    if metadata_urls:
        # case-insensitive key lookup preferring known keys first
        lower_map = {str(k).lower(): v for k, v in metadata_urls.items() if v}
        for key in preferred_keys:
            val = lower_map.get(key.lower())
            if not val:
                continue
            parsed = _github_root_from_url(str(val))
            if parsed:
                _add(*parsed)
                meta_hits.append(f"{parsed[0]}/{parsed[1]}")

        # also scan remaining values
        for val in metadata_urls.values():
            parsed = _github_root_from_url(str(val))
            if parsed:
                _add(*parsed)

    if meta_hits:
        # Prefer explicit metadata field hits; if unique, choose it
        unique = list(dict.fromkeys(meta_hits))
        if len(unique) == 1:
            return unique[0], candidates
        return None, unique

    if readme_text:
        counts: dict[str, int] = {}
        for match in GITHUB_URL_RE.finditer(readme_text):
            owner, repo = match.group(1), _normalize_repo_name(match.group(2))
            if not repo:
                continue
            # Skip non-root path contexts by checking surrounding path
            full = match.group(0)
            # Reject if URL continues into issues/pull/etc — check original text slice
            start = match.end()
            rest = readme_text[start:start + 40]
            if re.match(r"/(issues|pull|actions|commit|blob|tree|wiki|releases)/", rest, re.I):
                continue
            if re.search(r"/(issues|pull|actions|commit|blob|tree)/", full, re.I):
                continue
            key = f"{owner}/{repo}"
            counts[key] = counts.get(key, 0) + 1
            _add(owner, repo)

        if counts:
            ranked = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
            if len(ranked) == 1 or (len(ranked) > 1 and ranked[0][1] > ranked[1][1]):
                return ranked[0][0], list(counts.keys())
            return None, list(counts.keys())

    if len(candidates) == 1:
        return candidates[0], candidates
    return None, candidates


def _github_root_from_url(url: str) -> tuple[str, str] | None:
    if not url:
        return None
    text = url.strip()
    m = re.match(
        r"^(?:https?://)?(?:www\.)?github\.com/"
        r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?(?:[?#].*)?$",
        text,
        re.IGNORECASE,
    )
    if not m:
        return None
    # Ensure no deeper path after repo
    parsed = urlparse(text if "://" in text else f"https://{text}")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) != 2:
        # allow trailing .git only
        if not (len(parts) == 2):
            return None
    return m.group(1), m.group(2).removesuffix(".git")
