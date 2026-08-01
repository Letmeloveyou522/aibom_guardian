"""
repository_checker.py
-----------------------------------
Checks the provenance and supply-chain trustworthiness of packages,
GitHub repositories, and Hugging Face models/datasets.

Public entry point:
    check_repository(target, ...) -> dict

Also usable as a CLI:
    python repository_checker.py https://github.com/pallets/flask
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_HOSTS = frozenset({
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "api.securityscorecards.dev",
    "huggingface.co",
    "pypi.org",
    "files.pythonhosted.org",
})

ALLOWED_PORTS = frozenset({443, None})

GITHUB_API = "https://api.github.com"
OPENSSF_API = "https://api.securityscorecards.dev"
HF_API = "https://huggingface.co"
PYPI_API = "https://pypi.org"

COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SHORT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,39}$")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PYPI_SPEC_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:==([A-Za-z0-9](?:[A-Za-z0-9._+-]*[A-Za-z0-9])?))?$"
)
GITHUB_OWNER_REPO_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?$"
)
CODEOWNERS_OWNER_RE = re.compile(r"@[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?")
GITHUB_URL_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/"
    r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)

SIGNATURE_SUFFIXES = (
    ".sig", ".asc", ".sigstore", ".bundle", ".pem", ".crt", ".cosign",
    ".intoto.jsonl", ".intoto.json",
)
SIGNATURE_FILENAMES = frozenset({
    "provenance.json", "attestation.json",
})

BRANCH_LIKE = frozenset({
    "main", "master", "dev", "develop", "development", "trunk",
    "latest", "head", "default",
})

BOT_LOGINS = frozenset({
    "dependabot", "dependabot[bot]", "renovate", "renovate[bot]",
    "github-actions[bot]", "greenkeeper[bot]", "imgbot[bot]",
    "codecov[bot]", "snyk-bot",
})

INVALID_LICENSE_VALUES = frozenset({
    "", "unknown", "other", "none", "n/a", "na", "null",
})

MAX_HF_FILES_DETAIL = 30
MAX_EVIDENCE_CHARS = 200
WEAK_CHECK_THRESHOLD = 5
CONTRIBUTOR_MIN_COMMITS = 5
CONTRIBUTOR_MAX_MAINTAINERS = 10
REDIRECT_MAX = 5

USER_AGENT = "AIBOM-Guard"


# ---------------------------------------------------------------------------
# Helpers: issues / errors / dates
# ---------------------------------------------------------------------------

def _issue(
    issue_type: str,
    severity: str,
    detail: str,
    evidence: Any = None,
    recommendation: str | None = None,
) -> dict:
    return {
        "type": issue_type,
        "severity": severity,
        "detail": detail,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _error(
    source: str,
    code: str,
    detail: str,
    retryable: bool = False,
) -> dict:
    return {
        "source": source,
        "code": code,
        "detail": detail,
        "retryable": retryable,
    }


def _normalize_date(value: str | None) -> str | None:
    """Normalize ISO timestamps to YYYY-MM-DD when possible."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        return dt.date().isoformat()
    except ValueError:
        if re.match(r"^\d{4}-\d{2}-\d{2}", text):
            return text[:10]
        return None


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _days_since(iso_date: str | None, now: datetime | None = None) -> int | None:
    dt = _parse_datetime(iso_date)
    if dt is None:
        # try YYYY-MM-DD
        if iso_date and re.match(r"^\d{4}-\d{2}-\d{2}$", iso_date):
            dt = datetime.fromisoformat(iso_date).replace(tzinfo=timezone.utc)
        else:
            return None
    ref = now or datetime.now(timezone.utc)
    return max(0, (ref - dt).days)


def _safe_path_for_log(path: str | Path) -> str:
    """Avoid leaking home-directory paths in logs."""
    name = Path(path).name
    return name or "<path>"


def _normalize_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _is_commit_sha(value: str | None) -> bool:
    return bool(value and COMMIT_SHA_RE.fullmatch(value))


def _classify_revision(value: str | None) -> tuple[str | None, bool]:
    """Return (revision_type, revision_pinned)."""
    if not value:
        return None, False
    if _is_commit_sha(value):
        return "commit", True
    if value.lower() in BRANCH_LIKE or "/" in value:
        return "branch", False
    if re.match(r"^v?\d+\.\d+", value, re.IGNORECASE):
        return "tag", False
    if SHORT_SHA_RE.fullmatch(value):
        return "short_sha", False
    return "ref", False


# ---------------------------------------------------------------------------
# SSRF / safe HTTP
# ---------------------------------------------------------------------------

class SSRFError(ValueError):
    """Raised when a URL fails SSRF validation."""


# RFC 6052 well-known prefix used by NAT64/DNS64 to reach IPv4 hosts from an
# IPv6-only network. Addresses inside it report is_reserved=True even though
# the IPv4 they carry is perfectly public.
_NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """
    Return the IPv4 address an IPv6 address actually carries, if any.

    Covers IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d) forms.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64_WELL_KNOWN_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # On an IPv6-only / NAT64 network, github.com resolves to something like
    # 64:ff9b::14c8:f5f7 - which is 20.200.245.247, a real GitHub address, but
    # which ipaddress reports as is_reserved. Without this unwrapping every
    # GitHub and Hugging Face lookup fails as "not publicly routable".
    #
    # This does not weaken the SSRF defense: the embedded IPv4 is run through
    # exactly the same checks, so 64:ff9b::7f00:1 (127.0.0.1) is still blocked.
    embedded = _embedded_ipv4(ip) if isinstance(ip, ipaddress.IPv6Address) else None
    if embedded is not None:
        return _is_blocked_ip(embedded)

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_public_url(url: str, *, allow_http: bool = False) -> str:
    """
    Validate that ``url`` is safe to request (SSRF defense).
    Returns the normalized URL string on success.
    """
    if not url or not isinstance(url, str):
        raise SSRFError("empty or invalid URL")

    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https",) and not (allow_http and scheme == "http"):
        raise SSRFError(f"disallowed URL scheme: {scheme or '<none>'}")

    if parsed.username or parsed.password:
        raise SSRFError("URL must not contain userinfo credentials")

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise SSRFError("URL missing host")

    if host in ("localhost", "localhost.localdomain"):
        raise SSRFError("localhost is not allowed")

    if host not in ALLOWED_HOSTS:
        raise SSRFError(f"host not in allowlist: {host}")

    port = parsed.port
    if port is not None and port not in (443, 80 if allow_http else 443):
        if not (allow_http and port == 80):
            raise SSRFError(f"disallowed port: {port}")

    # Block literal IPs even if somehow in allowlist
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip):
            raise SSRFError(f"blocked IP address: {host}")
        raise SSRFError(f"raw IP addresses are not allowed: {host}")
    except ValueError:
        pass  # hostname, not IP

    # Resolve DNS and reject private/link-local answers (DNS rebinding defense)
    try:
        infos = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for {host}: {exc}") from exc

    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            raise SSRFError(f"resolved address is not publicly routable: {addr}")

    path = parsed.path or ""
    if ".." in path.split("/"):
        raise SSRFError("path traversal is not allowed in URL path")

    return parsed.geturl() if parsed.geturl().startswith("http") else url.strip()


def _build_session(timeout: float) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        connect=3,
        read=3,
        status=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.request_timeout = timeout  # type: ignore[attr-defined]
    return session


class SafeHTTPClient:
    """HTTP client with SSRF checks, redirect re-validation, and retries."""

    def __init__(
        self,
        timeout: float = 10.0,
        default_headers: dict | None = None,
    ):
        self.timeout = timeout
        self.session = _build_session(timeout)
        self.default_headers = default_headers or {"User-Agent": USER_AGENT}
        self._cache: dict[str, Any] = {}

    def get_json(
        self,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        cache_key: str | None = None,
        allow_statuses: tuple[int, ...] = (200,),
    ) -> tuple[Any | None, requests.Response | None, dict | None]:
        """
        GET JSON safely.

        Returns (data, response, error_dict).
        On expected API failures, data may be None and error_dict set.
        """
        if cache_key and cache_key in self._cache:
            return self._cache[cache_key]

        try:
            validate_public_url(url)
        except SSRFError as exc:
            err = _error("http", "ssrf_blocked", str(exc), retryable=False)
            return None, None, err

        merged = dict(self.default_headers)
        if headers:
            # Never log Authorization; just merge for the request.
            merged.update(headers)

        try:
            response = self._get_with_redirects(url, merged, params)
        except SSRFError as exc:
            return None, None, _error("http", "ssrf_blocked", str(exc), False)
        except requests.exceptions.Timeout:
            return None, None, _error("http", "timeout", f"request timed out: {urlparse(url).netloc}", True)
        except requests.exceptions.RequestException as exc:
            return None, None, _error("http", "network", f"request failed: {type(exc).__name__}", True)

        if response.status_code not in allow_statuses and response.status_code not in (200,):
            # Caller may still want the response for 404 handling
            pass

        data = None
        if response.status_code == 200:
            try:
                data = response.json()
            except ValueError:
                return None, response, _error("http", "invalid_json", "response was not valid JSON", False)

        result = (data, response, None)
        if cache_key and response.status_code == 200:
            self._cache[cache_key] = result
        return result

    def get_text(
        self,
        url: str,
        *,
        headers: dict | None = None,
        cache_key: str | None = None,
    ) -> tuple[str | None, requests.Response | None, dict | None]:
        try:
            validate_public_url(url)
        except SSRFError as exc:
            return None, None, _error("http", "ssrf_blocked", str(exc), False)

        merged = dict(self.default_headers)
        if headers:
            merged.update(headers)

        try:
            response = self._get_with_redirects(url, merged, None)
        except SSRFError as exc:
            return None, None, _error("http", "ssrf_blocked", str(exc), False)
        except requests.exceptions.Timeout:
            return None, None, _error("http", "timeout", "request timed out", True)
        except requests.exceptions.RequestException as exc:
            return None, None, _error("http", "network", f"request failed: {type(exc).__name__}", True)

        if response.status_code != 200:
            return None, response, None

        text = response.text
        result = (text, response, None)
        if cache_key:
            self._cache[cache_key] = result
        return result

    def _get_with_redirects(
        self,
        url: str,
        headers: dict,
        params: dict | None,
    ) -> requests.Response:
        current = validate_public_url(url)
        for _ in range(REDIRECT_MAX + 1):
            response = self.session.get(
                current,
                headers=headers,
                params=params,
                timeout=self.timeout,
                allow_redirects=False,
            )
            if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    return response
                next_url = urljoin(current, location)
                current = validate_public_url(next_url)
                params = None  # params already applied on first hop
                continue
            return response
        raise SSRFError("too many redirects")


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------

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
# Dataset documentation heuristics
# ---------------------------------------------------------------------------

def check_dataset_documentation(
    readme_text: str | None,
    card_data: dict | None = None,
) -> dict:
    """Deterministic Dataset Card / README documentation checks."""
    card_data = card_data or {}
    text = readme_text or ""
    checked = True
    card_exists = bool(text.strip()) or bool(card_data)

    license_value = _extract_dataset_license(card_data, text)
    license_documented = license_value is not None

    source_documented, source_evidence, source_conf = _section_documented(
        text,
        headings=(
            r"source", r"data\s+sources?", r"origin", r"dataset\s+source",
            r"출처", r"원천\s*데이터", r"데이터\s*출처",
        ),
        body_hints=(
            r"https?://", r"\barxiv\b", r"\bdoi\b", r"collected from",
            r"derived from", r"based on", r"원본", r"출처",
        ),
    )
    collection_documented, collection_evidence, collection_conf = _section_documented(
        text,
        headings=(
            r"data\s+collection", r"collection\s+process", r"collection\s+method",
            r"curation", r"acquisition", r"수집\s*방법", r"데이터\s*수집",
            r"구축\s*방법", r"생성\s*방법",
        ),
        body_hints=(
            r"we collected", r"scraped", r"crawled", r"annotated",
            r"수집", r"크롤", r"구축",
        ),
    )
    processing_documented, processing_evidence, processing_conf = _section_documented(
        text,
        headings=(
            r"preprocessing", r"cleaning", r"annotation", r"labeling",
            r"filtering", r"processing", r"전처리", r"정제", r"라벨링",
            r"어노테이션", r"필터링", r"가공\s*방법",
        ),
        body_hints=(
            r"preprocessed", r"filtered", r"cleaned", r"tokeniz",
            r"전처리", r"정제", r"필터",
        ),
    )
    citation_documented, citation_evidence, citation_conf = _section_documented(
        text,
        headings=(r"citation", r"citing", r"bibtex", r"참고\s*문헌", r"인용"),
        body_hints=(r"@\w+\{", r"please cite", r"bibtex", r"인용"),
    )

    missing = []
    if not license_documented:
        missing.append("license")
    if source_documented is False:
        missing.append("source")
    if collection_documented is False:
        missing.append("collection_method")
    if processing_documented is False:
        missing.append("processing_method")
    if citation_documented is False:
        missing.append("citation")

    return {
        "checked": checked,
        "card_exists": card_exists,
        "license": license_value,
        "license_documented": license_documented,
        "source_documented": source_documented,
        "collection_method_documented": collection_documented,
        "processing_method_documented": processing_documented,
        "citation_documented": citation_documented,
        "missing_fields": missing,
        "evidence": {
            "source": source_evidence,
            "collection_method": collection_evidence,
            "processing_method": processing_evidence,
            "citation": citation_evidence,
            "license": license_value,
        },
        "confidence": {
            "source": source_conf,
            "collection_method": collection_conf,
            "processing_method": processing_conf,
            "citation": citation_conf,
        },
    }


def _extract_dataset_license(card_data: dict, text: str) -> str | None:
    for key in ("license", "licence", "licenses"):
        if key in card_data and card_data[key] is not None:
            val = card_data[key]
            if isinstance(val, list):
                if not val:
                    continue
                val = val[0]
            lic = str(val).strip()
            if lic.lower() not in INVALID_LICENSE_VALUES:
                return lic

    # YAML front matter
    fm = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if fm:
        for line in fm.group(1).splitlines():
            m = re.match(r"^license\s*:\s*[\"']?([^\"'\n#]+)", line, re.IGNORECASE)
            if m:
                lic = m.group(1).strip()
                if lic.lower() not in INVALID_LICENSE_VALUES:
                    return lic

    # License section
    section = _extract_section(text, (r"license", r"licence", r"라이선스"))
    if section:
        # Prefer an SPDX-like token
        token = re.search(r"\b([A-Za-z0-9.+-]+(?:-[0-9.]+)?)\b", section)
        if token:
            lic = token.group(1)
            if lic.lower() not in INVALID_LICENSE_VALUES and lic.lower() not in (
                "the", "a", "an", "this", "under", "see",
            ):
                return lic
    return None


def _extract_section(text: str, heading_patterns: tuple[str, ...]) -> str | None:
    if not text:
        return None
    heading_re = "|".join(heading_patterns)
    pattern = re.compile(
        rf"^(?:\#{{1,3}}\s*|{re.escape('##')}\s*)?(?:{heading_re})\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    match = pattern.search(text)
    if not match:
        # also allow bold headings
        pattern2 = re.compile(
            rf"^\*\*(?:{heading_re})\*\*\s*$",
            re.IGNORECASE | re.MULTILINE,
        )
        match = pattern2.search(text)
    if not match:
        return None
    start = match.end()
    next_heading = re.search(r"^\#{1,3}\s+\S", text[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else min(len(text), start + 800)
    return text[start:end].strip()


def _section_documented(
    text: str,
    headings: tuple[str, ...],
    body_hints: tuple[str, ...],
) -> tuple[bool | None, str | None, str]:
    section = _extract_section(text, headings)
    if section:
        snippet = section[:MAX_EVIDENCE_CHARS]
        # Require some substance beyond the heading itself
        if len(section) >= 20 and re.search("|".join(body_hints), section, re.IGNORECASE):
            return True, snippet, "high"
        if len(section) >= 40:
            return True, snippet, "medium"
        return None, snippet, "low"

    # Do not treat a lone keyword in the body as documented
    return False, None, "high"


# ---------------------------------------------------------------------------
# GitHub URL extraction from text/metadata
# ---------------------------------------------------------------------------

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
        repo = repo.removesuffix(".git")
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
            owner, repo = match.group(1), match.group(2).removesuffix(".git")
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


# ---------------------------------------------------------------------------
# Trust score
# ---------------------------------------------------------------------------

def calculate_trust_score(
    *,
    archived: bool | None = None,
    last_commit: str | None = None,
    last_release: str | None = None,
    maintainer_count: int | None = None,
    maintainer_count_method: str | None = None,
    stars: int | None = None,
    openssf_score: float | None = None,
    openssf_available: bool = False,
    revision_pinned: bool = False,
    hash_verified: bool | None = None,
    signature_status: str = "not_found",
    signature_verified: bool = False,
    has_license: bool = False,
    has_readme: bool = False,
    has_codeowners: bool = False,
    dataset_doc: dict | None = None,
    is_dataset: bool = False,
    issues: list | None = None,
    now: datetime | None = None,
    partial_data: bool = False,
) -> dict:
    """Return trust_score, verdict, score_breakdown, confidence."""
    issues = issues or []
    now = now or datetime.now(timezone.utc)

    # --- Repository health (25) ---
    health = 0.0
    if archived is True:
        health = 0.0
    else:
        health += 6  # not archived / unknown treated neutrally later
        if archived is None:
            health -= 2

        days_commit = _days_since(last_commit, now)
        if days_commit is None:
            health += 0
        elif days_commit <= 90:
            health += 7
        elif days_commit <= 365:
            health += 4
        elif days_commit <= 730:
            health += 2

        days_release = _days_since(last_release, now)
        if days_release is None:
            health += 1  # unknown / no release — small credit only
        elif days_release <= 180:
            health += 5
        elif days_release <= 540:
            health += 3

        if maintainer_count and maintainer_count >= 2:
            health += 4
        elif maintainer_count == 1:
            health += 2
        elif has_codeowners:
            health += 3

        # Popularity as a small auxiliary signal only (max 3)
        if stars is not None:
            if stars >= 1000:
                health += 3
            elif stars >= 100:
                health += 2
            elif stars >= 10:
                health += 1

    health = max(0.0, min(25.0, health))

    # --- OpenSSF (30) ---
    openssf_component: float | None
    if openssf_available and openssf_score is not None:
        clamped = max(0.0, min(10.0, float(openssf_score)))
        openssf_component = clamped / 10.0 * 30.0
    else:
        openssf_component = None  # not_available

    # --- Provenance (30) ---
    if hash_verified is False or signature_status == "failed":
        provenance_component = 0.0
    else:
        provenance_component = 0.0
        if revision_pinned:
            provenance_component += 8
        if hash_verified is True:
            provenance_component += 12
        if signature_verified:
            provenance_component += 10
        elif signature_status == "present":
            provenance_component += 3
        provenance_component = min(30.0, provenance_component)

    # --- Transparency (15) ---
    transparency = 0.0
    if is_dataset and dataset_doc:
        if dataset_doc.get("license_documented"):
            transparency += 5
        if dataset_doc.get("source_documented") is True:
            transparency += 5
        if (
            dataset_doc.get("collection_method_documented") is True
            or dataset_doc.get("processing_method_documented") is True
        ):
            transparency += 5
    else:
        if has_license:
            transparency += 5
        if has_readme:
            transparency += 5
        if has_codeowners or (maintainer_count and maintainer_count >= 1):
            transparency += 5
    transparency = min(15.0, transparency)

    # Combine — if OpenSSF missing, redistribute weight into other pillars
    # while lowering confidence (do NOT treat as 0).
    if openssf_component is None:
        available_max = 25 + 30 + 15  # 70 without openssf
        raw = health + provenance_component + transparency
        trust = int(round((raw / available_max) * 100)) if available_max else 0
        openssf_reported = None
    else:
        trust = int(round(health + openssf_component + provenance_component + transparency))
        openssf_reported = round(openssf_component, 2)

    trust = max(0, min(100, trust))

    # Confidence
    signals = 0
    signals_total = 8
    if archived is not None:
        signals += 1
    if last_commit:
        signals += 1
    if openssf_available:
        signals += 2
    if maintainer_count is not None:
        signals += 1
    if hash_verified is not None:
        signals += 1
    if signature_status not in ("unavailable",):
        signals += 1
    if has_license or (dataset_doc and dataset_doc.get("license_documented")):
        signals += 1
    confidence = signals / signals_total
    if partial_data:
        confidence *= 0.75
    if openssf_component is None:
        confidence *= 0.85
    confidence = round(max(0.0, min(1.0, confidence)), 2)

    severities = {i.get("severity") for i in issues}
    critical = "critical" in severities
    high = "high" in severities

    if critical:
        verdict = "BLOCK"
    elif confidence < 0.5:
        verdict = "CONDITIONAL"
    elif trust < 50 and confidence >= 0.5:
        verdict = "BLOCK"
    elif trust >= 80 and confidence >= 0.7 and not high:
        verdict = "ALLOW"
    else:
        verdict = "CONDITIONAL"

    return {
        "trust_score": trust,
        "verdict": verdict,
        "score_breakdown": {
            "repository_health": round(health, 2),
            "openssf": openssf_reported,
            "openssf_status": "available" if openssf_available else "not_available",
            "provenance": round(provenance_component, 2),
            "transparency": round(transparency, 2),
            "confidence": confidence,
        },
        "confidence": confidence,
    }


def evaluate_provenance(
    *,
    revision_pinned: bool,
    hash_verified: bool | None,
    signature_verified: bool,
    signature_status: str,
) -> tuple[bool, str]:
    if hash_verified is False or signature_status == "failed":
        return False, "weak"

    if revision_pinned and hash_verified is True and signature_verified:
        return True, "strong"
    if revision_pinned and (hash_verified is True or signature_verified):
        return True, "partial"
    if revision_pinned or hash_verified is True or signature_verified or signature_status == "present":
        return False, "weak"
    return False, "unknown"


# ---------------------------------------------------------------------------
# Main checker
# ---------------------------------------------------------------------------

class RepositoryChecker:
    """Collect provenance and trust signals for a software/AI artifact source."""

    def __init__(
        self,
        github_token: str | None = None,
        hf_token: str | None = None,
        timeout: float = 10.0,
        now: datetime | None = None,
    ):
        self.github_token = github_token or os.getenv("GITHUB_TOKEN") or None
        self.hf_token = (
            hf_token
            or os.getenv("HF_TOKEN")
            or os.getenv("HUGGINGFACE_TOKEN")
            or None
        )
        self.timeout = timeout
        self.now = now or datetime.now(timezone.utc)
        self.http = SafeHTTPClient(timeout=timeout)
        self._api_cache: dict[str, Any] = {}

    # -- public -------------------------------------------------------------

    def check(
        self,
        target: str,
        *,
        target_type: str = "auto",
        revision: str | None = None,
        local_file: str | None = None,
        expected_sha256: str | None = None,
        artifact_filename: str | None = None,
        signature_file: str | None = None,
        signature_bundle: str | None = None,
        signature_key: str | None = None,
        certificate_identity: str | None = None,
        certificate_oidc_issuer: str | None = None,
    ) -> dict:
        detected = detect_target_type(target, target_type)
        issues: list[dict] = list(detected.get("issues") or [])
        errors: list[dict] = []

        result = self._empty_result(target, detected)
        result["issues"] = issues
        result["errors"] = errors

        if detected.get("type") in (None, "invalid"):
            scoring = calculate_trust_score(
                issues=issues, now=self.now, partial_data=True,
            )
            result.update({
                "trust_score": scoring["trust_score"],
                "verdict": scoring["verdict"],
                "score_breakdown": scoring["score_breakdown"],
            })
            return result

        if detected.get("type") == "ambiguous":
            # Do not invent a provider; return structured ambiguity.
            scoring = calculate_trust_score(
                issues=issues, now=self.now, partial_data=True,
            )
            result.update({
                "trust_score": scoring["trust_score"],
                "verdict": "CONDITIONAL",
                "score_breakdown": scoring["score_breakdown"],
            })
            return result

        dtype = detected["type"]
        effective_revision = revision or detected.get("revision")

        if dtype == "github":
            self._merge_github(
                result,
                detected["owner"],
                detected["name"],
                revision=effective_revision,
            )
        elif dtype in ("hf_model", "hf_dataset"):
            self._merge_huggingface(
                result,
                detected["normalized"],
                repo_type="dataset" if dtype == "hf_dataset" else "model",
                revision=effective_revision,
            )
        elif dtype == "pypi":
            self._merge_pypi(
                result,
                detected["name"],
                version=detected.get("version"),
                local_file=local_file,
                artifact_filename=artifact_filename,
            )
        elif dtype == "local":
            result["target"]["type"] = "local"

        # Provenance / hash / signature (shared)
        prov = self.check_provenance(
            revision=effective_revision,
            local_file=local_file,
            expected_sha256=expected_sha256,
            artifact_filename=artifact_filename,
            signature_file=signature_file,
            signature_bundle=signature_bundle,
            signature_key=signature_key,
            certificate_identity=certificate_identity,
            certificate_oidc_issuer=certificate_oidc_issuer,
            published_hashes=result.get("_published_hashes") or [],
            release_assets=result.get("_release_assets") or [],
            version_pinned=bool(detected.get("version_pinned")),
            pypi_version=detected.get("version"),
        )
        result.pop("_published_hashes", None)
        result.pop("_release_assets", None)

        result["issues"].extend(prov.get("issues") or [])
        result["errors"].extend(prov.get("errors") or [])
        result["provenance"] = prov["provenance"]
        result["signature"] = prov["signature"]
        result["signature_verified"] = prov["signature_verified"]
        result["provenance_detail"] = prov["provenance_detail"]

        # For PyPI, keep version_pinned distinct from revision_pinned
        if dtype == "pypi":
            result["provenance_detail"]["version"] = detected.get("version")
            result["provenance_detail"]["version_pinned"] = bool(detected.get("version_pinned"))

        repo_info = result.get("repository") or {}
        dataset = result.get("dataset") or {}
        scoring = calculate_trust_score(
            archived=repo_info.get("archived"),
            last_commit=result.get("last_commit"),
            last_release=result.get("last_release"),
            maintainer_count=result.get("maintainer_count"),
            maintainer_count_method=result.get("maintainer_count_method"),
            stars=result.get("github_star"),
            openssf_score=result.get("openssf_score"),
            openssf_available=bool((result.get("openssf") or {}).get("available")),
            revision_pinned=bool(prov["provenance_detail"].get("revision_pinned")),
            hash_verified=prov["provenance_detail"].get("hash_verified"),
            signature_status=prov["provenance_detail"].get("signature_status") or "not_found",
            signature_verified=bool(prov["signature_verified"]),
            has_license=bool(repo_info.get("license") or (result.get("huggingface") or {}).get("license")),
            has_readme=bool(result.get("_has_readme")),
            has_codeowners=result.get("maintainer_count_method") == "codeowners",
            dataset_doc=dataset if dataset.get("checked") else None,
            is_dataset=dtype == "hf_dataset",
            issues=result["issues"],
            now=self.now,
            partial_data=bool(result["errors"]),
        )
        result.pop("_has_readme", None)
        result["trust_score"] = scoring["trust_score"]
        result["verdict"] = scoring["verdict"]
        result["score_breakdown"] = scoring["score_breakdown"]
        return result

    # -- GitHub -------------------------------------------------------------

    def check_github_repository(
        self,
        owner: str,
        repo: str,
        *,
        revision: str | None = None,
    ) -> dict:
        issues: list[dict] = []
        errors: list[dict] = []
        out: dict[str, Any] = {
            "available": False,
            "issues": issues,
            "errors": errors,
        }

        headers = self._github_headers()
        url = f"{GITHUB_API}/repos/{owner}/{repo}"
        data, response, err = self.http.get_json(
            url,
            headers=headers,
            cache_key=f"github:repo:{owner}/{repo}",
            allow_statuses=(200, 404, 403, 401),
        )
        if err:
            errors.append({**err, "source": "github"})
            return out

        assert response is not None
        if response.status_code == 404:
            errors.append(_error("github", "not_found", f"repository {owner}/{repo} not found", False))
            return out
        if response.status_code in (401, 403):
            remaining = response.headers.get("X-RateLimit-Remaining")
            reset = response.headers.get("X-RateLimit-Reset")
            detail = "GitHub API rate limit or authorization error"
            if remaining is not None:
                detail += f" (remaining={remaining}"
                if reset:
                    detail += f", reset={reset}"
                detail += ")"
            errors.append(_error(
                "github",
                "rate_limit" if remaining == "0" else "forbidden",
                detail,
                True,
            ))
            return out
        if response.status_code != 200 or not isinstance(data, dict):
            errors.append(_error("github", "http_error", f"unexpected status {response.status_code}", True))
            return out

        default_branch = data.get("default_branch")
        license_info = data.get("license") or {}
        license_spdx = None
        if isinstance(license_info, dict):
            license_spdx = license_info.get("spdx_id") or license_info.get("name")
            if license_spdx == "NOASSERTION":
                license_spdx = None

        last_commit_iso = None
        if default_branch:
            commits_url = f"{GITHUB_API}/repos/{owner}/{repo}/commits"
            cdata, cresp, cerr = self.http.get_json(
                commits_url,
                headers=headers,
                params={"sha": default_branch, "per_page": 1},
                cache_key=f"github:commits:{owner}/{repo}:{default_branch}",
                allow_statuses=(200, 404, 409),
            )
            if cerr:
                errors.append({**cerr, "source": "github_commits"})
            elif cresp is not None and cresp.status_code in (404, 409):
                # empty repository — not a hard failure
                issues.append(_issue(
                    "repository", "info", "repository has no commits yet",
                    evidence=f"status={cresp.status_code}",
                ))
            elif isinstance(cdata, list) and cdata:
                commit = cdata[0].get("commit") or {}
                committer = commit.get("committer") or {}
                author = commit.get("author") or {}
                last_commit_iso = (
                    committer.get("date")
                    or author.get("date")
                    or data.get("pushed_at")
                )
            else:
                last_commit_iso = data.get("pushed_at")
        else:
            last_commit_iso = data.get("pushed_at")

        last_release_iso = None
        release_assets: list[dict] = []
        rel_url = f"{GITHUB_API}/repos/{owner}/{repo}/releases/latest"
        rdata, rresp, rerr = self.http.get_json(
            rel_url,
            headers=headers,
            cache_key=f"github:release:{owner}/{repo}",
            allow_statuses=(200, 404),
        )
        if rerr:
            errors.append({**rerr, "source": "github_release"})
        elif rresp is not None and rresp.status_code == 404:
            last_release_iso = None
            issues.append(_issue(
                "repository", "medium", "no public release found",
                recommendation="publish signed releases with digests",
            ))
        elif isinstance(rdata, dict):
            last_release_iso = rdata.get("published_at") or rdata.get("created_at")
            for asset in rdata.get("assets") or []:
                if not isinstance(asset, dict):
                    continue
                release_assets.append({
                    "name": asset.get("name"),
                    "digest": asset.get("digest"),
                    "url": asset.get("browser_download_url"),
                })

        maintainer_count, method, maint_issues = self._resolve_maintainers(owner, repo, headers)
        issues.extend(maint_issues)

        rev_type, rev_pinned = _classify_revision(revision)

        out.update({
            "available": True,
            "github_star": data.get("stargazers_count"),
            "github_fork": data.get("forks_count"),
            "last_commit": _normalize_date(last_commit_iso),
            "last_commit_at": last_commit_iso,
            "last_release": _normalize_date(last_release_iso),
            "last_release_at": last_release_iso,
            "maintainer_count": maintainer_count,
            "maintainer_count_method": method,
            "repository": {
                "provider": "github",
                "owner": owner,
                "name": repo,
                "html_url": data.get("html_url"),
                "default_branch": default_branch,
                "created_at": _normalize_date(data.get("created_at")),
                "created_at_full": data.get("created_at"),
                "updated_at": _normalize_date(data.get("updated_at")),
                "updated_at_full": data.get("updated_at"),
                "pushed_at": data.get("pushed_at"),
                "archived": data.get("archived"),
                "fork": data.get("fork"),
                "license": license_spdx,
                "owner_login": (data.get("owner") or {}).get("login"),
            },
            "revision": revision,
            "revision_type": rev_type,
            "revision_pinned": rev_pinned,
            "release_assets": release_assets,
            "has_description": bool(data.get("description")),
        })

        if data.get("archived"):
            issues.append(_issue(
                "repository", "high", "repository is archived",
                evidence=f"{owner}/{repo}",
                recommendation="prefer an actively maintained fork or alternative",
            ))
        if method == "contributors_estimate":
            issues.append(_issue(
                "repository", "info",
                "maintainer_count is estimated from contributors, not actual permission holders",
                evidence=method,
            ))
        if method != "codeowners":
            issues.append(_issue(
                "repository", "medium", "CODEOWNERS not found",
                recommendation="add a CODEOWNERS file to clarify maintainers",
            ))
        if maintainer_count == 1:
            issues.append(_issue(
                "repository", "medium", "only one maintainer estimated",
                evidence=maintainer_count,
            ))
        days = _days_since(last_commit_iso, self.now)
        if days is not None and days > 365:
            issues.append(_issue(
                "repository", "medium", "last commit is older than one year",
                evidence=out["last_commit"],
            ))

        scorecard = self.check_openssf_scorecard(owner, repo)
        out["openssf"] = scorecard
        out["openssf_score"] = scorecard.get("score")
        if scorecard.get("error"):
            errors.append(_error("openssf", "unavailable", scorecard["error"], True))
        if scorecard.get("available") and scorecard.get("score") is not None:
            if float(scorecard["score"]) <= 3:
                issues.append(_issue(
                    "repository", "high", "OpenSSF Scorecard score is very low",
                    evidence=scorecard["score"],
                    recommendation="address weak Scorecard checks",
                ))

        out["issues"] = issues
        out["errors"] = errors
        return out

    def check_openssf_scorecard(self, owner: str, repo: str) -> dict:
        url = f"{OPENSSF_API}/projects/github.com/{owner}/{repo}"
        data, response, err = self.http.get_json(
            url,
            cache_key=f"openssf:{owner}/{repo}",
            allow_statuses=(200, 404),
        )
        if err:
            return {
                "available": False,
                "score": None,
                "date": None,
                "commit": None,
                "weak_checks": [],
                "check_count": 0,
                "error": err.get("detail") or "scorecard request failed",
            }
        if response is not None and response.status_code == 404:
            return {
                "available": False,
                "score": None,
                "date": None,
                "commit": None,
                "weak_checks": [],
                "check_count": 0,
                "error": "scorecard result not available",
            }
        if not isinstance(data, dict):
            return {
                "available": False,
                "score": None,
                "date": None,
                "commit": None,
                "weak_checks": [],
                "check_count": 0,
                "error": "scorecard result not available",
            }

        score = data.get("score")
        if score is not None:
            try:
                score = float(score)
                if score < 0 or score > 10:
                    return {
                        "available": False,
                        "score": None,
                        "date": _normalize_date(data.get("date")),
                        "commit": data.get("commit"),
                        "weak_checks": [],
                        "check_count": 0,
                        "error": f"score out of range: {score}",
                    }
            except (TypeError, ValueError):
                score = None

        checks = data.get("checks") or []
        weak = []
        for check in checks:
            if not isinstance(check, dict):
                continue
            cscore = check.get("score")
            try:
                cscore_f = float(cscore) if cscore is not None else None
            except (TypeError, ValueError):
                cscore_f = None
            if cscore_f is not None and cscore_f <= WEAK_CHECK_THRESHOLD:
                docs = check.get("documentation") or {}
                if isinstance(docs, dict):
                    doc_url = docs.get("url")
                else:
                    doc_url = docs
                weak.append({
                    "name": check.get("name"),
                    "score": cscore_f,
                    "reason": check.get("reason"),
                    "documentation": doc_url,
                })

        return {
            "available": score is not None,
            "score": score,
            "date": _normalize_date(data.get("date")),
            "commit": data.get("commit"),
            "weak_checks": weak,
            "check_count": len(checks) if isinstance(checks, list) else 0,
            "error": None if score is not None else "scorecard score missing",
        }

    def _resolve_maintainers(
        self,
        owner: str,
        repo: str,
        headers: dict,
    ) -> tuple[int | None, str, list[dict]]:
        issues: list[dict] = []
        for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
            data, response, err = self.http.get_json(
                url,
                headers=headers,
                cache_key=f"github:contents:{owner}/{repo}:{path}",
                allow_statuses=(200, 404),
            )
            if err:
                continue
            if response is not None and response.status_code == 404:
                continue
            if not isinstance(data, dict):
                continue
            # Prefer download_url to avoid base64 decode edge cases
            download = data.get("download_url")
            content_text = None
            if download:
                try:
                    validate_public_url(download)
                    text, _, terr = self.http.get_text(
                        download,
                        headers=headers,
                        cache_key=f"github:raw:{owner}/{repo}:{path}",
                    )
                    if terr is None:
                        content_text = text
                except SSRFError:
                    content_text = None
            if content_text is None and data.get("encoding") == "base64" and data.get("content"):
                import base64
                try:
                    content_text = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                except (ValueError, UnicodeError):
                    content_text = None
            if content_text:
                owners = parse_codeowners(content_text)
                if owners:
                    return len(owners), "codeowners", issues

        # Contributors estimate
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contributors"
        data, response, err = self.http.get_json(
            url,
            headers=headers,
            params={"anon": "false", "per_page": 100},
            cache_key=f"github:contrib:{owner}/{repo}",
            allow_statuses=(200, 404, 204),
        )
        if err:
            return None, "unknown", issues
        if response is not None and response.status_code in (204, 404):
            return None, "unknown", issues
        if not isinstance(data, list):
            return None, "unknown", issues
        count, method = estimate_maintainers_from_contributors(data)
        return count, method, issues

    def _github_headers(self) -> dict:
        headers = {
            "Accept": "application/vnd.github+json",
            # Spec default; override with GITHUB_API_VERSION when needed.
            "X-GitHub-Api-Version": os.getenv("GITHUB_API_VERSION", "2026-03-10"),
            "User-Agent": USER_AGENT,
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def _merge_github(self, result: dict, owner: str, repo: str, revision: str | None) -> None:
        gh = self.check_github_repository(owner, repo, revision=revision)
        result["issues"].extend(gh.get("issues") or [])
        result["errors"].extend(gh.get("errors") or [])
        if not gh.get("available"):
            return
        for key in (
            "github_star", "github_fork", "last_commit", "last_release",
            "maintainer_count", "maintainer_count_method", "openssf_score",
            "repository", "openssf",
        ):
            if key in gh:
                result[key] = gh[key]
        result["_has_readme"] = bool(gh.get("has_description"))
        result["_release_assets"] = gh.get("release_assets") or []
        # Collect published digests from release assets
        hashes = []
        for asset in result["_release_assets"]:
            digest = asset.get("digest")
            norm = _normalize_sha256(digest) if digest else None
            if norm:
                hashes.append({"hash": norm, "source": "github_release", "name": asset.get("name")})
        result["_published_hashes"] = hashes
        if revision:
            result["provenance_detail"]["requested_revision"] = revision
            rtype, pinned = _classify_revision(revision)
            result["provenance_detail"]["revision_type"] = rtype
            result["provenance_detail"]["revision_pinned"] = pinned

    # -- Hugging Face -------------------------------------------------------

    def check_huggingface_repository(
        self,
        repo_id: str,
        *,
        repo_type: str = "model",
        revision: str | None = None,
    ) -> dict:
        issues: list[dict] = []
        errors: list[dict] = []
        headers = self._hf_headers()
        api_type = "datasets" if repo_type == "dataset" else "models"
        url = f"{HF_API}/api/{api_type}/{repo_id}"
        params = {}
        if revision:
            params["revision"] = revision

        data, response, err = self.http.get_json(
            url,
            headers=headers,
            params=params or None,
            cache_key=f"hf:{api_type}:{repo_id}:{revision or ''}",
            allow_statuses=(200, 401, 403, 404),
        )
        if err:
            errors.append({**err, "source": "huggingface"})
            return {"available": False, "issues": issues, "errors": errors}

        assert response is not None
        if response.status_code == 404:
            errors.append(_error("huggingface", "not_found", f"{repo_type} {repo_id} not found", False))
            return {"available": False, "issues": issues, "errors": errors}
        if response.status_code in (401, 403):
            if self.hf_token:
                errors.append(_error(
                    "huggingface", "forbidden",
                    "token lacks permission for this repository (may be private)",
                    False,
                ))
            else:
                errors.append(_error(
                    "huggingface", "auth_required",
                    "repository may be private; no HF token configured",
                    False,
                ))
            return {"available": False, "issues": issues, "errors": errors}
        if response.status_code != 200 or not isinstance(data, dict):
            errors.append(_error("huggingface", "http_error", f"status {response.status_code}", True))
            return {"available": False, "issues": issues, "errors": errors}

        requested = revision or "main"
        # sha / siblings may include resolved commit
        resolved = data.get("sha") or data.get("rdfs:label") or None
        rev_type, rev_pinned = _classify_revision(revision)
        if revision is None:
            rev_type, rev_pinned = "branch", False

        card_data = data.get("cardData") or data.get("card_data") or {}
        if not isinstance(card_data, dict):
            card_data = {}

        license_value = card_data.get("license") or data.get("license")
        if isinstance(license_value, list):
            license_value = license_value[0] if license_value else None
        if license_value and str(license_value).lower() in INVALID_LICENSE_VALUES:
            license_value = None

        siblings = data.get("siblings") or []
        files_summary = self._summarize_hf_files(siblings)

        # README
        readme_text = None
        readme_url = f"{HF_API}/{repo_id}/raw/{requested}/README.md"
        if repo_type == "dataset":
            readme_url = f"{HF_API}/datasets/{repo_id}/raw/{requested}/README.md"
        try:
            validate_public_url(readme_url)
            text, rresp, rerr = self.http.get_text(
                readme_url,
                headers=headers,
                cache_key=f"hf:readme:{repo_type}:{repo_id}:{requested}",
            )
            if rerr:
                errors.append({**rerr, "source": "huggingface_readme"})
            elif rresp is not None and rresp.status_code == 200:
                readme_text = text
        except SSRFError as exc:
            errors.append(_error("huggingface_readme", "ssrf_blocked", str(exc), False))

        dataset_doc = {
            "checked": False,
            "missing_fields": [],
        }
        if repo_type == "dataset":
            dataset_doc = check_dataset_documentation(readme_text, card_data)
            if not dataset_doc.get("card_exists"):
                issues.append(_issue(
                    "dataset", "high", "dataset card / README missing",
                    recommendation="add a Dataset Card with license and source info",
                ))
            if not dataset_doc.get("license_documented"):
                issues.append(_issue(
                    "dataset", "high", "dataset license not documented",
                    recommendation="declare an SPDX license in the Dataset Card",
                ))
            if dataset_doc.get("source_documented") is False:
                issues.append(_issue(
                    "dataset", "medium", "dataset source not documented",
                ))
            if dataset_doc.get("collection_method_documented") is False:
                issues.append(_issue(
                    "dataset", "medium", "data collection method not documented",
                ))

        # Linked GitHub
        meta_urls = {}
        for key in ("repository", "source_code", "source", "code", "github"):
            if card_data.get(key):
                meta_urls[key] = card_data[key]
        chosen, candidates = extract_github_candidates(meta_urls, readme_text)

        github_payload = None
        github_candidates = candidates
        if chosen:
            parts = chosen.split("/", 1)
            github_payload = self.check_github_repository(parts[0], parts[1], revision=None)
            issues.extend(github_payload.get("issues") or [])
            errors.extend(github_payload.get("errors") or [])
        elif len(candidates) > 1:
            issues.append(_issue(
                "repository", "medium", "ambiguous_repository_source",
                evidence=candidates,
                recommendation="set an explicit repository URL in model/dataset card metadata",
            ))

        author = data.get("author") or repo_id.split("/")[0]
        last_modified = data.get("lastModified") or data.get("last_modified")

        return {
            "available": True,
            "issues": issues,
            "errors": errors,
            "huggingface": {
                "repo_id": repo_id,
                "repo_type": repo_type,
                "author": author,
                "last_modified": _normalize_date(last_modified),
                "last_modified_at": last_modified,
                "downloads": data.get("downloads"),
                "likes": data.get("likes"),
                "license": license_value,
                "requested_revision": requested,
                "resolved_revision": resolved,
                "revision_type": rev_type,
                "revision_pinned": rev_pinned,
                "files": files_summary,
            },
            "dataset": dataset_doc,
            "github_repository": chosen,
            "github_candidates": github_candidates,
            "github": github_payload,
            "readme": bool(readme_text),
            "published_hashes": files_summary.get("hash_samples") or [],
        }

    def check_dataset_documentation(
        self,
        readme_text: str | None,
        card_data: dict | None = None,
    ) -> dict:
        return check_dataset_documentation(readme_text, card_data)

    def _summarize_hf_files(self, siblings: list) -> dict:
        total = 0
        model_files = 0
        with_hash = 0
        important: list[dict] = []
        hash_samples: list[dict] = []
        model_exts = (".bin", ".safetensors", ".pt", ".pth", ".onnx", ".gguf", ".h5")

        for sib in siblings:
            if not isinstance(sib, dict):
                continue
            total += 1
            name = sib.get("rfilename") or sib.get("filename") or ""
            lfs = sib.get("lfs") or {}
            sha = None
            if isinstance(lfs, dict):
                sha = lfs.get("sha256") or lfs.get("oid")
            sha_norm = _normalize_sha256(sha) if sha else None
            if sha_norm:
                with_hash += 1
                if len(hash_samples) < 20:
                    hash_samples.append({
                        "hash": sha_norm,
                        "source": "huggingface_lfs",
                        "name": name,
                    })
            is_model = name.lower().endswith(model_exts)
            if is_model:
                model_files += 1
            if is_model or name.lower() in ("config.json", "tokenizer.json", "README.md"):
                if len(important) < MAX_HF_FILES_DETAIL:
                    important.append({
                        "filename": name,
                        "size": sib.get("size") or (lfs.get("size") if isinstance(lfs, dict) else None),
                        "blob_id": sib.get("blob_id") or sib.get("oid"),
                        "lfs": bool(lfs),
                        "lfs_sha256": sha_norm,
                    })

        return {
            "total_files": total,
            "model_files": model_files,
            "files_with_hash": with_hash,
            "important_files": important,
            "hash_samples": hash_samples,
        }

    def _hf_headers(self) -> dict:
        headers = {"User-Agent": USER_AGENT}
        if self.hf_token:
            headers["Authorization"] = f"Bearer {self.hf_token}"
        return headers

    def _merge_huggingface(
        self,
        result: dict,
        repo_id: str,
        *,
        repo_type: str,
        revision: str | None,
    ) -> None:
        hf = self.check_huggingface_repository(repo_id, repo_type=repo_type, revision=revision)
        result["issues"].extend(hf.get("issues") or [])
        result["errors"].extend(hf.get("errors") or [])
        if not hf.get("available"):
            return
        result["huggingface"] = hf.get("huggingface")
        result["dataset"] = hf.get("dataset") or result.get("dataset")
        result["github_repository"] = hf.get("github_repository")
        result["github_candidates"] = hf.get("github_candidates")
        result["_has_readme"] = bool(hf.get("readme"))
        result["_published_hashes"] = hf.get("published_hashes") or []

        meta = hf.get("huggingface") or {}
        result["provenance_detail"]["requested_revision"] = meta.get("requested_revision")
        result["provenance_detail"]["resolved_revision"] = meta.get("resolved_revision")
        result["provenance_detail"]["revision_type"] = meta.get("revision_type")
        result["provenance_detail"]["revision_pinned"] = meta.get("revision_pinned")

        gh = hf.get("github")
        if isinstance(gh, dict) and gh.get("available"):
            for key in (
                "github_star", "github_fork", "last_commit", "last_release",
                "maintainer_count", "maintainer_count_method", "openssf_score",
                "repository", "openssf",
            ):
                if key in gh and result.get(key) in (None, {}, []):
                    result[key] = gh[key]
            result["_release_assets"] = gh.get("release_assets") or []

    # -- PyPI ---------------------------------------------------------------

    def check_pypi_package(
        self,
        package_name: str,
        *,
        version: str | None = None,
        local_file: str | None = None,
        artifact_filename: str | None = None,
    ) -> dict:
        issues: list[dict] = []
        errors: list[dict] = []
        normalized = _normalize_pypi_name(package_name)
        url = f"{PYPI_API}/pypi/{normalized}/json"
        data, response, err = self.http.get_json(
            url,
            cache_key=f"pypi:{normalized}",
            allow_statuses=(200, 404),
        )
        if err:
            errors.append({**err, "source": "pypi"})
            return {"available": False, "issues": issues, "errors": errors}
        assert response is not None
        if response.status_code == 404 or not isinstance(data, dict):
            errors.append(_error("pypi", "not_found", f"package {package_name} not found", False))
            return {"available": False, "issues": issues, "errors": errors}

        info = data.get("info") or {}
        releases = data.get("releases") or {}
        version_pinned = version is not None
        chosen_version = version or info.get("version")
        files = []
        if chosen_version and chosen_version in releases:
            files = releases.get(chosen_version) or []
        elif not version:
            files = data.get("urls") or []

        published_hashes = []
        matched_hash = None
        target_name = artifact_filename
        if local_file and not target_name:
            target_name = Path(local_file).name

        for fmeta in files:
            if not isinstance(fmeta, dict):
                continue
            digests = fmeta.get("digests") or {}
            sha = _normalize_sha256(digests.get("sha256"))
            fname = fmeta.get("filename")
            if sha:
                published_hashes.append({
                    "hash": sha,
                    "source": "pypi",
                    "name": fname,
                })
            if target_name and fname == target_name and sha:
                matched_hash = sha
            # Intentionally ignore deprecated has_sig field

        project_urls = info.get("project_urls") or {}
        if not isinstance(project_urls, dict):
            project_urls = {}
        # Also consider home_page
        urls_for_search = dict(project_urls)
        if info.get("home_page"):
            urls_for_search.setdefault("Homepage", info["home_page"])

        chosen, candidates = extract_github_candidates(urls_for_search, None)
        github_payload = None
        if chosen:
            owner, name = chosen.split("/", 1)
            github_payload = self.check_github_repository(owner, name)
            issues.extend(github_payload.get("issues") or [])
            errors.extend(github_payload.get("errors") or [])
        elif len(candidates) > 1:
            issues.append(_issue(
                "repository", "medium", "ambiguous_repository_source",
                evidence=candidates,
            ))
        elif not candidates:
            issues.append(_issue(
                "repository", "high", "could not locate GitHub source repository for package",
                evidence=package_name,
            ))

        if not version_pinned:
            issues.append(_issue(
                "revision", "medium", "PyPI package version is not pinned",
                evidence=package_name,
                recommendation="pin an exact version with package==version",
            ))

        return {
            "available": True,
            "issues": issues,
            "errors": errors,
            "pypi": {
                "name": package_name,
                "normalized_name": normalized,
                "version": chosen_version,
                "version_pinned": version_pinned,
                "summary": info.get("summary"),
                "license": info.get("license"),
                "home_page": info.get("home_page"),
                "project_urls": project_urls,
                "file_count": len(files),
                "matched_file_sha256": matched_hash,
            },
            "github_repository": chosen,
            "github_candidates": candidates,
            "github": github_payload,
            "published_hashes": published_hashes,
        }

    def _merge_pypi(
        self,
        result: dict,
        package_name: str,
        *,
        version: str | None,
        local_file: str | None,
        artifact_filename: str | None,
    ) -> None:
        pp = self.check_pypi_package(
            package_name,
            version=version,
            local_file=local_file,
            artifact_filename=artifact_filename,
        )
        result["issues"].extend(pp.get("issues") or [])
        result["errors"].extend(pp.get("errors") or [])
        if not pp.get("available"):
            return
        result["pypi"] = pp.get("pypi")
        result["github_repository"] = pp.get("github_repository")
        result["github_candidates"] = pp.get("github_candidates")
        result["_published_hashes"] = pp.get("published_hashes") or []
        result["_has_readme"] = bool((pp.get("pypi") or {}).get("summary"))

        license_val = (pp.get("pypi") or {}).get("license")
        gh = pp.get("github")
        if isinstance(gh, dict) and gh.get("available"):
            for key in (
                "github_star", "github_fork", "last_commit", "last_release",
                "maintainer_count", "maintainer_count_method", "openssf_score",
                "repository", "openssf",
            ):
                if key in gh:
                    result[key] = gh[key]
            result["_release_assets"] = gh.get("release_assets") or []
            if not result["repository"].get("license") and license_val:
                result["repository"]["license"] = license_val
        elif license_val:
            result.setdefault("repository", {})
            result["repository"] = {
                "provider": "pypi",
                "owner": None,
                "name": package_name,
                "default_branch": None,
                "created_at": None,
                "updated_at": None,
                "archived": None,
                "fork": None,
                "license": license_val,
            }

    # -- Provenance ---------------------------------------------------------

    def check_provenance(
        self,
        *,
        revision: str | None = None,
        local_file: str | None = None,
        expected_sha256: str | None = None,
        artifact_filename: str | None = None,
        signature_file: str | None = None,
        signature_bundle: str | None = None,
        signature_key: str | None = None,
        certificate_identity: str | None = None,
        certificate_oidc_issuer: str | None = None,
        published_hashes: list | None = None,
        release_assets: list | None = None,
        version_pinned: bool = False,
        pypi_version: str | None = None,
    ) -> dict:
        issues: list[dict] = []
        errors: list[dict] = []
        published_hashes = list(published_hashes or [])
        release_assets = list(release_assets or [])

        rev_type, rev_pinned = _classify_revision(revision)
        if revision and not rev_pinned and rev_type in ("branch", "tag", "ref", "short_sha"):
            issues.append(_issue(
                "revision", "medium",
                "revision is not an immutable commit SHA",
                evidence=revision,
                recommendation="pin a full 40-character commit SHA",
            ))

        actual_hash = None
        hash_verified = None
        expected_hash = _normalize_sha256(expected_sha256) if expected_sha256 else None
        hash_source = None

        if expected_sha256 and expected_hash is None:
            issues.append(_issue(
                "hash", "high", "expected SHA-256 is not a valid 64-char hex digest",
                evidence=expected_sha256[:20] + "...",
            ))

        if local_file:
            try:
                actual_hash = calculate_sha256(local_file)
            except FileNotFoundError:
                errors.append(_error("hash", "not_found", "local file not found", False))
            except PermissionError:
                errors.append(_error("hash", "permission", "local file not readable", False))
            except ValueError as exc:
                errors.append(_error("hash", "invalid_file", str(exc), False))

        # Gather expected hashes from publications matching a concrete filename.
        # Different release assets naturally have different digests — that is
        # NOT a conflict unless the same filename (or source pair) disagrees.
        fname = artifact_filename or (Path(local_file).name if local_file else None)
        matching_published = []
        if fname:
            by_name_hashes: dict[str, set[str]] = {}
            by_name_items: dict[str, list[dict]] = {}
            for item in published_hashes:
                h = item.get("hash")
                name = item.get("name")
                if not h or not name:
                    continue
                by_name_hashes.setdefault(name, set()).add(h)
                by_name_items.setdefault(name, []).append(item)
                if name == fname:
                    matching_published.append(item)

            if fname in by_name_hashes and len(by_name_hashes[fname]) > 1:
                issues.append(_issue(
                    "hash", "critical",
                    "conflicting published SHA-256 digests from different sources",
                    evidence=list(by_name_hashes[fname]),
                ))
                hash_verified = False

        if expected_hash:
            hash_source = "user"
        elif matching_published:
            vals = {m["hash"] for m in matching_published}
            if len(vals) > 1:
                issues.append(_issue(
                    "hash", "critical",
                    "conflicting published SHA-256 digests",
                    evidence=list(vals),
                ))
                hash_verified = False
            elif len(vals) == 1:
                expected_hash = next(iter(vals))
                hash_source = matching_published[0].get("source")

        if actual_hash and expected_hash:
            if actual_hash.lower() == expected_hash.lower():
                hash_verified = True
            else:
                hash_verified = False
                issues.append(_issue(
                    "hash", "critical",
                    "local file SHA-256 does not match the published digest",
                    evidence={"expected": expected_hash, "actual": actual_hash},
                    recommendation="do not use this artifact; verify the download source",
                ))
        elif actual_hash and not expected_hash:
            hash_verified = None
            issues.append(_issue(
                "hash", "medium", "hash verification material is insufficient",
                recommendation="provide expected_sha256 or a matching published digest",
            ))

        # Signature detection / optional cosign verify
        sig_evidence = []
        signature_present = False

        def _note_sig(path_or_name: str, source: str) -> None:
            nonlocal signature_present
            signature_present = True
            sig_evidence.append({"name": path_or_name, "source": source})

        if signature_file:
            _note_sig(Path(signature_file).name, "user_signature_file")
        if signature_bundle:
            _note_sig(Path(signature_bundle).name, "user_signature_bundle")

        if local_file:
            parent = Path(local_file).resolve().parent
            base = Path(local_file).name
            for sibling in parent.iterdir() if parent.is_dir() else []:
                if sibling.name == base:
                    continue
                if _looks_like_signature(sibling.name) and (
                    sibling.name.startswith(base) or base in sibling.name
                    or sibling.suffix in {".sig", ".asc", ".bundle", ".sigstore"}
                ):
                    _note_sig(sibling.name, "local_adjacent")

        for asset in release_assets:
            name = asset.get("name") or ""
            if _looks_like_signature(name):
                _note_sig(name, "github_release")

        signature_status = "not_found"
        signature_verified = False

        if (certificate_identity and not certificate_oidc_issuer) or (
            certificate_oidc_issuer and not certificate_identity
        ):
            issues.append(_issue(
                "signature", "medium",
                "keyless verification requires both certificate_identity and certificate_oidc_issuer",
            ))

        # Enough material to attempt cryptographic verification with cosign
        has_blob_bundle = bool(local_file and signature_bundle)
        has_blob_key = bool(local_file and signature_file and signature_key)
        has_keyless = bool(
            local_file
            and certificate_identity
            and certificate_oidc_issuer
            and (signature_bundle or signature_file)
        )
        can_verify = has_blob_bundle or has_blob_key or has_keyless

        if can_verify:
            verified, status, detail = self._verify_cosign(
                local_file=local_file,
                signature_file=signature_file,
                signature_bundle=signature_bundle,
                signature_key=signature_key,
                certificate_identity=certificate_identity,
                certificate_oidc_issuer=certificate_oidc_issuer,
            )
            signature_status = status
            signature_verified = verified
            if status == "failed":
                issues.append(_issue(
                    "signature", "critical", "signature verification failed",
                    evidence=_redact_sensitive(detail or ""),
                ))
            elif status == "unavailable":
                # Materials exist but tooling is missing — still count as present evidence
                if signature_present:
                    signature_status = "present"
                issues.append(_issue(
                    "signature", "info",
                    detail or "cosign not available for cryptographic verification",
                ))
            elif status == "present":
                issues.append(_issue(
                    "signature", "medium",
                    "signature evidence present but not cryptographically verified",
                    recommendation="provide signature bundle/key and ensure cosign is installed",
                ))
        elif signature_present:
            signature_status = "present"
            signature_verified = False
            issues.append(_issue(
                "signature", "medium", "signature evidence present but not cryptographically verified",
                recommendation="provide signature bundle/key and ensure cosign is installed",
            ))
        else:
            signature_status = "not_found"
            issues.append(_issue(
                "signature", "medium", "no signature found",
                recommendation="verify a signed release or Sigstore bundle",
            ))

        provenance, prov_status = evaluate_provenance(
            revision_pinned=rev_pinned,
            hash_verified=hash_verified,
            signature_verified=signature_verified,
            signature_status=signature_status,
        )

        detail = {
            "status": prov_status,
            "requested_revision": revision,
            "resolved_revision": revision if rev_pinned else None,
            "revision_type": rev_type,
            "revision_pinned": rev_pinned,
            "version": pypi_version,
            "version_pinned": version_pinned,
            "hash_algorithm": "sha256",
            "expected_hash": expected_hash,
            "actual_hash": actual_hash,
            "hash_source": hash_source,
            "hash_verified": hash_verified,
            "local_file": Path(local_file).name if local_file else None,
            "signature_status": signature_status,
            "signature_evidence": sig_evidence,
        }

        return {
            "provenance": provenance,
            "signature": signature_present,
            "signature_verified": signature_verified,
            "provenance_detail": detail,
            "issues": issues,
            "errors": errors,
        }

    def _verify_cosign(
        self,
        *,
        local_file: str,
        signature_file: str | None,
        signature_bundle: str | None,
        signature_key: str | None,
        certificate_identity: str | None,
        certificate_oidc_issuer: str | None,
    ) -> tuple[bool, str, str | None]:
        cosign = shutil.which("cosign")
        if not cosign:
            return False, "unavailable", "cosign executable not found on PATH"

        cmd = [cosign, "verify-blob", local_file]
        if signature_bundle:
            cmd.extend(["--bundle", signature_bundle])
        elif signature_file and signature_key:
            cmd.extend(["--key", signature_key, "--signature", signature_file])
        elif certificate_identity and certificate_oidc_issuer and signature_bundle:
            cmd.extend([
                "--bundle", signature_bundle,
                "--certificate-identity", certificate_identity,
                "--certificate-oidc-issuer", certificate_oidc_issuer,
            ])
        elif certificate_identity and certificate_oidc_issuer and signature_file:
            cmd.extend([
                "--signature", signature_file,
                "--certificate-identity", certificate_identity,
                "--certificate-oidc-issuer", certificate_oidc_issuer,
            ])
        else:
            return False, "present", "insufficient material for cosign verify-blob"

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 5,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, "failed", "cosign verification timed out"
        except OSError as exc:
            return False, "failed", f"cosign execution error: {type(exc).__name__}"

        stdout = _redact_sensitive(proc.stdout or "")
        stderr = _redact_sensitive(proc.stderr or "")
        combined = f"{stdout}\n{stderr}".lower()
        if proc.returncode == 0 and ("verified" in combined or "equality check passed" in combined or not stderr.strip()):
            return True, "verified", None
        return False, "failed", stderr or stdout or f"exit={proc.returncode}"

    def calculate_sha256(self, path: str | Path, chunk_size: int = 1024 * 1024) -> str:
        return calculate_sha256(path, chunk_size=chunk_size)

    def calculate_trust_score(self, **kwargs) -> dict:
        kwargs.setdefault("now", self.now)
        return calculate_trust_score(**kwargs)

    # -- result skeleton ----------------------------------------------------

    def _empty_result(self, target: str, detected: dict) -> dict:
        return {
            "target": {
                "input": target,
                "type": detected.get("type"),
                "normalized": detected.get("normalized"),
            },
            "github_star": None,
            "github_fork": None,
            "last_commit": None,
            "last_release": None,
            "maintainer_count": None,
            "maintainer_count_method": None,
            "openssf_score": None,
            "provenance": False,
            "signature": False,
            "signature_verified": False,
            "trust_score": 0,
            "verdict": "CONDITIONAL",
            "repository": {},
            "openssf": {
                "available": False,
                "score": None,
                "date": None,
                "weak_checks": [],
            },
            "provenance_detail": {
                "status": "unknown",
                "requested_revision": detected.get("revision"),
                "resolved_revision": None,
                "revision_type": None,
                "revision_pinned": False,
                "hash_algorithm": "sha256",
                "expected_hash": None,
                "actual_hash": None,
                "hash_source": None,
                "hash_verified": None,
                "signature_status": "not_found",
                "signature_evidence": [],
            },
            "dataset": {
                "checked": False,
                "missing_fields": [],
            },
            "score_breakdown": {
                "repository_health": 0,
                "openssf": None,
                "provenance": 0,
                "transparency": 0,
                "confidence": 0,
            },
            "issues": [],
            "errors": [],
            "github_repository": None,
            "github_candidates": [],
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_repository(
    target: str,
    *,
    target_type: str = "auto",
    revision: str | None = None,
    local_file: str | None = None,
    expected_sha256: str | None = None,
    artifact_filename: str | None = None,
    signature_file: str | None = None,
    signature_bundle: str | None = None,
    signature_key: str | None = None,
    certificate_identity: str | None = None,
    certificate_oidc_issuer: str | None = None,
    timeout: float = 10.0,
) -> dict:
    """
    Inspect a package, GitHub repository, or Hugging Face model/dataset
    for supply-chain trust signals.

    Returns a JSON-serializable dict with trust_score and verdict.
    """
    checker = RepositoryChecker(timeout=timeout)
    return checker.check(
        target,
        target_type=target_type,
        revision=revision,
        local_file=local_file,
        expected_sha256=expected_sha256,
        artifact_filename=artifact_filename,
        signature_file=signature_file,
        signature_bundle=signature_bundle,
        signature_key=signature_key,
        certificate_identity=certificate_identity,
        certificate_oidc_issuer=certificate_oidc_issuer,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AIBOM-Guard repository / supply-chain trust checker",
    )
    parser.add_argument("target", help="GitHub URL, HF URL/id, or PyPI package")
    parser.add_argument(
        "--type", dest="target_type", default="auto",
        choices=["auto", "github", "hf_model", "hf_dataset", "pypi", "local"],
    )
    parser.add_argument("--revision", default=None)
    parser.add_argument("--local-file", default=None)
    parser.add_argument("--expected-sha256", default=None)
    parser.add_argument("--artifact-filename", default=None)
    parser.add_argument("--signature-file", default=None)
    parser.add_argument("--signature-bundle", default=None)
    parser.add_argument("--signature-key", default=None)
    parser.add_argument("--certificate-identity", default=None)
    parser.add_argument("--certificate-oidc-issuer", default=None)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--json", action="store_true", help="print full JSON result")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    result = check_repository(
        args.target,
        target_type=args.target_type,
        revision=args.revision,
        local_file=args.local_file,
        expected_sha256=args.expected_sha256,
        artifact_filename=args.artifact_filename,
        signature_file=args.signature_file,
        signature_bundle=args.signature_bundle,
        signature_key=args.signature_key,
        certificate_identity=args.certificate_identity,
        certificate_oidc_issuer=args.certificate_oidc_issuer,
        timeout=args.timeout,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"target : {result['target']}")
        print(f"score  : {result['trust_score']}")
        print(f"verdict: {result['verdict']}")
        print(f"openssf: {result.get('openssf_score')}")
        print(f"prov   : {result.get('provenance')} ({(result.get('provenance_detail') or {}).get('status')})")
        if result.get("issues"):
            print("issues :")
            for issue in result["issues"][:10]:
                print(f"  - [{issue['severity']}] {issue['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
