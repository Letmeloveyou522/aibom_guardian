"""
repository_checker.py
-----------------------------------
Supply-chain / repository trust checks for AIBOM-Guard.

Looks up whether a package or model's source looks trustworthy:
1) GitHub repo signals (stars, forks, last commit/release, maintainers)
2) OpenSSF Scorecard score
3) Provenance signals (signature presence, hash check, revision pin)
4) Hugging Face dataset metadata completeness (optional)

Usage:
    python repository_checker.py psf/requests
    python repository_checker.py --package requests --version 2.28.0
    python repository_checker.py --dataset glue
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime
from typing import Any

import requests

GITHUB_API = "https://api.github.com"
OPENSSF_API = "https://api.securityscorecards.dev"
PYPI_API = "https://pypi.org/pypi"
HF_API = "https://huggingface.co/api/datasets"

# 40-char hex looks like a full git commit SHA
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
GITHUB_URL_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "aibom-guard-repository-checker",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _date_only(value: str | None) -> str | None:
    """Normalize ISO timestamps to YYYY-MM-DD."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return value[:10] if len(value) >= 10 else value


def parse_github_url(url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL or 'owner/repo' string."""
    if not url:
        return None

    text = url.strip().rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]

    match = GITHUB_URL_RE.search(text)
    if match:
        owner, repo = match.group(1), match.group(2)
        return owner, repo

    if "/" in text and "://" not in text:
        parts = text.split("/")
        if len(parts) == 2 and parts[0] and parts[1]:
            return parts[0], parts[1]

    return None


def fetch_github_repo(owner: str, repo: str) -> dict[str, Any]:
    """
    Fetch basic trust signals from a GitHub repository.

    Returns keys used by the final report, plus an optional 'error'.
    """
    result: dict[str, Any] = {
        "github_star": None,
        "github_fork": None,
        "last_commit": None,
        "last_release": None,
        "maintainer_count": None,
        "repo_url": f"https://github.com/{owner}/{repo}",
    }

    try:
        repo_resp = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}",
            headers=_github_headers(),
            timeout=15,
        )
        repo_resp.raise_for_status()
        data = repo_resp.json()
        result["github_star"] = data.get("stargazers_count")
        result["github_fork"] = data.get("forks_count")
    except requests.exceptions.RequestException as e:
        print(f"[WARNING] GitHub repo lookup failed for {owner}/{repo}: {e}")
        result["error"] = str(e)
        return result

    try:
        commits_resp = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/commits",
            headers=_github_headers(),
            params={"per_page": 1},
            timeout=15,
        )
        commits_resp.raise_for_status()
        commits = commits_resp.json()
        if commits:
            result["last_commit"] = _date_only(
                commits[0].get("commit", {}).get("committer", {}).get("date")
                or commits[0].get("commit", {}).get("author", {}).get("date")
            )
    except requests.exceptions.RequestException as e:
        print(f"[WARNING] GitHub commits lookup failed for {owner}/{repo}: {e}")

    try:
        releases_resp = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/releases",
            headers=_github_headers(),
            params={"per_page": 1},
            timeout=15,
        )
        releases_resp.raise_for_status()
        releases = releases_resp.json()
        if releases:
            result["last_release"] = _date_only(releases[0].get("published_at"))
    except requests.exceptions.RequestException as e:
        print(f"[WARNING] GitHub releases lookup failed for {owner}/{repo}: {e}")

    # Contributors list is a practical MVP proxy for "maintainer count".
    # GitHub returns at most 30 items without pagination; good enough as a signal.
    try:
        contrib_resp = requests.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/contributors",
            headers=_github_headers(),
            params={"per_page": 30, "anon": "false"},
            timeout=15,
        )
        contrib_resp.raise_for_status()
        contributors = contrib_resp.json()
        if isinstance(contributors, list):
            result["maintainer_count"] = len(contributors)
    except requests.exceptions.RequestException as e:
        print(f"[WARNING] GitHub contributors lookup failed for {owner}/{repo}: {e}")

    return result


def fetch_openssf_score(owner: str, repo: str) -> float | None:
    """
    Query OpenSSF Scorecard for a GitHub repository.
    Returns the overall score (0-10), or None if unavailable.
    """
    url = f"{OPENSSF_API}/projects/github.com/{owner}/{repo}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()
        score = data.get("score")
        return float(score) if score is not None else None
    except (requests.exceptions.RequestException, TypeError, ValueError) as e:
        print(f"[WARNING] OpenSSF Scorecard lookup failed for {owner}/{repo}: {e}")
        return None


def resolve_github_from_pypi(package_name: str) -> tuple[str, str] | None:
    """Try to find a GitHub owner/repo from a PyPI package's project URLs."""
    try:
        response = requests.get(f"{PYPI_API}/{package_name}/json", timeout=15)
        response.raise_for_status()
        info = response.json().get("info", {})
    except requests.exceptions.RequestException as e:
        print(f"[WARNING] PyPI metadata lookup failed for {package_name}: {e}")
        return None

    candidates = []
    for key in ("home_page", "project_url", "download_url"):
        if info.get(key):
            candidates.append(info[key])

    project_urls = info.get("project_urls") or {}
    # Prefer Source/Repository/Homepage-style keys first
    preferred_keys = (
        "source", "source code", "repository", "repo", "code",
        "github", "homepage", "home",
    )
    for preferred in preferred_keys:
        for key, value in project_urls.items():
            if key and preferred in key.lower() and value:
                candidates.insert(0, value)
    for value in project_urls.values():
        if value:
            candidates.append(value)

    for url in candidates:
        parsed = parse_github_url(url)
        if parsed:
            return parsed
    return None


def _pypi_files(package_name: str, version: str) -> list[dict]:
    try:
        response = requests.get(
            f"{PYPI_API}/{package_name}/{version}/json",
            timeout=15,
        )
        response.raise_for_status()
        return response.json().get("urls", []) or []
    except requests.exceptions.RequestException as e:
        print(f"[WARNING] PyPI file list lookup failed for {package_name}=={version}: {e}")
        return []


def check_signature_presence(
    package_name: str | None = None,
    version: str | None = None,
    owner: str | None = None,
    repo: str | None = None,
) -> bool:
    """
    MVP check: does a signature / attestation artifact appear to exist?

    Looks for:
    - PyPI file entries with .asc digests or attestations metadata
    - GitHub release assets named *.sig / *.asc / *.att / *.intoto.jsonl
    """
    if package_name and version:
        files = _pypi_files(package_name, version)
        for f in files:
            filename = (f.get("filename") or "").lower()
            if filename.endswith((".asc", ".sig")):
                return True
            if f.get("has_sig"):
                return True
            digests = f.get("digests") or {}
            # Presence of attestations field on modern PyPI responses
            if f.get("attestations") or digests.get("attestations"):
                return True

        # Package-level attestations endpoint (best-effort)
        try:
            att = requests.get(
                f"{PYPI_API}/{package_name}/{version}/integrity",
                timeout=10,
            )
            if att.status_code == 200 and att.content:
                return True
        except requests.exceptions.RequestException:
            pass

    if owner and repo:
        try:
            releases_resp = requests.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/releases",
                headers=_github_headers(),
                params={"per_page": 3},
                timeout=15,
            )
            releases_resp.raise_for_status()
            for release in releases_resp.json():
                for asset in release.get("assets", []) or []:
                    name = (asset.get("name") or "").lower()
                    if name.endswith((".sig", ".asc", ".att", ".intoto.jsonl")):
                        return True
        except requests.exceptions.RequestException as e:
            print(f"[WARNING] GitHub release signature check failed: {e}")

    return False


def verify_file_hash(file_path: str, expected_sha256: str) -> bool | None:
    """
    Compare a local file's SHA-256 against a published digest.
    Returns True/False, or None if the file cannot be read.
    """
    if not file_path or not expected_sha256:
        return None
    try:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest().lower() == expected_sha256.lower()
    except OSError as e:
        print(f"[WARNING] Could not hash file {file_path}: {e}")
        return None


def get_pypi_sha256(package_name: str, version: str, filename: str | None = None) -> str | None:
    """Return a published SHA-256 digest for a PyPI distribution file."""
    files = _pypi_files(package_name, version)
    if not files:
        return None
    if filename:
        for f in files:
            if f.get("filename") == filename:
                return (f.get("digests") or {}).get("sha256")
    # Prefer the first wheel, else first artifact
    for f in files:
        if (f.get("packagetype") == "bdist_wheel") or (f.get("filename") or "").endswith(".whl"):
            return (f.get("digests") or {}).get("sha256")
    return (files[0].get("digests") or {}).get("sha256")


def is_revision_pinned(ref: str | None) -> bool:
    """
    True when a git dependency is pinned to a full commit SHA.
    Accepts raw SHAs or URLs like git+https://...@<sha>.
    """
    if not ref:
        return False

    text = ref.strip()
    if COMMIT_SHA_RE.match(text):
        return True

    # git+https://github.com/org/repo.git@abcdef...
    if "@" in text:
        after_at = text.rsplit("@", 1)[-1]
        # strip optional #egg=... fragment
        after_at = after_at.split("#", 1)[0].strip()
        if COMMIT_SHA_RE.match(after_at):
            return True
        # short SHAs (7+ hex) count as "somewhat pinned" for MVP? Keep strict: full 40 only.
        return False

    return False


def check_provenance(
    package_name: str | None = None,
    version: str | None = None,
    owner: str | None = None,
    repo: str | None = None,
    revision_ref: str | None = None,
    local_file: str | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """
    Gather provenance signals and a list of issues.

    provenance is True when revision is pinned AND (signature exists OR hash verified).
    """
    signature = check_signature_presence(package_name, version, owner, repo)
    revision_pinned = is_revision_pinned(revision_ref)

    if local_file and not expected_sha256 and package_name and version:
        expected_sha256 = get_pypi_sha256(package_name, version)

    hash_verified = verify_file_hash(local_file, expected_sha256) if local_file else None

    issues: list[dict[str, str]] = []
    if not signature:
        issues.append({"type": "provenance", "detail": "no signature found"})
    if revision_ref is not None and not revision_pinned:
        issues.append({
            "type": "provenance",
            "detail": "revision is not pinned to a full commit hash",
        })
    if local_file and hash_verified is False:
        issues.append({"type": "provenance", "detail": "file hash does not match published digest"})
    if local_file and hash_verified is None:
        issues.append({"type": "provenance", "detail": "file hash could not be verified"})

    provenance = bool(revision_pinned and (signature or hash_verified is True))
    # For PyPI packages without a git ref, treat signature OR successful hash as enough.
    if revision_ref is None and package_name:
        provenance = bool(signature or hash_verified is True)
        if not provenance and not any(i["detail"] == "no signature found" for i in issues):
            issues.append({"type": "provenance", "detail": "no signature found"})

    return {
        "provenance": provenance,
        "signature": signature,
        "revision_pinned": revision_pinned if revision_ref is not None else None,
        "hash_verified": hash_verified,
        "issues": issues,
    }


def check_hf_dataset(dataset_id: str) -> dict[str, Any]:
    """
    Check whether a Hugging Face dataset card documents source, license,
    and collection method well enough for a basic supply-chain review.
    """
    result: dict[str, Any] = {
        "dataset_id": dataset_id,
        "has_license": False,
        "has_source": False,
        "has_collection_method": False,
        "license": None,
        "complete": False,
        "issues": [],
    }

    try:
        response = requests.get(f"{HF_API}/{dataset_id}", timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"[WARNING] Hugging Face dataset lookup failed for {dataset_id}: {e}")
        result["issues"].append({
            "type": "dataset",
            "detail": f"could not fetch dataset metadata: {e}",
        })
        return result

    card = data.get("cardData") or {}
    license_value = (
        card.get("license")
        or data.get("license")
        or (data.get("tags") or [None])[0]  # weak fallback; refined below
    )
    # Prefer explicit license fields / license:* tags
    if not card.get("license") and not data.get("license"):
        license_value = None
        for tag in data.get("tags") or []:
            if isinstance(tag, str) and tag.lower().startswith("license:"):
                license_value = tag.split(":", 1)[1]
                break

    result["license"] = license_value
    result["has_license"] = bool(license_value)

    source_keys = ("source", "source_datasets", "homepage", "url", "pretty_name")
    result["has_source"] = any(card.get(k) for k in source_keys) or bool(data.get("author"))

    collection_keys = (
        "annotation_creators", "language_creators", "multilinguality",
        "size_categories", "task_categories", "dataset_info", "configs",
    )
    result["has_collection_method"] = any(card.get(k) for k in collection_keys)

    if not result["has_license"]:
        result["issues"].append({"type": "dataset", "detail": "license not documented"})
    if not result["has_source"]:
        result["issues"].append({"type": "dataset", "detail": "source / origin not documented"})
    if not result["has_collection_method"]:
        result["issues"].append({
            "type": "dataset",
            "detail": "collection / annotation method not documented",
        })

    result["complete"] = (
        result["has_license"] and result["has_source"] and result["has_collection_method"]
    )
    return result


def check_repository(
    owner: str | None = None,
    repo: str | None = None,
    package_name: str | None = None,
    version: str | None = None,
    revision_ref: str | None = None,
    local_file: str | None = None,
    expected_sha256: str | None = None,
    dataset_id: str | None = None,
) -> dict[str, Any]:
    """
    Run the full repository / supply-chain trust check and return a report dict.
    """
    issues: list[dict[str, str]] = []

    if not owner or not repo:
        if package_name:
            resolved = resolve_github_from_pypi(package_name)
            if resolved:
                owner, repo = resolved
            else:
                issues.append({
                    "type": "repository",
                    "detail": f"could not resolve GitHub repo for package '{package_name}'",
                })
        elif not dataset_id:
            issues.append({
                "type": "repository",
                "detail": "owner/repo or package_name or dataset_id is required",
            })

    github: dict[str, Any] = {
        "github_star": None,
        "github_fork": None,
        "last_commit": None,
        "last_release": None,
        "maintainer_count": None,
    }
    openssf_score = None

    if owner and repo:
        github = fetch_github_repo(owner, repo)
        if github.pop("error", None):
            issues.append({
                "type": "repository",
                "detail": f"GitHub lookup failed for {owner}/{repo}",
            })
        openssf_score = fetch_openssf_score(owner, repo)
        if openssf_score is None:
            issues.append({
                "type": "openssf",
                "detail": "OpenSSF Scorecard score not available",
            })

    # Skip package provenance when this is a dataset-only check.
    run_provenance = bool(
        package_name or version or revision_ref or local_file or (owner and repo)
    )
    if dataset_id and not (package_name or version or revision_ref or local_file or owner):
        run_provenance = False

    if run_provenance:
        provenance = check_provenance(
            package_name=package_name,
            version=version,
            owner=owner,
            repo=repo,
            revision_ref=revision_ref,
            local_file=local_file,
            expected_sha256=expected_sha256,
        )
        issues.extend(provenance.get("issues") or [])
    else:
        provenance = {
            "provenance": None,
            "signature": None,
            "revision_pinned": None,
            "hash_verified": None,
            "issues": [],
        }

    dataset = None
    if dataset_id:
        dataset = check_hf_dataset(dataset_id)
        issues.extend(dataset.get("issues") or [])

    report = {
        "github_star": github.get("github_star"),
        "github_fork": github.get("github_fork"),
        "last_commit": github.get("last_commit"),
        "last_release": github.get("last_release"),
        "maintainer_count": github.get("maintainer_count"),
        "openssf_score": openssf_score,
        "provenance": provenance.get("provenance"),
        "signature": provenance.get("signature"),
        "revision_pinned": provenance.get("revision_pinned"),
        "hash_verified": provenance.get("hash_verified"),
        "dataset": dataset,
        "issues": issues,
    }

    if owner and repo:
        report["repo"] = f"{owner}/{repo}"
    if package_name:
        report["package"] = package_name
        report["version"] = version

    return report


def _parse_cli(argv: list[str]) -> dict[str, Any]:
    """Minimal CLI without argparse dependency complexity."""
    args: dict[str, Any] = {
        "owner_repo": None,
        "package": None,
        "version": None,
        "dataset": None,
        "revision": None,
        "file": None,
        "sha256": None,
    }

    i = 0
    positional = []
    while i < len(argv):
        token = argv[i]
        if token in ("--package", "-p") and i + 1 < len(argv):
            args["package"] = argv[i + 1]
            i += 2
        elif token in ("--version", "-v") and i + 1 < len(argv):
            args["version"] = argv[i + 1]
            i += 2
        elif token in ("--dataset", "-d") and i + 1 < len(argv):
            args["dataset"] = argv[i + 1]
            i += 2
        elif token == "--revision" and i + 1 < len(argv):
            args["revision"] = argv[i + 1]
            i += 2
        elif token == "--file" and i + 1 < len(argv):
            args["file"] = argv[i + 1]
            i += 2
        elif token == "--sha256" and i + 1 < len(argv):
            args["sha256"] = argv[i + 1]
            i += 2
        elif token in ("-h", "--help"):
            args["help"] = True
            i += 1
        elif token.startswith("-"):
            print(f"[WARNING] Unknown option: {token}")
            i += 1
        else:
            positional.append(token)
            i += 1

    if positional:
        args["owner_repo"] = positional[0]
    return args


if __name__ == "__main__":
    cli = _parse_cli(sys.argv[1:])

    if cli.get("help") or (
        not cli.get("owner_repo")
        and not cli.get("package")
        and not cli.get("dataset")
    ):
        print(
            "Usage:\n"
            "  python repository_checker.py <owner>/<repo>\n"
            "  python repository_checker.py --package <name> --version <ver>\n"
            "  python repository_checker.py --dataset <hf_dataset_id>\n"
            "\nOptional:\n"
            "  --revision <git-url-or-sha>  --file <path>  --sha256 <digest>\n"
            "\nEnv:\n"
            "  GITHUB_TOKEN   optional, raises GitHub API rate limit"
        )
        sys.exit(0 if cli.get("help") else 1)

    owner = repo = None
    if cli.get("owner_repo"):
        parsed = parse_github_url(cli["owner_repo"])
        if not parsed:
            print(f"Could not parse GitHub repo from: {cli['owner_repo']}")
            sys.exit(1)
        owner, repo = parsed

    result = check_repository(
        owner=owner,
        repo=repo,
        package_name=cli.get("package"),
        version=cli.get("version"),
        revision_ref=cli.get("revision"),
        local_file=cli.get("file"),
        expected_sha256=cli.get("sha256"),
        dataset_id=cli.get("dataset"),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
