"""
PyPI package checks, as a mixin on RepositoryChecker.
"""

from __future__ import annotations

from pathlib import Path

from ._constants import PYPI_API
from ._evidence import _normalize_sha256, extract_github_candidates
from ._helpers import _error, _issue, _normalize_pypi_name


class PyPIMixin:
    """check_pypi_package and everything only it needs."""

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
