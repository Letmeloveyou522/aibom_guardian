"""GitHub checks, as a mixin on RepositoryChecker."""

from __future__ import annotations

import os
from typing import Any

from ._constants import (
    GITHUB_API,
    OPENSSF_API,
    USER_AGENT,
    WEAK_CHECK_THRESHOLD,
)
from ._evidence import (
    _normalize_sha256,
    estimate_maintainers_from_contributors,
    parse_codeowners,
)
from ._helpers import (
    _classify_revision,
    _days_since,
    _error,
    _issue,
    _normalize_date,
)
from ._http import SSRFError, validate_public_url


class GitHubMixin:
    """check_github_repository and everything only it needs."""

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
