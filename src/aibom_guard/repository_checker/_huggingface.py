"""
Hugging Face model and dataset checks, as a mixin on RepositoryChecker.
"""

from __future__ import annotations

from ._constants import (
    HF_API,
    INVALID_LICENSE_VALUES,
    MAX_HF_FILES_DETAIL,
    USER_AGENT,
)
from ._datasets import check_dataset_documentation
from ._evidence import _normalize_sha256, extract_github_candidates
from ._helpers import (
    _classify_revision,
    _error,
    _issue,
    _normalize_date,
)
from ._http import SSRFError, validate_public_url


class HuggingFaceMixin:
    """check_huggingface_repository and everything only it needs."""

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
