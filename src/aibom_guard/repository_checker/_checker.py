"""
RepositoryChecker: construction, the check() router, and the result skeleton.

The per-ecosystem work lives in the mixins this class composes.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ._evidence import calculate_sha256
from ._github import GitHubMixin
from ._http import SafeHTTPClient
from ._huggingface import HuggingFaceMixin
from ._provenance import ProvenanceMixin
from ._pypi import PyPIMixin
from ._scoring import calculate_trust_score
from ._targets import detect_target_type


class RepositoryChecker(
    GitHubMixin,
    HuggingFaceMixin,
    PyPIMixin,
    ProvenanceMixin,
):
    """
    Collect provenance and trust signals for a software/AI artifact source.

    The mixins hold per-ecosystem methods only - no state, no __init__, no
    overlapping names. check() is still the single entry point.
    """

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
                "verdict": "WARNING",
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
            "verdict": "WARNING",
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
