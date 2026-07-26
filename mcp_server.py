"""
mcp_server.py
-----------------------------------
Exposes AIBOM-Guard's scanning logic as an MCP (Model Context Protocol)
server, so AI agents/clients (e.g. Claude Desktop, Cursor) can call it
directly - for example, asking "is package X version Y safe to use?"
and getting back a real answer backed by OSV + license checks.

This file doesn't reimplement scanning logic - it wraps the functions
in license_checker.py, osv_client.py, and repository_checker.py as MCP
tools.

Run it directly to start the server:
    python3 mcp_server.py
"""

from __future__ import annotations

import logging
from importlib.metadata import PackageNotFoundError, metadata
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from license_checker import classify_license
from osv_client import query_vulnerabilities
from repository_checker import check_repository

logger = logging.getLogger(__name__)

# "aibom-guard" is the name the MCP client will show for this server
mcp = FastMCP("aibom-guard")

ALLOWED_TARGET_TYPES = frozenset({
    "auto",
    "github",
    "hf_model",
    "hf_dataset",
    "pypi",
    "local",
})
MAX_TARGET_LENGTH = 2048
TOOL_CHECK_REPO_TRUST = "check_repo_trust"


def _error_response(
    error_type: str,
    detail: str,
    *,
    tool: str = TOOL_CHECK_REPO_TRUST,
) -> dict:
    return {
        "success": False,
        "tool": tool,
        "error": {
            "type": error_type,
            "detail": detail,
        },
    }


def _safe_path_label(path: str | None) -> str | None:
    """Return only a basename so full local paths are not echoed."""
    if not path:
        return None
    try:
        return Path(path).name or "<path>"
    except (TypeError, ValueError):
        return "<path>"


def validate_check_repo_trust_inputs(
    target: Any,
    target_type: Any = "auto",
    revision: Any = None,
    local_file: Any = None,
    expected_sha256: Any = None,
) -> tuple[dict | None, dict | None]:
    """
    Validate MCP tool inputs.

    Returns (normalized_kwargs, error_response).
    On success error_response is None; on failure normalized_kwargs is None.
    """
    if not isinstance(target, str):
        return None, _error_response(
            "invalid_input",
            "target must be a string",
        )

    cleaned = target.strip()
    if not cleaned:
        return None, _error_response(
            "invalid_input",
            "target cannot be empty",
        )
    if len(cleaned) > MAX_TARGET_LENGTH:
        return None, _error_response(
            "invalid_input",
            f"target exceeds maximum length of {MAX_TARGET_LENGTH} characters",
        )

    if not isinstance(target_type, str):
        return None, _error_response(
            "invalid_target_type",
            "target_type must be a string",
        )
    normalized_type = target_type.strip().lower()
    if normalized_type not in ALLOWED_TARGET_TYPES:
        return None, _error_response(
            "invalid_target_type",
            "target_type must be one of: auto, github, hf_model, hf_dataset, pypi, local",
        )

    if revision is not None and not isinstance(revision, str):
        return None, _error_response(
            "invalid_input",
            "revision must be a string when provided",
        )
    if local_file is not None and not isinstance(local_file, str):
        return None, _error_response(
            "invalid_input",
            "local_file must be a string when provided",
        )
    if expected_sha256 is not None and not isinstance(expected_sha256, str):
        return None, _error_response(
            "invalid_input",
            "expected_sha256 must be a string when provided",
        )

    cleaned_revision = revision.strip() if isinstance(revision, str) else None
    if cleaned_revision == "":
        cleaned_revision = None

    cleaned_local = local_file.strip() if isinstance(local_file, str) else None
    if cleaned_local == "":
        cleaned_local = None

    cleaned_hash = expected_sha256.strip() if isinstance(expected_sha256, str) else None
    if cleaned_hash == "":
        cleaned_hash = None

    return {
        "target": cleaned,
        "target_type": normalized_type,
        "revision": cleaned_revision,
        "local_file": cleaned_local,
        "expected_sha256": cleaned_hash,
    }, None


def build_repository_check_summary(result: dict) -> dict:
    """
    Build a short deterministic summary from a check_repository result.
    Does not call any external LLM.
    """
    verdict = result.get("verdict") or "CONDITIONAL"
    trust_score = result.get("trust_score")
    issues = result.get("issues") or []
    provenance = result.get("provenance_detail") or {}
    dataset = result.get("dataset") or {}
    target_info = result.get("target") or {}

    def _first_issue(*severities: str) -> dict | None:
        wanted = set(severities)
        for issue in issues:
            if issue.get("severity") in wanted:
                return issue
        return None

    critical = _first_issue("critical")
    high = _first_issue("high")

    main_reason = None
    recommended_action = None

    if critical:
        main_reason = critical.get("detail") or "A critical supply-chain issue was found."
        recommended_action = (
            critical.get("recommendation")
            or "Do not use this artifact until the critical issue is resolved."
        )
    elif high:
        main_reason = high.get("detail") or "A high-severity trust issue was found."
        recommended_action = (
            high.get("recommendation")
            or "Review the high-severity findings before relying on this target."
        )
    elif target_info.get("type") == "ambiguous" or any(
        "ambiguous_target" in str(i.get("detail", "")) for i in issues
    ):
        main_reason = (
            "The short owner/repo form is ambiguous between GitHub and Hugging Face."
        )
        recommended_action = (
            "Set target_type explicitly to github, hf_model, or hf_dataset."
        )
    elif provenance.get("hash_verified") is False:
        main_reason = "Local file SHA-256 does not match the expected or published digest."
        recommended_action = (
            "Discard the local file and re-download from a trusted published source."
        )
    elif provenance.get("signature_status") == "failed":
        main_reason = "Signature verification failed for the provided artifact."
        recommended_action = (
            "Verify the signature material and only use artifacts with a passing check."
        )
    elif not provenance.get("revision_pinned") and not provenance.get("version_pinned"):
        main_reason = (
            "Neither an immutable commit SHA nor a pinned package version was verified "
            "as a strong provenance anchor."
        )
        recommended_action = (
            "Pin a full commit SHA for source, or an exact package==version for PyPI."
        )
    elif provenance.get("version_pinned") and not provenance.get("revision_pinned"):
        if provenance.get("hash_verified") is not True:
            main_reason = (
                "Package version is pinned, but source revision and artifact signature "
                "were not verified."
            )
            recommended_action = (
                "Verify the downloaded wheel SHA-256 against the digest published by PyPI."
            )
        else:
            main_reason = (
                "Package version and hash look consistent, but the upstream source "
                "commit is not pinned."
            )
            recommended_action = (
                "Record the linked GitHub commit SHA for reproducible builds."
            )
    elif provenance.get("hash_verified") is None and provenance.get("revision_pinned"):
        main_reason = (
            "Revision is pinned, but artifact hash integrity was not verified."
        )
        recommended_action = (
            "Provide local_file and expected_sha256 (or a matching published digest)."
        )
    elif provenance.get("signature_status") in ("not_found", "present", "unavailable"):
        if provenance.get("signature_status") == "not_found":
            main_reason = "No signature or provenance attestation was found."
            recommended_action = (
                "Prefer signed releases or a Sigstore/cosign bundle when available."
            )
        else:
            main_reason = (
                "Signature evidence exists but was not cryptographically verified."
            )
            recommended_action = (
                "Provide a signature bundle/key and run verification with cosign."
            )
    elif dataset.get("checked") and dataset.get("missing_fields"):
        missing = ", ".join(dataset.get("missing_fields") or [])
        main_reason = f"Dataset documentation is incomplete (missing: {missing})."
        recommended_action = (
            "Add license, source, and collection details to the Dataset Card."
        )
    elif any("older than" in str(i.get("detail", "")).lower() for i in issues):
        main_reason = "Repository activity appears stale based on recent commit history."
        recommended_action = (
            "Confirm the project is still maintained before depending on it."
        )
    elif verdict == "ALLOW":
        main_reason = (
            "No critical supply-chain issues were found and the overall trust score "
            "supports acceptance."
        )
        recommended_action = (
            "Continue monitoring OpenSSF Scorecard and release integrity over time."
        )
    else:
        main_reason = (
            "Some trust signals are incomplete, so the result remains conditional."
        )
        recommended_action = (
            "Review issues and score_breakdown, then pin revision/hash where possible."
        )

    return {
        "verdict": verdict,
        "trust_score": trust_score,
        "main_reason": main_reason,
        "recommended_action": recommended_action,
    }


@mcp.tool()
def check_package(name: str, version: str, ecosystem: str = "PyPI") -> dict:
    """
    Look up known CVEs/vulnerabilities and license status for one package version.

    Use this when the user asks specifically about vulnerabilities, CVE lists,
    or whether a package version has known security advisories via OSV.

    This tool does NOT analyze GitHub activity, OpenSSF Scorecard, commit
    pinning, artifact SHA-256 integrity, signatures, provenance, or Hugging
    Face dataset documentation. For those supply-chain trust checks, use
    check_repo_trust instead.

    Args:
        name: Package name, e.g. "requests"
        version: Package version, e.g. "2.28.0"
        ecosystem: Package ecosystem, e.g. "PyPI" or "npm" (default: PyPI)
    """
    vulns = query_vulnerabilities(name, version, ecosystem)

    try:
        meta = metadata(name)
        lic_raw = meta.get("License", "") or "UNKNOWN"
    except PackageNotFoundError:
        lic_raw = "NOT_INSTALLED"

    lic_status = classify_license(lic_raw)

    score = 100
    if lic_status == "BLOCKED":
        score -= 60
    elif lic_status == "REVIEW":
        score -= 20
    elif lic_status == "UNKNOWN":
        score -= 15

    critical_count = sum(
        1 for v in vulns if str(v.get("severity", "")).upper() in ("CRITICAL", "HIGH")
    )
    other_count = len(vulns) - critical_count
    score -= critical_count * 30
    score -= other_count * 10
    score = max(score, 0)

    if score >= 80:
        verdict = "ALLOW"
    elif score >= 50:
        verdict = "CONDITIONAL"
    else:
        verdict = "BLOCK"

    return {
        "package": name,
        "version": version,
        "license_status": lic_status,
        "license_raw": lic_raw,
        "vulnerabilities": vulns,
        "trust_score": score,
        "verdict": verdict,
    }


@mcp.tool()
def check_license(license_string: str) -> str:
    """
    Classify a license string as ALLOWED, REVIEW, BLOCKED, or UNKNOWN,
    based on the competition's open-source license policy (only
    OSI-approved, non-restrictive licenses are ALLOWED).

    Args:
        license_string: A license name, e.g. "MIT" or "GPL-3.0"
    """
    return classify_license(license_string)


@mcp.tool()
def check_repo_trust(
    target: str,
    target_type: str = "auto",
    revision: str | None = None,
    local_file: str | None = None,
    expected_sha256: str | None = None,
) -> dict:
    """
    Analyze supply-chain trust signals for a GitHub repository,
    Hugging Face model or dataset, PyPI package, or local artifact.

    Prefer this tool for repository trustworthiness, OpenSSF Scorecard,
    provenance, revision/commit pinning, SHA-256 integrity, signatures,
    maintainer signals, and Hugging Face dataset documentation.

    Do NOT use this for CVE-only lookups; use check_package when the user
    only wants vulnerability/advisory results for a package version.

    Checks may include:
    - GitHub repository activity and maintainers
    - OpenSSF Scorecard
    - license and repository transparency
    - revision or commit pinning
    - SHA-256 integrity verification
    - signature and provenance evidence
    - Hugging Face dataset documentation
    - trust score, verdict, issues, and recommendations

    target_type values:
    - auto
    - github
    - hf_model
    - hf_dataset
    - pypi
    - local

    For ambiguous namespace/repository inputs (e.g. owner/repo), explicitly
    specify github, hf_model, or hf_dataset.

    local_file / expected_sha256 are paths and digests relative to the
    MCP server process environment (the machine running this server), not
    the remote chat client's filesystem.

    Optional env vars on the server: GITHUB_TOKEN, GITHUB_API_VERSION,
    HF_TOKEN, HUGGINGFACE_TOKEN.
    """
    normalized, error = validate_check_repo_trust_inputs(
        target,
        target_type=target_type,
        revision=revision,
        local_file=local_file,
        expected_sha256=expected_sha256,
    )
    if error is not None:
        return error

    assert normalized is not None
    local_label = _safe_path_label(normalized.get("local_file"))
    logger.info(
        "check_repo_trust target_type=%s has_revision=%s local_file=%s has_hash=%s",
        normalized["target_type"],
        bool(normalized.get("revision")),
        local_label,
        bool(normalized.get("expected_sha256")),
    )

    try:
        result = check_repository(
            normalized["target"],
            target_type=normalized["target_type"],
            revision=normalized.get("revision"),
            local_file=normalized.get("local_file"),
            expected_sha256=normalized.get("expected_sha256"),
        )
    except (ValueError, TypeError, FileNotFoundError, PermissionError, OSError) as exc:
        logger.warning(
            "check_repo_trust expected failure: %s",
            type(exc).__name__,
        )
        return _error_response(
            "analysis_error",
            "Repository trust analysis could not be completed for the given input.",
        )
    except Exception:
        logger.exception("check_repo_trust failed")
        return _error_response(
            "internal_error",
            "Repository trust analysis failed unexpectedly.",
        )

    if not isinstance(result, dict):
        return _error_response(
            "internal_error",
            "Repository trust analysis returned an unexpected result type.",
        )

    summary = build_repository_check_summary(result)
    response = {
        **result,
        "summary": summary,
    }
    # Preserve checker fields; only set MCP metadata if absent.
    if "success" not in response:
        response["success"] = True
    if "tool" not in response:
        response["tool"] = TOOL_CHECK_REPO_TRUST
    return response


if __name__ == "__main__":
    # This starts the MCP server using stdio transport, which is what
    # Claude Desktop / Cursor expect for locally-run MCP servers.
    mcp.run()
