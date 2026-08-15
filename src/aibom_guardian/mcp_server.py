"""
mcp_server.py
-----------------------------------
Exposes AIBOM-Guardian's scanning logic as an MCP (Model Context Protocol)
server, so AI agents/clients (e.g. Claude Desktop, Cursor) can call it
directly - for example, asking "is package X version Y safe to use?"
and getting back a real answer backed by OSV + license checks.

No scanning logic lives here; it wraps license_checker, osv_client,
repository_checker and scanner.scan_model as MCP tools.

Scope: one target per call, JSON back. No requirements.txt parsing, no
scan_report.json / sbom.json, no Ollama. Use ``aibom-guardian`` for those.

OSV None contract (shared with scanner / score_engine)
------------------------------------------------------
``query_vulnerabilities`` returns ``None`` on network/API failure.
That must be passed through as ``issues=None`` — never coerced to ``[]`` —
so score_engine lowers confidence and yields WARNING (unverified ≠ clean).

Tools:
    check_package   — OSV CVE + license + Trust Score for one package pin
    check_license   — classify a license string (dict: status/spdx_id/family/…)
    check_repo_trust — supply-chain trust for GitHub / HF / PyPI / local
    check_model     — Hugging Face model scan (scan_report ``models[]`` shape)

Start the server with ``aibom-guardian-mcp`` or
``python -m aibom_guardian.mcp_server``.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from ._adapters import (
    _build_check_result,
    _vulns_to_issues,
    attach_license_unverified,
)
from .license_checker import classify_license_detailed
from .osv_client import query_vulnerabilities
from .repository_checker import check_repository
from .scanner import resolve_license, scan_model
from .score_engine import calculate_trust_score

logger = logging.getLogger(__name__)

# "aibom-guardian" is the name the MCP client will show for this server
mcp = FastMCP("aibom-guardian")

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
TOOL_CHECK_MODEL = "check_model"
TOOL_CHECK_PACKAGE = "check_package"
TOOL_CHECK_LICENSE = "check_license"


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
        from pathlib import Path

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
    verdict = result.get("verdict") or "WARNING"
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

    Looks up known vulnerabilities via the OSV database, resolves the license
    for the **pinned PyPI release**, and returns a Trust Score (0-100) plus a
    verdict of ALLOW, WARNING or BLOCK as computed by score_engine.

    OSV failure contract: when the OSV API cannot be reached,
    ``vulnerabilities`` is ``null`` (JSON) / ``None``, ``osv_unverified`` is
    true, and the verdict is WARNING with low confidence — never treated as
    "no known CVEs".

    Ecosystem support: **PyPI only**. License resolution reads PyPI release
    metadata (with an installed-copy fallback). Other ecosystems are rejected
    rather than returning a half-checked result.

    This tool does NOT analyze GitHub activity, OpenSSF Scorecard, commit
    pinning, artifact SHA-256 integrity, signatures, provenance, or Hugging
    Face dataset documentation. For those supply-chain trust checks, use
    check_repo_trust instead. For Hugging Face models, use check_model.

    Args:
        name: Package name, e.g. "requests"
        version: Package version, e.g. "2.28.0"
        ecosystem: Must be "PyPI" (default). Other values return an error.
    """
    if not isinstance(ecosystem, str) or ecosystem.strip().upper() != "PYPI":
        return _error_response(
            "unsupported_ecosystem",
            "check_package supports the PyPI ecosystem only "
            f"(got {ecosystem!r}). License resolution is PyPI-specific.",
            tool=TOOL_CHECK_PACKAGE,
        )

    vulns = query_vulnerabilities(name, version, "PyPI")
    osv_unverified = vulns is None
    # Never coerce None → [] — score_engine must see issues is None.
    issues_for_score = _vulns_to_issues(vulns)

    lic = resolve_license(name, version)
    lic_raw = lic["license"]
    lic_detail = classify_license_detailed(lic_raw)
    lic_status = lic_detail["status"]

    # Same path as scanner.run_scan: an unverified license must reach
    # score_engine so confidence drops / WARNING is possible. Still never
    # turns OSV None into a list.
    detail = None
    if lic.get("unverified"):
        if lic.get("source") == "none":
            detail = (
                f"No license could be read for {name}=={version}: "
                f"{lic.get('error')}, and it is not installed locally."
            )
        else:
            seen = f" (version {lic['version']})" if lic.get("version") else ""
            detail = (
                f"License for {name}=={version} was read from "
                f"{lic.get('source')}{seen} because {lic.get('error')}. A "
                f"package can change license between releases, so these "
                f"terms may not be the pinned release's."
            )
    issues_for_score = attach_license_unverified(
        issues_for_score, lic, detail=detail,
    )

    score_result = calculate_trust_score(
        _build_check_result(lic_status, issues_for_score)
    )

    return {
        "success": True,
        "tool": TOOL_CHECK_PACKAGE,
        "package": name,
        "version": version,
        "license_status": lic_status,
        "license_raw": lic_raw,
        "license_spdx_id": lic_detail["spdx_id"],
        "license_family": lic_detail["family"],
        "license_obligations": lic_detail["obligations"],
        "license_source": lic["source"],
        "license_version": lic["version"],
        "license_unverified": lic["unverified"],
        "vulnerabilities": vulns,
        "osv_unverified": osv_unverified,
        "trust_score": score_result["trust_score"],
        "verdict": score_result["verdict"],
        "hard_block": score_result["hard_block"],
        "hard_block_reasons": score_result["hard_block_reasons"],
        "score_breakdown": score_result["breakdown"],
        "confidence": score_result["confidence"],
    }


@mcp.tool()
def check_license(license_string: str) -> dict:
    """
    Classify a license string as ALLOWED, REVIEW, BLOCKED, or UNKNOWN,
    based on the open-source license policy (only OSI-approved,
    non-restrictive licenses are ALLOWED).

    Returns the same MCP envelope shape as the other tools
    (``success``, ``tool``, plus classification fields):

        status, spdx_id, family, reason, obligations, source, reference

    Args:
        license_string: A license name, e.g. "MIT" or "GPL-3.0"
    """
    if not isinstance(license_string, str):
        return _error_response(
            "invalid_input",
            "license_string must be a string.",
            tool=TOOL_CHECK_LICENSE,
        )
    detail = classify_license_detailed(license_string)
    return {
        "success": True,
        "tool": TOOL_CHECK_LICENSE,
        "input": license_string,
        "status": detail["status"],
        "spdx_id": detail.get("spdx_id") or "",
        "family": detail["family"],
        "reason": detail["reason"],
        "obligations": detail.get("obligations") or [],
        "source": detail.get("source") or "",
        "reference": detail.get("reference") or "",
    }


@mcp.tool()
def check_model(
    model_ref: str,
    max_pickle_size_mb: int = 0,
) -> dict:
    """
    Scan one Hugging Face model for license, weight format, pickle risk,
    model-card completeness, and Trust Score.

    The returned object matches one entry of ``scan_report.json``'s
    ``models`` array (same fields as ``scanner.scan_model``): model_id,
    license_status, verdict, risk_score, issues, model_card, file_formats,
    confidence, etc. Agents can merge it into
    ``{"packages": [...], "models": [this], "unscanned": []}``.

    This is the MCP counterpart of ``aibom-guardian ... --model REF``.
    It does not write SBOM files; use the CLI for CycloneDX / ML-BOM output.

    Args:
        model_ref: Hugging Face id or URL, e.g. "bert-base-uncased" or
            "https://huggingface.co/google/gemma-2b"
        max_pickle_size_mb: Download and scan pickle weights up to this
            size (MB). Default 0 = metadata only (same as CLI default).
    """
    if not isinstance(model_ref, str) or not model_ref.strip():
        return _error_response(
            "invalid_input",
            "model_ref must be a non-empty string",
            tool=TOOL_CHECK_MODEL,
        )

    cleaned = model_ref.strip()
    try:
        max_mb = int(max_pickle_size_mb)
    except (TypeError, ValueError):
        return _error_response(
            "invalid_input",
            "max_pickle_size_mb must be an integer",
            tool=TOOL_CHECK_MODEL,
        )
    if max_mb < 0:
        return _error_response(
            "invalid_input",
            "max_pickle_size_mb must be >= 0",
            tool=TOOL_CHECK_MODEL,
        )

    logger.info(
        "check_model model_ref=%s max_pickle_size_mb=%s",
        cleaned[:120],
        max_mb,
    )

    try:
        report = scan_model(cleaned, max_pickle_size_mb=max_mb)
    except (ValueError, TypeError, FileNotFoundError, PermissionError, OSError) as exc:
        logger.warning("check_model expected failure: %s", type(exc).__name__)
        return _error_response(
            "analysis_error",
            "Model scan could not be completed for the given input.",
            tool=TOOL_CHECK_MODEL,
        )
    except Exception:
        logger.exception("check_model failed")
        return _error_response(
            "internal_error",
            "Model scan failed unexpectedly.",
            tool=TOOL_CHECK_MODEL,
        )

    if report is None:
        return _error_response(
            "analysis_error",
            "Model could not be read (missing hub access, bad id, or checker unavailable).",
            tool=TOOL_CHECK_MODEL,
        )

    # Preserve scan_model / scan_report models[] fields; add MCP envelope.
    response = {
        **report,
        "success": True,
        "tool": TOOL_CHECK_MODEL,
    }
    return response


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
    For full AI-model BOM fields (pickle, model card, license family),
    use check_model.

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


def main() -> None:
    """
    Start the MCP server on stdio transport.

    It stays in the foreground waiting on stdin; that is stdio MCP, not a hang.
    """
    mcp.run()


if __name__ == "__main__":
    main()
