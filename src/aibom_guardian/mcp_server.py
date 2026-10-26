"""
mcp_server.py
-----------------------------------
Exposes AIBOM-Guardian's scanning logic as an MCP (Model Context Protocol)
server, so AI agents/clients (e.g. Claude Desktop, Cursor) can call it
directly - for example, asking "is package X version Y safe to use?"
and getting back a real answer backed by OSV + license checks.

No scanning logic lives here; it wraps license_checker, osv_client,
repository_checker and scanner.scan_model as MCP tools.

Scope: individual targets or a configured Python project, JSON back. No
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
import os
import re
import sqlite3
from pathlib import Path
from functools import wraps
from threading import RLock
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Settings as FastMCPSettings

from ._adapters import (
    _build_check_result as _build_check_result,
    _vulns_to_issues,
    attach_license_unverified as attach_license_unverified,
)
from .license_checker import classify_license_detailed
from .osv_client import query_vulnerabilities
from .repository_checker import check_repository
from .scanner import resolve_license, scan_model, collect_scan, collect_packages, Pinned


__all__ = ["_build_check_result", "attach_license_unverified"]

logger = logging.getLogger(__name__)
_SCAN_LOCK = RLock()


def _serialized(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with _SCAN_LOCK:
            return function(*args, **kwargs)
    return wrapped


# "aibom-guardian" is the name the MCP client will show for this server
# MCP 1.28.1 defines Settings before FastMCP; resolve its lifespan forward ref
# after both classes exist. Do not hide warnings or change dependency versions.
FastMCPSettings.model_rebuild()
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


def _project_file(relative_path: str) -> Path:
    configured = os.environ.get("AIBOM_GUARDIAN_PROJECT_ROOT")
    if not configured:
        raise ValueError("Set AIBOM_GUARDIAN_PROJECT_ROOT in the server environment first")
    root = Path(configured).resolve(strict=True)
    supplied = Path(relative_path)
    if supplied.is_absolute() or supplied.drive or not relative_path.strip():
        raise ValueError("Use a project-relative file path")
    target = (root / supplied).resolve(strict=True)
    if not target.is_relative_to(root) or not target.is_file():
        raise ValueError("File must be inside the configured project root")
    if target.stat().st_size > 1024 * 1024:
        raise ValueError("Input exceeds the 1 MiB limit")
    return target


@mcp.tool(structured_output=False)
@_serialized
def scan_project(requirements_path: str, direct_only: bool = False,
                 offline: bool = False) -> dict[str, Any]:
    """Scan a Python requirements file inside AIBOM_GUARDIAN_PROJECT_ROOT.

    Uses the CLI collector, including recommendations and optional transitive
    dependencies. Returns JSON without writing reports or installing packages.
    Package names/versions are sent to public registries during online scans.
    Offline scans report unverified findings, not a clean result.
    Read summary first; packages contains full evidence. Dependency conflict
    entries are requirements, not distinct omitted packages.
    Returns one JSON text block, without a duplicate structuredContent report.
    """
    try:
        path = _project_file(requirements_path)
        from . import license_checker
        previous = license_checker._OFFLINE
        try:
            report = collect_scan(str(path), transitive=not direct_only, offline=offline)
        finally:
            license_checker.set_offline(previous)
        from .reporting import project_summary
        return {"success": True, "tool": "scan_project",
                "summary": project_summary(report), **report}
    except (OSError, ValueError) as exc:
        logger.warning("Project scan rejected: %s", type(exc).__name__)
        return _error_response("invalid_project_input", "Check the configured project root, relative path and input format.", tool="scan_project")


@mcp.tool()
@_serialized
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
    lic = resolve_license(name, version)
    pin = Pinned(name, version, "==" + version, False)
    evidence = {id(pin): {"license": lic, "vulns": vulns,
                         "issues": _vulns_to_issues(vulns), "alternatives": [],
                         "repository_info": None}}
    row = collect_packages([pin], evidence=evidence)[0]
    return {**row, "success": True, "tool": TOOL_CHECK_PACKAGE,
            "scoring_model": "score_engine"}



@mcp.tool(structured_output=False)
@_serialized
def compare_package_candidate(name: str, current_version: str, candidate_version: str) -> dict:
    """Recheck two explicit PyPI versions. Does not modify files, install, or run tests.

    Compatibility is not verified. Advisory absence is not a safe-update guarantee.
    """
    from packaging.version import Version, InvalidVersion
    from .reporting import compare_reports
    try:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            raise ValueError("Invalid package name")
        Version(current_version)
        Version(candidate_version)
    except (ValueError, InvalidVersion, TypeError):
        return _error_response("invalid_input", "Supply a PyPI name and two exact versions.",
                               tool="compare_package_candidate")
    before = check_package(name, current_version)
    after = check_package(name, candidate_version)
    comparison = compare_reports({"packages": [before]}, {"packages": [after]})
    return {"success": True, "tool": "compare_package_candidate", "comparison": comparison,
            "compatibility_verified": False, "tests_executed": False,
            "before": before, "candidate": after}


def _monitor_database():
    configured = os.environ.get("AIBOM_GUARDIAN_MONITOR_DB")
    if not configured:
        raise ValueError("Configure AIBOM_GUARDIAN_MONITOR_DB after initializing a baseline")
    return Path(configured).resolve(strict=True)


@mcp.tool(structured_output=False)
@_serialized
def monitor_history(limit: int = 5) -> dict:
    """Read saved runs from the server-configured monitor database. No external requests."""
    from .monitoring import history
    try:
        return {"success": True, "tool": "monitor_history", **history(_monitor_database(), limit)}
    except (OSError, ValueError, sqlite3.Error):
        return _error_response("monitor_unavailable", "Check the configured monitor database and limit (1-30).",
                               tool="monitor_history")


@mcp.tool(structured_output=False)
@_serialized
def check_monitor() -> dict:
    """Recheck saved exact versions via OSV and model metadata; persist history locally.

    Requires AIBOM_GUARDIAN_MONITOR_DB. Does not send email or modify project dependencies.
    """
    from .monitoring import check_once
    try:
        return {"success": True, "tool": "check_monitor", **check_once(_monitor_database())}
    except (OSError, ValueError, sqlite3.Error):
        return _error_response("monitor_unavailable", "Check the configured monitor database.", tool="check_monitor")


@mcp.tool()
@_serialized
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
@_serialized
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
@_serialized
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
        # Distinct from check_package's score_engine trust_score.
        "scoring_model": "repository_trust",
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
