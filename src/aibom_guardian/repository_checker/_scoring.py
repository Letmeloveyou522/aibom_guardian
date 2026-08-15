"""
Repository trust score - not the final verdict.

score_engine blends this number into the package or model score. The
thresholds match score_engine's so both mean the same thing on one scale.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ._helpers import _days_since


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
        verdict = "WARNING"
    elif trust < 50 and confidence >= 0.5:
        verdict = "BLOCK"
    elif trust >= 80 and confidence >= 0.7 and not high:
        verdict = "ALLOW"
    else:
        verdict = "WARNING"

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
