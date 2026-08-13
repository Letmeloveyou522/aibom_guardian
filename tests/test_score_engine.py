"""
test_score_engine.py
-----------------------------------
Unit tests for score_engine.py.

These pin the current weights and thresholds. Re-tuning CATEGORY_WEIGHTS or
the verdict gates should fail here, showing exactly what changed - the
numbers are an agreed decision, not a fact about the world.
"""

import pytest

from aibom_guard.score_engine import (
    ALLOW_THRESHOLD,
    BLOCK_THRESHOLD,
    CATEGORY_WEIGHTS,
    calculate_trust_score,
)


def check(license_status="ALLOWED", issues=None, kind="library",
          model_info=None, repository_info=None):
    """Build a check_result the way scanner._build_check_result does."""
    return {
        "type": kind,
        "license_status": license_status,
        "issues": [] if issues is None else issues,
        "model_info": model_info,
        "repository_info": repository_info,
    }


def cve(severity="high", **extra):
    return {"type": "cve", "id": "GHSA-test", "severity": severity, **extra}


# ---------------------------------------------------------------------------
# Contract: the keys scanner.py and mcp_server.py read
# ---------------------------------------------------------------------------

def test_returns_every_key_the_callers_use():
    """scanner.run_scan and mcp_server.check_package index these directly."""
    result = calculate_trust_score(check())
    for key in ("trust_score", "verdict", "hard_block", "hard_block_reasons",
                "breakdown", "confidence"):
        assert key in result, f"missing '{key}' - callers index it directly"

    assert isinstance(result["trust_score"], int)
    assert isinstance(result["hard_block"], bool)
    assert isinstance(result["hard_block_reasons"], list)
    assert isinstance(result["breakdown"], dict)


def test_verdict_vocabulary_matches_the_rest_of_the_project():
    """repository_checker and recommendation both emit these three."""
    for payload in (check(), check("BLOCKED"), check(issues=[cve("critical")])):
        assert calculate_trust_score(payload)["verdict"] in (
            "ALLOW", "WARNING", "BLOCK")


def test_score_is_always_within_range():
    heavy = [{"type": t, "severity": "critical"} for t in CATEGORY_WEIGHTS] * 3
    for payload in (check(), check("BLOCKED", heavy)):
        score = calculate_trust_score(payload)["trust_score"]
        assert 0 <= score <= 100


def test_malformed_input_does_not_raise():
    """One bad record must not abort a whole scan."""
    for payload in (None, {}, {"issues": "not-a-list"}, {"license_status": 42},
                    {"issues": [None, "x", {"type": "cve"}]}):
        result = calculate_trust_score(payload)
        assert 0 <= result["trust_score"] <= 100


# ---------------------------------------------------------------------------
# Clean case
# ---------------------------------------------------------------------------

def test_clean_package_is_allowed():
    result = calculate_trust_score(check())
    assert result["trust_score"] == 100
    assert result["verdict"] == "ALLOW"
    assert result["hard_block"] is False
    assert result["hard_block_reasons"] == []


# ---------------------------------------------------------------------------
# Severity handling - the bug this engine exists to fix
# ---------------------------------------------------------------------------

def test_severity_is_ranked_not_counted():
    """
    The original scanner deducted a flat 10 per vulnerability, so a critical
    RCE and a trivial info leak cost the same. Severity must move the number.
    """
    scores = {
        level: calculate_trust_score(check(issues=[cve(level)]))["trust_score"]
        for level in ("low", "medium", "high", "critical")
    }
    assert scores["low"] > scores["medium"] > scores["high"] > scores["critical"]


def test_raw_cvss_vector_is_not_silently_treated_as_harmless():
    """
    OSV returns severities like "CVSS:3.1/AV:N/AC:L/...", which never equals
    "HIGH". The original code compared them for equality, so every finding
    scored as harmless. An ungradable severity must still cost points.
    """
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    result = calculate_trust_score(check(issues=[cve(vector)]))
    assert result["trust_score"] < 100, "an unrated CVE must not score as clean"


def test_cvss_score_resolves_an_unrated_severity():
    """When recommendation supplies cvss_score, use the NVD qualitative scale."""
    graded = calculate_trust_score(check(issues=[cve("", cvss_score=9.8)]))
    assert graded["hard_block"] is True          # 9.8 -> critical
    medium = calculate_trust_score(check(issues=[cve("", cvss_score=5.0)]))
    assert medium["hard_block"] is False


def test_unknown_severity_lowers_confidence():
    """Findings we could not grade mean we understand the artifact less."""
    known = calculate_trust_score(check(issues=[cve("medium")]))
    unrated = calculate_trust_score(check(issues=[cve("???")]))
    assert unrated["confidence"] < known["confidence"]


# ---------------------------------------------------------------------------
# The seven categories
# ---------------------------------------------------------------------------

def test_all_seven_protocol_categories_are_scored():
    """Producers emit exactly these issue types - the list is a contract."""
    assert set(CATEGORY_WEIGHTS) == {
        "cve", "hallucination", "typosquatting", "malicious",
        "pii", "license", "provenance"}
    assert sum(CATEGORY_WEIGHTS.values()) == 100


def test_categories_are_ordered_by_seriousness():
    weights = CATEGORY_WEIGHTS
    assert weights["malicious"] > weights["cve"] > weights["license"]
    assert weights["license"] > weights["typosquatting"] > weights["pii"]
    # Detectable package-path categories outrank the unused pii placeholder.
    assert weights["typosquatting"] > weights["hallucination"] > weights["provenance"]
    assert weights["provenance"] > weights["pii"]


def test_malicious_and_pii_producer_coverage_is_documented():
    """
    malicious is model-path only; pii has no producer yet.
    Weights stay in CATEGORY_WEIGHTS so a future emitter needs no schema change,
    but the module docstring must spell that out (README is owned elsewhere).
    """
    from aibom_guard import score_engine
    doc = score_engine.__doc__ or ""
    assert "picklescan" in doc.lower() or "model" in doc.lower()
    assert "pii" in doc.lower()
    assert "no module currently emits" in doc.lower() or "reserved" in doc.lower()
    assert CATEGORY_WEIGHTS["malicious"] >= CATEGORY_WEIGHTS["cve"]
    assert CATEGORY_WEIGHTS["pii"] > 0
    assert sum(CATEGORY_WEIGHTS.values()) == 100


def test_breakdown_reports_every_category_even_when_clean():
    """A reader must tell "checked and clean" from "never looked"."""
    breakdown = calculate_trust_score(check())["breakdown"]
    for name in CATEGORY_WEIGHTS:
        assert name in breakdown
        assert breakdown[name]["deduction"] == 0


def test_one_critical_finding_saturates_its_category():
    """Further findings of the same kind cannot deduct beyond the weight."""
    one = calculate_trust_score(check(issues=[cve("critical")]))
    five = calculate_trust_score(check(issues=[cve("critical")] * 5))
    assert one["breakdown"]["cve"]["deduction"] == CATEGORY_WEIGHTS["cve"]
    assert five["breakdown"]["cve"]["deduction"] == CATEGORY_WEIGHTS["cve"]


def test_unrecognised_issue_type_is_charged_and_named():
    """Silently ignoring an unknown finding is the failure mode to avoid."""
    result = calculate_trust_score(check(issues=[
        {"type": "quantum_entanglement", "severity": "high"}]))
    assert result["trust_score"] < 100
    assert "quantum_entanglement" in result["breakdown"]["unrecognised"]["types"]


# ---------------------------------------------------------------------------
# License
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status,expect_block", [
    ("ALLOWED", False), ("REVIEW", False), ("UNKNOWN", False),
    ("NOT_INSTALLED", False), ("BLOCKED", True),
])
def test_license_status_drives_the_license_category(status, expect_block):
    result = calculate_trust_score(check(license_status=status))
    assert result["hard_block"] is expect_block
    if status == "ALLOWED":
        assert result["breakdown"]["license"]["deduction"] == 0
    else:
        assert result["breakdown"]["license"]["deduction"] > 0


def test_blocked_license_is_a_hard_block():
    result = calculate_trust_score(check(license_status="BLOCKED"))
    assert result["verdict"] == "BLOCK"
    assert any("BLOCKED" in reason for reason in result["hard_block_reasons"])


def test_license_ranking_is_monotonic():
    scores = {s: calculate_trust_score(check(license_status=s))["trust_score"]
              for s in ("ALLOWED", "REVIEW", "UNKNOWN", "BLOCKED")}
    assert scores["ALLOWED"] > scores["REVIEW"] > scores["UNKNOWN"] > scores["BLOCKED"]


# ---------------------------------------------------------------------------
# Hard blocks
# ---------------------------------------------------------------------------

def test_malicious_finding_hard_blocks():
    result = calculate_trust_score(check(issues=[
        {"type": "malicious", "id": "MAL-001", "severity": "high"}]))
    assert result["hard_block"] is True
    assert result["verdict"] == "BLOCK"


def test_critical_severity_hard_blocks():
    """Mirrors repository_checker: a critical finding blocks outright."""
    result = calculate_trust_score(check(issues=[cve("critical")]))
    assert result["hard_block"] is True
    assert result["verdict"] == "BLOCK"


def test_model_checker_flags_hard_block():
    """model_checker reports these as flags rather than as issues."""
    for flag in ("is_malicious", "license_blocked"):
        result = calculate_trust_score(check(kind="model", model_info={flag: True}))
        assert result["hard_block"] is True, flag


def test_hard_blocked_score_cannot_look_comfortable():
    """A BLOCK verdict beside a score of 95 would contradict itself."""
    result = calculate_trust_score(check(issues=[
        {"type": "malicious", "id": "MAL-001", "severity": "low"}]))
    assert result["verdict"] == "BLOCK"
    assert result["trust_score"] < BLOCK_THRESHOLD


def test_hard_block_reasons_are_deduplicated():
    result = calculate_trust_score(check(license_status="BLOCKED", issues=[
        {"type": "malicious", "id": "SAME"}, {"type": "malicious", "id": "SAME"}]))
    assert len(result["hard_block_reasons"]) == len(set(result["hard_block_reasons"]))


# ---------------------------------------------------------------------------
# Verdict thresholds (mirrored from repository_checker)
# ---------------------------------------------------------------------------

def test_high_severity_prevents_allow_even_at_a_good_score():
    """repository_checker gates ALLOW on 'not high'; this matches it."""
    result = calculate_trust_score(check(issues=[cve("high")]))
    assert result["trust_score"] >= ALLOW_THRESHOLD
    assert result["verdict"] == "WARNING"


def test_low_confidence_withholds_a_verdict_rather_than_guessing():
    """
    `issues: None` means the scan never ran. That must not read as ALLOW,
    and it must not read as BLOCK either - there is no evidence for either.
    """
    result = calculate_trust_score({
        "type": "library", "license_status": "UNKNOWN", "issues": None,
        "model_info": None, "repository_info": None})
    assert result["confidence"] < 0.5
    assert result["verdict"] == "WARNING"


def test_optional_repository_context_does_not_block_allow():
    """
    A fully-inspected library with no supply-chain data must still be able to
    reach ALLOW - repository_info is optional for a library.
    """
    assert calculate_trust_score(check())["verdict"] == "ALLOW"


# ---------------------------------------------------------------------------
# model_checker and repository_checker integration
# ---------------------------------------------------------------------------

def test_issues_from_model_info_are_scored():
    """model_checker findings flow through the same categories as a CVE."""
    result = calculate_trust_score(check(kind="model", model_info={
        "issues": [{"type": "provenance", "severity": "high",
                    "detail": "no model card"}]}))
    assert result["breakdown"]["provenance"]["issues"] == 1
    assert result["trust_score"] < 100


def test_issues_from_repository_info_are_scored_without_blend():
    """No trust_score → repository issues deduct like any other finding."""
    result = calculate_trust_score(check(repository_info={
        "issues": [{"type": "provenance", "severity": "medium"}]}))
    assert result["breakdown"]["provenance"]["issues"] == 1
    assert result["breakdown"]["provenance"]["deduction"] > 0
    assert result["breakdown"]["_summary"]["repository_issues_deducted"] is True


def test_repository_issues_visible_but_not_double_deducted_when_blending():
    """
    No double deduction: when a trust_score is blended in, repository issues
    stay visible in the breakdown but do not deduct again on top of it.
    scanner reads provenance.issues to confirm they were still passed through.
    """
    blend_only = calculate_trust_score(check(repository_info={"trust_score": 20}))
    both = calculate_trust_score(check(repository_info={
        "trust_score": 20,
        "issues": [{"type": "provenance", "severity": "medium",
                    "detail": "unsigned release"}],
    }))
    assert both["trust_score"] == blend_only["trust_score"]
    assert both["breakdown"]["provenance"]["issues"] == 1
    assert both["breakdown"]["provenance"]["deduction"] == 0
    assert both["breakdown"]["_summary"]["repository_issues_deducted"] is False
    assert both["breakdown"]["_summary"]["repository_trust"] == 20


def test_blended_repository_alias_still_maps_to_provenance():
    """signature/repository/dataset aliases stay visible under provenance."""
    result = calculate_trust_score(check(repository_info={
        "trust_score": 90,
        "issues": [{"type": "signature", "severity": "medium",
                    "detail": "no signature found"}],
    }))
    assert result["breakdown"]["provenance"]["issues"] == 1
    assert "unrecognised" not in result["breakdown"]
    assert result["breakdown"]["provenance"]["deduction"] == 0


def test_repository_trust_pulls_the_final_score():
    """An artifact from an untrustworthy source is not trustworthy."""
    without = calculate_trust_score(check())["trust_score"]
    with_bad = calculate_trust_score(check(repository_info={"trust_score": 20}))
    with_good = calculate_trust_score(check(repository_info={"trust_score": 100}))
    assert with_bad["trust_score"] < without
    assert with_good["trust_score"] == 100
    assert with_bad["breakdown"]["_summary"]["repository_trust"] == 20


def test_partial_data_marker_lowers_confidence():
    full = calculate_trust_score(check(repository_info={"trust_score": 90}))
    partial = calculate_trust_score(check(repository_info={
        "trust_score": 90, "partial_data": True}))
    assert partial["confidence"] < full["confidence"]


def test_malformed_repository_trust_is_ignored_not_fatal():
    result = calculate_trust_score(check(repository_info={"trust_score": "n/a"}))
    assert result["trust_score"] == 100
    assert result["breakdown"]["_summary"]["repository_trust"] is None
    # Unusable trust_score → fall back to deducting repository issues.
    with_issue = calculate_trust_score(check(repository_info={
        "trust_score": "n/a",
        "issues": [{"type": "provenance", "severity": "medium"}],
    }))
    assert with_issue["breakdown"]["provenance"]["deduction"] > 0
    assert with_issue["breakdown"]["_summary"]["repository_issues_deducted"] is True


# ---------------------------------------------------------------------------
# verified: False must not deduct
# ---------------------------------------------------------------------------

def test_unverified_hallucination_does_not_deduct_score():
    """
    PyPI network failure reports type=hallucination with verified=False.
    That must not cost hallucination points the way a confirmed 404 does.
    """
    unverified = calculate_trust_score(check(issues=[{
        "type": "hallucination",
        "detail": "Could not verify package (network: timeout)",
        "verified": False,
    }]))
    confirmed = calculate_trust_score(check(issues=[{
        "type": "hallucination",
        "detail": "Package does not exist on PyPI",
        "verified": True,
    }]))
    assert unverified["breakdown"]["hallucination"]["deduction"] == 0
    assert unverified["breakdown"]["hallucination"]["issues"] == 0
    assert confirmed["breakdown"]["hallucination"]["deduction"] > 0
    assert unverified["trust_score"] == 100
    assert confirmed["trust_score"] < 100


def test_unverified_hallucination_lowers_confidence():
    """An incomplete check is a confidence gap, not a clean pass."""
    clean = calculate_trust_score(check())
    unverified = calculate_trust_score(check(issues=[{
        "type": "hallucination",
        "detail": "Could not verify",
        "verified": False,
    }]))
    assert unverified["confidence"] < clean["confidence"]
    assert unverified["verdict"] != "ALLOW" or unverified["confidence"] < 0.7


def test_unverified_finding_does_not_hard_block():
    result = calculate_trust_score(check(issues=[{
        "type": "malicious", "id": "maybe", "severity": "critical",
        "verified": False,
    }]))
    assert result["hard_block"] is False
    assert result["trust_score"] == 100


def test_missing_verified_flag_still_scores():
    """Backward compatible: omit verified → treat as confirmed."""
    result = calculate_trust_score(check(issues=[{
        "type": "hallucination",
        "detail": "Package does not exist on PyPI",
    }]))
    assert result["breakdown"]["hallucination"]["deduction"] > 0


# ---------------------------------------------------------------------------
# Default severity for detector-style findings
# ---------------------------------------------------------------------------

def test_ungraded_typosquat_is_not_treated_as_half_strength():
    """
    detect_typosquatting() reports no severity - it either matched a popular
    package name or it did not. Falling back to "unknown" (factor 0.5) meant
    a confirmed typosquat cost 5 of its 10 points.
    """
    from aibom_guard.score_engine import CATEGORY_DEFAULT_SEVERITY, CATEGORY_WEIGHTS

    result = calculate_trust_score(check(issues=[
        {"type": "typosquatting", "detail": "'reqeusts' resembles 'requests'"}]))
    expected = CATEGORY_WEIGHTS["typosquatting"] * 0.7   # high
    assert result["breakdown"]["typosquatting"]["deduction"] == pytest.approx(expected)
    assert CATEGORY_DEFAULT_SEVERITY["typosquatting"] == "high"


def test_ungraded_cve_stays_unknown():
    """
    CVSS severity is a real published rating. Inventing one for an unrated
    CVE would be a guess, so cve has no default.
    """
    from aibom_guard.score_engine import CATEGORY_DEFAULT_SEVERITY

    assert "cve" not in CATEGORY_DEFAULT_SEVERITY
    result = calculate_trust_score(check(issues=[{"type": "cve", "id": "X"}]))
    assert result["confidence"] < 1.0      # ungraded finding lowers confidence


def test_explicit_severity_beats_the_category_default():
    low = calculate_trust_score(check(issues=[
        {"type": "typosquatting", "severity": "low"}]))
    defaulted = calculate_trust_score(check(issues=[{"type": "typosquatting"}]))
    assert low["trust_score"] > defaulted["trust_score"]


def test_cvss_score_beats_the_category_default():
    result = calculate_trust_score(check(issues=[
        {"type": "provenance", "cvss_score": 9.8}]))
    assert result["hard_block"] is True     # 9.8 -> critical, not the medium default


def test_ungraded_malicious_still_hard_blocks():
    result = calculate_trust_score(check(issues=[{"type": "malicious", "id": "M"}]))
    assert result["hard_block"] is True


# ---------------------------------------------------------------------------
# Category aliases for producers outside the seven-type protocol
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw_type", ["repository", "signature", "dataset"])
def test_module2_issue_types_map_to_provenance(raw_type):
    """
    repository_checker emits these three, none of which are protocol types.
    Unmapped they land in `unrecognised`, where every supply-chain finding is
    worth the same flat deduction regardless of what it says.
    """
    result = calculate_trust_score(check(issues=[
        {"type": raw_type, "severity": "medium", "detail": "..."}]))
    assert result["breakdown"]["provenance"]["issues"] == 1
    assert "unrecognised" not in result["breakdown"]


def test_alias_map_does_not_swallow_genuinely_unknown_types():
    result = calculate_trust_score(check(issues=[
        {"type": "quantum_entanglement", "severity": "high"}]))
    assert "unrecognised" in result["breakdown"]
    assert result["breakdown"]["unrecognised"]["types"] == ["quantum_entanglement"]


def test_alias_map_is_case_insensitive():
    result = calculate_trust_score(check(issues=[
        {"type": "Signature", "severity": "medium"}]))
    assert result["breakdown"]["provenance"]["issues"] == 1
