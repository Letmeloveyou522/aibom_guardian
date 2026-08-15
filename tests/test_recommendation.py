"""
test_recommendation.py
-----------------------------------
Unit tests for recommendation.py.

The demo CLI lives at `examples/demo_recommendation.py` (no assertions).
These are the actual unit tests. No network: every detector is driven with
a hand-built PyPIPackageInfo.
"""

from datetime import datetime, timedelta, timezone

import pytest

from aibom_guard.recommendation import (
    PyPIPackageInfo,
    RecommendationEngine,
    detect_deprecated,
    detect_hallucination,
    detect_typosquatting,
    recommend_package_alternatives,
)


def info(name="requests", exists=True, latest="2.34.2", yanked=None,
         last_upload=None):
    return PyPIPackageInfo(
        name=name, exists=exists, latest_version=latest,
        yanked_versions=yanked or {}, last_upload=last_upload,
    )


def types_of(issues):
    return sorted({i["type"] for i in issues})


# ---------------------------------------------------------------------------
# Hallucination - the AI-specific supply-chain risk
# ---------------------------------------------------------------------------

def test_nonexistent_package_is_a_hallucination():
    """
    An LLM-suggested dependency that does not exist on PyPI is a live
    dependency-confusion vector: the name is unclaimed, so anyone can claim
    it and every install of that requirements.txt runs their code.
    """
    issues = detect_hallucination(info("nonexistent-ai-pkg", exists=False))
    assert types_of(issues) == ["hallucination"]
    assert "nonexistent-ai-pkg" in issues[0]["detail"]
    assert issues[0].get("verified") is True


def test_existing_package_is_not_a_hallucination():
    assert detect_hallucination(info("requests", exists=True)) == []


def test_pypi_network_error_is_unverified_not_confirmed_hallucination():
    """
    A transient PyPI failure must carry verified=False so score_engine
    excludes it from Trust Score deductions.
    """
    broken = PyPIPackageInfo(
        name="maybe-real", exists=False, error="network: timed out")
    issues = detect_hallucination(broken)
    assert len(issues) == 1
    assert issues[0]["type"] == "hallucination"
    assert issues[0]["verified"] is False
    assert "timed out" in issues[0]["detail"] or "network" in issues[0]["detail"]


# ---------------------------------------------------------------------------
# Typosquatting
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("typo,official", [
    ("reqeusts", "requests"),
    ("numpyy", "numpy"),
    ("djanga", "django"),
])
def test_near_miss_of_a_popular_package_is_flagged(typo, official):
    issues = detect_typosquatting(typo, package_exists=False)
    assert types_of(issues) == ["typosquatting"]
    assert official in issues[0]["detail"]


def test_the_official_package_is_not_flagged_against_itself():
    assert detect_typosquatting("requests", package_exists=True) == []


def test_an_unrelated_name_is_not_flagged():
    assert detect_typosquatting("zzz-internal-tooling", package_exists=True) == []


def test_typosquat_detection_does_not_need_pypi():
    """It runs on the name alone, so it still works when PyPI is unreachable."""
    assert detect_typosquatting("reqeusts", package_exists=None)


def test_package_exists_does_not_suppress_near_miss():
    """
    package_exists is kept for API compatibility but must not gate detection:
    real typosquat packages often exist on PyPI.
    """
    # exists=True near-miss of a popular name → still flagged
    flagged = detect_typosquatting("reqeusts", package_exists=True)
    assert types_of(flagged) == ["typosquatting"]
    # exists=False → same result (existence is irrelevant)
    assert detect_typosquatting("reqeusts", package_exists=False) == flagged
    # Official popular name cleared regardless of the flag
    assert detect_typosquatting("requests", package_exists=False) == []
    assert detect_typosquatting("requests", package_exists=True) == []


# ---------------------------------------------------------------------------
# Deprecated / yanked
# ---------------------------------------------------------------------------

def test_yanked_version_is_reported():
    issues = detect_deprecated(
        info(yanked={"2.28.0": "security issue"}), version="2.28.0")
    assert issues, "a yanked release must be reported"


def test_unyanked_version_is_not_reported():
    assert detect_deprecated(
        info(yanked={"1.0.0": "broken"}), version="2.28.0") == []


def test_long_unmaintained_package_is_reported():
    stale = datetime.now(timezone.utc) - timedelta(days=365 * 4)
    assert detect_deprecated(info(last_upload=stale), version="2.28.0")


def test_recently_updated_package_is_not_reported():
    fresh = datetime.now(timezone.utc) - timedelta(days=10)
    assert detect_deprecated(info(last_upload=fresh), version="2.34.2") == []


# ---------------------------------------------------------------------------
# Alternatives
# ---------------------------------------------------------------------------

def test_cve_produces_a_confirmed_upgrade_suggestion():
    alts = recommend_package_alternatives(
        "requests", "2.28.0",
        [{"type": "cve", "id": "GHSA-x", "severity": "high"}],
        info(latest="2.34.2"), has_cve=True)
    assert alts
    assert any("2.34.2" in a["target"] for a in alts)
    assert alts[0]["confidence"] == "confirmed"


def test_typosquat_produces_a_spelling_correction():
    """
    The correction comes from the detector's `official_package` field, not
    from parsing `detail` - so the two must stay in step. This test drives
    the real detector output rather than a hand-written fixture.
    """
    issues = detect_typosquatting("reqeusts", package_exists=False)
    assert issues[0]["official_package"] == "requests"

    alts = recommend_package_alternatives(
        "reqeusts", "1.0.0", issues, info("reqeusts", exists=False),
        has_cve=False)
    assert any("requests" in a["target"] for a in alts)
    assert alts[0]["confidence"] == "confirmed"


def test_clean_package_gets_no_alternatives():
    assert recommend_package_alternatives(
        "requests", "2.34.2", [], info(latest="2.34.2"), has_cve=False) == []


# ---------------------------------------------------------------------------
# Engine contract - what scanner.py depends on
# ---------------------------------------------------------------------------

def test_analyze_package_returns_the_team_protocol_shape():
    engine = RecommendationEngine()
    result = engine.analyze_package("requests", "2.28.0", skip_pypi=True,
                                    cve_issues=[])
    assert set(result) == {"issues", "alternatives"}
    assert isinstance(result["issues"], list)


def test_analyze_package_merges_the_cve_issues_it_is_handed():
    """
    scanner.py relies on this: it passes the OSV findings in and uses the
    return value as the complete issue list. If the engine stopped merging
    them, every CVE would silently vanish from the score.
    """
    engine = RecommendationEngine()
    cve = {"type": "cve", "id": "GHSA-x", "severity": "high", "summary": "s"}
    result = engine.analyze_package("requests", "2.28.0", skip_pypi=True,
                                    cve_issues=[cve])
    assert [i["id"] for i in result["issues"] if i["type"] == "cve"] == ["GHSA-x"]


def test_analyze_package_does_not_duplicate_cve_issues():
    engine = RecommendationEngine()
    cve = {"type": "cve", "id": "GHSA-x", "severity": "high", "summary": "s"}
    result = engine.analyze_package("requests", "2.28.0", skip_pypi=True,
                                    cve_issues=[cve])
    assert sum(1 for i in result["issues"] if i.get("id") == "GHSA-x") == 1


def test_skip_pypi_avoids_the_network():
    """Offline mode and unit tests both depend on this flag."""
    engine = RecommendationEngine()
    engine.pypi = None      # any call would raise AttributeError
    result = engine.analyze_package("reqeusts", "1.0.0", skip_pypi=True)
    # Typosquat detection still runs; it needs no network.
    assert types_of(result["issues"]) == ["typosquatting"]


def test_every_issue_declares_a_protocol_type():
    """
    score_engine buckets by `issues[].type`. An issue without one lands in
    `unrecognised` and is scored as a flat deduction.
    """
    protocol = {"cve", "hallucination", "typosquatting", "malicious",
                "license", "provenance"}
    engine = RecommendationEngine()
    result = engine.analyze_package("reqeusts", "1.0.0", skip_pypi=True)
    for issue in result["issues"]:
        assert issue.get("type") in protocol, issue


# ---------------------------------------------------------------------------
# AI explanation prompt (merged from yelin0726)
# ---------------------------------------------------------------------------

def test_explanation_prompt_includes_supply_chain_and_fix():
    """
    Explaining the CVE while ignoring that the package ships unsigned from
    an unmaintained repository tells the developer only half the story.
    """
    from aibom_guard.ai_explainer import build_prompt

    prompt = build_prompt([{
        "package": "requests", "version": "2.28.0", "verdict": "WARNING",
        "license_status": "ALLOWED",
        "vulnerabilities": [{"summary": "proxy header leak"}],
        "issues": [{"type": "typosquatting", "detail": "resembles requests"}],
        "alternatives": [{"target": "requests==2.34.2"}],
        "supply_chain": {"openssf_score": 8.2,
                         "issues": [{"detail": "no signature found"}]},
    }])

    assert "typosquatting" in prompt          # non-CVE finding wins
    assert "no signature found" in prompt     # supply-chain context
    assert "requests==2.34.2" in prompt       # the fix
