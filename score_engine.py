"""
score_engine.py
-----------------------------------
Module 4 - Trust Score and final verdict.

    (1) model_checker ──┐
    (2) repository_checker ┼──> (4) score_engine ──> (5) AIBOM / MCP
    (3) recommendation ──┘        (Trust Score)       (sbom / scanner)

Every other module *collects evidence*; this module is the only place that
turns evidence into a number and a verdict. Modules 1-3 deliberately do not
score (see the module 3 README: "점수/최종 판정은 하지 않음 - ④ score_engine 전담").

Public API
----------
    calculate_trust_score(check_result: dict) -> dict

Input (assembled by scanner._build_check_result / mcp_server._build_check_result):

    {
        "type": "library" | "model" | "repository",
        "license_status": "ALLOWED" | "REVIEW" | "BLOCKED" | "UNKNOWN" | ...,
        "issues": [ {"type": ..., "severity": ..., "id": ..., "summary": ...}, ... ],
        "model_info": dict | None,        # module 1 output
        "repository_info": dict | None,   # module 2 output
    }

Output (consumed by scanner.run_scan and mcp_server.check_package):

    {
        "trust_score": int,               # 0-100
        "verdict": "ALLOW" | "CONDITIONAL" | "BLOCK",
        "hard_block": bool,
        "hard_block_reasons": [str, ...],
        "breakdown": {...},               # per-category detail, for reports
        "confidence": float,              # 0.0-1.0, how much evidence we had
    }

Where the numbers come from
---------------------------
The weights and thresholds here are not invented in isolation - they follow
what the team already agreed on elsewhere in the codebase:

  * The seven categories are exactly the seven `issues[].type` values in the
    team Data Protocol (module 3 README): cve, hallucination, typosquatting,
    malicious, pii, license, provenance. The original scanner.py comment
    ("refine this using the 7-category weighted scoring") refers to these.
  * The verdict thresholds (>=80 ALLOW, <50 BLOCK, critical -> BLOCK) and the
    confidence gate are taken from repository_checker.calculate_trust_score()
    so that a package score and a repository score mean the same thing.
  * The verdict vocabulary is ALLOW / CONDITIONAL / BLOCK, matching
    repository_checker.py, the module 3 README and the original scanner.

Any tuning should be done in CATEGORY_WEIGHTS / SEVERITY_FACTORS below rather
than scattered through the logic, and test_score_engine.py pins the current
behaviour so a change is visible in review.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

__all__ = [
    "calculate_trust_score",
    "CATEGORY_WEIGHTS",
    "CATEGORY_DEFAULT_SEVERITY",
    "SEVERITY_FACTORS",
    "ALLOW_THRESHOLD",
    "BLOCK_THRESHOLD",
]


# ---------------------------------------------------------------------------
# Tuning surface - everything adjustable lives here
# ---------------------------------------------------------------------------

# The seven categories of the team Data Protocol, and how many points each may
# subtract from a perfect 100. Ordered worst-first; the weights sum to 100 so a
# single maximally bad finding in every category lands exactly at 0.
CATEGORY_WEIGHTS: dict[str, int] = {
    "malicious": 30,        # confirmed malicious code - nothing outranks this
    "cve": 25,              # known, published vulnerabilities
    "license": 15,          # legal blocker (competition Article 8)
    "typosquatting": 10,    # name-confusion supply-chain attack
    "hallucination": 8,     # package/model does not exist -> name is hijackable
    "provenance": 7,        # origin cannot be verified
    "pii": 5,               # sensitive data exposure
}

# How much of a category's weight one issue consumes, by severity.
# "unknown" sits between medium and high on purpose: an unrated finding must
# not be treated as harmless, which is how unscored issues quietly disappear.
SEVERITY_FACTORS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "unknown": 0.5,
    "medium": 0.4,
    "low": 0.2,
}

# Issue types that producers emit outside the seven-type Data Protocol,
# mapped onto the category they belong to.
#
# repository_checker (module 2) reports "repository", "signature" and
# "dataset". All three are statements about where an artifact came from and
# whether it can be verified, which is what `provenance` covers. Without this
# mapping they land in `unrecognised` and every supply-chain finding is worth
# the same flat 3 points regardless of what it says.
#
# Mapping here rather than editing module 2 keeps the change at the
# integration point. The cleaner long-term fix is for module 2 to emit
# protocol types directly.
CATEGORY_ALIASES: dict[str, str] = {
    "repository": "provenance",
    "signature": "provenance",
    "dataset": "provenance",
    "integrity": "provenance",
    "vulnerability": "cve",
    "deprecated": "provenance",
}

# Severity to assume when a producer reports a finding without grading it.
#
# Modules 2 and 3 emit detector-style findings: detect_typosquatting() either
# matched a popular package name or it did not, and it has no severity scale
# to report. Falling back to "unknown" (factor 0.5) halved those deductions,
# so a confirmed typosquat cost 5 of its 10 points - there is no such thing
# as a low-severity typosquat.
#
# `cve` is deliberately absent: CVSS severity is a real published rating, and
# inventing one for an unrated CVE would be a guess rather than a default.
CATEGORY_DEFAULT_SEVERITY: dict[str, str] = {
    "malicious": "critical",
    "typosquatting": "high",
    "hallucination": "high",
    "provenance": "medium",
    "pii": "medium",
    "license": "medium",
}

# License status -> fraction of the license category consumed.
LICENSE_PENALTY: dict[str, float] = {
    "BLOCKED": 1.0,          # non-commercial / proprietary - unusable
    "UNKNOWN": 0.4,          # cannot prove compliance
    "NOT_INSTALLED": 0.4,    # license could not be read at all
    "REVIEW": 0.3,           # copyleft - needs a human decision
    "ALLOWED": 0.0,
}

# Verdict thresholds, mirroring repository_checker.calculate_trust_score().
ALLOW_THRESHOLD = 80
BLOCK_THRESHOLD = 50

# Below this, we do not have enough evidence to clear something as ALLOW.
MIN_CONFIDENCE_FOR_ALLOW = 0.7
MIN_CONFIDENCE_FOR_BLOCK = 0.5

# Issues whose `type` is not one of the seven still have to cost something.
# Silently ignoring an unrecognised finding is the exact failure mode this
# engine exists to prevent, so they are pooled here and reported by name.
UNRECOGNISED_WEIGHT = 10

# Weight given to module 2's repository trust when blending it with the
# package/model score. A trustworthy artifact from an untrustworthy source is
# not trustworthy, so the repository score pulls the final number.
REPOSITORY_BLEND = 0.3


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_severity(raw: Any) -> str:
    """
    Map any severity representation onto the five known levels.

    OSV returns raw CVSS vectors ("CVSS:3.1/AV:N/AC:L/..."), module 3 returns
    lowercase words, and some sources return nothing at all. Comparing a CVSS
    vector against "HIGH" never matches, which silently graded every finding
    as harmless in the original scanner - so vectors are resolved through
    cvss_score when the caller supplies one, and anything still unresolved
    becomes "unknown" rather than being dropped.
    """
    text = str(raw or "").strip().lower()
    if text in SEVERITY_FACTORS:
        return text
    return "unknown"


def _severity_of(issue: dict) -> str:
    """
    Severity of one issue.

    Resolution order: the stated severity, then the CVSS base score, then
    the category default for detector-style findings that carry no rating.
    """
    severity = _normalise_severity(issue.get("severity"))
    if severity != "unknown":
        return severity

    # CVSS v3 qualitative rating scale (NVD): 9.0+ critical, 7.0+ high,
    # 4.0+ medium, 0.1+ low.
    score = issue.get("cvss_score")
    try:
        value = float(score)
    except (TypeError, ValueError):
        value = None
    if value is not None:
        if value >= 9.0:
            return "critical"
        if value >= 7.0:
            return "high"
        if value >= 4.0:
            return "medium"
        if value > 0.0:
            return "low"

    return CATEGORY_DEFAULT_SEVERITY.get(_issue_type(issue), "unknown")


def _issue_type(issue: dict) -> str:
    """The scoring category an issue belongs to, after alias resolution."""
    text = str(issue.get("type") or "").strip().lower()
    if not text:
        return "unspecified"
    return CATEGORY_ALIASES.get(text, text)


def _collect_issues(check_result: dict) -> list[dict]:
    """
    Gather issues from the top level and from both context slots.

    Modules 1 and 2 report their own findings in the same `issues` shape, so
    a model's dangerous pickle and a repository's missing signature flow
    through exactly the same weighting as a CVE.
    """
    issues: list[dict] = []
    for source in (
        check_result.get("issues"),
        (check_result.get("model_info") or {}).get("issues"),
        (check_result.get("repository_info") or {}).get("issues"),
    ):
        if isinstance(source, Iterable) and not isinstance(source, (str, bytes)):
            issues.extend(item for item in source if isinstance(item, dict))
    return issues


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _score_categories(issues: list[dict], license_status: str) -> tuple[dict, list[str]]:
    """
    Apply the seven-category weighted deduction.

    Within a category the severity factors are summed and saturated at 1.0, so
    one critical finding consumes the whole category budget and further
    findings of the same kind cannot push the total below zero. Every category
    is reported even when it scored nothing, so a reader can tell "checked and
    clean" apart from "never looked".
    """
    load: dict[str, float] = {name: 0.0 for name in CATEGORY_WEIGHTS}
    counts: dict[str, int] = {name: 0 for name in CATEGORY_WEIGHTS}
    unrecognised: dict[str, int] = {}

    for issue in issues:
        category = _issue_type(issue)
        factor = SEVERITY_FACTORS[_severity_of(issue)]
        if category in load:
            load[category] += factor
            counts[category] += 1
        else:
            unrecognised[category] = unrecognised.get(category, 0) + 1

    # The license category is driven by license_checker's verdict as well as by
    # any explicit license issue, whichever is worse.
    license_load = LICENSE_PENALTY.get(str(license_status or "").upper(), 0.4)
    load["license"] = max(load["license"], license_load)

    breakdown: dict[str, Any] = {}
    total_deduction = 0.0
    for name, weight in CATEGORY_WEIGHTS.items():
        saturated = min(1.0, load[name])
        deduction = weight * saturated
        total_deduction += deduction
        breakdown[name] = {
            "weight": weight,
            "issues": counts[name],
            "deduction": round(deduction, 2),
        }

    if unrecognised:
        # Cost them something and name them, so an unknown finding type shows
        # up as a gap to fix rather than as a clean result.
        deduction = min(UNRECOGNISED_WEIGHT, 3.0 * sum(unrecognised.values()))
        total_deduction += deduction
        breakdown["unrecognised"] = {
            "weight": UNRECOGNISED_WEIGHT,
            "issues": sum(unrecognised.values()),
            "deduction": round(deduction, 2),
            "types": sorted(unrecognised),
        }

    return breakdown, [] if not unrecognised else sorted(unrecognised)


def _hard_blocks(issues: list[dict], license_status: str,
                 model_info: Optional[dict]) -> list[str]:
    """
    Conditions that block regardless of the numeric score.

    A hard block exists because some findings are not a matter of degree.
    Following repository_checker, a critical-severity finding blocks outright;
    so does confirmed malicious code and a license that forbids the use.
    """
    reasons: list[str] = []

    if str(license_status or "").upper() == "BLOCKED":
        reasons.append(
            "License is BLOCKED (non-commercial or proprietary): the package "
            "cannot be used under the project's open-source licensing rules."
        )

    for issue in issues:
        if _issue_type(issue) == "malicious":
            identifier = issue.get("id") or issue.get("detail") or issue.get("summary") or "?"
            reasons.append(f"Malicious code reported: {identifier}")

    critical = [i for i in issues if _severity_of(i) == "critical"]
    for issue in critical:
        identifier = issue.get("id") or issue.get("summary") or issue.get("detail") or "?"
        reasons.append(
            f"Critical severity {_issue_type(issue)} finding: {identifier}")

    # Module 1 reports these as explicit flags rather than as issues.
    info = model_info or {}
    if info.get("is_malicious"):
        reasons.append("Model checker flagged the model as malicious.")
    if info.get("license_blocked"):
        reasons.append("Model checker flagged the model's license as blocked.")

    # De-duplicate while preserving order.
    seen: set[str] = set()
    return [r for r in reasons if not (r in seen or seen.add(r))]


def _confidence(check_result: dict, issues: list[dict]) -> float:
    """
    How much of the expected evidence we actually received, 0.0-1.0.

    This is what stops the engine from handing out a confident ALLOW to
    something nobody managed to inspect. A missing input lowers confidence
    instead of silently scoring as clean - the same approach
    repository_checker takes with its partial_data flag.
    """
    kind = str(check_result.get("type") or "library").lower()

    # (present, weight) pairs. Weight expresses how much that evidence is
    # *expected* for this kind of artifact, so an optional input that is
    # absent cannot drag a fully-inspected package below the ALLOW gate.
    signals: list[tuple[bool, float]] = []

    license_status = str(check_result.get("license_status") or "").upper()
    signals.append((license_status not in ("", "UNKNOWN", "NOT_INSTALLED"), 1.0))

    # An empty list means "scanned, nothing found"; None means "never ran".
    signals.append((check_result.get("issues") is not None, 1.0))

    if kind == "model":
        signals.append((bool(check_result.get("model_info")), 1.0))
    elif kind == "repository":
        signals.append((bool(check_result.get("repository_info")), 1.0))
    else:
        # For a library, supply-chain context is valuable but optional, so its
        # absence lowers confidence only mildly - hence the half weight.
        signals.append((bool(check_result.get("repository_info")), 0.5))

    total_weight = sum(weight for _, weight in signals)
    confidence = sum(weight for present, weight in signals if present) / total_weight

    # An explicit partial-data marker from an upstream module.
    for context in (check_result.get("model_info"), check_result.get("repository_info")):
        if isinstance(context, dict) and context.get("partial_data"):
            confidence *= 0.75

    if any(_severity_of(i) == "unknown" for i in issues):
        # We found things we could not grade. Reporting them at full
        # confidence would overstate how well we understand this artifact.
        confidence *= 0.85

    return round(max(0.0, min(1.0, confidence)), 2)


def _blend_repository_trust(score: float, repository_info: Optional[dict]) -> tuple[float, Optional[int]]:
    """Pull the score toward module 2's repository trust, when available."""
    if not isinstance(repository_info, dict):
        return score, None
    raw = repository_info.get("trust_score")
    try:
        repo_trust = float(raw)
    except (TypeError, ValueError):
        return score, None
    blended = (1.0 - REPOSITORY_BLEND) * score + REPOSITORY_BLEND * repo_trust
    return blended, int(round(repo_trust))


def _decide_verdict(score: int, confidence: float, hard_block: bool,
                    issues: list[dict]) -> str:
    """
    Turn the number into ALLOW / CONDITIONAL / BLOCK.

    Mirrors repository_checker.calculate_trust_score() so that a package
    verdict and a repository verdict are directly comparable.
    """
    if hard_block:
        return "BLOCK"
    if confidence < MIN_CONFIDENCE_FOR_BLOCK:
        # Too little evidence to condemn or to clear.
        return "CONDITIONAL"
    if score < BLOCK_THRESHOLD:
        return "BLOCK"
    has_high = any(_severity_of(i) == "high" for i in issues)
    if score >= ALLOW_THRESHOLD and confidence >= MIN_CONFIDENCE_FOR_ALLOW and not has_high:
        return "ALLOW"
    return "CONDITIONAL"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def calculate_trust_score(check_result: dict) -> dict:
    """
    Compute the Trust Score and verdict for one checked artifact.

    Args:
        check_result: see the module docstring. Missing or malformed keys are
            tolerated - they lower `confidence` rather than raising, so one
            incomplete record cannot abort a whole scan.

    Returns:
        dict with trust_score, verdict, hard_block, hard_block_reasons,
        breakdown and confidence.
    """
    if not isinstance(check_result, dict):
        check_result = {}

    license_status = str(check_result.get("license_status") or "UNKNOWN")
    model_info = check_result.get("model_info")
    repository_info = check_result.get("repository_info")

    issues = _collect_issues(check_result)
    breakdown, unrecognised_types = _score_categories(issues, license_status)

    total_deduction = sum(
        entry["deduction"] for entry in breakdown.values() if isinstance(entry, dict)
    )
    score: float = max(0.0, 100.0 - total_deduction)

    score, repo_trust = _blend_repository_trust(score, repository_info)

    confidence = _confidence(check_result, issues)
    reasons = _hard_blocks(issues, license_status, model_info)
    hard_block = bool(reasons)

    trust_score = int(round(max(0.0, min(100.0, score))))
    if hard_block:
        # A blocked artifact must not display a comfortable number next to a
        # BLOCK verdict; the two would contradict each other in the report.
        trust_score = min(trust_score, BLOCK_THRESHOLD - 1)

    verdict = _decide_verdict(trust_score, confidence, hard_block, issues)

    breakdown["_summary"] = {
        "base": 100,
        "total_deduction": round(total_deduction, 2),
        "repository_trust": repo_trust,
        "repository_blend": REPOSITORY_BLEND if repo_trust is not None else None,
        "issue_count": len(issues),
        "confidence": confidence,
        "thresholds": {"allow": ALLOW_THRESHOLD, "block": BLOCK_THRESHOLD},
    }
    if unrecognised_types:
        breakdown["_summary"]["unrecognised_types"] = unrecognised_types

    return {
        "trust_score": trust_score,
        "verdict": verdict,
        "hard_block": hard_block,
        "hard_block_reasons": reasons,
        "breakdown": breakdown,
        "confidence": confidence,
    }


if __name__ == "__main__":
    # Manual smoke test: python3 score_engine.py
    import json

    samples = {
        "clean library": {
            "type": "library", "license_status": "ALLOWED", "issues": [],
            "model_info": None, "repository_info": None,
        },
        "one high CVE": {
            "type": "library", "license_status": "ALLOWED",
            "issues": [{"type": "cve", "id": "GHSA-x", "severity": "high"}],
            "model_info": None, "repository_info": None,
        },
        "critical CVE": {
            "type": "library", "license_status": "ALLOWED",
            "issues": [{"type": "cve", "id": "GHSA-y", "severity": "critical"}],
            "model_info": None, "repository_info": None,
        },
        "blocked license": {
            "type": "library", "license_status": "BLOCKED", "issues": [],
            "model_info": None, "repository_info": None,
        },
        "typosquat": {
            "type": "library", "license_status": "ALLOWED",
            "issues": [{"type": "typosquatting", "severity": "high",
                        "detail": "'reqeusts' resembles 'requests'"}],
            "model_info": None, "repository_info": None,
        },
    }

    for label, payload in samples.items():
        result = calculate_trust_score(payload)
        print(f"{label:>18} -> {result['trust_score']:>3}  {result['verdict']:<12} "
              f"conf={result['confidence']}  hard_block={result['hard_block']}")
    print()
    print(json.dumps(calculate_trust_score(samples["critical CVE"]), indent=2,
                     ensure_ascii=False))
