"""
score_engine.py
-----------------------------------
Trust Score and final verdict - the only place either is decided.

    model_checker ──────┐
    repository_checker ─┼──> score_engine ──> sbom_generator / scanner
    recommendation ─────┘     (Trust Score)    mcp_server

The other modules collect evidence and do not score. That is what makes the
CLI and the MCP server return the same verdict for the same package.

Public API
----------
    calculate_trust_score(check_result: dict) -> dict

Input (assembled by _adapters._build_check_result, which both the CLI and the
MCP server go through):

    {
        "type": "library" | "model" | "repository",
        "license_status": "ALLOWED" | "REVIEW" | "BLOCKED" | "UNKNOWN" | ...,
        "issues": [ {"type": ..., "severity": ..., "id": ..., "summary": ...}, ... ],
        "model_info": dict | None,        # model_checker output
        "repository_info": dict | None,   # repository_checker output
    }

Output (consumed by scanner.run_scan and mcp_server.check_package):

    {
        "trust_score": int,               # 0-100
        "verdict": "ALLOW" | "WARNING" | "BLOCK",
        "hard_block": bool,
        "hard_block_reasons": [str, ...],
        "breakdown": {...},               # per-category detail, for reports
        "confidence": float,              # 0.0-1.0, how much evidence we had
    }

Rules that are not obvious from the arithmetic
---------------------------------------------
* The seven ``issues[].type`` values are a contract with every producer:
  cve, hallucination, typosquatting, malicious, pii, license, provenance.
* Thresholds (>=80 ALLOW, <50 BLOCK, critical -> BLOCK) match
  ``repository_checker.calculate_trust_score()`` so both scores share a scale.
  repository_checker keeps CONDITIONAL internally; scanner normalises it.
* Weights say how bad a finding is, not how likely it is. ``malicious`` is
  filled only by picklescan on model weights, and ``pii`` has no producer at
  all yet - its weight is a reserved slot.
* ``verified: False`` issues do not deduct, only lower confidence. A PyPI
  outage must not score like a confirmed hallucinated package.
* When ``repository_info.trust_score`` is blended in, its issues are not
  deducted again on top; they still show in the breakdown and still affect
  confidence, hard blocks and the ALLOW gate.

Tune CATEGORY_WEIGHTS / SEVERITY_FACTORS below, not the logic.
test_score_engine.py pins the current numbers.
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

# Points each category may subtract from a perfect 100. Worst first; they sum
# to 100, so one maximally bad finding in every category lands exactly at 0.
CATEGORY_WEIGHTS: dict[str, int] = {
    "malicious": 28,        # model_checker picklescan only; also hard-blocks
    "cve": 25,              # published vulnerabilities (OSV)
    "license": 15,          # legal blocker
    "typosquatting": 12,    # recommendation.detect_typosquatting
    "hallucination": 10,    # non-existent package, verified: True only
    "provenance": 8,        # origin / yank / stale; repository findings
    "pii": 2,               # reserved: no producer yet
}

# How much of a category's weight one issue consumes. "unknown" sits above
# "medium" deliberately - an unrated finding must not be treated as harmless.
SEVERITY_FACTORS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.7,
    "unknown": 0.5,
    "medium": 0.4,
    "low": 0.2,
}

# repository_checker emits "repository", "signature" and "dataset" - all
# statements about where an artifact came from, so they map to `provenance`.
# Unmapped they fall into `unrecognised`, where every finding costs a flat 3
# points regardless of what it says.
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

# Weight given to repository_checker's trust score when blending it with
# the package/model score. A trustworthy artifact from an untrustworthy
# source is not trustworthy, so the repository score pulls the final number.
REPOSITORY_BLEND = 0.3


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_severity(raw: Any) -> str:
    """
    Map any severity representation onto the five known levels.

    OSV returns raw CVSS vectors ("CVSS:3.1/AV:N/AC:L/..."), recommendation
    returns lowercase words, and some sources return nothing at all. Comparing
    a CVSS vector against "HIGH" never matches, which silently graded every
    finding as harmless in the original scanner - so vectors are resolved
    through cvss_score when the caller supplies one, and anything still
    unresolved becomes "unknown" rather than being dropped.
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


def _is_scoreable(issue: dict) -> bool:
    """
    Whether an issue may subtract from the Trust Score.

    ``verified: False`` means the check did not complete (network / API
    failure). Treating that like a confirmed finding is how a PyPI outage
    used to cost a full hallucination deduction — so unverified issues are
    excluded from deductions (they still affect confidence).
    """
    if not isinstance(issue, dict):
        return False
    # Explicit False only; missing / True / other → score as usual.
    return issue.get("verified") is not False


def _repository_trust_usable(repository_info: Optional[dict]) -> bool:
    """True when repository_checker's trust_score can be blended in."""
    if not isinstance(repository_info, dict):
        return False
    try:
        float(repository_info.get("trust_score"))
    except (TypeError, ValueError):
        return False
    return True


def _collect_issues(
    check_result: dict,
    *,
    include_repository_issues: bool = True,
) -> list[dict]:
    """
    Gather issues from the top level and from both context slots.

    Modules 1 and 2 report their own findings in the same `issues` shape, so
    a model's dangerous pickle and a repository's missing signature flow
    through exactly the same weighting as a CVE.

    When ``include_repository_issues`` is False (trust_score is being blended),
    repository_checker's issues are omitted from *deduction* input; callers may
    surface them separately for breakdown counts.
    """
    sources: list[Any] = [
        check_result.get("issues"),
        (check_result.get("model_info") or {}).get("issues"),
    ]
    if include_repository_issues:
        sources.append((check_result.get("repository_info") or {}).get("issues"))

    issues: list[dict] = []
    for source in sources:
        if isinstance(source, Iterable) and not isinstance(source, (str, bytes)):
            issues.extend(item for item in source if isinstance(item, dict))
    return issues


def _repository_issues_only(repository_info: Optional[dict]) -> list[dict]:
    if not isinstance(repository_info, dict):
        return []
    source = repository_info.get("issues")
    if not isinstance(source, Iterable) or isinstance(source, (str, bytes)):
        return []
    return [item for item in source if isinstance(item, dict)]


def _surface_issue_counts(breakdown: dict, issues: list[dict]) -> list[str]:
    """
    Record issue counts in the breakdown without changing deductions.

    Used when repository trust is blended: repository_checker findings must stay
    visible (scanner asserts provenance.issues) but must not deduct again.
    """
    surfaced_unrecognised: list[str] = []
    for issue in issues:
        if not _is_scoreable(issue):
            continue
        category = _issue_type(issue)
        if category in CATEGORY_WEIGHTS:
            breakdown[category]["issues"] += 1
            continue
        block = breakdown.setdefault(
            "unrecognised",
            {
                "weight": UNRECOGNISED_WEIGHT,
                "issues": 0,
                "deduction": 0.0,
                "types": [],
            },
        )
        block["issues"] += 1
        types = set(block.get("types") or [])
        types.add(category)
        block["types"] = sorted(types)
        surfaced_unrecognised.append(category)
    return sorted(set(surfaced_unrecognised))


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

    Issues with ``verified: False`` are skipped here - unverified is not
    the same as confirmed, and only confirmed findings deduct.
    """
    load: dict[str, float] = {name: 0.0 for name in CATEGORY_WEIGHTS}
    counts: dict[str, int] = {name: 0 for name in CATEGORY_WEIGHTS}
    unrecognised: dict[str, int] = {}

    for issue in issues:
        if not _is_scoreable(issue):
            continue
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

    Unverified findings (``verified: False``) never hard-block — an incomplete
    check is not evidence of malice.
    """
    reasons: list[str] = []

    if str(license_status or "").upper() == "BLOCKED":
        reasons.append(
            "License is BLOCKED (non-commercial or proprietary): the package "
            "cannot be used under the project's open-source licensing rules."
        )

    for issue in issues:
        if not _is_scoreable(issue):
            continue
        if _issue_type(issue) == "malicious":
            identifier = issue.get("id") or issue.get("detail") or issue.get("summary") or "?"
            reasons.append(f"Malicious code reported: {identifier}")

    critical = [
        i for i in issues
        if _is_scoreable(i) and _severity_of(i) == "critical"
    ]
    for issue in critical:
        identifier = issue.get("id") or issue.get("summary") or issue.get("detail") or "?"
        reasons.append(
            f"Critical severity {_issue_type(issue)} finding: {identifier}")

    # model_checker reports these as explicit flags rather than as issues.
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

    if any(_severity_of(i) == "unknown" for i in issues if _is_scoreable(i)):
        # We found things we could not grade. Reporting them at full
        # confidence would overstate how well we understand this artifact.
        confidence *= 0.85

    # Incomplete checks (verified: False) — evidence gap, not a clean pass.
    if any(isinstance(i, dict) and i.get("verified") is False for i in issues):
        confidence *= 0.85

    return round(max(0.0, min(1.0, confidence)), 2)


def _blend_repository_trust(score: float, repository_info: Optional[dict]) -> tuple[float, Optional[int]]:
    """Pull the score toward repository_checker's trust score, when available."""
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
    Turn the number into ALLOW / WARNING / BLOCK.

    Mirrors repository_checker.calculate_trust_score() so that a package
    verdict and a repository verdict are directly comparable.
    """
    if hard_block:
        return "BLOCK"
    if confidence < MIN_CONFIDENCE_FOR_BLOCK:
        # Too little evidence to condemn or to clear.
        return "WARNING"
    if score < BLOCK_THRESHOLD:
        return "BLOCK"
    # Only confirmed (scoreable) high findings block ALLOW — an unverified
    # network failure must not permanently deny ALLOW via a phantom "high".
    has_high = any(
        _is_scoreable(i) and _severity_of(i) == "high" for i in issues
    )
    if score >= ALLOW_THRESHOLD and confidence >= MIN_CONFIDENCE_FOR_ALLOW and not has_high:
        return "ALLOW"
    return "WARNING"


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

    # Blend path: do not category-deduct repository_info.issues (already in
    # trust_score). Still collect them for confidence / hard-block / visibility.
    blend_repo = _repository_trust_usable(repository_info)
    scoring_issues = _collect_issues(
        check_result, include_repository_issues=not blend_repo
    )
    all_issues = _collect_issues(check_result, include_repository_issues=True)

    breakdown, unrecognised_types = _score_categories(scoring_issues, license_status)

    if blend_repo:
        surfaced = _surface_issue_counts(
            breakdown, _repository_issues_only(repository_info)
        )
        if surfaced:
            unrecognised_types = sorted(set(unrecognised_types) | set(surfaced))

    total_deduction = sum(
        entry["deduction"] for entry in breakdown.values() if isinstance(entry, dict)
    )
    score: float = max(0.0, 100.0 - total_deduction)

    score, repo_trust = _blend_repository_trust(score, repository_info)

    confidence = _confidence(check_result, all_issues)
    reasons = _hard_blocks(all_issues, license_status, model_info)
    hard_block = bool(reasons)

    trust_score = int(round(max(0.0, min(100.0, score))))
    if hard_block:
        # A blocked artifact must not display a comfortable number next to a
        # BLOCK verdict; the two would contradict each other in the report.
        trust_score = min(trust_score, BLOCK_THRESHOLD - 1)

    verdict = _decide_verdict(trust_score, confidence, hard_block, all_issues)

    breakdown["_summary"] = {
        "base": 100,
        "total_deduction": round(total_deduction, 2),
        "repository_trust": repo_trust,
        "repository_blend": REPOSITORY_BLEND if repo_trust is not None else None,
        "repository_issues_deducted": not blend_repo,
        "issue_count": len(all_issues),
        "scored_issue_count": sum(1 for i in scoring_issues if _is_scoreable(i)),
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
