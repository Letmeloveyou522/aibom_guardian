"""
license_checker.py
-----------------------------------
Decides whether a package's license complies with the project rules
(Article 8: only OSI-approved open source licenses are allowed).

- ALLOWED: safe to use, OSI-approved and commercially usable
- REVIEW:  usable but needs a human check (e.g. GPL-family copyleft)
- BLOCKED: carries a non-commercial or proprietary restriction
- UNKNOWN: could not be identified - not the same as safe

Public API is `classify_license(license_string) -> str`, unchanged.

Why this is more than a keyword list
------------------------------------
`importlib.metadata` does not hand back a tidy SPDX identifier. What it
returns falls into three very different shapes:

  "MIT"                                     a short identifier
  "License :: OSI Approved :: MIT License"  a PyPI trove classifier
  "Copyright (c) 2005-2024, NumPy ..."      the entire license text, 47 KB
                                            of it, including every bundled
                                            third-party license

Treating all three as one string and grepping for keywords produces both
kinds of error, and both were live before this rewrite:

  * numpy (BSD-3-Clause) was BLOCKED. Its 47,527-character License field
    contains the word "including" (matched the bare keyword "nc"), the word
    "proprietary" inside a sentence *permitting* linking with proprietary
    programs, and the word "noncommercial" from a bundled third-party
    license that does not govern numpy itself.
  * "GNU General Public License v3 (GPLv3)" - the actual classifier string
    PyPI serves - was UNKNOWN, because the allow/review sets were matched
    for exact equality against "gpl-3.0". Copyleft slipped through ungraded.

So identifiers and full license texts are now handled separately, and
matching is done on word boundaries rather than raw substrings.
"""

import re

__all__ = ["classify_license", "classify_license_detailed",
           "ALLOWED", "REVIEW", "BLOCKED", "UNKNOWN"]

ALLOWED = "ALLOWED"
REVIEW = "REVIEW"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"

# Sentinels the callers pass in when there was nothing to read. They are not
# license strings and must not be pattern-matched.
_NON_LICENSE_VALUES = {"", "unknown", "none", "null", "not_installed",
                       "no license", "unlicensed"}

# A License field longer than this is the license *text*, not an identifier.
_FULL_TEXT_MIN_CHARS = 300

# Only the opening of a long license text describes the package's own
# license; bundled third-party licenses are appended after it. Everything
# past this point is somebody else's terms and must not drive the verdict.
_PRIMARY_TEXT_WINDOW = 4000


# ---------------------------------------------------------------------------
# Identifier patterns. Word-boundary regexes, checked in order.
# ---------------------------------------------------------------------------

# Restrictions that disqualify a package outright. Note there is no bare "nc"
# here: as a substring it matches "including", "France", "Incorporated" and
# most other English text.
_BLOCKED_PATTERNS = [
    r"\bnon[\s\-]?commercial\b",
    r"\bcc[\s\-]?by[\s\-]?nc\b",
    r"\bnc[\s\-](?:nd|sa)\b",
    r"\bproprietary\b",
    r"\bcommercial\s+license\s+required\b",
    r"\ball\s+rights\s+reserved\s*$",
    r"\bevaluation\s+(?:use\s+)?only\b",
    r"\bacademic\s+use\s+only\b",
]

# ---------------------------------------------------------------------------
# AI model licenses
# ---------------------------------------------------------------------------
# The licenses that ship with open-weight models are not OSI-approved and
# almost all of them carry use restrictions. Article 8 asks for OSI-approved
# open source, so grading a Llama or OpenRAIL model as ALLOWED - or, worse,
# letting it through as UNKNOWN - is the exact mistake this project exists to
# prevent.
#
# They are graded here rather than lumped in with software licenses because
# the reason differs: it is not copyleft, it is a field-of-use restriction.

# Behavioural-use licenses (RAIL family) forbid named uses outright, and
# licenses with an acceptable-use policy incorporate restrictions by
# reference. Neither is open source under the OSI definition.
_AI_RESTRICTED_PATTERNS = [
    r"\bopen\s?rail\b",
    # RAIL variants: "-rail-m", "rail++", "bloom-rail-1.0", "bigscience-rail".
    # A trailing letter or digit is required so the word "railway" - which
    # \b already excludes - and any other ordinary use cannot match.
    r"\brail[\s\-]?\+*[msd]\b", r"\brail[\s\-]?\d",
    r"\b(?:bigscience|big\s?science|bloom)[\s\-]?(?:bloom[\s\-]?)?rail\b",
    r"\bresponsible\s+ai\s+license\b",
    r"\bacceptable\s+use\s+policy\b",
    r"\bcreativeml\b",
    r"\bfair\s+ai\s+public\s+license\b",       # FAIPL has revenue conditions
    r"\bstability\s+ai\s+non[\s\-]?commercial\b",
    r"\bcoqui\s+public\s+model\b",
]

# Community / bespoke vendor licenses. Commercially usable up to a point,
# but with named-entity carve-outs, monthly-active-user ceilings, naming
# obligations or a separate acceptable-use policy. A human has to read them.
_AI_COMMUNITY_PATTERNS = [
    r"\bllama\s?[234](?:\.\d)?\b", r"\bllama[\s\-]?community\b",
    r"\bgemma\b", r"\bgoogle\s+gemma\b",
    r"\bqwen\b", r"\btongyi\s+qianwen\b",
    r"\bdeepseek\b",
    r"\bfalcon[\s\-]?(?:llm|180b)\b",
    r"\bmistral\s+ai\s+(?:research|non[\s\-]?production)\b",
    r"\bcohere\b", r"\bc4ai\b",
    r"\bnvidia\s+(?:open\s+model|community)\b",
    r"\bseallm\b", r"\byi\s+(?:series|license)\b",
    r"\bglm\b", r"\bchatglm\b",
    r"\bbaichuan\b", r"\binternlm\b",
    r"\bstabilityai\s+community\b",
    r"\bapple\s+(?:ascl|sample\s+code)\b",
]

# Copyleft and weak-copyleft: usable, but a human has to decide.
# LGPL must be tested before GPL, since "lgpl" contains "gpl".
_REVIEW_PATTERNS = [
    r"\bl\s?gpl\b", r"\blesser\s+general\s+public\b",
    r"\ba\s?gpl\b", r"\baffero\b",
    r"\bgpl\b", r"\bgnu\s+general\s+public\b", r"\bgplv?[23]\b",
    r"\bmpl\b", r"\bmozilla\s+public\b",
    r"\bepl\b", r"\beclipse\s+public\b",
    r"\bcddl\b", r"\bcommon\s+development\b",
    r"\bcc[\s\-]?by[\s\-]?sa\b",
    r"\bsleepycat\b",
]

# OSI-approved and commercially usable.
_ALLOWED_PATTERNS = [
    r"\bmit\b",
    r"\bapache\b",
    r"\bbsd\b", r"\b[023]\-?clause\b", r"\bsimplified\s+bsd\b", r"\bnew\s+bsd\b",
    r"\bisc\b",
    r"\bzlib\b", r"\blibpng\b",
    r"\b0bsd\b",
    r"\bcc0\b", r"\bpublic\s+domain\b", r"\bunlicense\b",
    r"\bpython\s+software\s+foundation\b", r"\bpsf\b",
    r"\bpostgresql\b", r"\bboost\b",
    r"\bhpnd\b", r"\bhistorical\s+permission\b",
    r"\bwtfpl\b",
]

# ---------------------------------------------------------------------------
# Full-text signatures. These identify a license from its actual wording.
# ---------------------------------------------------------------------------

_TEXT_SIGNATURES = [
    # (status, signature regex, label)
    (BLOCKED, r"non[\s\-]?commercial\s+use", "non-commercial clause"),
    (REVIEW, r"gnu\s+lesser\s+general\s+public\s+license", "LGPL"),
    (REVIEW, r"gnu\s+affero\s+general\s+public\s+license", "AGPL"),
    (REVIEW, r"gnu\s+general\s+public\s+license", "GPL"),
    (REVIEW, r"mozilla\s+public\s+license", "MPL"),
    (REVIEW, r"eclipse\s+public\s+license", "EPL"),
    (ALLOWED, r"permission\s+is\s+hereby\s+granted,\s+free\s+of\s+charge", "MIT"),
    (ALLOWED, r"apache\s+license.{0,40}version\s+2", "Apache-2.0"),
    (ALLOWED, r"redistributions\s+in\s+binary\s+form\s+must\s+reproduce", "BSD"),
    (ALLOWED, r"permission\s+to\s+use,\s+copy,\s+modify,\s+and/or\s+distribute", "ISC"),
    (ALLOWED, r"this\s+software\s+is\s+provided\s+['\"]as[\-\s]is['\"]", "zlib/BSD-like"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise(text: str) -> str:
    """Lowercase and collapse whitespace so patterns match predictably."""
    return re.sub(r"\s+", " ", text.lower()).strip()


def _strip_classifier(part: str) -> str:
    """
    Reduce a PyPI trove classifier to its license name.

    "License :: OSI Approved :: MIT License" -> "mit license"
    """
    if "::" in part:
        part = part.split("::")[-1]
    return part.strip()


def _match(patterns, text: str) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)


def _classify_identifier(part: str) -> str:
    return _classify_identifier_detailed(part)[0]


def _classify_identifier_detailed(part: str) -> tuple:
    """
    Classify one short license identifier.

    Returns (status, family, reason). `family` names which rule fired, so a
    report can distinguish "REVIEW because GPL copyleft" from "REVIEW because
    Llama community license" - very different conversations for a reviewer.
    """
    text = _normalise(_strip_classifier(part))
    if not text or text in _NON_LICENSE_VALUES:
        return UNKNOWN, "none", "No license declared."

    # Order matters: a restriction outranks whatever else the string says, so
    # "MIT, non-commercial use only" is BLOCKED rather than ALLOWED.
    if _match(_BLOCKED_PATTERNS, text):
        return BLOCKED, "restricted", (
            "Carries a non-commercial or proprietary restriction.")

    if _match(_AI_RESTRICTED_PATTERNS, text):
        return BLOCKED, "ai-behavioural", (
            "Behavioural-use (RAIL-family) or acceptable-use-policy license. "
            "It forbids named uses, so it is not OSI-approved open source.")

    if _match(_AI_COMMUNITY_PATTERNS, text):
        return REVIEW, "ai-community", (
            "Open-weight vendor community license. Redistribution is allowed "
            "but conditioned - typically a named-entity carve-out, a "
            "monthly-active-user ceiling, naming obligations, or a separate "
            "acceptable-use policy. Not OSI-approved; a human must read it.")

    if _match(_REVIEW_PATTERNS, text):
        return REVIEW, "copyleft", (
            "Copyleft or weak-copyleft license; check the obligations it "
            "places on derived work.")

    if _match(_ALLOWED_PATTERNS, text):
        return ALLOWED, "permissive", "OSI-approved and commercially usable."

    return UNKNOWN, "unrecognised", (
        "License string could not be identified. Not the same as safe.")


def _classify_full_text(text: str) -> str:
    """
    Classify a full license text by its opening wording.

    Only the first `_PRIMARY_TEXT_WINDOW` characters are considered. A
    package's own license comes first; anything after it is a bundled
    third-party license that does not govern this package, and scanning it
    is what turned BSD-licensed numpy into a BLOCKED result.
    """
    head = _normalise(text[:_PRIMARY_TEXT_WINDOW])
    for status, signature, _label in _TEXT_SIGNATURES:
        if re.search(signature, head):
            return status
    return UNKNOWN


def _combine(statuses: set, disjunctive: bool) -> str:
    """
    Reduce several license verdicts to one.

    Disjunctive ("MIT OR GPL-3.0") means the consumer may pick a term, so the
    most permissive wins. Conjunctive ("MIT AND CC-BY-NC") means every term
    applies at once, so the strictest wins.
    """
    if disjunctive:
        for status in (ALLOWED, REVIEW, UNKNOWN, BLOCKED):
            if status in statuses:
                return status
        return UNKNOWN

    for status in (BLOCKED, UNKNOWN, REVIEW, ALLOWED):
        if status in statuses:
            return status
    return UNKNOWN


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_license(license_string) -> str:
    """
    Classify a license string as ALLOWED / REVIEW / BLOCKED / UNKNOWN.

    Accepts a short identifier ("MIT"), a PyPI trove classifier
    ("License :: OSI Approved :: MIT License"), a compound expression
    ("BSD-3-Clause AND MIT"), or an entire license text.

    UNKNOWN means "could not identify", never "fine". Callers grade it as a
    risk rather than a pass - see score_engine.LICENSE_PENALTY.
    """
    if license_string is None:
        return UNKNOWN
    if not isinstance(license_string, str):
        license_string = str(license_string)

    raw = license_string.strip()
    if not raw or raw.lower() in _NON_LICENSE_VALUES:
        return UNKNOWN

    # Full license text: identify by wording, not by keyword spotting.
    if len(raw) >= _FULL_TEXT_MIN_CHARS or raw.count("\n") > 3:
        return _classify_full_text(raw)

    # Compound expression. "OR" is checked first so that a mixed
    # "A AND B OR C" is treated as the (more common) dual-license form.
    normalised = _normalise(raw)
    disjunctive = bool(re.search(r"\bor\b|/", normalised))
    parts = re.split(r"\bor\b|\band\b|[,;/]", normalised) if (
        disjunctive or re.search(r"\band\b|[,;]", normalised)) else [normalised]

    statuses = {_classify_identifier(part) for part in parts if part.strip()}
    if not statuses:
        return UNKNOWN
    return _combine(statuses, disjunctive)


def classify_license_detailed(license_string) -> dict:
    """
    Like `classify_license`, but also says which rule fired and why.

    Returns {"status", "family", "reason"} where family is one of
    permissive / copyleft / ai-community / ai-behavioural / restricted /
    unrecognised / none.

    Used by the model scanner and the SBOM writer, where "REVIEW because
    Llama community license" and "REVIEW because GPL" need to be told apart.
    """
    status = classify_license(license_string)

    if license_string is None or not str(license_string).strip():
        return {"status": UNKNOWN, "family": "none",
                "reason": "No license declared."}

    raw = str(license_string).strip()
    if len(raw) >= _FULL_TEXT_MIN_CHARS or raw.count("\n") > 3:
        return {"status": status, "family": "full-text",
                "reason": "Identified from the full license text."}

    # For a compound expression, report the rule that produced the verdict.
    normalised = _normalise(raw)
    parts = re.split(r"\bor\b|\band\b|[,;/]", normalised) or [normalised]
    for part in parts:
        if not part.strip():
            continue
        part_status, family, reason = _classify_identifier_detailed(part)
        if part_status == status:
            return {"status": status, "family": family, "reason": reason}

    return {"status": status, "family": "compound",
            "reason": "Combined verdict over several license terms."}


if __name__ == "__main__":
    samples = [
        # software licenses
        "MIT License",
        "License :: OSI Approved :: MIT License",
        "BSD-3-Clause AND MIT",
        "MIT OR GPL-3.0",
        "GNU General Public License v3 (GPLv3)",
        "Apache Software License",
        "CC-BY-NC-4.0",
        "France Telecom License",
        "NOT_INSTALLED",
        "",
        # AI model licenses - what this project is actually about
        "llama3.1",
        "Llama 3.1 Community License Agreement",
        "gemma",
        "Gemma Terms of Use",
        "openrail",
        "CreativeML OpenRAIL-M",
        "bigscience-openrail-m",
        "Tongyi Qianwen LICENSE AGREEMENT",
        "deepseek",
        "cc-by-nc-4.0",
    ]
    for sample in samples:
        detail = classify_license_detailed(sample)
        print(f"{sample!r:44} -> {detail['status']:8} [{detail['family']}]")

    # The regression that started this rewrite.
    try:
        from importlib.metadata import metadata

        numpy_license = metadata("numpy").get("License", "")
        print(f"\nnumpy License field: {len(numpy_license)} chars "
              f"-> {classify_license(numpy_license)}  (expected ALLOWED)")
    except Exception as exc:  # noqa: BLE001 - numpy may not be installed
        print(f"\n(numpy not available: {exc})")
