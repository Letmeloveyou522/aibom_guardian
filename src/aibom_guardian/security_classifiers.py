"""
security_classifiers.py
-----------------------------------
Text classifiers that do not belong to license, OSV, or picklescan.

``scan_text_for_pii`` looks for emails, Korean mobile numbers and credit-card
PANs in free text (a model card, a README). Findings use ``type: pii`` so
``score_engine.CATEGORY_ALIASES`` folds them into provenance — this module
does not score.
"""

from __future__ import annotations

import re

# Contact-form emails, not ``user@localhost``. TLD length matches the IANA
# minimum of 2; longer new gTLDs still fit.
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# 010 / 011 / 016 / 017 / 018 / 019, with optional hyphen or space grouping.
_KR_MOBILE_RE = re.compile(
    r"(?<!\d)(01[016789](?:[-\s]?\d{3,4})[-\s]?\d{4})(?!\d)"
)

# 13–19 digits, optional space/hyphen separators. Luhn decides if it is a PAN.
_CARD_RE = re.compile(r"(?<!\d)(\d(?:[-\s]?\d){12,18})(?!\d)")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        n = ord(char) - 48
        if index % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _finding(pii_kind: str, detail: str) -> dict:
    return {
        "type": "pii",
        "severity": "medium",
        "detail": detail,
        "pii_kind": pii_kind,
    }


def scan_text_for_pii(text, source="") -> list[dict]:
    """
    Return PII findings in ``text``.

    ``source`` is a label for the detail string (for example ``README.md``),
    not a filesystem path that is opened here.
    """
    if not text:
        return []

    blob = str(text)
    where = f" in {source}" if source else ""
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, match: str, detail: str) -> None:
        key = (kind, match)
        if key in seen:
            return
        seen.add(key)
        findings.append(_finding(kind, detail))

    for match in _EMAIL_RE.findall(blob):
        add("email", match.lower(),
            f"Email address found{where}: {match}")

    for match in _KR_MOBILE_RE.findall(blob):
        add("phone", match,
            f"Korean mobile number found{where}: {match}")

    for match in _CARD_RE.findall(blob):
        digits = re.sub(r"\D", "", match)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            add("credit_card", digits,
                f"Credit card number found{where}: {match}")

    return findings
