"""
Tests for security_classifiers.scan_text_for_pii.

No network: the detector is regex + Luhn on the string it is given.
"""

from aibom_guardian.security_classifiers import scan_text_for_pii


def kinds(findings):
    return {f["pii_kind"] for f in findings}


def test_email_is_reported_as_pii():
    findings = scan_text_for_pii(
        "Maintainer: leak@example.com", source="README.md")
    assert len(findings) == 1
    assert findings[0]["type"] == "pii"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["pii_kind"] == "email"
    assert "leak@example.com" in findings[0]["detail"]
    assert "README.md" in findings[0]["detail"]


def test_korean_mobile_number_is_reported():
    findings = scan_text_for_pii("문의: 010-1234-5678")
    assert kinds(findings) == {"phone"}
    assert "010-1234-5678" in findings[0]["detail"]


def test_luhn_valid_card_is_reported():
    findings = scan_text_for_pii("billing 4111-1111-1111-1111")
    assert kinds(findings) == {"credit_card"}


def test_luhn_invalid_digits_are_ignored():
    assert scan_text_for_pii("4111-1111-1111-1112") == []


def test_clean_prose_is_silent():
    text = "A 1.1 billion parameter decoder-only transformer on C4."
    assert scan_text_for_pii(text) == []


def test_duplicate_matches_are_reported_once():
    findings = scan_text_for_pii("a@example.com and a@example.com")
    assert len(findings) == 1
