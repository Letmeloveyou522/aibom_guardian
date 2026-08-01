"""
test_license_checker.py
-----------------------------------
Unit tests for license_checker.classify_license().

    python3 -m pytest test_license_checker.py -q

The regression tests near the bottom pin the two failures that motivated the
rewrite: numpy being BLOCKED, and PyPI's real GPL classifier string grading
as UNKNOWN.
"""

import pytest

from license_checker import ALLOWED, BLOCKED, REVIEW, UNKNOWN, classify_license


# ---------------------------------------------------------------------------
# Short identifiers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "MIT", "MIT License", "Apache-2.0", "Apache 2.0", "Apache Software License",
    "BSD", "BSD-3-Clause", "BSD-2-Clause", "New BSD License", "ISC", "ISC License",
    "zlib", "0BSD", "CC0-1.0", "Public Domain", "The Unlicense",
    "Python Software Foundation License", "Boost Software License 1.0",
])
def test_permissive_licenses_are_allowed(text):
    assert classify_license(text) == ALLOWED


@pytest.mark.parametrize("text", [
    "GPL-3.0", "GPLv3", "GNU General Public License",
    "LGPL", "LGPL-2.1", "GNU Lesser General Public License",
    "AGPL-3.0", "GNU Affero General Public License",
    "MPL-2.0", "Mozilla Public License 2.0",
    "EPL-2.0", "Eclipse Public License", "CDDL-1.0", "CC-BY-SA-4.0",
])
def test_copyleft_licenses_need_review(text):
    assert classify_license(text) == REVIEW


@pytest.mark.parametrize("text", [
    "CC-BY-NC-4.0", "CC BY NC 4.0", "Creative Commons Attribution Non Commercial",
    "Noncommercial use only", "non-commercial", "Proprietary",
    "Commercial license required", "Academic use only", "Evaluation use only",
])
def test_restricted_licenses_are_blocked(text):
    assert classify_license(text) == BLOCKED


# ---------------------------------------------------------------------------
# PyPI trove classifiers - the shape importlib.metadata actually returns
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("classifier,expected", [
    ("License :: OSI Approved :: MIT License", ALLOWED),
    ("License :: OSI Approved :: Apache Software License", ALLOWED),
    ("License :: OSI Approved :: BSD License", ALLOWED),
    ("License :: OSI Approved :: GNU General Public License v3 (GPLv3)", REVIEW),
    ("License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)", REVIEW),
    ("License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)", REVIEW),
    ("License :: Free for non-commercial use", BLOCKED),
])
def test_trove_classifiers_are_understood(classifier, expected):
    """
    These are the exact strings PyPI serves. Matching the allow/review sets
    for equality against "gpl-3.0" missed every one of them.
    """
    assert classify_license(classifier) == expected


# ---------------------------------------------------------------------------
# No false positives from ordinary words
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "France Telecom License",       # contains "nc" inside "France"
    "Incompatible License",         # contains "nc" inside "Incompatible"
    "Encyclopedia License",
    "Nunc Software License",
])
def test_ordinary_words_containing_nc_are_not_blocked(text):
    """
    A bare "nc" keyword matched as a substring flags most English text.
    These are unrecognised licenses, so UNKNOWN - but never BLOCKED.
    """
    assert classify_license(text) == UNKNOWN


def test_lgpl_is_not_swallowed_by_the_gpl_pattern():
    """"lgpl" contains "gpl", so ordering matters."""
    assert classify_license("LGPL-3.0") == REVIEW
    assert classify_license("GPL-3.0") == REVIEW


# ---------------------------------------------------------------------------
# Compound expressions
# ---------------------------------------------------------------------------

def test_conjunctive_expressions_take_the_strictest_term():
    """Every term of an AND applies at once."""
    assert classify_license("BSD-3-Clause AND MIT") == ALLOWED
    assert classify_license("MIT AND GPL-3.0") == REVIEW
    assert classify_license("MIT AND CC-BY-NC-4.0") == BLOCKED


def test_disjunctive_expressions_take_the_most_permissive_term():
    """A dual license lets the consumer choose, so MIT OR GPL is usable as MIT."""
    assert classify_license("MIT OR GPL-3.0") == ALLOWED
    assert classify_license("GPL-3.0 OR LGPL-2.1") == REVIEW


def test_comma_separated_licenses():
    assert classify_license("MIT, Apache-2.0") == ALLOWED
    assert classify_license("MIT, Proprietary") == BLOCKED


# ---------------------------------------------------------------------------
# Missing / unusable input - UNKNOWN, never a pass
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [
    None, "", "   ", "UNKNOWN", "NOT_INSTALLED", "None", "unlicensed",
])
def test_absent_license_is_unknown(value):
    assert classify_license(value) == UNKNOWN


def test_unrecognised_license_is_unknown_not_allowed():
    """Failing to identify a license must not read as approval."""
    assert classify_license("Weird Vendor License v7") == UNKNOWN


def test_non_string_input_does_not_raise():
    for value in (42, 3.14, ["MIT"], {"license": "MIT"}):
        assert classify_license(value) in (ALLOWED, REVIEW, BLOCKED, UNKNOWN)


# ---------------------------------------------------------------------------
# Full license text
# ---------------------------------------------------------------------------

BSD_3_CLAUSE_TEXT = """Copyright (c) 2005-2024, NumPy Developers.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

    * Neither the name of the NumPy Developers nor the names of any
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED.
"""

MIT_TEXT = """MIT License

Copyright (c) 2024 Somebody

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
"""


def test_full_bsd_text_is_allowed():
    assert classify_license(BSD_3_CLAUSE_TEXT) == ALLOWED


def test_full_mit_text_is_allowed():
    assert classify_license(MIT_TEXT) == ALLOWED


def test_full_gpl_text_needs_review():
    text = "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n" + "x " * 200
    assert classify_license(text) == REVIEW


def test_bundled_third_party_licenses_do_not_drive_the_verdict():
    """
    numpy appends every bundled dependency's license to its own. Those terms
    do not govern numpy, and scanning them is what produced the BLOCKED
    verdict this rewrite fixes.
    """
    bundled = BSD_3_CLAUSE_TEXT + "\n" * 3 + (
        "----\nSome vendored library\nThis component may be used only "
        "noncommercially and is proprietary.\n" * 40
    )
    assert classify_license(bundled) == ALLOWED


def test_a_genuinely_non_commercial_text_is_still_blocked():
    """The primary-license window must not become a blanket exemption."""
    text = ("Creative Commons Attribution-NonCommercial 4.0\n\n"
            "You may not use the material for non-commercial use.\n" + "x " * 200)
    assert classify_license(text) == BLOCKED


# ---------------------------------------------------------------------------
# Regressions
# ---------------------------------------------------------------------------

def test_regression_numpy_is_not_blocked():
    """
    numpy is BSD-3-Clause. Its License field is 47 KB of text whose ordinary
    English ("including") matched the bare keyword "nc", and whose bundled
    licenses contributed "noncommercial" and "proprietary".
    """
    numpy_metadata = pytest.importorskip("importlib.metadata")
    try:
        license_field = numpy_metadata.metadata("numpy").get("License", "")
    except Exception:  # noqa: BLE001
        pytest.skip("numpy is not installed in this environment")
    if not license_field or len(license_field) < 300:
        pytest.skip("this numpy build does not ship the full license text")
    assert classify_license(license_field) == ALLOWED


# ---------------------------------------------------------------------------
# AI model licenses - the point of an AIBOM
# ---------------------------------------------------------------------------

from license_checker import classify_license_detailed


@pytest.mark.parametrize("text", [
    "openrail", "OpenRAIL-M", "CreativeML OpenRAIL-M",
    "bigscience-openrail-m", "bigscience-bloom-rail-1.0",
    "Responsible AI License", "Fair AI Public License 1.0-SD",
])
def test_behavioural_use_licenses_are_blocked(text):
    """
    RAIL-family licenses forbid named uses, so they are not OSI-approved
    open source. Article 8 asks for OSI-approved; these fail it.
    """
    assert classify_license(text) == BLOCKED
    assert classify_license_detailed(text)["family"] == "ai-behavioural"


@pytest.mark.parametrize("text", [
    "llama3.1", "Llama 3.1 Community License Agreement", "llama2",
    "gemma", "Gemma Terms of Use",
    "Tongyi Qianwen LICENSE AGREEMENT", "qwen",
    "deepseek", "InternLM", "ChatGLM", "Baichuan",
])
def test_vendor_community_licenses_need_review(text):
    """
    Usable but conditioned - MAU ceilings, named-entity carve-outs, naming
    obligations, separate acceptable-use policies. Never silently ALLOWED.
    """
    assert classify_license(text) == REVIEW
    assert classify_license_detailed(text)["family"] == "ai-community"


def test_no_ai_license_is_ever_allowed():
    """
    The regression that mattered: before this, every one of these came back
    UNKNOWN, so an AIBOM tool passed AI licenses through ungraded.
    """
    ai_licenses = [
        "llama3.1", "gemma", "openrail", "CreativeML OpenRAIL-M",
        "Tongyi Qianwen LICENSE AGREEMENT", "deepseek",
        "Llama 3.1 Community License Agreement", "Gemma Terms of Use",
    ]
    for text in ai_licenses:
        status = classify_license(text)
        assert status in (REVIEW, BLOCKED), f"{text} graded {status}"
        assert status != UNKNOWN


def test_ai_and_software_licenses_are_distinguishable():
    """
    "REVIEW because GPL" and "REVIEW because Llama community license" are
    very different conversations for a reviewer.
    """
    assert classify_license_detailed("GPL-3.0")["family"] == "copyleft"
    assert classify_license_detailed("llama3.1")["family"] == "ai-community"
    assert classify_license_detailed("MIT")["family"] == "permissive"


def test_apache_licensed_model_is_still_allowed():
    """Plenty of open-weight models really are Apache-2.0; do not over-block."""
    assert classify_license("apache-2.0") == ALLOWED
    assert classify_license_detailed("apache-2.0")["family"] == "permissive"


def test_non_commercial_beats_the_ai_rules():
    """cc-by-nc on a model is a hard restriction, not a community licence."""
    detail = classify_license_detailed("cc-by-nc-4.0")
    assert detail["status"] == BLOCKED
    assert detail["family"] == "restricted"


def test_detailed_always_reports_a_reason():
    for text in ["MIT", "GPL-3.0", "llama3.1", "openrail", "", "Weird v9"]:
        detail = classify_license_detailed(text)
        assert set(detail) == {"status", "family", "reason"}
        assert detail["reason"]


def test_ai_patterns_do_not_fire_on_ordinary_words():
    """'rail' and 'yi' appear in normal text; they must not match alone."""
    for text in ["Railway Software License", "Yi Ling Public License"]:
        assert classify_license(text) == UNKNOWN
