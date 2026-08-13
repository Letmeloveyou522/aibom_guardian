"""
test_license_checker.py
-----------------------------------
Unit tests for license_checker.classify_license().

The regression tests near the bottom pin the two failures that motivated the
rewrite: numpy being BLOCKED, and PyPI's real GPL classifier string grading
as UNKNOWN.
"""

import logging

import pytest

from aibom_guard.license_checker import ALLOWED, BLOCKED, REVIEW, UNKNOWN, classify_license


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


def test_classifiers_normalise_to_spdx():
    """
    Classifier strings must map onto SPDX ids before grading, so
    GPLv3 is recognised as GPL-3.0-only rather than UNKNOWN.
    """
    from aibom_guard.license_checker import normalize_to_spdx

    assert normalize_to_spdx(
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ) == "GPL-3.0-only"
    assert normalize_to_spdx(
        "License :: OSI Approved :: MIT License"
    ) == "MIT"
    assert normalize_to_spdx(
        "License :: OSI Approved :: Apache Software License"
    ) == "Apache-2.0"
    assert normalize_to_spdx("GPLv3") == "GPL-3.0-only"


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
# Registries decide, and the answer says which one
# ---------------------------------------------------------------------------

from aibom_guard.license_checker import classify_license_detailed, registry_versions


def test_registry_versions_are_reported():
    """
    A verdict is only auditable if the data behind it is pinned. Callers
    record this next to the result.
    """
    versions = registry_versions()
    assert versions["spdx_license_list"]
    assert versions["blue_oak_council_list"]


@pytest.mark.parametrize("text,spdx_id", [
    ("MIT", "MIT"),
    ("Apache Software License", "Apache-2.0"),
    ("License :: OSI Approved :: BSD License", "BSD-3-Clause"),
    ("GPLv3", "GPL-3.0-only"),
    ("GPL-2.0-or-later", "GPL-2.0-or-later"),
    ("MPL-2.0", "MPL-2.0"),
    ("BSL-1.0", "BSL-1.0"),
])
def test_licenses_resolve_to_their_spdx_identifier(text, spdx_id):
    """Identification comes from the SPDX list, not from keyword matching."""
    assert classify_license_detailed(text)["spdx_id"] == spdx_id


def test_permissive_non_osi_licenses_are_not_blocked():
    """
    `isOsiApproved` records whether anyone filed with OSI, not how restrictive
    a license is. These four are all isOsiApproved: false and all permissive -
    Blue Oak Council rates every one of them. Grading on the OSI flag alone
    blocks the lot.
    """
    for text in ["CC0-1.0", "BSD-Source-Code", "BSD-4-Clause", "WTFPL"]:
        detail = classify_license_detailed(text)
        assert detail["status"] == ALLOWED, text
        assert detail["source"] == "blue-oak-council", text


def test_unrated_non_osi_licenses_are_review_not_blocked():
    """
    In SPDX, neither OSI-approved nor Blue Oak rated. Absence of evidence is
    not evidence of a restriction, so this is a human's call, not a block.
    """
    detail = classify_license_detailed("MIT-Festival")
    assert detail["status"] == REVIEW
    assert detail["family"] == "unrated"


def test_every_verdict_states_an_obligation():
    """
    A verdict that does not say what you have to do is not usable for
    compliance. REVIEW especially: "needs review" is not an instruction.
    """
    for text in ["MIT", "GPL-3.0-only", "AGPL-3.0-only", "LGPL-2.1-only",
                 "MPL-2.0", "CC-BY-NC-4.0", "BUSL-1.1", "MIT-Festival"]:
        detail = classify_license_detailed(text)
        assert detail["obligations"], text
        assert all(line.strip() for line in detail["obligations"]), text


@pytest.mark.parametrize("spdx_id,expected_phrase", [
    ("AGPL-3.0-only", "network"),
    ("GPL-3.0-only", "complete corresponding source"),
    ("LGPL-2.1-only", "relink"),
    ("MPL-2.0", "File-level"),
])
def test_copyleft_obligations_distinguish_the_families(spdx_id, expected_phrase):
    """
    "REVIEW" is the same word for AGPL and MPL, but the duty is not: AGPL
    reaches hosted use, MPL reaches only the files you took.
    """
    obligations = " ".join(classify_license_detailed(spdx_id)["obligations"])
    assert expected_phrase in obligations


# ---------------------------------------------------------------------------
# The version is never invented
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "LGPL", "GPL", "MPL", "EPL", "AGPL", "CDDL",
    "GNU General Public License", "Mozilla Public License",
])
def test_a_bare_family_name_does_not_claim_a_version(text):
    """
    paramiko publishes "LGPL" and is LGPL-2.1. Resolving that to LGPL-3.0-only
    hands back a confident wrong answer, and the two versions do not impose
    the same terms. The family is reported; the version is left unresolved.
    """
    detail = classify_license_detailed(text)
    assert detail["status"] == REVIEW, text
    assert detail["spdx_id"] == "", text
    assert detail["source"] == "family-fallback", text
    assert "could not be resolved" in detail["reason"]


@pytest.mark.parametrize("text", [
    "GPL v3", "LGPL with exceptions", "LGPLv2+", "Affero GPL",
    "GPL (see LICENSE file)", "LGPL+BSD",
])
def test_copyleft_is_never_missed_because_the_string_is_untidy(text):
    """
    These are strings PyPI actually serves - PyQt5 publishes "GPL v3",
    psycopg2 "LGPL with exceptions", pyzmq "LGPL+BSD". None resolves to an
    SPDX id, and letting them fall through to UNKNOWN is how copyleft ships
    ungraded.
    """
    assert classify_license(text) == REVIEW, text


def test_the_fallback_never_produces_allowed():
    """
    The fallback names copyleft families only. Guessing "this looks
    permissive" would risk a false pass, which is the failure mode that
    matters - so an unidentifiable license stays UNKNOWN and is penalised as
    unverified rather than waved through.
    """
    for text in ["Weird Vendor License v7", "Some Corp Internal License",
                 "France Telecom License", "Nunc Software License"]:
        assert classify_license(text) == UNKNOWN, text


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
    """
    The keys scanner.py and the SBOM writer read must always be present. The
    set is a subset check, not equality: `spdx_id`, `obligations`, `source`
    and `reference` were added when grading moved onto the SPDX and Blue Oak
    registries, and pinning the exact key set would block any later field.
    """
    required = {"status", "family", "reason", "obligations", "spdx_id",
                "source", "reference"}
    for text in ["MIT", "GPL-3.0", "llama3.1", "openrail", "", "Weird v9"]:
        detail = classify_license_detailed(text)
        assert required <= set(detail), text
        assert detail["reason"]
        assert isinstance(detail["obligations"], list)


def test_ai_patterns_do_not_fire_on_ordinary_words():
    """'rail' and 'yi' appear in normal text; they must not match alone."""
    for text in ["Railway Software License", "Yi Ling Public License"]:
        assert classify_license(text) == UNKNOWN


# ---------------------------------------------------------------------------
# Source-available licenses - published code, but not open source
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "Commons Clause",
    "Apache-2.0 WITH Commons Clause",
    "MIT WITH Commons Clause",
    "BUSL-1.1",
    "Business Source License 1.1",
    "BSL-1.1",
    "Elastic License 2.0",
    "Elastic-2.0",
    "SSPL-1.0",
    "Server Side Public License",
    "PolyForm Shield 1.0.0",
    "Redis Source Available License",
    "Confluent Community License",
    "FSL-1.1-MIT",
])
def test_source_available_licenses_are_blocked(text):
    """
    A field-of-use carve-out - usually "you may not offer this as a service" -
    is not open source. SPDX records these as isOsiApproved: false and Blue
    Oak Council rates none of them.
    """
    detail = classify_license_detailed(text)
    assert detail["status"] == BLOCKED, text
    assert detail["family"] == "source-available", text
    assert detail["obligations"], text


def test_commons_clause_outranks_the_license_it_sits_on():
    """
    SPDX's WITH form carries a real open-source license on its left, so
    resolving only that side grades the string as Apache-2.0. Commons Clause
    is in neither the SPDX license list nor its 84 exceptions, so no lookup
    will catch it - it has to be graded as a restriction.
    """
    assert classify_license("Apache-2.0") == ALLOWED
    assert classify_license("Apache-2.0 WITH Commons Clause") == BLOCKED
    assert classify_license("Apache-2.0 AND Commons Clause") == BLOCKED


def test_boost_is_not_confused_with_business_source():
    """
    SPDX lists BSL-1.0 (Boost) as isOsiApproved: true and BUSL-1.1 (Business
    Source) as false. MariaDB, Sentry, CockroachDB and Terraform all write
    Business Source as "BSL-1.1", so only the version tells them apart.
    """
    assert classify_license("Boost Software License 1.0") == ALLOWED
    assert classify_license("BSL-1.0") == ALLOWED
    assert classify_license("BSL-1.1") == BLOCKED
    assert classify_license("BUSL-1.1") == BLOCKED


def test_source_available_full_text_is_blocked():
    """
    A Commons Clause LICENSE file is the Apache text with a condition bolted
    on, so the Apache full-text signature matches it too. The restriction has
    to be tested first or the file grades ALLOWED.
    """
    text = (
        '"Commons Clause" License Condition v1.0\n\n'
        "The Software is provided to you by the Licensor under the License, "
        "as defined below, subject to the following condition. Without "
        "limiting other conditions in the License, the grant of rights under "
        "the License will not include, and the License does not grant to you, "
        "the right to Sell the Software.\n\n"
        + "Apache License Version 2.0, January 2004. " * 20
    )
    assert classify_license(text) == BLOCKED


def test_a_gpl_text_carries_the_same_obligations_as_the_identifier():
    """
    Identifying a license from its text and identifying it from its id must
    land in the same place, or the verdict depends on which field the package
    happened to fill in.
    """
    text = ("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"
            + "Preamble. " * 100)
    from_text = classify_license_detailed(text)
    assert from_text["status"] == REVIEW
    assert "complete corresponding source" in " ".join(from_text["obligations"])


# ---------------------------------------------------------------------------
# SPDX operator precedence - AND over OR, parentheses over both
# ---------------------------------------------------------------------------

def test_spdx_specification_worked_examples():
    """
    The two examples the SPDX spec prints in its own precedence section, where
    the default operator order is given as "+ WITH AND OR". Each must grade
    the same as its fully-parenthesised equivalent.
    """
    assert (classify_license("LGPL-2.1-only OR BSD-3-Clause AND MIT")
            == classify_license("(BSD-3-Clause AND MIT) OR LGPL-2.1-only"))
    assert (classify_license("MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)")
            == classify_license("MIT AND (BSD-3-Clause OR LGPL-2.1-or-later)"))


def test_parenthesised_or_does_not_disarm_a_top_level_and():
    """
    Asking "is there an OR anywhere?" treats the whole string as a dual
    license, so a restriction ANDed at the top level is dropped. Whichever
    side of the OR the consumer picks, the AND term still applies.
    """
    assert classify_license("(MIT OR Apache-2.0) AND CC-BY-NC-4.0") == BLOCKED
    assert classify_license("(MIT OR Apache-2.0) AND Commons Clause") == BLOCKED
    assert classify_license("(MIT OR Apache-2.0) AND GPL-3.0-only") == REVIEW


def test_parenthesised_or_inside_an_and_takes_the_strictest_branch():
    assert classify_license("MIT AND (GPL-3.0-only OR LGPL-2.1-only)") == REVIEW
    assert classify_license("MIT AND (Apache-2.0 OR BSD-3-Clause)") == ALLOWED


def test_parenthesised_and_inside_an_or_is_still_choosable():
    """The consumer may take the MIT branch and ignore the restricted one."""
    assert classify_license("MIT OR (GPL-3.0-only AND CC-BY-NC-4.0)") == ALLOWED


def test_and_binds_tighter_than_or_without_parentheses():
    """"A AND B OR C" is "(A AND B) OR C", so C alone is selectable."""
    assert classify_license("MIT AND GPL-3.0-only OR BSD-3-Clause") == ALLOWED
    assert classify_license("MIT AND CC-BY-NC-4.0 OR Apache-2.0") == ALLOWED


def test_redundant_parentheses_change_nothing():
    assert classify_license("(MIT)") == ALLOWED
    assert classify_license("((MIT AND GPL-3.0-only))") == REVIEW


def test_spdx_ids_containing_the_operator_words_stay_whole():
    """
    "GPL-2.0-or-later" is one SPDX id, not "GPL-2.0-" OR "-later". Splitting
    on the word "or" tears canonical identifiers in half.
    """
    assert classify_license_detailed("GPL-2.0-or-later")["spdx_id"] \
        == "GPL-2.0-or-later"
    assert classify_license_detailed("LGPL-2.1-or-later")["spdx_id"] \
        == "LGPL-2.1-or-later"


def test_with_exception_is_not_an_operator():
    """
    WITH modifies the license on its left rather than listing a second one, so
    the pair has to be graded together - see the Commons Clause tests.
    """
    assert classify_license("Apache-2.0 WITH LLVM-exception") == ALLOWED
    assert classify_license("GPL-2.0-only WITH Classpath-exception-2.0") == REVIEW


def test_slash_is_a_dual_license():
    """"MIT/Apache-2.0" is how PyPI metadata usually spells a dual license."""
    assert classify_license("MIT/Apache-2.0") == ALLOWED


@pytest.mark.parametrize("text", [
    "(MIT AND Proprietary",         # unbalanced open
    "MIT ) AND Proprietary",        # stray close
    "MIT AND",                      # dangling operator
    "AND Proprietary",              # leading operator
    "() AND Proprietary",           # empty group
])
def test_malformed_expressions_fail_closed(text):
    """Broken input must not silently drop a term."""
    assert classify_license(text) != ALLOWED


def test_malformed_expressions_do_not_raise():
    for text in ["(", ")", "()", "((((", "MIT AND (", "/", ",", "OR OR OR"]:
        assert classify_license(text) in (ALLOWED, REVIEW, BLOCKED, UNKNOWN)


# ---------------------------------------------------------------------------
# Registry loading: downloaded once, cached, and degrades safely
# ---------------------------------------------------------------------------

from aibom_guard import license_checker


@pytest.fixture
def isolated_registry(tmp_path, monkeypatch):
    """Point the registry cache at an empty directory and reset the loader."""
    monkeypatch.setattr(license_checker, "_cache_dir", lambda: tmp_path)
    license_checker._registry.cache_clear()
    yield tmp_path
    license_checker.set_offline(False)
    license_checker._registry.cache_clear()


def test_offline_without_a_cache_never_invents_a_verdict(isolated_registry, caplog):
    """
    With no registry loaded the tool must not guess. It says so, and the
    verdicts it can still reach come from rules that live in code.

    "It says so" is checked on the log, not on stderr: mcp_server calls
    classify_license, so this module has to stay quiet on both std streams and
    report through logging instead.
    """
    license_checker.set_offline(True)

    with caplog.at_level(logging.WARNING, logger="aibom_guard.license_checker"):
        versions = license_checker.registry_versions()
        assert versions["available"] is False
        assert versions["spdx_source"] == "unavailable"

        detail = classify_license_detailed("MIT")
        assert detail["status"] == UNKNOWN
        assert detail["source"] == "registry-unavailable"

    assert "unavailable" in caplog.text


def test_degrading_never_turns_a_restriction_into_a_pass(isolated_registry):
    """
    Losing the registry may cost identification, never safety: a use
    restriction and a copyleft family are both recognised from code alone.
    """
    license_checker.set_offline(True)

    assert classify_license("Apache-2.0 WITH Commons Clause") == BLOCKED
    assert classify_license("BUSL-1.1") == BLOCKED
    assert classify_license("CreativeML OpenRAIL-M") == BLOCKED
    assert classify_license("GPL-3.0-only") == REVIEW
    assert classify_license("LGPL with exceptions") == REVIEW
    # And nothing reaches ALLOWED without the registry to vouch for it.
    for text in ["MIT", "Apache-2.0", "BSD-3-Clause", "CC0-1.0"]:
        assert classify_license(text) != ALLOWED, text


def test_a_cached_registry_is_used_without_the_network(isolated_registry, monkeypatch):
    """Offline is only "do not fetch"; an existing cache still answers."""
    import shutil
    from pathlib import Path

    fixtures = Path(__file__).resolve().parent / "fixtures"
    for name in ("spdx-licenses.json", "blueoak-list.json"):
        shutil.copy(fixtures / name, isolated_registry / name)

    def explode(*args, **kwargs):
        raise AssertionError("offline must not reach the network")

    monkeypatch.setattr("requests.get", explode)
    license_checker.set_offline(True)

    assert license_checker.registry_versions()["spdx_source"] == "cache"
    assert classify_license("MIT") == ALLOWED
    assert classify_license("GPL-3.0-only") == REVIEW


def test_registry_versions_travel_with_the_verdict():
    """
    A license decision is auditable only if the data behind it is named, so
    the loaded list versions have to be reportable.
    """
    versions = license_checker.registry_versions()
    assert set(versions) >= {"spdx_license_list", "spdx_source",
                             "blue_oak_council_list", "blue_oak_source",
                             "available"}
