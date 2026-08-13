"""
test_osv_client.py
-----------------------------------
Unit tests for osv_client's alias de-duplication and OSV failure contract.

No network: merge helpers and query_vulnerabilities() use mocks.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from aibom_guard.osv_client import (
    _extract_severity,
    merge_aliased_vulnerabilities,
    query_vulnerabilities,
)


def item(vuln_id, severity="medium", aliases=None, detail="something",
         cvss_score=None):
    entry = {
        "type": "cve", "id": vuln_id, "severity": severity,
        "detail": detail, "summary": detail, "aliases": aliases or [],
    }
    if cvss_score is not None:
        entry["cvss_score"] = cvss_score
    return entry


def ids(merged):
    return sorted(m["id"] for m in merged)


# ---------------------------------------------------------------------------
# Core behaviour
# ---------------------------------------------------------------------------

def test_empty_input():
    assert merge_aliased_vulnerabilities([]) == []


def test_unrelated_entries_are_left_alone():
    merged = merge_aliased_vulnerabilities([item("GHSA-a"), item("GHSA-b")])
    assert ids(merged) == ["GHSA-a", "GHSA-b"]


def test_aliased_pair_collapses_to_one():
    """
    OSV returns one entry per database, so a single flaw arrives twice.
    requests 2.28.0 came back as 8 entries for 4 distinct vulnerabilities.
    """
    merged = merge_aliased_vulnerabilities([
        item("GHSA-9hjg-9r4m-mvj7", aliases=["PYSEC-2026-1872"]),
        item("PYSEC-2026-1872", aliases=["GHSA-9hjg-9r4m-mvj7"]),
    ])
    assert len(merged) == 1
    assert merged[0]["merged_count"] == 2


def test_one_sided_alias_still_merges():
    """Only one of the pair needs to name the other."""
    merged = merge_aliased_vulnerabilities([
        item("GHSA-x", aliases=["PYSEC-1"]),
        item("PYSEC-1"),
    ])
    assert len(merged) == 1


def test_alias_relation_is_transitive():
    """A names B, B names C, but A never names C - all three are one flaw."""
    merged = merge_aliased_vulnerabilities([
        item("CVE-2024-1", aliases=["GHSA-x"]),
        item("GHSA-x", aliases=["PYSEC-9"]),
        item("PYSEC-9"),
    ])
    assert len(merged) == 1
    assert merged[0]["merged_count"] == 3


# ---------------------------------------------------------------------------
# Which identifier survives
# ---------------------------------------------------------------------------

def test_cve_id_is_preferred():
    merged = merge_aliased_vulnerabilities([
        item("PYSEC-1", aliases=["CVE-2024-1"]),
        item("CVE-2024-1", aliases=["PYSEC-1"]),
    ])
    assert merged[0]["id"] == "CVE-2024-1"


def test_ghsa_beats_pysec():
    merged = merge_aliased_vulnerabilities([
        item("PYSEC-1", aliases=["GHSA-x"]),
        item("GHSA-x", aliases=["PYSEC-1"]),
    ])
    assert merged[0]["id"] == "GHSA-x"


def test_folded_ids_are_kept_as_aliases():
    """A reader must still find the entry under the id they know."""
    merged = merge_aliased_vulnerabilities([
        item("GHSA-x", aliases=["PYSEC-1"]),
        item("PYSEC-1", aliases=["GHSA-x"]),
    ])
    assert merged[0]["aliases"] == ["PYSEC-1"]


# ---------------------------------------------------------------------------
# Merging must not lose information
# ---------------------------------------------------------------------------

def test_worst_severity_wins():
    merged = merge_aliased_vulnerabilities([
        item("GHSA-x", severity="low", aliases=["PYSEC-1"]),
        item("PYSEC-1", severity="critical", aliases=["GHSA-x"]),
    ])
    assert merged[0]["severity"] == "critical"


def test_highest_cvss_wins():
    """
    The pair GHSA-gc5v / PYSEC-2026-2275 really did report 4.4 and 5.5.
    Taking the first would understate the finding.
    """
    merged = merge_aliased_vulnerabilities([
        item("GHSA-x", aliases=["PYSEC-1"], cvss_score=4.4),
        item("PYSEC-1", aliases=["GHSA-x"], cvss_score=5.5),
    ])
    assert merged[0]["cvss_score"] == 5.5


def test_real_summary_beats_no_description():
    """
    PYSEC entries frequently carry "No description". If such an entry wins
    the id preference, the useful text must still survive.
    """
    merged = merge_aliased_vulnerabilities([
        item("CVE-2024-1", aliases=["GHSA-x"], detail="No description"),
        item("GHSA-x", aliases=["CVE-2024-1"], detail="Proxy header leak"),
    ])
    assert merged[0]["id"] == "CVE-2024-1"        # preference still applies
    assert merged[0]["detail"] == "Proxy header leak"
    assert merged[0]["summary"] == "Proxy header leak"


def test_longer_summary_is_preferred():
    """When both members have real text, keep the more informative one."""
    merged = merge_aliased_vulnerabilities([
        item("CVE-2024-1", aliases=["GHSA-x"], detail="Short note"),
        item(
            "GHSA-x",
            aliases=["CVE-2024-1"],
            detail="Requests does not verify TLS certificates when ...",
        ),
    ])
    assert merged[0]["id"] == "CVE-2024-1"
    assert "TLS certificates" in merged[0]["detail"]


def test_missing_cvss_on_the_winner_is_taken_from_the_alias():
    merged = merge_aliased_vulnerabilities([
        item("CVE-2024-1", aliases=["GHSA-x"]),
        item("GHSA-x", aliases=["CVE-2024-1"], cvss_score=9.8),
    ])
    assert merged[0]["cvss_score"] == 9.8


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

def test_results_are_sorted_most_severe_first():
    merged = merge_aliased_vulnerabilities([
        item("GHSA-low", severity="low"),
        item("GHSA-crit", severity="critical"),
        item("GHSA-med", severity="medium"),
    ])
    assert [m["severity"] for m in merged] == ["critical", "medium", "low"]


def test_order_is_stable_between_runs():
    entries = [item("GHSA-b", severity="high"), item("GHSA-a", severity="high")]
    assert ids(merge_aliased_vulnerabilities(entries)) == \
           ids(merge_aliased_vulnerabilities(list(reversed(entries))))


def test_backward_compatible_keys_survive():
    """scanner, sbom_generator and mcp_server index these directly."""
    merged = merge_aliased_vulnerabilities([item("GHSA-x")])
    for key in ("type", "id", "severity", "summary", "detail"):
        assert key in merged[0]


def test_single_entry_reports_merged_count_one():
    merged = merge_aliased_vulnerabilities([item("GHSA-x")])
    assert merged[0]["merged_count"] == 1
    assert merged[0]["aliases"] == []


@pytest.mark.parametrize("bad", [
    {"id": "GHSA-x"},                              # no severity/aliases keys
    {"id": "GHSA-y", "aliases": None},
])
def test_partial_entries_do_not_raise(bad):
    assert len(merge_aliased_vulnerabilities([bad])) == 1


# ---------------------------------------------------------------------------
# OSV failure is not the same as no vulnerabilities
# ---------------------------------------------------------------------------

def test_query_network_failure_returns_none_not_empty_list():
    """A failed OSV call must not look like 'zero CVEs found'."""
    with patch("aibom_guard.osv_client.requests.post") as post:
        post.side_effect = requests.exceptions.Timeout("timed out")
        result = query_vulnerabilities("requests", "2.28.0")
    assert result is None
    assert result != []


def test_query_http_error_returns_none():
    response = MagicMock()
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("503")
    with patch("aibom_guard.osv_client.requests.post", return_value=response):
        result = query_vulnerabilities("requests", "2.28.0")
    assert result is None


def test_query_invalid_json_returns_none():
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("No JSON")
    with patch("aibom_guard.osv_client.requests.post", return_value=response):
        result = query_vulnerabilities("requests", "2.28.0")
    assert result is None


def test_query_success_with_no_vulns_returns_empty_list():
    """Successful empty result must stay [] so callers can tell it from None."""
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"vulns": []}
    with patch("aibom_guard.osv_client.requests.post", return_value=response):
        result = query_vulnerabilities("some-safe-pkg", "1.0.0")
    assert result == []


def test_query_success_returns_parsed_list():
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "vulns": [{
            "id": "GHSA-test",
            "summary": "example",
            "severity": [{
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }],
            "aliases": [],
        }],
    }
    with patch("aibom_guard.osv_client.requests.post", return_value=response):
        result = query_vulnerabilities("requests", "2.28.0")
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["id"] == "GHSA-test"
    assert result[0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# A silently swallowed exception has to be logged, not dropped
# ---------------------------------------------------------------------------

def test_non_numeric_severity_score_is_logged_not_swallowed_silently(caplog):
    """
    A free-text severity score that is neither CVSS nor float used to hit
    bare ``except ValueError: pass``. It must now leave a debug log trail.
    """
    import logging

    vuln = {
        "severity": [{"type": "OTHER", "score": "not-a-number"}],
        "database_specific": {},
    }
    with caplog.at_level(logging.DEBUG, logger="aibom_guard.osv_client"):
        label, score, vector = _extract_severity(vuln)
    assert label == "unknown"
    assert score is None
    assert vector is None
    assert any("not numeric or CVSS" in rec.message for rec in caplog.records)


# ---------------------------------------------------------------------------
# A merged entry has to keep the title, not the preamble
# ---------------------------------------------------------------------------

def _entry(vuln_id, summary, is_title, aliases=(), severity="medium"):
    return {"type": "cve", "id": vuln_id, "severity": severity,
            "detail": summary, "summary": summary, "is_title": is_title,
            "aliases": sorted(aliases)}


def test_a_title_beats_a_longer_body_when_merging_aliases():
    """
    GHSA entries carry a one-line `summary`; their PYSEC aliases usually carry
    only `details`, a paragraph that opens with background. Ranking by length
    picked the paragraph, so the report showed "Requests is a HTTP library.
    Prior to version 2.33.0, ..." truncated at 240 characters instead of the
    finding itself.
    """
    ghsa = _entry("GHSA-gc5v-m9x4-r6x2",
                  "Requests has Insecure Temp File Reuse in its "
                  "extract_zipped_paths() utility function",
                  is_title=True, aliases=["PYSEC-2026-2275"])
    pysec = _entry("PYSEC-2026-2275",
                   "Requests is a HTTP library. Prior to version 2.33.0, the "
                   "requests.utils.extract_zipped_paths() utility function "
                   "uses a predictable filename when extracting files from "
                   "zip archives into the system temporary directory.",
                   is_title=False, aliases=["GHSA-gc5v-m9x4-r6x2"])

    merged = merge_aliased_vulnerabilities([ghsa, pysec])

    assert len(merged) == 1
    assert merged[0]["summary"].startswith("Requests has Insecure Temp File")


def test_a_body_is_still_used_when_no_alias_has_a_title():
    body = _entry("PYSEC-1", "A long description of the flaw.", is_title=False)
    merged = merge_aliased_vulnerabilities([body])
    assert merged[0]["summary"] == "A long description of the flaw."


def test_real_text_still_beats_the_placeholder():
    placeholder = _entry("GHSA-1", "No description", is_title=False,
                         aliases=["PYSEC-1"])
    real = _entry("PYSEC-1", "Actual description.", is_title=False,
                  aliases=["GHSA-1"])

    merged = merge_aliased_vulnerabilities([placeholder, real])

    assert merged[0]["summary"] == "Actual description."


def test_the_longer_text_wins_between_two_titles():
    short = _entry("GHSA-1", "Short title", is_title=True, aliases=["PYSEC-1"])
    longer = _entry("PYSEC-1", "A rather more specific title", is_title=True,
                    aliases=["GHSA-1"])

    merged = merge_aliased_vulnerabilities([short, longer])

    assert merged[0]["summary"] == "A rather more specific title"
