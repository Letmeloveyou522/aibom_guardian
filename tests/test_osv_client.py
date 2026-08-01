"""
test_osv_client.py
-----------------------------------
Unit tests for osv_client's alias de-duplication.

    python3 -m pytest test_osv_client.py -q

No network: merge_aliased_vulnerabilities() is a pure function over the
already-parsed entries.
"""

import pytest

from osv_client import merge_aliased_vulnerabilities


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
