"""
Tests for SARIF output.

GitHub code scanning rejects a document that does not match the schema, and a
wrong line number puts the annotation on the wrong dependency - both fail
quietly, so they are asserted here.
"""

from __future__ import annotations

import json

import pytest

from aibom_guardian.sarif import build_sarif, write_sarif


def package(name="requests", version="2.28.0", issues=None, **overrides):
    row = {
        "package": name,
        "version": version,
        "line": 3,
        "direct": True,
        "verdict": "WARNING",
        "issues": issues if issues is not None else [],
    }
    row.update(overrides)
    return row


CVE = {"type": "cve", "id": "GHSA-x", "severity": "high",
       "detail": "Proxy header leak"}


def results(report, path="requirements.txt"):
    return build_sarif(report, path)["runs"][0]["results"]


class TestDocumentShape:
    def test_the_envelope_is_sarif_210(self):
        doc = build_sarif([package(issues=[CVE])], "requirements.txt")
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        assert len(doc["runs"]) == 1

    def test_the_driver_names_the_tool_and_its_version(self):
        import aibom_guardian

        driver = build_sarif([], "requirements.txt")["runs"][0]["tool"]["driver"]
        assert driver["name"] == "AIBOM-Guardian"
        assert driver["version"] == aibom_guardian.__version__

    def test_a_clean_scan_is_a_run_with_no_results(self):
        """Not an empty file - "we looked and found nothing" is a valid run."""
        doc = build_sarif([package()], "requirements.txt")
        assert doc["runs"][0]["results"] == []

    def test_every_result_rule_is_declared(self):
        doc = build_sarif([package(issues=[CVE, {"type": "license",
                                                 "severity": "medium",
                                                 "detail": "copyleft"}])],
                          "requirements.txt")
        declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        used = {r["ruleId"] for r in doc["runs"][0]["results"]}
        assert used <= declared

    def test_it_serialises(self, tmp_path):
        out = tmp_path / "out.sarif"
        write_sarif([package(issues=[CVE])], "requirements.txt", str(out))
        assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


class TestLocations:
    def test_a_finding_points_at_the_line_that_caused_it(self):
        [result] = results([package(issues=[CVE], line=7)])
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 7

    def test_the_uri_is_the_scanned_file(self):
        [result] = results([package(issues=[CVE])], "reqs/prod.txt")
        location = result["locations"][0]["physicalLocation"]["artifactLocation"]
        assert location["uri"] == "reqs/prod.txt"

    @pytest.mark.parametrize("line", [0, None])
    def test_a_transitive_package_still_gets_a_valid_line(self, line):
        """SARIF requires startLine >= 1, and 0 makes GitHub drop the result."""
        [result] = results([package(issues=[CVE], line=line, direct=False)])
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


class TestSeverityMapping:
    @pytest.mark.parametrize("severity,level", [
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("unknown", "warning"),
    ])
    def test_severity_becomes_a_sarif_level(self, severity, level):
        [result] = results([package(issues=[{"type": "cve", "severity": severity,
                                             "detail": "x"}])])
        assert result["level"] == level

    def test_an_unrated_finding_is_not_silently_downgraded(self):
        """No severity must not become "note" and disappear into the noise."""
        [result] = results([package(issues=[{"type": "cve", "detail": "x"}])])
        assert result["level"] == "warning"


class TestMessages:
    def test_the_message_names_the_package_and_version(self):
        [result] = results([package(issues=[CVE])])
        assert "requests==2.28.0" in result["message"]["text"]

    def test_a_transitive_package_says_it_was_pulled_in(self):
        [result] = results([package(issues=[CVE], direct=False)])
        assert "pulled in" in result["message"]["text"]

    def test_the_advisory_id_appears(self):
        [result] = results([package(issues=[CVE])])
        assert "GHSA-x" in result["message"]["text"]

    def test_the_id_is_not_repeated_when_the_detail_already_has_it(self):
        issue = {"type": "cve", "id": "GHSA-x", "severity": "high",
                 "detail": "GHSA-x leaks the proxy header"}
        [result] = results([package(issues=[issue])])
        assert result["message"]["text"].count("GHSA-x") == 1


class TestFingerprints:
    def test_the_same_finding_fingerprints_the_same(self):
        first = results([package(issues=[CVE])])[0]
        second = results([package(issues=[CVE])])[0]
        assert first["partialFingerprints"] == second["partialFingerprints"]

    def test_a_different_version_is_a_different_finding(self):
        """Otherwise upgrading looks like the same alert staying open."""
        old = results([package(version="2.28.0", issues=[CVE])])[0]
        new = results([package(version="2.31.0", issues=[CVE])])[0]
        assert old["partialFingerprints"] != new["partialFingerprints"]


class TestScannerIntegration:
    def test_the_cli_writes_the_file(self, tmp_path, monkeypatch):
        from aibom_guardian import scanner

        reqs = tmp_path / "requirements.txt"
        reqs.write_text("requests==2.28.0\n", encoding="utf-8")

        monkeypatch.setattr(scanner, "build_final_sbom", lambda *a, **k: None)
        monkeypatch.setattr(scanner, "explain_results", lambda r: "")
        monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
        monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: None)
        monkeypatch.setattr(scanner, "_requires_dist", lambda n, v: [])
        monkeypatch.setattr(
            scanner, "resolve_license",
            lambda name, version=None, offline=False: {
                "license": "MIT", "source": "pypi:license_expression",
                "version": version, "unverified": False, "error": None})
        monkeypatch.chdir(tmp_path)

        out = tmp_path / "out.sarif"
        scanner.run_scan(str(reqs), explain=False, sarif_path=str(out))

        assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"
