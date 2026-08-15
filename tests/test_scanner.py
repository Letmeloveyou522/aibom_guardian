"""
test_scanner.py
-----------------------------------
Unit tests for the scanner pipeline wiring.

scanner.py had no tests at all, which is why modules 2 and 3 could sit
unwired for as long as they did - nothing asserted that their output reaches
score_engine. Every network call is stubbed, so this runs offline.
"""

import json
import logging

import pytest

from aibom_guard import scanner
from aibom_guard import _requirements


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def reqs(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("requests==2.28.0\n", encoding="utf-8")
    return str(path)


@pytest.fixture
def no_network(monkeypatch):
    """
    Nothing here may reach pypi.org.

    parse_requirements resolves version ranges against the real index, so it
    needs stubbing too - otherwise a test's answer changes the day a new
    release lands.
    """
    monkeypatch.setattr(_requirements, "_pypi_versions",
                        lambda name: ["1.0.0", "2.0.0", "2.5.0"])
    monkeypatch.setattr(_requirements, "_requires_dist", lambda name, version: [])
    return monkeypatch


@pytest.fixture
def no_side_effects(tmp_path, monkeypatch, no_network):
    """Stub out everything that touches the network or the real filesystem."""
    monkeypatch.setattr(scanner, "build_final_sbom", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "explain_results", lambda r: "(stubbed)")
    monkeypatch.setattr(
        scanner, "resolve_license",
        lambda name, version=None, offline=False: {
            "license": "MIT", "source": "pypi:license_expression",
            "version": version, "unverified": False, "error": None,
        })
    monkeypatch.chdir(tmp_path)


class FakeEngine:
    """Stands in for RecommendationEngine."""

    def __init__(self, issues=None, alternatives=None, boom=False):
        self.issues = issues
        self.alternatives = alternatives or []
        self.boom = boom
        self.calls = []

    def analyze_package(self, name, version=None, *, cve_issues=None, **kw):
        self.calls.append((name, version, cve_issues))
        if self.boom:
            raise RuntimeError("PyPI unreachable")
        # Mirrors the real engine: it merges the CVE issues it is handed
        # into its own list and returns the complete set.
        merged = list(cve_issues or [])
        merged.extend(self.issues or [])
        return {"issues": merged, "alternatives": self.alternatives}


CVE = {"type": "cve", "id": "GHSA-x", "severity": "medium",
       "summary": "boom", "detail": "boom", "cvss_score": 5.5}


# ---------------------------------------------------------------------------
# parse_requirements
# ---------------------------------------------------------------------------

def _names(packages):
    return [(p.name, p.version) for p in packages]


def test_parse_requirements_reads_pinned_entries(tmp_path, no_network):
    path = tmp_path / "r.txt"
    path.write_text("# comment\n\nrequests==2.28.0\nnumpy == 1.24.0\n",
                    encoding="utf-8")
    packages, unscanned = scanner.parse_requirements(str(path))
    assert _names(packages) == [("requests", "2.28.0"), ("numpy", "1.24.0")]
    assert all(p.resolved is False for p in packages)
    assert unscanned == []


def test_version_ranges_resolve_to_what_would_be_installed(tmp_path, no_network):
    """
    Real requirements files are not all exact pins. Only reading `==` meant
    this project's own requirements.txt scanned one line out of seven and
    still exited 0 - a gate that checks almost nothing and reports success.
    """
    path = tmp_path / "r.txt"
    path.write_text("requests>=2.0\nflask\nnumpy==1.24.0\ncelery~=2.0\n",
                    encoding="utf-8")

    packages, unscanned = scanner.parse_requirements(str(path))

    assert _names(packages) == [("requests", "2.5.0"), ("flask", "2.5.0"),
                                ("numpy", "1.24.0"), ("celery", "2.5.0")]
    assert unscanned == []
    # The report has to say which versions the file chose and which we did.
    assert [p.resolved for p in packages] == [True, True, False, True]


def test_upper_bounds_are_respected(tmp_path, no_network):
    path = tmp_path / "r.txt"
    path.write_text("requests>=1.0,<2.5\n", encoding="utf-8")
    packages, _ = scanner.parse_requirements(str(path))
    assert _names(packages) == [("requests", "2.0.0")]


def test_extras_and_markers_are_understood(tmp_path, no_network):
    path = tmp_path / "r.txt"
    path.write_text(
        'celery[redis]>=1.0\n'
        'pywin32==306 ; sys_platform == "no-such-platform"\n',
        encoding="utf-8")

    packages, unscanned = scanner.parse_requirements(str(path))

    assert _names(packages) == [("celery", "2.5.0")]
    # A marker that is false here describes a dependency this platform never
    # installs, so it is skipped rather than reported as unscanned.
    assert unscanned == []


@pytest.mark.parametrize("line,reason", [
    ("-r other.txt", "pip directive"),
    ("--index-url https://example.invalid/simple", "pip directive"),
    ("git+https://github.com/psf/requests.git", "URL"),
    ("./local/wheel.whl", "not a valid requirement"),
])
def test_unscannable_lines_are_reported_not_dropped(tmp_path, no_network,
                                                    capsys, line, reason):
    path = tmp_path / "r.txt"
    path.write_text(line + "\n", encoding="utf-8")

    packages, unscanned = scanner.parse_requirements(str(path))

    assert packages == []
    assert unscanned == [line]
    assert "Not scanned" in capsys.readouterr().out


def test_offline_cannot_resolve_a_range_and_says_so(tmp_path, capsys):
    path = tmp_path / "r.txt"
    path.write_text("requests>=2.0\nnumpy==1.24.0\n", encoding="utf-8")

    packages, unscanned = scanner.parse_requirements(str(path), offline=True)

    assert _names(packages) == [("numpy", "1.24.0")]
    assert unscanned == ["requests>=2.0"]
    assert "offline" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# _build_check_result - the score_engine contract
# ---------------------------------------------------------------------------

def test_build_check_result_shape():
    result = scanner._build_check_result("ALLOWED", [CVE])
    assert set(result) == {"type", "license_status", "issues",
                           "model_info", "repository_info"}
    assert result["issues"] == [CVE]


def test_vulns_to_issues_preserves_cvss_score():
    """
    score_engine falls back to the CVSS base score when a severity label is
    missing. Dropping the field here silently disabled that path.
    """
    issues = scanner._vulns_to_issues([
        {"id": "GHSA-x", "severity": "", "summary": "s", "cvss_score": 9.8}])
    assert issues[0]["cvss_score"] == 9.8


def test_vulns_to_issues_preserves_aliases():
    issues = scanner._vulns_to_issues([
        {"id": "GHSA-x", "severity": "high", "summary": "s",
         "aliases": ["PYSEC-1"]}])
    assert issues[0]["aliases"] == ["PYSEC-1"]


# ---------------------------------------------------------------------------
# recommendation wiring
# ---------------------------------------------------------------------------

def test_recommendation_issues_reach_the_report(reqs, no_side_effects, monkeypatch):
    """
    The whole point of the wiring: a typosquat found by recommendation has to
    up in the report and in the score, not just in examples/demo_module3.py.
    """
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    engine = FakeEngine(issues=[{"type": "typosquatting",
                                 "detail": "looks like 'requests'"}],
                        alternatives=[{"target": "requests",
                                       "confidence": "confirmed",
                                       "reason": "fix the typo"}])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: engine)

    report = scanner.run_scan(reqs, explain=False)

    assert [i["type"] for i in report[0]["issues"]] == ["typosquatting"]
    assert report[0]["alternatives"][0]["target"] == "requests"
    assert report[0]["score_breakdown"]["typosquatting"]["deduction"] > 0
    assert report[0]["trust_score"] < 100


def test_cve_issues_are_not_double_counted(reqs, no_side_effects, monkeypatch):
    """
    analyze_package() merges the CVEs it is handed into its return value.
    Appending `vulns` again would deduct twice for one vulnerability.
    """
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [CVE])
    engine = FakeEngine()
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: engine)

    report = scanner.run_scan(reqs, explain=False)

    cve_ids = [i["id"] for i in report[0]["issues"] if i["type"] == "cve"]
    assert cve_ids == ["GHSA-x"], "the CVE must appear exactly once"
    assert report[0]["score_breakdown"]["cve"]["issues"] == 1


def test_recommendation_failure_degrades_to_cve_only(reqs, no_side_effects,
                                                     monkeypatch, caplog):
    """A PyPI outage must not abort the scan."""
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [CVE])
    monkeypatch.setattr(scanner, "RecommendationEngine",
                        lambda *a, **k: FakeEngine(boom=True))

    with caplog.at_level(logging.WARNING, logger="aibom_guard.scanner"):
        report = scanner.run_scan(reqs, explain=False)

    assert len(report) == 1
    assert [i["type"] for i in report[0]["issues"]] == ["cve"]
    assert "recommendation engine failed" in caplog.text


def test_missing_recommendation_module_warns(reqs, no_side_effects, monkeypatch,
                                             capsys):
    """An absent recommendation module must be announced, not silently skipped."""
    monkeypatch.setattr(scanner, "HAS_RECOMMENDATION", False)
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])

    scanner.run_scan(reqs, explain=False)

    out = capsys.readouterr().out
    assert "typosquatting" in out and "NOT run" in out


# ---------------------------------------------------------------------------
# repository_checker wiring
# ---------------------------------------------------------------------------

def test_supply_chain_is_off_by_default(reqs, no_side_effects, monkeypatch):
    called = []
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())
    monkeypatch.setattr(scanner, "check_repository",
                        lambda *a, **k: called.append(a) or {})

    report = scanner.run_scan(reqs, explain=False)

    assert called == []
    assert "supply_chain" not in report[0]


def test_supply_chain_result_reaches_score_engine(reqs, no_side_effects,
                                                  monkeypatch):
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())
    monkeypatch.setattr(scanner, "check_repository", lambda *a, **k: {
        "trust_score": 20, "verdict": "BLOCK", "openssf_score": 2.1,
        "github_repository": "psf/requests",
        "issues": [{"type": "signature", "severity": "medium",
                    "detail": "no signature found"}],
    })

    report = scanner.run_scan(reqs, supply_chain=True, explain=False)

    assert report[0]["supply_chain"]["trust_score"] == 20
    # A low repository trust must pull the package score down...
    assert report[0]["score_breakdown"]["_summary"]["repository_trust"] == 20
    assert report[0]["trust_score"] < 100
    # ...and its issue must be categorised, not dumped in unrecognised.
    assert report[0]["score_breakdown"]["provenance"]["issues"] == 1
    assert "unrecognised" not in report[0]["score_breakdown"]


def test_supply_chain_failure_does_not_abort(reqs, no_side_effects, monkeypatch):
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    def boom(*a, **k):
        raise RuntimeError("GitHub rate limited")

    monkeypatch.setattr(scanner, "check_repository", boom)
    report = scanner.run_scan(reqs, supply_chain=True, explain=False)
    assert len(report) == 1
    assert "supply_chain" not in report[0]


# ---------------------------------------------------------------------------
# Offline mode - "did not look" is not "clean"
# ---------------------------------------------------------------------------

def test_offline_does_not_report_a_clean_allow(reqs, no_side_effects, monkeypatch):
    """
    Nothing was inspected offline, so a confident ALLOW would be a lie.
    score_engine sees issues=None, drops confidence and returns WARNING.
    """
    def fail(*a, **k):
        raise AssertionError("offline mode must not touch the network")

    monkeypatch.setattr(scanner, "query_vulnerabilities", fail)
    monkeypatch.setattr(scanner, "check_repository", fail)

    report = scanner.run_scan(reqs, offline=True, explain=False)

    assert report[0]["verdict"] == "WARNING"
    assert report[0]["scanned"] is False
    assert report[0]["confidence"] < 0.7


def test_online_scan_with_no_findings_is_allowed(reqs, no_side_effects, monkeypatch):
    """The mirror case: we did look, and there was nothing."""
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    report = scanner.run_scan(reqs, explain=False)

    assert report[0]["scanned"] is True
    assert report[0]["verdict"] == "ALLOW"
    assert report[0]["trust_score"] == 100


# ---------------------------------------------------------------------------
# Report / CLI
# ---------------------------------------------------------------------------

def test_report_is_written_and_json_serialisable(reqs, no_side_effects,
                                                 monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [CVE])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    scanner.run_scan(reqs, explain=False, report_path="out.json")

    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert set(data) == {"packages", "models", "unscanned"}
    assert data["packages"][0]["package"] == "requests"
    assert data["packages"][0]["issues"][0]["id"] == "GHSA-x"
    assert data["models"] == []
    assert data["unscanned"] == []


def test_empty_requirements_returns_nothing(tmp_path, no_side_effects):
    path = tmp_path / "empty.txt"
    path.write_text("# nothing here\n", encoding="utf-8")
    assert scanner.run_scan(str(path), explain=False) == []


def test_cli_exit_code_2_on_block(reqs, no_side_effects, monkeypatch):
    """So the scanner can gate a CI pipeline."""
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [
        {"type": "cve", "id": "GHSA-bad", "severity": "critical",
         "summary": "rce", "detail": "rce"}])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    assert scanner.main([reqs, "--no-explain"]) == 2


def test_cli_exit_code_0_when_clean(reqs, no_side_effects, monkeypatch):
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())
    assert scanner.main([reqs, "--no-explain"]) == 0


def test_cli_exit_code_1_on_missing_file(no_side_effects):
    assert scanner.main(["no-such-file.txt", "--no-explain"]) == 1


# ---------------------------------------------------------------------------
# model_checker wiring - AI models in the AIBOM
# ---------------------------------------------------------------------------

MODEL_REPORT = {
    "model_id": "CompVis/stable-diffusion-v1-4",
    "commit_sha": "133a221b",
    "license": "creativeml-openrail-m",
    "pipeline": "text-to-image",
    "file_formats": {"safetensors": [], "pickle": [{"path": "m.bin"}],
                     "has_safetensors": False, "pickle_only": True},
    "model_card": {"present": True, "completeness": 60,
                   "is_unedited_template": False},
    "trust_remote_code": False,
    "external_code_repos": [],
    "pickle_scan": {"status": "SKIPPED"},
    "issues": [{"type": "pickle_only", "severity": "HIGH",
                "message": "no safetensors weights"}],
}


def test_ai_license_is_graded_not_passed_through(reqs, no_side_effects, monkeypatch):
    """
    The whole point of an AIBOM: an OpenRAIL model must not slip through as
    UNKNOWN. The package path would never see this license.
    """
    monkeypatch.setattr(scanner, "check_model", lambda ref, **k: dict(MODEL_REPORT))
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    result = scanner.scan_model("CompVis/stable-diffusion-v1-4")

    assert result["license_status"] == "BLOCKED"
    assert result["license_family"] == "ai-behavioural"
    assert result["verdict"] == "BLOCK"
    assert result["hard_block"] is True


def test_llama_community_license_is_review_not_allowed(monkeypatch):
    monkeypatch.setattr(scanner, "check_model",
                        lambda ref, **k: dict(MODEL_REPORT, license="llama3.1"))
    result = scanner.scan_model("meta-llama/Llama-3.1-8B")
    assert result["license_status"] == "REVIEW"
    assert result["license_family"] == "ai-community"
    assert result["verdict"] != "ALLOW"


def test_model_findings_are_mapped_onto_protocol_categories(monkeypatch):
    """
    model_checker uses its own issue types. An unmapped one must surface as
    `unrecognised` rather than vanish from the score.
    """
    monkeypatch.setattr(scanner, "check_model", lambda ref, **k: dict(
        MODEL_REPORT, issues=[
            {"type": "malicious", "severity": "HIGH", "message": "eval in pickle"},
            {"type": "remote_code", "severity": "HIGH", "message": "auto_map"},
        ]))
    result = scanner.scan_model("org/model")
    assert result["score_breakdown"]["malicious"]["issues"] == 1
    assert result["score_breakdown"]["provenance"]["issues"] == 1
    assert result["hard_block"] is True


def test_remote_code_maps_to_provenance_not_malicious(monkeypatch):
    """trust_remote_code/auto_map alone must not hard-block as confirmed malware."""
    monkeypatch.setattr(scanner, "check_model", lambda ref, **k: dict(
        MODEL_REPORT,
        license="apache-2.0",
        issues=[
            {"type": "remote_code", "severity": "HIGH", "message": "auto_map present"},
        ]))
    result = scanner.scan_model("org/model")
    assert result["score_breakdown"]["malicious"]["issues"] == 0
    assert result["score_breakdown"]["provenance"]["issues"] == 1
    assert result["hard_block"] is False


# These two assert on the log rather than on stdout. mcp_server.check_model
# calls scan_model, and on stdio MCP stdout carries the JSON-RPC stream, so a
# print here corrupts the protocol - see tests/test_mcp_stdout_is_clean.py.
# The requirement is unchanged: the failure still has to be announced.


def test_model_scan_failure_is_reported(monkeypatch, caplog):
    def boom(*a, **k):
        raise RuntimeError("404 not found")

    monkeypatch.setattr(scanner, "check_model", boom)
    with caplog.at_level(logging.ERROR, logger="aibom_guard.scanner"):
        assert scanner.scan_model("org/missing") is None
    assert "could not read model" in caplog.text
    assert "404 not found" in caplog.text


def test_missing_model_checker_is_announced(monkeypatch, caplog):
    monkeypatch.setattr(scanner, "HAS_MODEL_CHECKER", False)
    with caplog.at_level(logging.WARNING, logger="aibom_guard.scanner"):
        assert scanner.scan_model("org/model") is None
    assert "unavailable" in caplog.text


def test_models_reach_the_sbom_writer(reqs, no_side_effects, monkeypatch):
    captured = {}

    def fake_sbom(reqs_path, report, out, model_reports=None):
        captured["models"] = model_reports

    monkeypatch.setattr(scanner, "build_final_sbom", fake_sbom)
    monkeypatch.setattr(scanner, "check_model", lambda ref, **k: dict(MODEL_REPORT))
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    scanner.run_scan(reqs, explain=False, models=["CompVis/stable-diffusion-v1-4"])

    assert len(captured["models"]) == 1
    assert captured["models"][0]["model_id"] == "CompVis/stable-diffusion-v1-4"


def test_a_blocked_model_fails_the_build(reqs, no_side_effects, monkeypatch):
    """A BLOCK model must fail CI exactly like a BLOCK package."""
    monkeypatch.setattr(scanner, "check_model", lambda ref, **k: dict(MODEL_REPORT))
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    assert scanner.main([reqs, "--no-explain", "--model", "org/sd"]) == 2


def test_offline_skips_models(reqs, no_side_effects, monkeypatch, capsys):
    def fail(*a, **k):
        raise AssertionError("offline must not fetch a model")

    monkeypatch.setattr(scanner, "check_model", fail)
    scanner.run_scan(reqs, offline=True, explain=False, models=["org/model"])
    assert "Offline" in capsys.readouterr().out


def test_model_findings_are_not_double_counted(monkeypatch):
    """
    score_engine harvests issues from `model_info` as well as from the
    top-level list. Passing the raw report as model_info counted every
    model finding twice.
    """
    monkeypatch.setattr(scanner, "check_model", lambda ref, **k: dict(
        MODEL_REPORT, issues=[
            {"type": "malicious", "severity": "HIGH", "message": "eval in pickle"}]))
    result = scanner.scan_model("org/model")
    assert result["score_breakdown"]["malicious"]["issues"] == 1


# ---------------------------------------------------------------------------
# Supply-chain surfacing (merged from yelin0726)
# ---------------------------------------------------------------------------

FULL_SUPPLY = {
    "trust_score": 65, "verdict": "WARNING", "openssf_score": 8.2,
    "github_repository": "psf/requests", "github_star": 54200,
    "last_commit": "2026-07-27", "signature": False, "provenance": False,
    "issues": [{"type": "signature", "severity": "medium",
                "detail": "no signature found"}],
}


def _wire(monkeypatch, supply=None):
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())
    if supply is not None:
        monkeypatch.setattr(scanner, "check_repository", lambda *a, **k: supply)


def test_supply_chain_summary_keeps_the_evidence_fields(reqs, no_side_effects,
                                                        monkeypatch):
    """
    OpenSSF score, stars, last commit and signature status are what a
    reviewer acts on; summarising them away leaves only a bare verdict.
    """
    _wire(monkeypatch, FULL_SUPPLY)
    report = scanner.run_scan(reqs, supply_chain=True, explain=False)
    supply = report[0]["supply_chain"]

    assert supply["openssf_score"] == 8.2
    assert supply["github_star"] == 54200
    assert supply["last_commit"] == "2026-07-27"
    assert supply["signature"] is False
    assert supply["provenance"] is False


def test_table_gains_supply_chain_columns_only_when_collected(reqs,
                                                              no_side_effects,
                                                              monkeypatch, capsys):
    _wire(monkeypatch)
    scanner.run_scan(reqs, explain=False)
    assert "OpenSSF" not in capsys.readouterr().out

    _wire(monkeypatch, FULL_SUPPLY)
    scanner.run_scan(reqs, supply_chain=True, explain=False)
    out = capsys.readouterr().out
    assert "OpenSSF" in out and "Signed" in out


# ---------------------------------------------------------------------------
# OSV None contract (Task A -> Task D)
# ---------------------------------------------------------------------------

def test_osv_none_passes_issues_none_to_score_engine(reqs, no_side_effects,
                                                      monkeypatch):
    """OSV failure must not be scored as a clean CVE-free package."""
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: None)
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    report = scanner.run_scan(reqs, explain=False)

    entry = report[0]
    assert entry["osv_unverified"] is True
    assert entry["vulnerabilities"] is None
    assert entry["scanned"] is False
    assert entry["verdict"] == "WARNING"
    assert entry["confidence"] < 0.7
    assert any(i.get("type") == "unverified" for i in entry["issues"])


def test_osv_none_is_announced_in_terminal(reqs, no_side_effects, monkeypatch, capsys):
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: None)
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    scanner.run_scan(reqs, explain=False)
    out = capsys.readouterr().out
    assert "OSV lookup failed" in out
    assert "unverified" in out.lower()


def test_osv_empty_list_is_still_a_successful_scan(reqs, no_side_effects, monkeypatch):
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    report = scanner.run_scan(reqs, explain=False)

    entry = report[0]
    assert entry["osv_unverified"] is False
    assert entry["vulnerabilities"] == []
    assert entry["scanned"] is True
    assert entry["verdict"] == "ALLOW"


def test_unscanned_lines_are_saved_in_report(reqs, no_side_effects, monkeypatch, tmp_path):
    reqs_path = tmp_path / "mixed.txt"
    reqs_path.write_text("requests==2.28.0\n-r base.txt\n./wheel.whl\n",
                         encoding="utf-8")
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    scanner.run_scan(str(reqs_path), explain=False, report_path="out.json")

    data = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert data["unscanned"] == ["-r base.txt", "./wheel.whl"]


def test_the_report_says_which_versions_it_chose(reqs, no_side_effects,
                                                 monkeypatch, tmp_path):
    reqs_path = tmp_path / "ranged.txt"
    reqs_path.write_text("requests==2.28.0\nflask>=1.0\n", encoding="utf-8")
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    report = scanner.run_scan(str(reqs_path), explain=False)

    pinned, resolved = report[0], report[1]
    assert pinned["version_resolved"] is False
    assert pinned["requirement"] == "==2.28.0"
    assert resolved["version_resolved"] is True
    assert resolved["requirement"] == ">=1.0"


# ---------------------------------------------------------------------------
# Exit codes - a gate that reports success while checking nothing
# ---------------------------------------------------------------------------

def test_a_block_always_fails():
    report = [{"verdict": "ALLOW"}, {"verdict": "BLOCK"}]
    for fail_on in ("block", "warning"):
        assert scanner.decide_exit_code(report, [], fail_on) == scanner.EXIT_BLOCK


def test_a_clean_scan_exits_zero():
    report = [{"verdict": "ALLOW"}, {"verdict": "ALLOW"}]
    assert scanner.decide_exit_code(report, []) == scanner.EXIT_CLEAN


def test_warnings_no_longer_pass_as_clean():
    """
    The old rule was `2 if any BLOCK else 0`, which disagreed with the
    documented contract that 0 means everything is ALLOW. A failed OSV lookup,
    a package that does not exist and an unreadable license all exited 0.
    """
    report = [{"verdict": "ALLOW"}, {"verdict": "WARNING"}]
    assert scanner.decide_exit_code(report, []) == scanner.EXIT_NOT_CLEAN
    assert scanner.decide_exit_code(report, [], "block") == scanner.EXIT_CLEAN


def test_unscanned_lines_make_the_scan_not_clean():
    """Coverage is part of the result: six of seven lines skipped is not a pass."""
    report = [{"verdict": "ALLOW"}]
    assert scanner.decide_exit_code(report, ["flask"]) == scanner.EXIT_NOT_CLEAN
    assert scanner.decide_exit_code(report, []) == scanner.EXIT_CLEAN


def test_fail_on_never_still_reports_a_block():
    """--fail-on never suppresses the gate, not the finding."""
    assert scanner.decide_exit_code([{"verdict": "BLOCK"}], [], "never") \
        == scanner.EXIT_BLOCK
    assert scanner.decide_exit_code([{"verdict": "WARNING"}], ["x"], "never") \
        == scanner.EXIT_CLEAN


def test_run_scan_carries_the_unscanned_lines_to_the_exit_code(
        reqs, no_side_effects, monkeypatch, tmp_path):
    reqs_path = tmp_path / "mixed.txt"
    reqs_path.write_text("requests==2.28.0\n-r base.txt\n", encoding="utf-8")
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    report = scanner.run_scan(str(reqs_path), explain=False)

    assert report.unscanned == ["-r base.txt"]
    assert scanner.decide_exit_code(report, report.unscanned) \
        == scanner.EXIT_NOT_CLEAN


# ---------------------------------------------------------------------------
# License resolution - the pinned release is the source of record
# ---------------------------------------------------------------------------

class FakeResponse:
    """Stands in for a requests.Response from the PyPI release endpoint."""

    def __init__(self, payload=None, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        if self.payload is None:
            raise ValueError("no json")
        return self.payload


@pytest.fixture(autouse=True)
def clear_release_cache():
    """resolve_license memoises per (package, version) for the process."""
    _requirements._RELEASE_CACHE.clear()
    yield
    _requirements._RELEASE_CACHE.clear()


def _fake_pypi(monkeypatch, info, status_code=200):
    """Point the release lookup at a canned PyPI payload."""
    class FakeSession:
        def get(self, url, timeout=None):
            return FakeResponse({"info": info}, status_code)

    monkeypatch.setattr(_requirements, "_PYPI_SESSION", FakeSession())


def test_license_comes_from_the_pinned_release_not_the_installed_copy(monkeypatch):
    """
    chardet 5.2.0 is LGPL-2.1 and chardet 7.5.1 is 0BSD. Reading whatever the
    environment happens to hold reports the wrong terms for a pinned
    dependency, and the copyleft obligation is simply missed.
    """
    _fake_pypi(monkeypatch, {"license": "LGPL-2.1-only"})
    monkeypatch.setattr(scanner, "_installed_license",
                        lambda name: ("0BSD", "license", "7.5.1"))

    result = scanner.resolve_license("chardet", "5.2.0")

    assert result["license"] == "LGPL-2.1-only"
    assert result["source"] == "pypi:license"
    assert result["version"] == "5.2.0"
    assert result["unverified"] is False


def test_a_package_that_is_not_installed_still_resolves(monkeypatch):
    """
    Before this, anything absent from the environment came back
    NOT_INSTALLED and graded UNKNOWN - so scanning a requirements file on a
    clean machine identified nothing at all.
    """
    _fake_pypi(monkeypatch, {"license": "GNU General Public License v2 (GPLv2)"})
    monkeypatch.setattr(scanner, "_installed_license",
                        lambda name: ("NOT_INSTALLED", "", None))

    result = scanner.resolve_license("mysqlclient", "2.2.4")

    assert result["source"] == "pypi:license"
    assert result["unverified"] is False


def test_pypi_failure_falls_back_but_says_so(monkeypatch):
    """A fallback that is not announced is indistinguishable from an answer."""
    _fake_pypi(monkeypatch, None, status_code=503)
    monkeypatch.setattr(scanner, "_installed_license",
                        lambda name: ("MIT", "license", "9.9.9"))

    result = scanner.resolve_license("somepkg", "1.0.0")

    assert result["source"] == "installed:license"
    assert result["unverified"] is True
    assert "503" in result["error"]


def test_offline_never_calls_pypi(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("offline scan must not reach the network")

    monkeypatch.setattr(scanner, "_pypi_release_license", explode)
    monkeypatch.setattr(scanner, "_installed_license",
                        lambda name: ("MIT", "license", "1.0.0"))

    result = scanner.resolve_license("somepkg", "1.0.0", offline=True)

    assert result["license"] == "MIT"
    assert result["error"] == "offline"


def test_installed_copy_is_trusted_only_when_it_is_the_pinned_version(monkeypatch):
    monkeypatch.setattr(scanner, "_installed_license",
                        lambda name: ("MIT", "license", "1.0.0"))

    same = scanner.resolve_license("somepkg", "1.0.0", offline=True)
    other = scanner.resolve_license("somepkg", "2.0.0", offline=True)

    assert same["unverified"] is False
    assert other["unverified"] is True


def test_the_field_that_identifies_the_license_wins(monkeypatch):
    """
    psycopg2 publishes License: "LGPL with exceptions" next to the classifier
    "GNU Lesser General Public License v3 (LGPLv3)". Taking fields in a fixed
    order throws away whichever one happens to be resolvable, so each is
    graded and the one that yields an SPDX id is used.
    """
    _fake_pypi(monkeypatch, {
        "license": "LGPL with exceptions",
        "classifiers": [
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        ],
    })

    result = scanner.resolve_license("psycopg2", "2.9.9")

    assert result["source"] == "pypi:classifier"


def test_an_unverified_license_lowers_confidence(reqs, no_side_effects, monkeypatch):
    """
    Same contract as the OSV failure marker: evidence we could not gather is
    recorded as `unverified` so score_engine lowers confidence, rather than
    passing another version's terms off as the answer.
    """
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())
    monkeypatch.setattr(
        scanner, "resolve_license",
        lambda name, version=None, offline=False: {
            "license": "MIT", "source": "installed:license",
            "version": "9.9.9", "unverified": True, "error": "http 503",
        })

    report = scanner.run_scan(reqs, explain=False)

    entry = report[0]
    assert entry["license_unverified"] is True
    assert entry["license_source"] == "installed:license"
    assert any(i["type"] == "unverified" for i in entry["issues"])
    assert entry["confidence"] < 1.0


def test_the_report_carries_the_licence_obligations(reqs, no_side_effects, monkeypatch):
    """"REVIEW" alone is not an instruction; the duty has to travel with it."""
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())
    monkeypatch.setattr(
        scanner, "resolve_license",
        lambda name, version=None, offline=False: {
            "license": "GPL-3.0-only", "source": "pypi:license_expression",
            "version": version, "unverified": False, "error": None,
        })

    entry = scanner.run_scan(reqs, explain=False)[0]

    assert entry["license_status"] == "REVIEW"
    assert entry["license_spdx_id"] == "GPL-3.0-only"
    assert entry["license_obligations"]


def test_a_byte_order_mark_does_not_break_the_first_line(tmp_path, no_network):
    """
    A requirements.txt saved by Notepad starts with a BOM. Reading it as plain
    utf-8 glues \ufeff to the first requirement, so the first line - and only
    the first - fails to parse.
    """
    path = tmp_path / "r.txt"
    path.write_bytes("\ufeffrequests==2.28.0\nnumpy==1.24.0\n".encode("utf-8"))

    packages, unscanned = scanner.parse_requirements(str(path))

    assert _names(packages) == [("requests", "2.28.0"), ("numpy", "1.24.0")]
    assert unscanned == []


def test_releases_this_interpreter_cannot_install_are_not_chosen(monkeypatch):
    """
    pytest 9 needs Python 3.10. Resolving `pytest>=8.0` to it on 3.9 would
    scan a release pip refuses to install - the wrong package entirely.
    """
    releases = {
        "8.3.5": [{"filename": "a.whl", "requires_python": ">=3.8"}],
        "9.1.1": [{"filename": "b.whl", "requires_python": ">=3.10"}],
    }

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"releases": releases}

    class FakeSession:
        def get(self, url, timeout=None):
            return FakeResponse()

    monkeypatch.setattr(_requirements, "_PYPI_SESSION", FakeSession())

    class Fake39:
        version_info = (3, 9, 18)

    monkeypatch.setattr(_requirements, "sys", Fake39)
    _requirements._RELEASE_CACHE.clear()
    assert scanner._resolve_specifier("pytest", ">=8.0") == "8.3.5"

    monkeypatch.undo()
    _requirements._RELEASE_CACHE.clear()
    monkeypatch.setattr(_requirements, "_PYPI_SESSION", FakeSession())
    assert scanner._resolve_specifier("pytest", ">=8.0") == "9.1.1"
    _requirements._RELEASE_CACHE.clear()


def test_a_bare_name_is_not_reported_as_a_pin(reqs, no_side_effects, monkeypatch,
                                              tmp_path):
    """
    `flask` with no specifier resolves to a version, but the file never named
    one. Reporting `requirement: "==3.1.3"` would claim a pin that does not
    exist in the project.
    """
    path = tmp_path / "r.txt"
    path.write_text("flask\n", encoding="utf-8")
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
    monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: FakeEngine())

    entry = scanner.run_scan(str(path), explain=False)[0]

    assert entry["requirement"] == "(any)"
    assert entry["version_resolved"] is True


def test_the_same_project_spelled_differently_is_one_row(tmp_path, no_network):
    """PEP 503: Django, django and DJANGO are one project, not three."""
    path = tmp_path / "r.txt"
    path.write_text("Django==2.0.0\ndjango==2.0.0\nDJANGO==2.0.0\n"
                    "my_pkg==1.0.0\nmy-pkg==1.0.0\n", encoding="utf-8")

    packages, _ = scanner.parse_requirements(str(path))

    assert len(packages) == 2
