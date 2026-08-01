"""
test_scanner.py
-----------------------------------
Unit tests for the scanner pipeline wiring.

    python3 -m pytest test_scanner.py -q

scanner.py had no tests at all, which is why modules 2 and 3 could sit
unwired for as long as they did - nothing asserted that their output reaches
score_engine. Every network call is stubbed, so this runs offline.
"""

import json

import pytest

import scanner


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def reqs(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("requests==2.28.0\n", encoding="utf-8")
    return str(path)


@pytest.fixture
def no_side_effects(tmp_path, monkeypatch):
    """Stub out everything that touches the network or the real filesystem."""
    monkeypatch.setattr(scanner, "build_final_sbom", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "explain_results", lambda r: "(stubbed)")
    monkeypatch.setattr(scanner, "get_license_for_package", lambda n: "MIT")
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

def test_parse_requirements_reads_pinned_entries(tmp_path):
    path = tmp_path / "r.txt"
    path.write_text("# comment\n\nrequests==2.28.0\nnumpy == 1.24.0\n",
                    encoding="utf-8")
    assert scanner.parse_requirements(str(path)) == [
        ("requests", "2.28.0"), ("numpy", "1.24.0")]


def test_parse_requirements_skips_unpinned(tmp_path, capsys):
    path = tmp_path / "r.txt"
    path.write_text("requests>=2.0\nflask\nnumpy==1.24.0\n", encoding="utf-8")
    assert scanner.parse_requirements(str(path)) == [("numpy", "1.24.0")]
    assert "Skipping" in capsys.readouterr().out


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
# Module 3 wiring
# ---------------------------------------------------------------------------

def test_recommendation_issues_reach_the_report(reqs, no_side_effects, monkeypatch):
    """
    The whole point of the wiring: a typosquat found by module 3 has to end
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
                                                     monkeypatch, capsys):
    """A PyPI outage must not abort the scan."""
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [CVE])
    monkeypatch.setattr(scanner, "RecommendationEngine",
                        lambda *a, **k: FakeEngine(boom=True))

    report = scanner.run_scan(reqs, explain=False)

    assert len(report) == 1
    assert [i["type"] for i in report[0]["issues"]] == ["cve"]
    assert "WARNING" in capsys.readouterr().out


def test_missing_recommendation_module_warns(reqs, no_side_effects, monkeypatch,
                                             capsys):
    """Absent module 3 must be announced, not silently skipped."""
    monkeypatch.setattr(scanner, "HAS_RECOMMENDATION", False)
    monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])

    scanner.run_scan(reqs, explain=False)

    out = capsys.readouterr().out
    assert "typosquatting" in out and "NOT run" in out


# ---------------------------------------------------------------------------
# Module 2 wiring
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
    # ...and module 2's issue must be categorised, not dumped in unrecognised.
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
    assert data[0]["package"] == "requests"
    assert data[0]["issues"][0]["id"] == "GHSA-x"


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
# Module 1 wiring - AI models in the AIBOM
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
    assert result["score_breakdown"]["malicious"]["issues"] == 2
    assert result["hard_block"] is True


def test_model_scan_failure_returns_none(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("404 not found")

    monkeypatch.setattr(scanner, "check_model", boom)
    assert scanner.scan_model("org/missing") is None
    assert "could not read model" in capsys.readouterr().out


def test_missing_model_checker_is_announced(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "HAS_MODEL_CHECKER", False)
    assert scanner.scan_model("org/model") is None
    assert "unavailable" in capsys.readouterr().out


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
