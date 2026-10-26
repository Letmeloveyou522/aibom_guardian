"""Project boundaries, shared collection and conservative comparisons."""
import copy
import asyncio
import hashlib
import io
import json

import pytest

from aibom_guardian import mcp_server, scanner, license_checker, _scanner_models
from aibom_guardian.reporting import compare_reports, set_scan_scope, project_summary
from aibom_guardian.score_engine import calculate_trust_score


def test_suspicious_requires_review_but_is_not_confirmed_malicious():
    result = calculate_trust_score({"type": "model", "license_status": "ALLOWED",
                                   "issues": [{"type": "suspicious", "severity": "medium"}]})
    assert result["verdict"] == "WARNING"
    assert result["hard_block"] is False
    malicious = calculate_trust_score({"type": "model", "license_status": "ALLOWED",
                                      "issues": [{"type": "malicious", "severity": "medium"}]})
    assert malicious["hard_block"] is True


def test_model_adapter_preserves_suspicion_and_score_direction(monkeypatch):
    monkeypatch.setattr(scanner, "HAS_MODEL_CHECKER", True)
    monkeypatch.setattr(scanner, "check_model", lambda *a, **kw: {
        "model_id": "fixture/model", "license": "mit",
        "pickle_scan": {"status": "OK", "suspicious": ["unknown.call"]},
        "issues": [{"type": "suspicious", "severity": "MEDIUM", "message": "Review unknown.call"}],
    })
    monkeypatch.setattr(_scanner_models, "classify_license_detailed", lambda _: {
        "status": "ALLOWED", "family": "permissive", "reason": "fixture"})
    result = scanner.scan_model("fixture/model", 8)
    assert result["verdict"] == "WARNING"
    assert result["hard_block"] is False
    assert result["trust_score"] == result["risk_score"]


def test_redirected_windows_output_does_not_abort_scan(monkeypatch):
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp949")
    monkeypatch.setattr(scanner.sys, "stdout", stream)
    scanner._configure_cli_logging(False)
    print("Unverified \u2014 check the report", file=stream, flush=True)
    assert b"Unverified" in raw.getvalue()


def test_project_cli_and_mcp_share_results_without_stdout_or_files(tmp_path, monkeypatch, capsys):
    path = tmp_path / "requirements.txt"
    path.write_text("demo==1.0\n-r hidden.txt\n", encoding="utf-8")
    monkeypatch.setenv("AIBOM_GUARDIAN_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setattr(scanner, "resolve_license", lambda *a, **kw: {
        "license": "MIT", "source": "fixture", "version": "1.0", "unverified": False, "error": None})
    monkeypatch.setattr(scanner, "classify_license_detailed", lambda _: {
        "status": "ALLOWED", "spdx_id": "MIT", "family": "permissive", "obligations": []})
    monkeypatch.setattr(scanner, "build_final_sbom", lambda *a: None)
    previous = license_checker._OFFLINE
    via_mcp = mcp_server.scan_project("requirements.txt", direct_only=True, offline=True)
    assert capsys.readouterr().out == ""
    assert license_checker._OFFLINE == previous
    assert sorted(p.name for p in tmp_path.iterdir()) == ["requirements.txt"]
    output = tmp_path / "report.json"
    scanner.run_scan(str(path), transitive=False, offline=True, explain=False, report_path=str(output))
    via_cli = json.loads(output.read_text(encoding="utf-8"))
    for field in ("packages", "models", "unscanned"):
        assert via_cli[field] == via_mcp[field]
    assert via_mcp["packages"][0]["vulnerabilities"] is None
    assert via_mcp["summary"]["vulnerabilities_unverified_count"] == 1
    assert via_mcp["metadata"]["input_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert via_mcp["unscanned"]
    assert via_mcp["metadata"]["scope"]["basis"] == "manifest"
    assert via_mcp["metadata"]["scope"]["installed_inventory"] is False
    license_checker.set_offline(previous)


def test_project_tool_requires_configured_root(tmp_path, monkeypatch):
    monkeypatch.delenv("AIBOM_GUARDIAN_PROJECT_ROOT", raising=False)
    assert mcp_server.scan_project("requirements.txt")["success"] is False
    root = tmp_path / "project"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("secret", encoding="utf-8")
    monkeypatch.setenv("AIBOM_GUARDIAN_PROJECT_ROOT", str(root))
    assert mcp_server.scan_project("../outside.txt")["success"] is False
    assert mcp_server.scan_project(str(tmp_path / "outside.txt"))["success"] is False


def test_monitor_mcp_is_server_configured_and_history_is_readable(tmp_path, monkeypatch):
    from aibom_guardian.monitoring import initialize
    monkeypatch.delenv("AIBOM_GUARDIAN_MONITOR_DB", raising=False)
    assert mcp_server.monitor_history()["success"] is False
    db = tmp_path / "monitor.db"
    initialize(db, {"packages": [{"package": "demo", "version": "1.0", "vulnerabilities": []}]})
    monkeypatch.setenv("AIBOM_GUARDIAN_MONITOR_DB", str(db))
    assert mcp_server.monitor_history()["runs"] == []
    assert mcp_server.monitor_history(100)["success"] is False


def test_candidate_compare_does_not_claim_compatibility(monkeypatch):
    monkeypatch.setattr(mcp_server, "check_package", lambda name, version: {
        "package": name, "version": version, "ecosystem": "PyPI", "scanned": True,
        "vulnerabilities": [{"id": "old"}] if version == "1.0" else []})
    result = mcp_server.compare_package_candidate("demo", "1.0", "2.0")
    assert result["comparison"]["findings"][0]["no_longer_reported"] == ["old"]
    assert result["compatibility_verified"] is False and result["tests_executed"] is False
    assert mcp_server.compare_package_candidate("demo", ">=1", "2.0")["success"] is False


def report(vulnerabilities, **extra):
    return {"packages": [{"ecosystem": "PyPI", "package": "Demo_pkg", "version": "1",
                          "scanned": True, "vulnerabilities": vulnerabilities, **extra}], "unscanned": []}


def test_project_mcp_wire_returns_one_json_document(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
    monkeypatch.setenv("AIBOM_GUARDIAN_PROJECT_ROOT", str(tmp_path))
    payload = {"metadata": {}, "packages": [], "models": [], "unscanned": ["unavailable"]}
    monkeypatch.setattr(mcp_server, "collect_scan", lambda *a, **kw: payload)
    result = asyncio.run(mcp_server.mcp.call_tool("scan_project", {"requirements_path": "requirements.txt"}))
    assert isinstance(result, list) and len(result) == 1
    assert result[0].type == "text"
    document = json.loads(result[0].text)
    assert document["success"] is True
    assert document["summary"]["unscanned_entry_count"] == 1
    assert document["unscanned"] == ["unavailable"]


def test_summary_keeps_allow_advisories_unknown_and_conflicts_distinct():
    data = {"packages": [
        {"package": "a", "direct": True, "verdict": "ALLOW", "vulnerabilities": [{"id": "x"}], "license_status": "ALLOWED"},
        {"package": "b", "direct": False, "verdict": "WARNING", "vulnerabilities": None, "license_status": "UNKNOWN", "license_unverified": True},
        {"package": "c", "direct": False, "verdict": "ALLOW", "vulnerabilities": [], "license_status": "ALLOWED"},
    ], "unscanned": ["a>=2 (dependency conflict: selected a==1; required by b)",
                      "a>=3 (dependency conflict: selected a==1; required by c)"]}
    result = project_summary(data)
    assert result["package_count"] == 3
    assert result["direct_count"] == 1 and result["transitive_count"] == 2
    assert result["packages_with_advisories"] == 1
    assert result["vulnerabilities_unverified_count"] == 1
    assert result["dependency_conflict_entry_count"] == 2
    assert [p["package"] for p in result["attention_packages"]] == ["b", "a"]
    assert result["attention_packages"][0]["advisory_count"] is None
    assert result["attention_packages"][1]["advisory_count"] == 1


def test_comparison_distinguishes_missing_and_verified_empty():
    before = report([{"id": "CVE-fixture"}])
    after = report([])
    after["packages"][0].update(package="demo-pkg", version="2")
    result = compare_reports(before, after)
    assert result["changed"][0]["after"] == "2"
    assert result["findings"][0]["no_longer_reported"] == ["CVE-fixture"]
    for incomplete in (report(None), report([], osv_unverified=True), report([], scanned=False)):
        finding = compare_reports(before, incomplete)["findings"][0]
        assert finding["status"] == "unverified"
        assert "no_longer_reported" not in finding
    after["unscanned"] = ["unresolved dependency"]
    assert compare_reports(before, after)["findings"][0]["status"] == "unverified"


def test_comparison_does_not_claim_removed_or_ambiguous_rows_fixed():
    before = report([{"id": "CVE-fixture"}])
    removed = compare_reports(before, {"packages": [], "unscanned": []})
    assert removed["removed"][0]["status"] == "absent_from_report"
    ambiguous = copy.deepcopy(before)
    ambiguous["packages"] *= 2
    assert compare_reports(before, ambiguous)["findings"][0]["status"] == "unverified"
    assert compare_reports(before, report([{}]))["findings"][0]["status"] == "unverified"
    with pytest.raises(ValueError):
        compare_reports([], before)


@pytest.mark.parametrize("transitive,offline,locked,basis,state", [
    (True, False, False, "registry_candidates", "included"),
    (True, True, False, "manifest", "skipped_offline"),
    (False, False, False, "manifest", "not_requested"),
    (True, True, True, "lockfile", "included"),
    (False, True, True, "lockfile", "not_requested"),
])
def test_scope_distinguishes_candidates_lockfile_and_offline(transitive, offline, locked, basis, state):
    metadata = {"options": {"transitive": transitive, "offline": offline}}
    scope = set_scan_scope(metadata, lockfile=locked)
    assert scope["basis"] == basis
    assert scope["transitive"] == state
    assert scope["installation_verified"] is False


def test_comparison_flags_environment_and_scope_changes():
    before, after = report([]), report([])
    before["metadata"] = {"environment": {"python": "3.11"}, "scope": {"basis": "manifest"}}
    after["metadata"] = {"environment": {"python": "3.13"}, "scope": {"basis": "registry_candidates"}}
    result = compare_reports(before, after)
    assert result["environment_changed"] is True
    assert result["scope_changed"] is True
