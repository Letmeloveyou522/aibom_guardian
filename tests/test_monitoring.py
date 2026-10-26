import json
import sqlite3

import pytest

from aibom_guardian.monitoring import initialize, check_once, history


def report(ids=(), unverified=False):
    return {"metadata": {"scope": {"basis": "registry_candidates"}}, "packages": [
        {"package": "Demo_Pkg", "version": "1.0", "ecosystem": "PyPI", "direct": True,
         "vulnerabilities": [{"id": i} for i in ids], "osv_unverified": unverified}],
        "models": [], "unscanned": []}


def test_monitor_changes_failures_recovery_and_dedup(tmp_path):
    db = tmp_path / "monitor.db"
    initialize(db, report(["old"]))
    calls = []

    def query(name, version, ecosystem):
        calls.append((name, version, ecosystem))
        return [{"id": "old"}, {"id": "new"}]

    first = check_once(db, package_query=query)
    assert first["events"][0]["type"] == "new_advisories"
    assert first["events"][0]["ids"] == ["new"]
    assert calls == [("demo-pkg", "1.0", "PyPI")]
    assert check_once(db, package_query=query)["events"] == []
    assert check_once(db, package_query=lambda *a, **kw: None)["events"][0]["type"] == "lookup_failed"
    failed = check_once(db, package_query=lambda *a, **kw: None)
    assert failed["events"] == [] and failed["complete"] is False
    recovered = check_once(db, package_query=query)
    assert [e["type"] for e in recovered["events"]] == ["lookup_recovered"]
    absent = check_once(db, package_query=lambda *a, **kw: [])
    assert absent["events"][0]["type"] == "no_longer_reported"
    assert absent["events"][0]["ids"] == ["new", "old"]
    assert len(history(db)["runs"]) == 5


def test_unknown_baseline_not_classified_as_new_and_no_reset(tmp_path):
    db = tmp_path / "monitor.db"
    initialize(db, report(unverified=True))
    with pytest.raises(ValueError):
        initialize(db, report())
    result = check_once(db, package_query=lambda *a, **kw: [{"id": "known"}])
    assert result["events"][0]["type"] == "baseline_verified"
    assert result["external_notifications_sent"] is False


def test_partial_scan_and_bad_response_remain_incomplete(tmp_path):
    db = tmp_path / "monitor.db"
    baseline = report()
    baseline["unscanned"] = ["conflict"]
    initialize(db, baseline)
    result = check_once(db, package_query=lambda *a, **kw: [{}])
    assert not result["complete"]
    assert result["baseline_unscanned"] == ["conflict"]
    assert result["lookup_failures"]
    assert not check_once(db, package_query=lambda *a, **kw: [])["complete"]


def test_model_pinned_metadata_change_and_failure(tmp_path):
    db = tmp_path / "monitor.db"
    model = {"model_id": "org/model", "commit_sha": "a" * 40, "license": "mit", "files": ["x.bin"]}
    initialize(db, {"packages": [], "models": [model]})
    calls = []

    def query(ref, **kwargs):
        calls.append(ref)
        return {**model, "license": "apache-2.0"}

    result = check_once(db, model_query=query)
    assert calls == ["org/model@" + "a" * 40]
    assert result["events"][0]["field"] == "license"
    assert check_once(db, model_query=query)["events"] == []
    result = check_once(db, model_query=lambda *a, **kw: {**model, "commit_sha": "b" * 40})
    assert result["events"][0]["type"] == "lookup_failed"


def test_explicit_mutable_model_tracking_records_commit_change(tmp_path):
    db = tmp_path / "monitor.db"
    model = {"model_id": "org/model", "commit_sha": "a" * 40, "requested_revision": "main"}
    initialize(db, {"packages": [], "models": [model]}, track_model_refs=True)
    def query(ref, **kwargs):
        assert ref == "org/model@main"
        return {**model, "commit_sha": "b" * 40}
    result = check_once(db, model_query=query)
    assert result["events"][0]["field"] == "commit_sha"
    assert check_once(db, model_query=query)["events"] == []


@pytest.mark.parametrize("version", ["^1.0", "1.*", "", None, ">=1"])
def test_ranges_are_not_monitor_identities(tmp_path, version):
    data = report()
    data["packages"][0]["version"] = version
    with pytest.raises(ValueError):
        initialize(tmp_path / "db", data)


def test_history_is_bounded_and_secrets_not_in_errors(tmp_path):
    db = tmp_path / "monitor.db"
    initialize(db, report())

    def fail(*a, **kw):
        raise ValueError("secret-token")

    for _ in range(33):
        check_once(db, package_query=fail)
    data = history(db, 30)
    assert len(data["runs"]) == 30
    assert "secret-token" not in json.dumps(data)


def test_duplicate_paths_do_not_duplicate_network_or_hide_unknown(tmp_path):
    db = tmp_path / "monitor.db"
    data = report(["x"])
    data["packages"].append({**data["packages"][0], "osv_unverified": True})
    assert initialize(db, data)["registered_components"] == 1
    assert check_once(db, package_query=lambda *a, **kw: [])["events"][0]["type"] == "baseline_verified"


@pytest.mark.parametrize('change', [{'models': [None]}, {'models': {}}, {'unscanned': None}, {'metadata': []}])
def test_malformed_report_rejected_before_creating_database(tmp_path, change):
    target = tmp_path / 'invalid.db'
    with pytest.raises(ValueError):
        initialize(target, {**report(), **change})
    assert not target.exists()


def test_missing_database_metadata_is_controlled_error(tmp_path):
    target = tmp_path / 'corrupt.db'
    with sqlite3.connect(target) as db:
        db.execute('CREATE TABLE metadata(value TEXT)')
    db.close()
    with pytest.raises(ValueError, match='metadata'):
        history(target)
    target.unlink()  # connection is closed even after validation failure


def test_initialization_closes_database(tmp_path):
    target = tmp_path / 'closed.db'
    initialize(target, report())
    target.unlink()


@pytest.mark.parametrize('ecosystem,version', [('PyPI', '1nonsense'), ('npm', '1.2'), ('npm', '01.2.3')])
def test_malformed_exact_versions_rejected(tmp_path, ecosystem, version):
    data = report()
    data['packages'][0].update(ecosystem=ecosystem, version=version)
    with pytest.raises(ValueError):
        initialize(tmp_path / 'db', data)
