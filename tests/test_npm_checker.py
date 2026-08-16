"""
Tests for npm_checker.py — all network calls mocked.
"""

import json

import pytest

from aibom_guardian import npm_checker
from aibom_guardian import scanner
from aibom_guardian.osv_client import query_vulnerabilities


@pytest.fixture
def package_json(tmp_path):
    path = tmp_path / "package.json"
    path.write_text(
        json.dumps(
            {
                "name": "demo-app",
                "dependencies": {
                    "express": "^4.18.2",
                    "lodash": "4.17.21",
                    "broken-range": "*",
                },
                "devDependencies": {
                    "eslint": "8.57.0",
                },
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def test_normalize_npm_version_exact():
    version, exact = npm_checker.normalize_npm_version("4.17.21")
    assert version == "4.17.21"
    assert exact is True


def test_normalize_npm_version_caret():
    version, exact = npm_checker.normalize_npm_version("^4.18.2")
    assert version == "4.18.2"
    assert exact is False


def test_normalize_npm_version_wildcard_is_unscannable():
    assert npm_checker.normalize_npm_version("*") is None
    assert npm_checker.normalize_npm_version("latest") is None
    assert npm_checker.normalize_npm_version("1.0.0 || 2.0.0") is None


def test_parse_package_json(package_json):
    packages, unscanned = npm_checker.parse_package_json(package_json)

    names = {p.name for p in packages}
    assert names == {"express", "lodash", "eslint"}
    assert any("broken-range" in line for line in unscanned)

    lodash = next(p for p in packages if p.name == "lodash")
    assert lodash.version == "4.17.21"
    assert lodash.section == "dependencies"
    assert lodash.exact is True


def test_fetch_npm_license_reads_registry(monkeypatch):
    class FakeResponse:
        status_code = 200

        @staticmethod
        def json():
            return {"license": "MIT", "name": "lodash", "version": "4.17.21"}

    monkeypatch.setattr(
        npm_checker, "_npm_session",
        lambda: type("S", (), {"get": lambda self, url, timeout=10: FakeResponse()})(),
    )
    npm_checker._REGISTRY_CACHE.clear()

    lic = npm_checker.fetch_npm_license("lodash", "4.17.21")
    assert lic["license"] == "MIT"
    assert lic["source"] == "npm:registry"
    assert lic["unverified"] is False


def test_fetch_npm_license_offline():
    lic = npm_checker.fetch_npm_license("lodash", "4.17.21", offline=True)
    assert lic["unverified"] is True
    assert lic["error"] == "offline"


def test_query_vulnerabilities_accepts_npm_ecosystem(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=10, **kwargs):
        captured["payload"] = json

        class Resp:
            def raise_for_status(self):
                return None

            def json(self):
                return {"vulns": []}

        return Resp()

    import aibom_guardian.osv_client as osv_mod

    monkeypatch.setattr(osv_mod.requests, "post", fake_post)

    result = query_vulnerabilities("lodash", "4.17.21", ecosystem="npm")
    assert result == []
    assert captured["payload"]["package"]["ecosystem"] == "npm"
    assert captured["payload"]["package"]["name"] == "lodash"


def test_run_npm_scan_wires_score_engine(package_json, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        npm_checker, "fetch_npm_license",
        lambda name, version, offline=False: {
            "license": "MIT",
            "source": "npm:registry",
            "version": version,
            "unverified": False,
            "error": None,
        },
    )
    monkeypatch.setattr(
        npm_checker, "query_vulnerabilities",
        lambda name, version, ecosystem="npm": [],
    )
    monkeypatch.setattr(scanner, "explain_results", lambda r: "(stub)")

    report = npm_checker.run_npm_scan(package_json, explain=False)

    assert len(report) == 3
    assert all(row["ecosystem"] == "npm" for row in report)
    assert all("trust_score" in row and "verdict" in row for row in report)
    assert (tmp_path / "scan_report.json").exists()


def test_scanner_cli_npm_option(tmp_path, monkeypatch):
    path = tmp_path / "package.json"
    path.write_text(
        json.dumps({"dependencies": {"lodash": "4.17.21"}}),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        npm_checker, "fetch_npm_license",
        lambda name, version, offline=False: {
            "license": "MIT",
            "source": "npm:registry",
            "version": version,
            "unverified": False,
            "error": None,
        },
    )
    monkeypatch.setattr(
        npm_checker, "query_vulnerabilities",
        lambda name, version, ecosystem="npm": [],
    )

    code = scanner.main(["--npm", str(path), "--no-explain"])
    assert code == 0
