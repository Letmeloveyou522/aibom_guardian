"""
Tests for npm transitive dependency resolution.

A package.json lists what a project asked for; what it installs includes
everything those packages pull in. express brings debug, and debug is
still a package the project ships.

Network is stubbed throughout. Mirrors tests/test_transitive.py.
"""

from __future__ import annotations

import json

import pytest

from aibom_guardian import npm_checker
from aibom_guardian import scanner
from aibom_guardian.npm_checker import (
    NPM_TRANSITIVE_MAX_DEPTH,
    NpmPackage,
    expand_npm_transitive,
)


@pytest.fixture(autouse=True)
def _clear_registry_cache():
    npm_checker._REGISTRY_CACHE.clear()
    yield
    npm_checker._REGISTRY_CACHE.clear()


@pytest.fixture
def deps(monkeypatch):
    """Stub the npm registry: a dependency table and a version list per package."""

    def _set(table, versions=("1.0.0", "2.0.0", "2.5.0")):
        monkeypatch.setattr(
            npm_checker, "_npm_dependencies",
            lambda name, version: dict(
                table.get(npm_checker._normalize_npm_name(name), {})
            ),
        )
        monkeypatch.setattr(
            npm_checker, "_npm_versions",
            lambda name: list(versions),
        )

    return _set


def direct(name, version="1.0.0"):
    return NpmPackage(name, version, version, "dependencies", True)


def names(packages):
    return sorted(p.name.lower() for p in packages)


class TestTreeWalk:
    def test_a_dependency_is_pulled_in(self, deps):
        deps({"express": {"debug": "1.0.0"}})
        packages, _ = expand_npm_transitive([direct("express")])
        assert names(packages) == ["debug", "express"]

    def test_the_tree_is_followed_to_the_bottom(self, deps):
        deps({"a": {"b": "1.0.0"}, "b": {"c": "1.0.0"}, "c": {"d": "1.0.0"}})
        packages, _ = expand_npm_transitive([direct("a")])
        assert names(packages) == ["a", "b", "c", "d"]

    def test_depth_is_recorded(self, deps):
        deps({"a": {"b": "1.0.0"}, "b": {"c": "1.0.0"}})
        packages, _ = expand_npm_transitive([direct("a")])
        assert {p.name: p.depth for p in packages} == {"a": 0, "b": 1, "c": 2}

    def test_direct_and_transitive_are_distinguishable(self, deps):
        deps({"a": {"b": "1.0.0"}})
        packages, _ = expand_npm_transitive([direct("a")])
        assert {p.name: p.direct for p in packages} == {"a": True, "b": False}

    def test_a_cycle_terminates(self, deps):
        """a -> b -> a. The visited set has to stop this, not the depth cap."""
        deps({"a": {"b": "1.0.0"}, "b": {"a": "1.0.0"}})
        packages, _ = expand_npm_transitive([direct("a")])
        assert names(packages) == ["a", "b"]

    def test_a_diamond_yields_one_copy(self, deps):
        deps({"a": {"b": "1.0.0", "c": "1.0.0"},
              "b": {"d": "1.0.0"},
              "c": {"d": "1.0.0"}})
        packages, _ = expand_npm_transitive([direct("a")])
        assert names(packages) == ["a", "b", "c", "d"]

    def test_depth_is_capped(self, deps):
        deps({chr(ord("a") + i): {chr(ord("a") + i + 1): "1.0.0"}
              for i in range(20)})
        packages, _ = expand_npm_transitive([direct("a")], max_depth=3)
        assert len(packages) == 4

    def test_default_depth_cap_matches_python(self):
        assert NPM_TRANSITIVE_MAX_DEPTH == 12


class TestVersionSelection:
    def test_a_dependency_range_resolves_to_a_version(self, deps):
        deps({"a": {"b": "^1.0.0"}}, versions=("1.0.0", "1.9.0", "2.0.0"))
        packages, _ = expand_npm_transitive([direct("a")])
        assert [(p.name, p.version) for p in packages if not p.direct] == [
            ("b", "1.9.0")
        ]

    def test_a_tilde_range_picks_the_newest_in_minor(self, deps):
        deps({"a": {"b": "~1.6.0"}}, versions=("1.6.0", "1.6.9", "1.7.0"))
        packages, _ = expand_npm_transitive([direct("a")])
        assert [(p.name, p.version) for p in packages if not p.direct] == [
            ("b", "1.6.9")
        ]

    def test_a_union_range_resolves_to_the_newest_match(self, deps):
        deps({"a": {"b": "^1.0.0 || ^2.0.0"}},
             versions=("1.5.0", "2.5.0", "3.0.0"))
        packages, _ = expand_npm_transitive([direct("a")])
        assert [(p.name, p.version) for p in packages if not p.direct] == [
            ("b", "2.5.0")
        ]

    def test_a_direct_pin_is_not_replaced_by_a_dependency_range(self, deps):
        """
        package.json said b@1.0.0. Another package asking for b@^2 must not
        silently change what the report says the project installs.
        """
        deps({"a": {"b": "^2.0.0"}})
        packages, _ = expand_npm_transitive([direct("a"), direct("b", "1.0.0")])
        b = [p for p in packages if p.name.lower() == "b"]
        assert len(b) == 1
        assert b[0].version == "1.0.0"
        assert b[0].direct is True

    def test_an_unresolvable_dependency_is_reported_not_dropped(self, deps):
        deps({"a": {"b": "^99.0.0"}})
        packages, unresolved = expand_npm_transitive([direct("a")])
        assert names(packages) == ["a"]
        assert len(unresolved) == 1
        assert "required by a" in unresolved[0]


class TestNameNormalisation:
    def test_one_package_is_not_scanned_twice_under_two_spellings(self, deps):
        deps({"a": {"Debug": "1.0.0"}})
        packages, _ = expand_npm_transitive([direct("a"), direct("debug")])
        assert len(packages) == 2


class TestOffline:
    def test_offline_returns_the_direct_list_unchanged(self, deps):
        """Resolving a tree means asking the registry, which offline forbids."""
        deps({"a": {"b": "1.0.0"}})
        packages, unresolved = expand_npm_transitive([direct("a")], offline=True)
        assert names(packages) == ["a"]
        assert unresolved == []


class TestRegistryCache:
    def test_the_same_release_is_fetched_once(self, monkeypatch):
        calls = []

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return {"dependencies": {"b": "1.0.0"}}

        def fake_get(url, timeout=10):
            calls.append(url)
            return FakeResponse()

        monkeypatch.setattr(
            npm_checker,
            "_npm_session",
            lambda: type("S", (), {"get": lambda self, url, timeout=10: fake_get(url, timeout)})(),
        )
        npm_checker._REGISTRY_CACHE.clear()
        first = npm_checker._npm_dependencies("express", "4.18.2")
        second = npm_checker._npm_dependencies("express", "4.18.2")
        assert first == second == {"b": "1.0.0"}
        assert len(calls) == 1

    def test_the_same_version_list_is_fetched_once(self, monkeypatch):
        calls = []

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return {"versions": {"1.0.0": {}, "2.0.0": {}}}

        def fake_get(url, timeout=10):
            calls.append(url)
            return FakeResponse()

        monkeypatch.setattr(
            npm_checker,
            "_npm_session",
            lambda: type("S", (), {"get": lambda self, url, timeout=10: fake_get(url, timeout)})(),
        )
        npm_checker._REGISTRY_CACHE.clear()
        first = npm_checker._npm_versions("debug")
        second = npm_checker._npm_versions("debug")
        assert first == second == ["1.0.0", "2.0.0"]
        assert len(calls) == 1


class TestScannerIntegration:
    def _pkg(self, tmp_path):
        path = tmp_path / "package.json"
        path.write_text(
            json.dumps({"dependencies": {"a": "1.0.0"}}),
            encoding="utf-8",
        )
        return str(path)

    @pytest.fixture
    def wired(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            npm_checker, "fetch_npm_license",
            lambda name, version, offline=False: {
                "license": "MIT", "source": "npm:registry",
                "version": version, "unverified": False, "error": None,
            },
        )
        monkeypatch.setattr(
            npm_checker, "query_vulnerabilities",
            lambda name, version, ecosystem="npm": [],
        )
        monkeypatch.setattr(scanner, "explain_results", lambda r: "(stubbed)")
        monkeypatch.setattr(npm_checker, "_npm_versions", lambda name: ["1.0.0"])
        monkeypatch.setattr(
            npm_checker, "_npm_dependencies",
            lambda name, version: {"b": "1.0.0"} if name == "a" else {},
        )
        monkeypatch.chdir(tmp_path)

    def test_dependencies_reach_the_report(self, tmp_path, wired):
        report = npm_checker.run_npm_scan(self._pkg(tmp_path), explain=False)
        assert [r["package"] for r in report] == ["a", "b"]

    def test_the_report_marks_which_were_pulled_in(self, tmp_path, wired):
        report = npm_checker.run_npm_scan(self._pkg(tmp_path), explain=False)
        assert {r["package"]: r["direct"] for r in report} == {"a": True, "b": False}

    def test_direct_only_skips_the_tree(self, tmp_path, wired):
        report = npm_checker.run_npm_scan(
            self._pkg(tmp_path), explain=False, transitive=False,
        )
        assert [r["package"] for r in report] == ["a"]

    def test_offline_scan_skips_the_tree(self, tmp_path, wired):
        report = npm_checker.run_npm_scan(
            self._pkg(tmp_path), explain=False, offline=True,
        )
        assert [r["package"] for r in report] == ["a"]

    def test_scan_prints_direct_and_transitive_counts(
            self, tmp_path, wired, capsys):
        npm_checker.run_npm_scan(self._pkg(tmp_path), explain=False)
        captured = capsys.readouterr()
        assert "1 direct + 1 transitive = 2 packages to scan." in captured.out
