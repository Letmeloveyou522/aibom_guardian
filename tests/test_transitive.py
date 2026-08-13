"""
Tests for transitive dependency resolution.

A requirements file lists what a project asked for; what it installs includes
everything those packages pull in. requests brings urllib3, and urllib3 is
the one with the CVE history.

Network is stubbed throughout.
"""

from __future__ import annotations

import pytest

from aibom_guard import scanner
from aibom_guard.scanner import Pinned, expand_transitive


@pytest.fixture
def deps(monkeypatch):
    """Stub PyPI: a dependency table and a version list per package."""

    def _set(table, versions=("1.0.0", "2.0.0", "2.5.0")):
        monkeypatch.setattr(
            scanner, "_requires_dist",
            lambda name, version: table.get(scanner._normalize_name(name), []))
        monkeypatch.setattr(scanner, "_pypi_versions", lambda name: list(versions))

    return _set


def direct(name, version="1.0.0"):
    return Pinned(name, version, f"{name}=={version}", False)


def names(packages):
    return sorted(p.name.lower() for p in packages)


class TestTreeWalk:
    def test_a_dependency_is_pulled_in(self, deps):
        deps({"requests": ["urllib3"]})
        packages, _ = expand_transitive([direct("requests")])
        assert names(packages) == ["requests", "urllib3"]

    def test_the_tree_is_followed_to_the_bottom(self, deps):
        deps({"a": ["b"], "b": ["c"], "c": ["d"]})
        packages, _ = expand_transitive([direct("a")])
        assert names(packages) == ["a", "b", "c", "d"]

    def test_depth_is_recorded(self, deps):
        deps({"a": ["b"], "b": ["c"]})
        packages, _ = expand_transitive([direct("a")])
        assert {p.name: p.depth for p in packages} == {"a": 0, "b": 1, "c": 2}

    def test_direct_and_transitive_are_distinguishable(self, deps):
        deps({"a": ["b"]})
        packages, _ = expand_transitive([direct("a")])
        assert {p.name: p.direct for p in packages} == {"a": True, "b": False}

    def test_a_cycle_terminates(self, deps):
        """a -> b -> a. The visited set has to stop this, not the depth cap."""
        deps({"a": ["b"], "b": ["a"]})
        packages, _ = expand_transitive([direct("a")])
        assert names(packages) == ["a", "b"]

    def test_a_diamond_yields_one_copy(self, deps):
        deps({"a": ["b", "c"], "b": ["d"], "c": ["d"]})
        packages, _ = expand_transitive([direct("a")])
        assert names(packages) == ["a", "b", "c", "d"]

    def test_depth_is_capped(self, deps):
        deps({chr(ord("a") + i): [chr(ord("a") + i + 1)] for i in range(20)})
        packages, _ = expand_transitive([direct("a")], max_depth=3)
        assert len(packages) == 4


class TestVersionSelection:
    def test_a_dependency_range_resolves_to_a_version(self, deps):
        deps({"a": ["b (>=1.0,<2.5)"]}, versions=("1.0.0", "2.0.0", "9.0.0"))
        packages, _ = expand_transitive([direct("a")])
        assert [(p.name, p.version) for p in packages if not p.direct] == [("b", "2.0.0")]

    def test_a_direct_pin_is_not_replaced_by_a_dependency_range(self, deps):
        """
        The file said b==1.0.0. Another package asking for b>=2 must not
        silently change what the report says the project installs.
        """
        deps({"a": ["b (>=2.0)"]})
        packages, _ = expand_transitive([direct("a"), direct("b", "1.0.0")])
        b = [p for p in packages if p.name.lower() == "b"]
        assert len(b) == 1
        assert b[0].version == "1.0.0"
        assert b[0].direct is True

    def test_an_unresolvable_dependency_is_reported_not_dropped(self, deps):
        deps({"a": ["b (>=99.0)"]})
        packages, unresolved = expand_transitive([direct("a")])
        assert names(packages) == ["a"]
        assert len(unresolved) == 1
        assert "required by a" in unresolved[0]


class TestMarkers:
    def test_optional_extras_are_skipped(self, deps):
        """An install that asked for no extras does not get them."""
        deps({"a": ["socks-helper ; extra == 'socks'", "b"]})
        packages, _ = expand_transitive([direct("a")])
        assert names(packages) == ["a", "b"]

    def test_a_false_python_version_marker_is_skipped(self, deps):
        deps({"a": ['ancient ; python_version < "3.0"', "b"]})
        packages, _ = expand_transitive([direct("a")])
        assert names(packages) == ["a", "b"]

    def test_a_true_marker_is_followed(self, deps):
        deps({"a": ['b ; python_version >= "3.0"']})
        packages, _ = expand_transitive([direct("a")])
        assert names(packages) == ["a", "b"]

    def test_a_malformed_requirement_is_skipped_not_fatal(self, deps):
        deps({"a": ["!!!not a requirement!!!", "b"]})
        packages, _ = expand_transitive([direct("a")])
        assert names(packages) == ["a", "b"]


class TestNameNormalisation:
    @pytest.mark.parametrize("written,pinned", [
        ("charset_normalizer", "charset-normalizer"),
        ("Jinja2", "jinja2"),
        ("zope.interface", "zope-interface"),
    ])
    def test_one_package_is_not_scanned_twice_under_two_spellings(
            self, deps, written, pinned):
        deps({"a": [written]})
        packages, _ = expand_transitive([direct("a"), direct(pinned)])
        assert len(packages) == 2


class TestOffline:
    def test_offline_returns_the_direct_list_unchanged(self, deps):
        """Resolving a tree means asking PyPI, which offline forbids."""
        deps({"a": ["b"]})
        packages, unresolved = expand_transitive([direct("a")], offline=True)
        assert names(packages) == ["a"]
        assert unresolved == []


class TestScannerIntegration:
    def _reqs(self, tmp_path):
        path = tmp_path / "requirements.txt"
        path.write_text("a==1.0.0\n", encoding="utf-8")
        return str(path)

    @pytest.fixture
    def wired(self, monkeypatch, tmp_path):
        monkeypatch.setattr(scanner, "build_final_sbom", lambda *a, **k: None)
        monkeypatch.setattr(scanner, "explain_results", lambda r: "(stubbed)")
        monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
        monkeypatch.setattr(scanner, "RecommendationEngine", lambda *a, **k: None)
        monkeypatch.setattr(
            scanner, "resolve_license",
            lambda name, version=None, offline=False: {
                "license": "MIT", "source": "pypi:license_expression",
                "version": version, "unverified": False, "error": None})
        monkeypatch.setattr(scanner, "_pypi_versions", lambda name: ["1.0.0"])
        monkeypatch.setattr(scanner, "_requires_dist",
                            lambda name, version: ["b"] if name == "a" else [])
        monkeypatch.chdir(tmp_path)

    def test_dependencies_reach_the_report(self, tmp_path, wired):
        report = scanner.run_scan(self._reqs(tmp_path), explain=False)
        assert [r["package"] for r in report] == ["a", "b"]

    def test_the_report_marks_which_were_pulled_in(self, tmp_path, wired):
        report = scanner.run_scan(self._reqs(tmp_path), explain=False)
        assert {r["package"]: r["direct"] for r in report} == {"a": True, "b": False}

    def test_direct_only_skips_the_tree(self, tmp_path, wired):
        report = scanner.run_scan(self._reqs(tmp_path), explain=False,
                                  transitive=False)
        assert [r["package"] for r in report] == ["a"]
