"""
Tests for transitive dependency resolution.

A requirements file lists what a project asked for; what it installs includes
everything those packages pull in. requests brings urllib3, and urllib3 is
the one with the CVE history.

Network is stubbed throughout.
"""

from __future__ import annotations

import pytest

from aibom_guardian import scanner
from aibom_guardian import _requirements
from aibom_guardian.scanner import Pinned, expand_transitive


@pytest.fixture
def deps(monkeypatch):
    """Stub PyPI: a dependency table and a version list per package."""

    def _set(table, versions=("1.0.0", "2.0.0", "2.5.0")):
        monkeypatch.setattr(
            _requirements, "_requires_dist",
            lambda name, version: table.get(_requirements._normalize_name(name), []))
        monkeypatch.setattr(_requirements, "_pypi_versions",
                            lambda name: list(versions))

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
    def test_requested_extra_is_expanded(self, deps):
        deps({'a': ['b; extra == "socks"', 'unused; extra == "test"']})
        packages, missing = expand_transitive([direct('a')._replace(extras=('socks',))])
        assert names(packages) == ['a', 'b']
        assert not missing

    def test_child_extras_are_propagated(self, deps):
        deps({'a': ['b[socks]'], 'b': ['c; extra == "socks"']})
        packages, missing = expand_transitive([direct('a')])
        assert names(packages) == ['a', 'b', 'c']
        assert next(p for p in packages if p.name == 'b').extras == ('socks',)
        assert not missing

    def test_late_extra_revisits_previously_seen_package(self, deps):
        deps({'a': ['c'], 'b': ['d; extra == "socks"'], 'c': ['b[socks]']})
        packages, missing = expand_transitive([direct('a'), direct('b')])
        assert names(packages) == ['a', 'b', 'c', 'd']
        assert not missing

    def test_extras_cycle_terminates(self, deps):
        deps({'a': ['b[socks]'], 'b': ['a[socks]']})
        packages, missing = expand_transitive([direct('a')])
        assert names(packages) == ['a', 'b']
        assert not missing

    def test_duplicate_input_extras_are_merged(self, tmp_path):
        path = tmp_path / 'requirements.txt'
        path.write_text('a[socks]==1.0.0\na[Test_Feature]==1.0.0\n')
        packages, missing = _requirements.parse_requirements(str(path), offline=True)
        assert len(packages) == 1
        assert packages[0].extras == ('socks', 'test-feature')
        assert not missing

    def test_extras_at_depth_limit_are_reported(self, deps):
        deps({'a': ['b[socks]'], 'b': ['c; extra == "socks"']})
        packages, missing = expand_transitive([direct('a')], max_depth=1)
        assert names(packages) == ['a', 'b']
        assert any('depth limit' in m for m in missing)

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


class TestIncompleteExpansion:
    def test_conflict_is_reported_without_replacing_pin(self, deps):
        deps({'a': ['b>=2']})
        packages, missing = expand_transitive([direct('a'), direct('b')])
        assert len(packages) == 2
        assert len(missing) == 1 and 'dependency conflict' in missing[0]

    def test_depth_boundary_is_reported(self, deps):
        deps({'a': ['b'], 'b': ['c']})
        packages, missing = expand_transitive([direct('a')], max_depth=1)
        assert names(packages) == ['a', 'b']
        assert len(missing) == 1 and 'depth limit' in missing[0]

    def test_failed_metadata_is_reported(self, monkeypatch):
        monkeypatch.setattr(_requirements, '_requires_dist', lambda *a: None)
        _, missing = expand_transitive([direct('a')])
        assert 'metadata lookup failed' in missing[0]

    @pytest.mark.parametrize('spec', ['!!!invalid!!!', 'b @ https://example.com/b.whl'])
    def test_unsupported_dependency_is_not_silently_dropped(self, deps, spec):
        deps({'a': [spec]})
        packages, missing = expand_transitive([direct('a')])
        assert names(packages) == ['a']
        assert len(missing) == 1 and spec in missing[0]

    def test_conflicting_input_pins(self, deps):
        deps({})
        _, missing = expand_transitive([direct('a'), direct('a', '2.0.0')])
        assert 'conflicting input pins' in missing[0]

    @pytest.mark.parametrize('payload', [{'info': {'requires_dist': 'wrong'}}, {}, None])
    def test_failed_metadata_is_not_cached_as_empty(self, monkeypatch, payload):
        class Response:
            def raise_for_status(self):
                if payload is None:
                    raise OSError('synthetic network failure')

            def json(self):
                return payload

        class Session:
            def get(self, *a, **kw):
                return Response()

        monkeypatch.setattr(_requirements, '_RELEASE_CACHE', {})
        monkeypatch.setattr(_requirements, '_PYPI_SESSION', Session())
        assert _requirements._requires_dist('a', '1.0.0') is None
        assert not _requirements._RELEASE_CACHE


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
        monkeypatch.setattr(_requirements, "_pypi_versions", lambda name: ["1.0.0"])
        monkeypatch.setattr(_requirements, "_requires_dist",
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
