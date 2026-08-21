"""
Tests for the concurrent lookup phase.

Scanning is network-bound, so the lookups run on a thread pool. The report
still has to read exactly as it did when they ran one at a time - same order,
same values, each result attached to the package it belongs to.
"""

from __future__ import annotations

import threading

import pytest

from aibom_guardian import scanner
from aibom_guardian.scanner import Pinned, _prefetch


def pinned(name, version="1.0.0"):
    return Pinned(name, version, f"{name}=={version}", False)


@pytest.fixture
def lookups(monkeypatch):
    """Make every lookup return something traceable to its package."""
    monkeypatch.setattr(
        scanner, "resolve_license",
        lambda name, version=None, offline=False: {
            "license": f"LIC-{name}", "source": "pypi:license",
            "version": version, "unverified": False, "error": None})
    monkeypatch.setattr(scanner, "query_vulnerabilities",
                        lambda n, v: [{"id": f"CVE-{n}", "severity": "low"}])
    monkeypatch.setattr(
        scanner, "analyze_package_risks",
        lambda engine, n, v, vulns, age=0: ([{"type": "cve", "id": f"CVE-{n}"}], []))
    monkeypatch.setattr(scanner, "check_supply_chain",
                        lambda n, v: {"repo": n})


PACKAGES = [pinned(f"pkg{i}") for i in range(12)]


def _run(jobs, packages=PACKAGES, **kwargs):
    return _prefetch(packages, engine_factory=lambda: object(),
                     offline=False, supply_chain=False, jobs=jobs, **kwargs)


class TestResultsStayWithTheirPackage:
    @pytest.mark.parametrize("jobs", [1, 2, 8, 32])
    def test_each_package_gets_its_own_result(self, lookups, jobs):
        fetched = _run(jobs)
        for entry in PACKAGES:
            assert fetched[id(entry)]["license"]["license"] == f"LIC-{entry.name}"

    def test_parallel_matches_serial(self, lookups):
        serial = _run(1)
        parallel = _run(8)
        assert ([serial[id(e)] for e in PACKAGES]
                == [parallel[id(e)] for e in PACKAGES])

    def test_two_packages_sharing_a_name_are_not_merged(self, lookups):
        """Keyed by identity, so the same name at two versions stays two rows."""
        a, b = pinned("same", "1.0.0"), pinned("same", "2.0.0")
        fetched = _run(4, packages=[a, b])
        assert len(fetched) == 2
        assert fetched[id(a)] is not fetched[id(b)]


class TestConcurrency:
    def test_lookups_actually_overlap(self, monkeypatch):
        """
        Without real overlap the speedup claim is untested. Each lookup holds
        briefly so several are genuinely in flight.
        """
        lock = threading.Lock()
        in_flight = 0
        peak = 0

        def slow(name, version=None, offline=False):
            nonlocal in_flight, peak
            with lock:
                in_flight += 1
                peak = max(peak, in_flight)
            threading.Event().wait(0.02)
            with lock:
                in_flight -= 1
            return {"license": "MIT", "source": "pypi:license",
                    "version": version, "unverified": False, "error": None}

        monkeypatch.setattr(scanner, "resolve_license", slow)
        monkeypatch.setattr(scanner, "query_vulnerabilities", lambda n, v: [])
        monkeypatch.setattr(scanner, "analyze_package_risks",
                            lambda e, n, v, vu, age=0: ([], []))

        _run(4)
        assert peak > 1, "no overlap - this test proves nothing"
        assert peak <= 4

    def test_jobs_1_never_starts_a_thread(self, lookups):
        main = threading.current_thread()
        seen = []

        original = scanner.resolve_license

        def record(name, version=None, offline=False):
            seen.append(threading.current_thread())
            return original(name, version, offline=offline)

        scanner.resolve_license = record
        try:
            _run(1)
        finally:
            scanner.resolve_license = original

        assert all(t is main for t in seen)

    def test_each_thread_builds_its_own_engine(self, lookups, monkeypatch):
        """
        RecommendationEngine holds a requests.Session, which is not safe to
        share. One engine per worker rather than one for the pool.
        """
        built = []
        lock = threading.Lock()

        def factory():
            with lock:
                built.append(threading.current_thread())
            return object()

        def slow(engine, name, version, vulns, age=0):
            threading.Event().wait(0.02)
            return [], []

        monkeypatch.setattr(scanner, "analyze_package_risks", slow)
        _prefetch(PACKAGES, engine_factory=factory, offline=False,
                  supply_chain=False, jobs=4)

        assert len(set(built)) == len(built), "an engine was reused across threads"
        assert len(built) > 1


class TestOfflineAndSupplyChain:
    def test_offline_skips_the_network_lookups(self, lookups, monkeypatch):
        monkeypatch.setattr(scanner, "query_vulnerabilities",
                            lambda n, v: pytest.fail("OSV called while offline"))
        fetched = _prefetch(PACKAGES, engine_factory=lambda: object(),
                            offline=True, supply_chain=False, jobs=4)
        assert all(f["vulns"] is None and f["issues"] is None
                   for f in fetched.values())

    def test_supply_chain_off_leaves_repository_info_none(self, lookups):
        fetched = _run(4)
        assert all(f["repository_info"] is None for f in fetched.values())

    def test_supply_chain_on_collects_it(self, lookups):
        fetched = _prefetch(PACKAGES, engine_factory=lambda: object(),
                            offline=False, supply_chain=True, jobs=4)
        for entry in PACKAGES:
            assert fetched[id(entry)]["repository_info"] == {"repo": entry.name}


class TestFailedLookups:
    def test_an_osv_failure_stays_none_for_that_package_only(self, lookups,
                                                             monkeypatch):
        monkeypatch.setattr(
            scanner, "query_vulnerabilities",
            lambda n, v: None if n == "pkg3" else [])

        fetched = _run(8)

        assert fetched[id(PACKAGES[3])]["vulns"] is None
        assert fetched[id(PACKAGES[3])]["issues"] is None
        assert all(fetched[id(e)]["vulns"] == []
                   for e in PACKAGES if e.name != "pkg3")
