"""
Tests for the release cooldown check.

A version published minutes ago has not been public long enough for anyone to
notice it was compromised. The September 2025 npm attack on chalk and debug
was withdrawn in about 2.5 hours; a one-day cooldown would have missed it
entirely.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aibom_guard.recommendation import (
    PyPIClient,
    PyPIPackageInfo,
    detect_fresh_release,
)

NOW = datetime.now(timezone.utc)


def info(**dates):
    return PyPIPackageInfo(
        name="demo",
        exists=True,
        release_dates={v: NOW - timedelta(days=d) for v, d in dates.items()},
    )


class TestThreshold:
    def test_a_release_under_the_cooldown_is_flagged(self):
        issues = detect_fresh_release(info(**{"1.0.0": 0}), "1.0.0", 7)
        assert len(issues) == 1
        assert issues[0]["type"] == "provenance"
        assert issues[0]["release_age_days"] == 0

    def test_a_release_past_the_cooldown_is_not(self):
        assert detect_fresh_release(info(**{"1.0.0": 30}), "1.0.0", 7) == []

    def test_the_boundary_day_passes(self):
        """Exactly N days old has served the cooldown."""
        assert detect_fresh_release(info(**{"1.0.0": 7}), "1.0.0", 7) == []

    @pytest.mark.parametrize("age,severity", [(0, "medium"), (1, "low"), (5, "low")])
    def test_severity_falls_as_the_release_ages(self, age, severity):
        issues = detect_fresh_release(info(**{"1.0.0": age}), "1.0.0", 7)
        assert issues[0]["severity"] == severity

    def test_the_version_under_scan_decides_not_the_newest(self):
        """
        A project can ship 3.0.0 today while the file pins 1.0.0 from a year
        ago. Judging the pin by the project's latest upload would flag it.
        """
        both = info(**{"1.0.0": 400, "3.0.0": 0})
        assert detect_fresh_release(both, "1.0.0", 7) == []
        assert len(detect_fresh_release(both, "3.0.0", 7)) == 1


class TestDisabled:
    @pytest.mark.parametrize("threshold", [0, -1])
    def test_zero_or_less_disables_the_check(self, threshold):
        assert detect_fresh_release(info(**{"1.0.0": 0}), "1.0.0", threshold) == []

    def test_no_version_means_nothing_to_judge(self):
        assert detect_fresh_release(info(**{"1.0.0": 0}), None, 7) == []

    def test_an_unknown_version_is_not_guessed_at(self):
        """No upload date for it, so no claim about its age."""
        assert detect_fresh_release(info(**{"1.0.0": 0}), "9.9.9", 7) == []

    def test_a_package_that_does_not_exist_is_left_alone(self):
        absent = PyPIPackageInfo(name="ghost", exists=False)
        assert detect_fresh_release(absent, "1.0.0", 7) == []


class TestReleaseDatesFromPyPI:
    def _payload(self, releases):
        return {"info": {"name": "demo", "version": "2.0.0"},
                "releases": releases}

    def test_each_version_gets_its_own_date(self):
        parsed = PyPIClient._parse_package_json("demo", self._payload({
            "1.0.0": [{"upload_time_iso_8601": "2020-01-15T00:00:00.000000Z"}],
            "2.0.0": [{"upload_time_iso_8601": "2026-08-01T00:00:00.000000Z"}],
        }))
        assert parsed.release_dates["1.0.0"].year == 2020
        assert parsed.release_dates["2.0.0"].year == 2026

    def test_the_earliest_file_dates_the_release(self):
        """
        Wheels for a release trickle in over hours. The cooldown starts when
        the version first appeared, not when the last wheel landed.
        """
        parsed = PyPIClient._parse_package_json("demo", self._payload({
            "1.0.0": [
                {"upload_time_iso_8601": "2026-08-01T18:00:00.000000Z"},
                {"upload_time_iso_8601": "2026-08-01T06:00:00.000000Z"},
            ],
        }))
        assert parsed.release_dates["1.0.0"].hour == 6

    def test_last_upload_still_tracks_the_whole_project(self):
        """The staleness check needs the newest upload across every release."""
        parsed = PyPIClient._parse_package_json("demo", self._payload({
            "1.0.0": [{"upload_time_iso_8601": "2020-01-15T00:00:00.000000Z"}],
            "2.0.0": [{"upload_time_iso_8601": "2026-08-01T00:00:00.000000Z"}],
        }))
        assert parsed.last_upload.year == 2026

    def test_unparseable_dates_are_skipped(self):
        parsed = PyPIClient._parse_package_json("demo", self._payload({
            "1.0.0": [{"upload_time_iso_8601": "not a date"}],
        }))
        assert parsed.release_dates == {}


class TestEngineWiring:
    def _engine(self, monkeypatch, package_info):
        from unittest.mock import MagicMock

        from aibom_guard.recommendation import RecommendationEngine

        client = MagicMock()
        client.get_package.return_value = package_info
        return RecommendationEngine(pypi_client=client)

    def test_off_by_default(self, monkeypatch):
        engine = self._engine(monkeypatch, info(**{"1.0.0": 0}))
        result = engine.analyze_package("demo", "1.0.0")
        assert not [i for i in result["issues"] if "cooldown" in i.get("detail", "")]

    def test_reaches_the_report_when_requested(self, monkeypatch):
        engine = self._engine(monkeypatch, info(**{"1.0.0": 0}))
        result = engine.analyze_package("demo", "1.0.0", min_release_age=7)
        fresh = [i for i in result["issues"] if "release_age_days" in i]
        assert len(fresh) == 1
