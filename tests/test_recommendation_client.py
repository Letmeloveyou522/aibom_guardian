"""
The PyPI client, the model-alternative recommender, and RecommendationEngine.
The detectors themselves are covered by tests/test_recommendation.py.

The distinction under test: PyPIClient returns ``exists=False`` both when
PyPI says 404 and when PyPI does not answer, and only ``error`` separates
them. Confusing the two scores a network blip as a hallucinated package.

Network is mocked throughout.
"""

from __future__ import annotations

import asyncio
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

import requests

from aibom_guard.recommendation import (
    PyPIClient,
    PyPIPackageInfo,
    RecommendationEngine,
    _parse_pypi_time,
    detect_hallucination,
    recommend_model_alternatives,
)


def _response(status=200, json_data=None):
    resp = MagicMock()
    resp.status_code = status
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("no json")
    return resp


def _pypi_json(**overrides):
    payload = {
        "info": {"name": "requests", "version": "2.31.0"},
        "releases": {
            "2.28.0": [{"upload_time_iso_8601": "2022-06-29T12:00:00.000000Z",
                        "yanked": False}],
            "2.31.0": [{"upload_time_iso_8601": "2026-05-22T09:30:00.000000Z",
                        "yanked": False}],
        },
    }
    payload.update(overrides)
    return payload


class TestPyPIClientOutcomes(unittest.TestCase):
    """
    Four outcomes that must stay distinguishable: found, genuinely absent,
    unreachable, and answered-with-nonsense.
    """

    def _client(self, response=None, raises=None):
        session = MagicMock()
        if raises is not None:
            session.get.side_effect = raises
        else:
            session.get.return_value = response
        return PyPIClient(session=session)

    def test_a_200_is_parsed(self):
        info = self._client(_response(200, _pypi_json())).get_package("requests")
        self.assertTrue(info.exists)
        self.assertIsNone(info.error)
        self.assertEqual(info.latest_version, "2.31.0")

    def test_a_404_is_a_confirmed_absence(self):
        info = self._client(_response(404)).get_package("no-such-pkg")
        self.assertFalse(info.exists)
        self.assertIsNone(info.error, "a 404 is an answer, not a failure")

    def test_a_network_error_is_not_an_absence(self):
        info = self._client(
            raises=requests.exceptions.ConnectionError("down")
        ).get_package("requests")
        self.assertFalse(info.exists)
        self.assertIsNotNone(info.error)
        self.assertIn("network", info.error)

    def test_a_5xx_is_not_an_absence(self):
        info = self._client(_response(503)).get_package("requests")
        self.assertFalse(info.exists)
        self.assertIn("503", info.error)

    def test_an_unparseable_body_is_not_an_absence(self):
        info = self._client(_response(200, None)).get_package("requests")
        self.assertFalse(info.exists)
        self.assertIn("invalid json", info.error)

    def test_the_four_outcomes_reach_detect_hallucination_correctly(self):
        """
        The contract that matters downstream: only a real 404 may be scored.
        Everything else is reported but marked unverified, so score_engine
        lowers confidence rather than deducting.
        """
        absent = self._client(_response(404)).get_package("ghost-pkg")
        unreachable = self._client(
            raises=requests.exceptions.Timeout("slow")).get_package("requests")

        confirmed = detect_hallucination(absent)
        unverified = detect_hallucination(unreachable)

        self.assertEqual(len(confirmed), 1)
        self.assertIs(confirmed[0]["verified"], True)

        self.assertEqual(len(unverified), 1)
        self.assertIs(unverified[0]["verified"], False)

    def test_a_package_name_is_url_escaped(self):
        """A name is attacker-supplied text; it must not shape the URL."""
        session = MagicMock()
        session.get.return_value = _response(404)
        PyPIClient(session=session).get_package("../../etc/passwd")
        called_url = session.get.call_args[0][0]
        self.assertNotIn("../", called_url)
        self.assertIn("%2F", called_url)

    def test_a_caller_supplied_session_is_not_closed(self):
        """Closing a session the caller owns would break their next request."""
        session = MagicMock()
        client = PyPIClient(session=session)
        client.close()
        session.close.assert_not_called()

    def test_the_context_manager_closes_its_own_session(self):
        with patch("aibom_guard.recommendation.requests.Session") as factory:
            created = factory.return_value
            with PyPIClient():
                pass
        created.close.assert_called_once()


class TestPackageJsonParsing(unittest.TestCase):
    def test_yanked_releases_are_collected_with_their_reason(self):
        payload = _pypi_json(releases={
            "1.0.0": [{"yanked": True, "yanked_reason": "security",
                       "upload_time_iso_8601": "2020-01-01T00:00:00.000000Z"}],
            "1.0.1": [{"yanked": False,
                       "upload_time_iso_8601": "2020-02-01T00:00:00.000000Z"}],
        })
        info = PyPIClient._parse_package_json("pkg", payload)
        self.assertEqual(info.yanked_versions, {"1.0.0": "security"})

    def test_a_yank_without_a_reason_still_records_the_yank(self):
        payload = _pypi_json(releases={"1.0.0": [{"yanked": True}]})
        info = PyPIClient._parse_package_json("pkg", payload)
        self.assertEqual(info.yanked_versions, {"1.0.0": "yanked"})

    def test_last_upload_is_the_newest_across_every_release(self):
        info = PyPIClient._parse_package_json("requests", _pypi_json())
        self.assertEqual(info.last_upload.year, 2026)

    def test_malformed_release_entries_are_skipped_not_fatal(self):
        payload = _pypi_json(releases={
            "1.0.0": "not-a-list",
            "1.0.1": ["not-a-dict", {"upload_time": "2021-03-04T05:06:07"}],
        })
        info = PyPIClient._parse_package_json("pkg", payload)
        self.assertTrue(info.exists)
        self.assertEqual(info.last_upload.year, 2021)

    def test_an_empty_document_does_not_crash(self):
        info = PyPIClient._parse_package_json("pkg", {})
        self.assertTrue(info.exists)
        self.assertIsNone(info.latest_version)
        self.assertIsNone(info.last_upload)


class TestUploadTimeParsing(unittest.TestCase):
    def test_the_formats_pypi_actually_serves(self):
        cases = {
            "2024-01-15T12:34:56.123456Z": (2024, 1, 15),
            "2024-01-15T12:34:56Z": (2024, 1, 15),
            "2024-01-15T12:34:56": (2024, 1, 15),
            "2024-01-15T12:34:56+00:00": (2024, 1, 15),
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                parsed = _parse_pypi_time(raw)
                self.assertIsNotNone(parsed, raw)
                self.assertEqual(
                    (parsed.year, parsed.month, parsed.day), expected)

    def test_every_parsed_time_is_timezone_aware(self):
        """
        A naive datetime compared against an aware one raises TypeError, and
        the staleness check compares against now(timezone.utc).
        """
        for raw in ("2024-01-15T12:34:56.123456Z", "2024-01-15T12:34:56"):
            with self.subTest(raw=raw):
                self.assertIsNotNone(_parse_pypi_time(raw).tzinfo)

    def test_junk_returns_none_rather_than_raising(self):
        for raw in ("", "not a date", "15/01/2024"):
            with self.subTest(raw=raw):
                self.assertIsNone(_parse_pypi_time(raw))


class TestModelAlternatives(unittest.TestCase):
    def test_pickle_only_is_told_to_move_to_safetensors(self):
        alts = recommend_model_alternatives({
            "model_id": "org/model",
            "files": ["pytorch_model.bin", "config.json"],
        })
        self.assertEqual(len(alts), 1)
        self.assertIn("safetensors", alts[0]["target"])
        self.assertIn("Replace", alts[0]["reason"])

    def test_a_mixed_repo_is_told_to_prefer_safetensors(self):
        alts = recommend_model_alternatives({
            "model_id": "org/model",
            "files": ["pytorch_model.bin", "model.safetensors"],
        })
        self.assertEqual(len(alts), 1)
        self.assertIn("Prefer", alts[0]["reason"])

    def test_a_safetensors_only_repo_needs_no_advice(self):
        alts = recommend_model_alternatives({
            "model_id": "org/model", "files": ["model.safetensors"]})
        self.assertEqual(alts, [])

    def test_siblings_dicts_are_understood(self):
        """model_checker and the Hub both hand back list[dict]."""
        alts = recommend_model_alternatives({
            "model_id": "org/model",
            "siblings": [{"rfilename": "pytorch_model.bin"},
                         {"filename": "config.json"}],
        })
        self.assertEqual(len(alts), 1)

    def test_the_has_safetensors_flag_is_honoured(self):
        alts = recommend_model_alternatives({
            "model_id": "org/model",
            "files": ["pytorch_model.bin"],
            "has_safetensors": True,
        })
        self.assertIn("Prefer", alts[0]["reason"])

    def test_a_critical_issue_suggests_a_different_model(self):
        alts = recommend_model_alternatives({
            "model_id": "org/model",
            "files": ["model.safetensors"],
            "issues": [{"type": "cve", "severity": "critical"}],
            "suggested_models": ["org/safe-model"],
        })
        targets = [a["target"] for a in alts]
        self.assertIn("org/safe-model (safetensors)", targets)

    def test_suggested_models_may_be_dicts(self):
        alts = recommend_model_alternatives({
            "model_id": "org/model",
            "issues": [{"type": "malicious", "severity": "high"}],
            "suggested_models": [{"model_id": "org/other", "reason": "audited"}],
        })
        self.assertEqual(alts[-1]["reason"], "audited")

    def test_a_blocked_license_alone_triggers_a_recommendation(self):
        alts = recommend_model_alternatives({
            "model_id": "org/openrail-model",
            "files": ["model.safetensors"],
            "license_blocked": True,
            "task": "text-generation",
        })
        self.assertEqual(len(alts), 1)
        self.assertIn("text-generation", alts[0]["target"])

    def test_the_generic_fallback_appears_when_no_candidates_are_known(self):
        alts = recommend_model_alternatives({
            "model_id": "org/model", "is_malicious": True})
        self.assertEqual(len(alts), 1)
        self.assertIn("clean-safetensors", alts[0]["target"])

    def test_a_model_with_no_identifiable_name_still_works(self):
        alts = recommend_model_alternatives({"files": ["weights.pt"]})
        self.assertIn("unknown-model", alts[0]["target"])

    def test_a_low_severity_cve_is_not_treated_as_critical(self):
        alts = recommend_model_alternatives({
            "model_id": "org/model",
            "files": ["model.safetensors"],
            "issues": [{"type": "cve", "severity": "low"}],
        })
        self.assertEqual(alts, [])

    def test_every_recommendation_is_suggested_never_confirmed(self):
        """
        These are judgement calls about which model to use, not mechanical
        fixes like a version bump. Labelling them "confirmed" would tell a
        user the tool had verified an alternative it never looked at.
        """
        alts = recommend_model_alternatives({
            "model_id": "org/model",
            "files": ["pytorch_model.bin"],
            "is_malicious": True,
            "suggested_models": ["org/a", {"model_id": "org/b"}],
        })
        self.assertTrue(alts)
        self.assertTrue(all(a["confidence"] == "suggested" for a in alts))


class TestEngineOrchestration(unittest.TestCase):
    def _engine(self, info):
        client = MagicMock()
        client.get_package.return_value = info
        return RecommendationEngine(pypi_client=client)

    def test_cve_issues_are_merged_and_typed(self):
        engine = self._engine(PyPIPackageInfo(name="requests", exists=True,
                                              latest_version="2.34.2"))
        result = engine.analyze_package(
            "requests", "2.28.0", cve_issues=[{"id": "GHSA-x", "severity": "high"}])

        cves = [i for i in result["issues"] if i["type"] == "cve"]
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["id"], "GHSA-x")

    def test_a_cve_produces_a_confirmed_upgrade_target(self):
        engine = self._engine(PyPIPackageInfo(name="requests", exists=True,
                                              latest_version="2.34.2"))
        result = engine.analyze_package(
            "requests", "2.28.0", cve_issues=[{"id": "GHSA-x", "severity": "high"}])

        upgrades = [a for a in result["alternatives"]
                    if a["confidence"] == "confirmed"]
        self.assertTrue(upgrades, result["alternatives"])
        self.assertIn("2.34.2", upgrades[0]["target"])

    def test_skip_pypi_avoids_the_network_entirely(self):
        client = MagicMock()
        engine = RecommendationEngine(pypi_client=client)
        engine.analyze_package("requests", "2.28.0", skip_pypi=True)
        client.get_package.assert_not_called()

    def test_skip_pypi_leaves_existence_unknown_rather_than_assumed(self):
        """
        Without a lookup the package's existence is unknown. Typosquatting
        detection is told that explicitly instead of being handed False,
        which would read as "this package does not exist".
        """
        client = MagicMock()
        engine = RecommendationEngine(pypi_client=client)
        result = engine.analyze_package("reqeusts", skip_pypi=True)
        hallucinations = [i for i in result["issues"]
                          if i["type"] == "hallucination"]
        self.assertEqual(hallucinations, [])

    def test_analyze_model_passes_upstream_issues_through_untouched(self):
        engine = RecommendationEngine(pypi_client=MagicMock())
        upstream = [{"type": "malicious", "severity": "critical", "id": "PS-1"}]
        result = engine.analyze_model({
            "model_id": "org/model",
            "files": ["pytorch_model.bin"],
            "issues": upstream,
        })
        self.assertEqual(result["issues"], upstream)
        self.assertTrue(result["alternatives"])

    def test_analyze_model_never_calls_pypi(self):
        client = MagicMock()
        RecommendationEngine(pypi_client=client).analyze_model({"model_id": "x"})
        client.get_package.assert_not_called()


class TestAsyncBatch(unittest.TestCase):
    def test_a_batch_returns_one_result_per_requested_package(self):
        infos = {
            "requests": PyPIPackageInfo(name="requests", exists=True,
                                        latest_version="2.34.2"),
            "ghost-pkg": PyPIPackageInfo(name="ghost-pkg", exists=False),
        }

        client = MagicMock()

        async def fake_aget_packages(names, concurrency=8):
            return {n: infos[n] for n in names}

        client.aget_packages = fake_aget_packages
        engine = RecommendationEngine(pypi_client=client)

        out = asyncio.run(engine.aanalyze_packages(
            [("requests", "2.28.0"), ("ghost-pkg", None)]))

        self.assertEqual(set(out), {"requests", "ghost-pkg"})
        ghost_types = [i["type"] for i in out["ghost-pkg"]["issues"]]
        self.assertIn("hallucination", ghost_types)

    def test_concurrency_is_bounded(self):
        """
        The throttle keeps a large requirements.txt from opening one
        connection per line.

        Each call sleeps so the lookups genuinely overlap - without that the
        peak is 1 whatever the semaphore does - and the counter is locked
        because asyncio.to_thread uses real threads.
        """
        lock = threading.Lock()
        in_flight = 0
        peak = 0

        def slow_get(name):
            nonlocal in_flight, peak
            with lock:
                in_flight += 1
                peak = max(peak, in_flight)
            time.sleep(0.02)
            with lock:
                in_flight -= 1
            return PyPIPackageInfo(name=name, exists=True)

        client = PyPIClient(session=MagicMock())
        with patch.object(client, "get_package", side_effect=slow_get):
            asyncio.run(client.aget_packages([f"pkg{i}" for i in range(20)],
                                             concurrency=4))

        # Overlap really happened, so the ceiling below is a real constraint.
        self.assertGreater(peak, 1, "no overlap - this test proves nothing")
        self.assertLessEqual(peak, 4)


if __name__ == "__main__":
    unittest.main()
