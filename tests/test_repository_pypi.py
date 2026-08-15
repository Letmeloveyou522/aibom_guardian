"""
The PyPI path of repository_checker.

It parses a document served by a third party and decides from it whether a
package's source can be located and which artifacts have published hashes, so
the tests cover malformed and missing fields as well as the happy path.

Network is mocked throughout.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from aibom_guardian.repository_checker import RepositoryChecker

FIXED_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)

SHA_A = "a" * 64
SHA_B = "b" * 64


def _response(status: int = 200, json_data=None):
    resp = MagicMock()
    resp.status_code = status
    resp.is_redirect = False
    resp.headers = {}
    resp.text = ""
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("no json")
    return resp


def _pypi_payload(**overrides):
    """A minimal but realistic /pypi/<name>/json body."""
    payload = {
        "info": {
            "version": "2.31.0",
            "summary": "Python HTTP for Humans.",
            "license": "Apache-2.0",
            "home_page": "https://requests.readthedocs.io",
            "project_urls": {"Source": "https://github.com/psf/requests"},
        },
        "releases": {
            "2.31.0": [
                {"filename": "requests-2.31.0-py3-none-any.whl",
                 "digests": {"sha256": SHA_A}},
                {"filename": "requests-2.31.0.tar.gz",
                 "digests": {"sha256": SHA_B}},
            ],
            "2.28.0": [
                {"filename": "requests-2.28.0-py3-none-any.whl",
                 "digests": {"sha256": SHA_B}},
            ],
        },
        "urls": [],
    }
    payload.update(overrides)
    return payload


class PyPIMixinTestCase(unittest.TestCase):
    def setUp(self):
        self.checker = RepositoryChecker(timeout=2.0, now=FIXED_NOW)
        # The GitHub half has its own tests; stub it so these assertions are
        # about the PyPI parsing and not about two subsystems at once.
        self.github_patch = patch.object(
            self.checker, "check_github_repository",
            return_value={"available": True, "issues": [], "errors": [],
                          "github_star": 50000, "repository": {"license": None}},
        )
        self.github_patch.start()
        self.addCleanup(self.github_patch.stop)

    def check(self, payload, status=200, **kwargs):
        response = _response(status, payload)
        with patch.object(self.checker.http, "get_json",
                          return_value=(payload, response, None)):
            return self.checker.check_pypi_package("requests", **kwargs)


class TestLookupFailures(PyPIMixinTestCase):
    def test_a_missing_package_is_unavailable_not_an_exception(self):
        response = _response(404, None)
        with patch.object(self.checker.http, "get_json",
                          return_value=(None, response, None)):
            result = self.checker.check_pypi_package("no-such-package-xyz")

        self.assertFalse(result["available"])
        self.assertEqual(result["errors"][0]["code"], "not_found")

    def test_a_transport_error_is_reported_not_swallowed(self):
        err = {"category": "http", "code": "timeout", "detail": "timed out",
               "retryable": True}
        with patch.object(self.checker.http, "get_json",
                          return_value=(None, None, err)):
            result = self.checker.check_pypi_package("requests")

        self.assertFalse(result["available"])
        self.assertEqual(result["errors"][0]["code"], "timeout")
        self.assertEqual(result["errors"][0]["source"], "pypi")

    def test_a_200_carrying_a_non_object_body_is_not_trusted(self):
        """
        A 200 with a JSON list, or a string, is not a package description.
        Reading .get() off it would raise; treating it as empty would invent
        a package with no files and no source.
        """
        response = _response(200, ["unexpected"])
        with patch.object(self.checker.http, "get_json",
                          return_value=(["unexpected"], response, None)):
            result = self.checker.check_pypi_package("requests")

        self.assertFalse(result["available"])
        self.assertEqual(result["errors"][0]["code"], "not_found")


class TestVersionSelection(PyPIMixinTestCase):
    def test_an_explicit_version_selects_that_release(self):
        result = self.check(_pypi_payload(), version="2.28.0")
        self.assertEqual(result["pypi"]["version"], "2.28.0")
        self.assertTrue(result["pypi"]["version_pinned"])
        self.assertEqual(result["pypi"]["file_count"], 1)

    def test_no_version_falls_back_to_the_latest_and_says_it_is_unpinned(self):
        result = self.check(_pypi_payload())

        self.assertEqual(result["pypi"]["version"], "2.31.0")
        self.assertFalse(result["pypi"]["version_pinned"])
        codes = [i["detail"] for i in result["issues"]]
        self.assertTrue(any("not pinned" in c for c in codes),
                        f"expected an unpinned-version issue, got {codes}")

    def test_an_unpinned_lookup_reports_no_pinning_issue(self):
        """The inverse: pinning must not produce the warning."""
        result = self.check(_pypi_payload(), version="2.31.0")
        details = [i["detail"] for i in result["issues"]]
        self.assertFalse(any("not pinned" in d for d in details), details)

    def test_a_version_absent_from_releases_yields_no_files(self):
        result = self.check(_pypi_payload(), version="9.9.9")
        self.assertEqual(result["pypi"]["version"], "9.9.9")
        self.assertEqual(result["pypi"]["file_count"], 0)
        self.assertEqual(result["published_hashes"], [])


class TestPublishedHashes(PyPIMixinTestCase):
    def test_every_sha256_is_collected(self):
        result = self.check(_pypi_payload(), version="2.31.0")
        hashes = {h["hash"] for h in result["published_hashes"]}
        self.assertEqual(hashes, {SHA_A, SHA_B})
        self.assertTrue(all(h["source"] == "pypi" for h in result["published_hashes"]))

    def test_a_named_artifact_is_matched_to_its_published_hash(self):
        result = self.check(
            _pypi_payload(), version="2.31.0",
            artifact_filename="requests-2.31.0.tar.gz",
        )
        self.assertEqual(result["pypi"]["matched_file_sha256"], SHA_B)

    def test_a_local_file_name_is_used_when_no_artifact_name_is_given(self):
        result = self.check(
            _pypi_payload(), version="2.31.0",
            local_file="/downloads/requests-2.31.0-py3-none-any.whl",
        )
        self.assertEqual(result["pypi"]["matched_file_sha256"], SHA_A)

    def test_an_unmatched_artifact_name_does_not_borrow_another_hash(self):
        """
        Reporting some other file's hash for the artifact under inspection
        would be worse than reporting none: it reads as a verified match.
        """
        result = self.check(
            _pypi_payload(), version="2.31.0",
            artifact_filename="requests-9.9.9.tar.gz",
        )
        self.assertIsNone(result["pypi"]["matched_file_sha256"])

    def test_files_without_digests_are_skipped_not_fatal(self):
        payload = _pypi_payload()
        payload["releases"]["2.31.0"] = [
            {"filename": "broken.whl"},
            {"filename": "broken2.whl", "digests": {}},
            "not-even-a-dict",
            {"filename": "good.whl", "digests": {"sha256": SHA_A}},
        ]
        result = self.check(payload, version="2.31.0")
        self.assertEqual([h["hash"] for h in result["published_hashes"]], [SHA_A])


class TestSourceRepositoryDiscovery(PyPIMixinTestCase):
    def test_a_project_url_locates_the_repository(self):
        result = self.check(_pypi_payload(), version="2.31.0")
        self.assertEqual(result["github_repository"], "psf/requests")

    def test_home_page_is_searched_when_project_urls_has_nothing(self):
        payload = _pypi_payload()
        payload["info"]["project_urls"] = {}
        payload["info"]["home_page"] = "https://github.com/psf/requests"
        result = self.check(payload, version="2.31.0")
        self.assertEqual(result["github_repository"], "psf/requests")

    def test_no_locatable_source_is_a_high_severity_issue(self):
        """
        A package whose source cannot be found cannot be reviewed at all, so
        this is reported rather than left as a quiet null.
        """
        payload = _pypi_payload()
        payload["info"]["project_urls"] = {"Docs": "https://example.org/docs"}
        payload["info"]["home_page"] = None

        result = self.check(payload, version="2.31.0")

        self.assertIsNone(result["github_repository"])
        repo_issues = [i for i in result["issues"] if i["type"] == "repository"]
        self.assertEqual(len(repo_issues), 1)
        self.assertEqual(repo_issues[0]["severity"], "high")

    def test_a_malformed_project_urls_field_does_not_crash(self):
        payload = _pypi_payload()
        payload["info"]["project_urls"] = "https://github.com/psf/requests"
        result = self.check(payload, version="2.31.0")
        self.assertEqual(result["pypi"]["project_urls"], {})


class TestMergeIntoResult(PyPIMixinTestCase):
    def _blank_result(self):
        return {"issues": [], "errors": [], "repository": {}}

    def test_license_survives_when_there_is_no_github_repository(self):
        """
        PyPI metadata is the only license source for a package with no
        locatable repository. Dropping it there would turn a declared license
        into UNKNOWN for exactly the packages that are hardest to review.
        """
        payload = _pypi_payload()
        payload["info"]["project_urls"] = {}
        payload["info"]["home_page"] = None

        result = self._blank_result()
        response = _response(200, payload)
        with patch.object(self.checker.http, "get_json",
                          return_value=(payload, response, None)):
            self.checker._merge_pypi(result, "requests", version="2.31.0",
                                     local_file=None, artifact_filename=None)

        self.assertEqual(result["repository"]["license"], "Apache-2.0")
        self.assertEqual(result["repository"]["provider"], "pypi")

    def test_a_failed_lookup_still_contributes_its_errors(self):
        result = self._blank_result()
        response = _response(404, None)
        with patch.object(self.checker.http, "get_json",
                          return_value=(None, response, None)):
            self.checker._merge_pypi(result, "nope", version=None,
                                     local_file=None, artifact_filename=None)

        self.assertEqual(result["errors"][0]["code"], "not_found")
        self.assertNotIn("pypi", result)


if __name__ == "__main__":
    unittest.main()
