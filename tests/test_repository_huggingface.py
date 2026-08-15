"""
The Hugging Face path of repository_checker.

It reads the Hub API's JSON to decide what license a model declares, whether
the revision is pinned, and which weight files carry a hash for the SBOM.
Each becomes a claim in the report, so the tests cover fields arriving in
unexpected shapes as well as the happy path.

Network is mocked throughout.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from aibom_guardian.repository_checker import RepositoryChecker

FIXED_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)
SHA = "c" * 64
COMMIT = "d" * 40


def _response(status: int = 200, json_data=None, text: str = ""):
    resp = MagicMock()
    resp.status_code = status
    resp.is_redirect = False
    resp.headers = {}
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("no json")
    return resp


def _model_payload(**overrides):
    payload = {
        "sha": COMMIT,
        "author": "google-bert",
        "lastModified": "2026-02-01T00:00:00.000Z",
        "downloads": 1234,
        "likes": 56,
        "cardData": {"license": "apache-2.0"},
        "siblings": [
            {"rfilename": "config.json"},
            {"rfilename": "model.safetensors",
             "lfs": {"sha256": SHA, "size": 440_000_000}},
            {"rfilename": "README.md"},
        ],
    }
    payload.update(overrides)
    return payload


class HuggingFaceTestCase(unittest.TestCase):
    def setUp(self):
        self.checker = RepositoryChecker(timeout=2.0, now=FIXED_NOW)
        self.github_patch = patch.object(
            self.checker, "check_github_repository",
            return_value={"available": True, "issues": [], "errors": []},
        )
        self.github_patch.start()
        self.addCleanup(self.github_patch.stop)

    def check(self, payload, *, status=200, readme="", readme_status=200, **kwargs):
        api_response = _response(status, payload)
        readme_response = _response(readme_status, text=readme)
        with patch.object(self.checker.http, "get_json",
                          return_value=(payload, api_response, None)), \
             patch.object(self.checker.http, "get_text",
                          return_value=(readme, readme_response, None)):
            return self.checker.check_huggingface_repository(
                "google-bert/bert-base-uncased", **kwargs)


class TestAccessFailures(HuggingFaceTestCase):
    def test_a_missing_repo_is_unavailable(self):
        result = self.check(None, status=404)
        self.assertFalse(result["available"])
        self.assertEqual(result["errors"][0]["code"], "not_found")

    def test_a_gated_repo_without_a_token_says_so(self):
        """
        401/403 on the Hub usually means gated or private, not broken. The
        distinction matters: the user's fix is to accept a license or set
        HF_TOKEN, and a generic "http error" would not tell them that.
        """
        result = self.check(None, status=403)
        self.assertFalse(result["available"])
        self.assertEqual(result["errors"][0]["code"], "auth_required")

    def test_a_gated_repo_with_a_token_reports_a_permission_problem(self):
        self.checker.hf_token = "hf_dummy"
        result = self.check(None, status=401)
        self.assertEqual(result["errors"][0]["code"], "forbidden")

    def test_a_transport_error_is_reported(self):
        err = {"category": "http", "code": "timeout", "detail": "timed out",
               "retryable": True}
        with patch.object(self.checker.http, "get_json",
                          return_value=(None, None, err)):
            result = self.checker.check_huggingface_repository("org/model")

        self.assertFalse(result["available"])
        self.assertEqual(result["errors"][0]["source"], "huggingface")

    def test_a_200_with_a_non_object_body_is_not_trusted(self):
        api_response = _response(200, ["nope"])
        with patch.object(self.checker.http, "get_json",
                          return_value=(["nope"], api_response, None)):
            result = self.checker.check_huggingface_repository("org/model")

        self.assertFalse(result["available"])
        self.assertEqual(result["errors"][0]["code"], "http_error")


class TestLicenseReading(HuggingFaceTestCase):
    def test_license_comes_from_card_data(self):
        result = self.check(_model_payload())
        self.assertEqual(result["huggingface"]["license"], "apache-2.0")

    def test_a_list_valued_license_takes_the_first_entry(self):
        """The Hub serves this as a list for some repos."""
        payload = _model_payload(cardData={"license": ["mit", "apache-2.0"]})
        result = self.check(payload)
        self.assertEqual(result["huggingface"]["license"], "mit")

    def test_an_empty_license_list_is_not_a_license(self):
        payload = _model_payload(cardData={"license": []})
        result = self.check(payload)
        self.assertIsNone(result["huggingface"]["license"])

    def test_placeholder_licenses_are_rejected(self):
        """
        "other", "unknown" and "none" are what the Hub form leaves behind when
        nobody chose. Passing them through would let license_checker grade a
        placeholder as if it were a declaration.
        """
        for value in ("other", "unknown", "none", "n/a", "NULL"):
            with self.subTest(value=value):
                result = self.check(_model_payload(cardData={"license": value}))
                self.assertIsNone(result["huggingface"]["license"])

    def test_a_malformed_card_data_field_does_not_crash(self):
        result = self.check(_model_payload(cardData="apache-2.0"))
        self.assertTrue(result["available"])
        self.assertIsNone(result["huggingface"]["license"])


class TestRevisionPinning(HuggingFaceTestCase):
    def test_no_revision_is_an_unpinned_branch(self):
        """
        A branch moves. If the report says "main" and the weights change an
        hour later, the report describes files that no longer exist.
        """
        result = self.check(_model_payload())
        hf = result["huggingface"]
        self.assertEqual(hf["requested_revision"], "main")
        self.assertEqual(hf["revision_type"], "branch")
        self.assertFalse(hf["revision_pinned"])

    def test_a_commit_sha_is_pinned(self):
        result = self.check(_model_payload(), revision=COMMIT)
        hf = result["huggingface"]
        self.assertEqual(hf["requested_revision"], COMMIT)
        self.assertTrue(hf["revision_pinned"])

    def test_a_named_branch_is_not_pinned(self):
        result = self.check(_model_payload(), revision="main")
        self.assertFalse(result["huggingface"]["revision_pinned"])

    def test_the_resolved_commit_is_recorded_alongside_the_request(self):
        result = self.check(_model_payload(), revision="main")
        self.assertEqual(result["huggingface"]["resolved_revision"], COMMIT)


class TestFileSummary(HuggingFaceTestCase):
    def test_weight_files_and_hashes_are_counted(self):
        result = self.check(_model_payload())
        files = result["huggingface"]["files"]
        self.assertEqual(files["total_files"], 3)
        self.assertEqual(files["model_files"], 1)
        self.assertEqual(files["files_with_hash"], 1)

    def test_lfs_hashes_become_published_hashes(self):
        result = self.check(_model_payload())
        self.assertEqual(
            result["published_hashes"],
            [{"hash": SHA, "source": "huggingface_lfs", "name": "model.safetensors"}],
        )

    def test_every_weight_extension_is_recognised(self):
        payload = _model_payload(siblings=[
            {"rfilename": f"weights{ext}"}
            for ext in (".bin", ".safetensors", ".pt", ".pth", ".onnx", ".gguf", ".h5")
        ] + [{"rfilename": "notes.txt"}])
        result = self.check(payload)
        self.assertEqual(result["huggingface"]["files"]["model_files"], 7)

    def test_malformed_siblings_are_skipped_not_fatal(self):
        payload = _model_payload(siblings=[
            "not-a-dict",
            {"rfilename": "model.safetensors", "lfs": "not-a-dict"},
            {"rfilename": "good.bin", "lfs": {"sha256": SHA}},
        ])
        result = self.check(payload)
        files = result["huggingface"]["files"]
        self.assertEqual(files["total_files"], 2)
        self.assertEqual(files["files_with_hash"], 1)

    def test_hash_samples_are_capped(self):
        payload = _model_payload(siblings=[
            {"rfilename": f"shard-{i}.safetensors", "lfs": {"sha256": SHA}}
            for i in range(40)
        ])
        result = self.check(payload)
        self.assertEqual(len(result["published_hashes"]), 20)
        self.assertEqual(result["huggingface"]["files"]["files_with_hash"], 40)


class TestDatasetDocumentation(HuggingFaceTestCase):
    def test_a_dataset_without_a_card_is_flagged(self):
        result = self.check(_model_payload(cardData={}), repo_type="dataset",
                            readme="", readme_status=404)
        details = [i["detail"] for i in result["issues"]]
        self.assertTrue(any("card" in d for d in details), details)
        self.assertTrue(any("license not documented" in d for d in details), details)

    def test_a_documented_dataset_raises_no_documentation_issues(self):
        readme = """# Corpus

## License
cc-by-4.0

## Data Sources
Collected from https://example.org/archive.

## Data Collection
Documents were gathered by a curated crawl.

## Preprocessing
Text was filtered and normalised.
"""
        result = self.check(_model_payload(cardData={"license": "cc-by-4.0"}),
                            repo_type="dataset", readme=readme)
        dataset_issues = [i for i in result["issues"] if i["type"] == "dataset"]
        self.assertEqual(dataset_issues, [])

    def test_a_model_repo_is_not_asked_for_dataset_documentation(self):
        result = self.check(_model_payload(), repo_type="model")
        self.assertFalse(result["dataset"]["checked"])
        self.assertEqual([i for i in result["issues"] if i["type"] == "dataset"], [])


class TestLinkedRepository(HuggingFaceTestCase):
    def test_a_card_repository_field_is_followed(self):
        payload = _model_payload(
            cardData={"license": "apache-2.0",
                      "repository": "https://github.com/google-research/bert"})
        result = self.check(payload)
        self.assertEqual(result["github_repository"], "google-research/bert")

    def test_a_repository_named_only_in_the_readme_is_found(self):
        """
        The trailing full stop is the point of this test. A repo name may
        legitimately contain dots, so the URL pattern allows them - which made
        a URL at the end of a sentence resolve to "bert.", 404 on the API, and
        get reported as "could not locate source repository".
        """
        readme = "Code lives at https://github.com/google-research/bert."
        result = self.check(_model_payload(), readme=readme)
        self.assertEqual(result["github_repository"], "google-research/bert")

    def test_a_dotted_repository_name_survives(self):
        """The other half: psf/requests.oauthlib is a real name."""
        readme = "See https://github.com/requests/requests.oauthlib for details."
        result = self.check(_model_payload(), readme=readme)
        self.assertEqual(result["github_repository"], "requests/requests.oauthlib")

    def test_conflicting_candidates_are_reported_rather_than_guessed(self):
        readme = ("See https://github.com/org-one/repo-a and also "
                  "https://github.com/org-two/repo-b for details.")
        result = self.check(_model_payload(), readme=readme)

        self.assertIsNone(result["github_repository"])
        ambiguous = [i for i in result["issues"]
                     if i["detail"] == "ambiguous_repository_source"]
        self.assertEqual(len(ambiguous), 1)


class TestMergeIntoResult(HuggingFaceTestCase):
    def _blank_result(self):
        return {"issues": [], "errors": [], "provenance_detail": {},
                "repository": {}, "dataset": None}

    def test_revision_details_reach_provenance(self):
        result = self._blank_result()
        api_response = _response(200, _model_payload())
        readme_response = _response(404, text="")
        with patch.object(self.checker.http, "get_json",
                          return_value=(_model_payload(), api_response, None)), \
             patch.object(self.checker.http, "get_text",
                          return_value=("", readme_response, None)):
            self.checker._merge_huggingface(result, "org/model",
                                            repo_type="model", revision=COMMIT)

        provenance = result["provenance_detail"]
        self.assertEqual(provenance["requested_revision"], COMMIT)
        self.assertEqual(provenance["resolved_revision"], COMMIT)
        self.assertTrue(provenance["revision_pinned"])

    def test_a_failed_lookup_contributes_errors_and_nothing_else(self):
        result = self._blank_result()
        api_response = _response(404, None)
        with patch.object(self.checker.http, "get_json",
                          return_value=(None, api_response, None)):
            self.checker._merge_huggingface(result, "org/missing",
                                            repo_type="model", revision=None)

        self.assertEqual(result["errors"][0]["code"], "not_found")
        self.assertNotIn("huggingface", result)


if __name__ == "__main__":
    unittest.main()
