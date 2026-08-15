"""
tests/test_repository_checker.py
-----------------------------------
Unit tests for repository_checker.py.
All network calls are mocked — no real external API traffic.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from aibom_guardian.repository_checker import (
    RepositoryChecker,
    SSRFError,
    calculate_sha256,
    calculate_trust_score,
    check_dataset_documentation,
    check_repository,
    detect_target_type,
    estimate_maintainers_from_contributors,
    evaluate_provenance,
    parse_codeowners,
    validate_public_url,
)


FIXED_NOW = datetime(2026, 7, 26, tzinfo=timezone.utc)


def _response(status: int = 200, json_data=None, text: str = "", headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.is_redirect = False
    resp.headers = headers or {}
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("no json")
    return resp


class TestTargetParsing(unittest.TestCase):
    def test_github_url(self):
        d = detect_target_type("https://github.com/owner/repo")
        self.assertEqual(d["type"], "github")
        self.assertEqual(d["normalized"], "owner/repo")

    def test_git_suffix_removed(self):
        d = detect_target_type("https://github.com/owner/repo.git")
        self.assertEqual(d["name"], "repo")
        self.assertEqual(d["normalized"], "owner/repo")

    def test_owner_repo_with_explicit_type(self):
        d = detect_target_type("owner/repo", "github")
        self.assertEqual(d["type"], "github")
        self.assertEqual(d["owner"], "owner")

    def test_commit_sha_in_url(self):
        sha = "a" * 40
        d = detect_target_type(f"https://github.com/owner/repo/commit/{sha}")
        self.assertEqual(d["revision"], sha)

    def test_branch_not_pinned(self):
        _type, pinned = __import__(
            "aibom_guardian.repository_checker", fromlist=["_classify_revision"]
        )._classify_revision("main")
        self.assertEqual(_type, "branch")
        self.assertFalse(pinned)

    def test_hf_model_url(self):
        d = detect_target_type("https://huggingface.co/namespace/model")
        self.assertEqual(d["type"], "hf_model")
        self.assertEqual(d["normalized"], "namespace/model")

    def test_hf_dataset_url(self):
        d = detect_target_type("https://huggingface.co/datasets/namespace/dataset")
        self.assertEqual(d["type"], "hf_dataset")
        self.assertEqual(d["normalized"], "namespace/dataset")

    def test_pypi_version_pin(self):
        d = detect_target_type("requests==2.31.0")
        self.assertEqual(d["type"], "pypi")
        self.assertEqual(d["version"], "2.31.0")
        self.assertTrue(d["version_pinned"])

    def test_ambiguous_owner_repo(self):
        d = detect_target_type("owner/repo")
        self.assertEqual(d["type"], "ambiguous")
        self.assertTrue(any(i["detail"].startswith("ambiguous_target") for i in d["issues"]))


class TestSSRF(unittest.TestCase):
    def test_localhost_blocked(self):
        with self.assertRaises(SSRFError):
            validate_public_url("https://localhost/secret")

    def test_private_ip_blocked(self):
        with self.assertRaises(SSRFError):
            validate_public_url("https://127.0.0.1/x")

    def test_http_blocked(self):
        with self.assertRaises(SSRFError):
            validate_public_url("http://github.com/owner/repo")

    def test_allowlisted_host_ok(self):
        # May fail DNS in offline envs — mock getaddrinfo
        with patch("aibom_guardian.repository_checker.socket.getaddrinfo") as gai:
            gai.return_value = [(None, None, None, None, ("1.1.1.1", 443))]
            url = validate_public_url("https://api.github.com/repos/o/r")
            self.assertTrue(url.startswith("https://"))

    def test_redirect_host_revalidated(self):
        checker = RepositoryChecker(timeout=1.0, now=FIXED_NOW)
        call_count = {"n": 0}

        def fake_get(url, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                resp = MagicMock()
                resp.status_code = 302
                resp.is_redirect = True
                resp.headers = {"Location": "https://127.0.0.1/evil"}
                return resp
            return _response(200, {"ok": True})

        with patch.object(checker.http.session, "get", side_effect=fake_get):
            with patch("aibom_guardian.repository_checker.socket.getaddrinfo") as gai:
                gai.return_value = [(None, None, None, None, ("140.82.112.3", 443))]
                data, resp, err = checker.http.get_json("https://api.github.com/repos/o/r")
        self.assertIsNone(data)
        self.assertIsNotNone(err)
        self.assertEqual(err["code"], "ssrf_blocked")


class TestCodeownersAndContributors(unittest.TestCase):
    def test_codeowners_count(self):
        content = """
# comment
* @alice @bob
docs/ @org/docs-team
*.md @alice
"""
        owners = parse_codeowners(content)
        self.assertEqual(len(owners), 3)
        self.assertIn("@alice", owners)
        self.assertIn("@bob", owners)
        self.assertIn("@org/docs-team", owners)

    def test_bot_contributors_excluded(self):
        contributors = [
            {"login": "alice", "contributions": 100, "type": "User"},
            {"login": "dependabot[bot]", "contributions": 90, "type": "Bot"},
            {"login": "renovate", "contributions": 80, "type": "User"},
            {"login": "bob", "contributions": 50, "type": "User"},
            {"login": "carol", "contributions": 2, "type": "User"},
        ]
        count, method = estimate_maintainers_from_contributors(contributors)
        self.assertEqual(method, "contributors_estimate")
        self.assertEqual(count, 2)  # alice + bob


class TestHashAndSignature(unittest.TestCase):
    def test_sha256_match(self):
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"hello-aibom")
            path = tmp.name
        try:
            digest = calculate_sha256(path)
            expected = digest
            checker = RepositoryChecker(now=FIXED_NOW)
            prov = checker.check_provenance(
                local_file=path,
                expected_sha256=expected,
            )
            self.assertTrue(prov["provenance_detail"]["hash_verified"])
        finally:
            Path(path).unlink(missing_ok=True)

    def test_sha256_mismatch(self):
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"hello-aibom")
            path = tmp.name
        try:
            checker = RepositoryChecker(now=FIXED_NOW)
            bad = "0" * 64
            prov = checker.check_provenance(local_file=path, expected_sha256=bad)
            self.assertFalse(prov["provenance_detail"]["hash_verified"])
            self.assertTrue(any(i["severity"] == "critical" for i in prov["issues"]))
        finally:
            Path(path).unlink(missing_ok=True)

    def test_expected_sha_format_error(self):
        checker = RepositoryChecker(now=FIXED_NOW)
        prov = checker.check_provenance(expected_sha256="not-a-hash")
        self.assertTrue(any("not a valid" in i["detail"] for i in prov["issues"]))

    def test_unlistable_directory_does_not_abort_the_scan(self):
        """
        check_provenance enumerates the artifact's siblings to find a detached
        signature. The artifact can sit somewhere the process may read but not
        list, and the unhandled PermissionError aborted the entire scan - the
        suite itself hit this whenever TEMP pointed at a restricted directory.

        Not being able to look must be recorded as unverified, never dropped:
        "no signature found" and "could not check" are different answers.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.whl"
            path.write_bytes(b"payload")

            with patch("aibom_guardian.repository_checker.Path.iterdir",
                       side_effect=PermissionError("access denied")):
                checker = RepositoryChecker(now=FIXED_NOW)
                prov = checker.check_provenance(local_file=str(path))

        self.assertFalse(prov["signature"])
        self.assertTrue(
            any(i["type"] == "unverified" for i in prov["issues"]),
            "an unlistable directory must be reported as unverified",
        )

    def test_signature_present_unverified(self):
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".whl") as tmp:
            tmp.write(b"payload")
            path = tmp.name
        sig = path + ".sig"
        Path(sig).write_text("sig", encoding="utf-8")
        try:
            with patch("aibom_guardian.repository_checker.shutil.which", return_value=None):
                checker = RepositoryChecker(now=FIXED_NOW)
                prov = checker.check_provenance(
                    local_file=path,
                    signature_file=sig,
                )
            self.assertTrue(prov["signature"])
            self.assertFalse(prov["signature_verified"])
            self.assertEqual(prov["provenance_detail"]["signature_status"], "present")
        finally:
            Path(path).unlink(missing_ok=True)
            Path(sig).unlink(missing_ok=True)

    def test_signature_verify_failed(self):
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"payload")
            path = tmp.name
        try:
            fake = MagicMock()
            fake.returncode = 1
            fake.stdout = ""
            fake.stderr = "error verifying"
            with patch("aibom_guardian.repository_checker.shutil.which", return_value="/usr/bin/cosign"):
                with patch("aibom_guardian.repository_checker.subprocess.run", return_value=fake):
                    checker = RepositoryChecker(now=FIXED_NOW)
                    prov = checker.check_provenance(
                        local_file=path,
                        signature_bundle="bundle.json",
                    )
            self.assertEqual(prov["provenance_detail"]["signature_status"], "failed")
            self.assertTrue(any(i["severity"] == "critical" for i in prov["issues"]))
        finally:
            Path(path).unlink(missing_ok=True)


class TestDatasetDocs(unittest.TestCase):
    def test_license_detection(self):
        readme = """---
license: cc-by-4.0
---
# Dataset
"""
        result = check_dataset_documentation(readme, {})
        self.assertTrue(result["license_documented"])
        self.assertEqual(result["license"], "cc-by-4.0")

    def test_source_section(self):
        readme = """# My Data

## Data Source
Data was collected from https://example.org/archive and the original dataset XYZ.

## Other
"""
        result = check_dataset_documentation(readme, {})
        self.assertTrue(result["source_documented"])

    def test_collection_section(self):
        readme = """# Data

## Data Collection
We collected documents via a curated crawl of public forums.

"""
        result = check_dataset_documentation(readme, {})
        self.assertTrue(result["collection_method_documented"])

    def test_card_missing(self):
        result = check_dataset_documentation("", {})
        self.assertFalse(result["card_exists"])
        self.assertIn("license", result["missing_fields"])


class TestGitHubAPI(unittest.TestCase):
    def _checker(self):
        return RepositoryChecker(timeout=2.0, now=FIXED_NOW)

    def test_github_ok_response(self):
        repo_json = {
            "stargazers_count": 100,
            "forks_count": 10,
            "default_branch": "main",
            "created_at": "2021-01-01T00:00:00Z",
            "updated_at": "2026-07-01T00:00:00Z",
            "pushed_at": "2026-07-01T00:00:00Z",
            "archived": False,
            "fork": False,
            "license": {"spdx_id": "MIT"},
            "html_url": "https://github.com/o/r",
            "owner": {"login": "o"},
            "description": "demo",
        }
        commits_json = [{
            "commit": {
                "committer": {"date": "2026-07-15T12:00:00Z"},
                "author": {"date": "2026-07-14T12:00:00Z"},
            }
        }]
        codeowners = "#\n* @alice @bob\n"

        def fake_get_json(url, **kwargs):
            if url.endswith("/repos/o/r"):
                return repo_json, _response(200, repo_json), None
            if "/commits" in url:
                return commits_json, _response(200, commits_json), None
            if url.endswith("/releases/latest"):
                return None, _response(404), None
            if "/contents/" in url:
                if "CODEOWNERS" in url and ".github" in url:
                    data = {"download_url": "https://raw.githubusercontent.com/o/r/main/.github/CODEOWNERS", "encoding": "base64", "content": ""}
                    return data, _response(200, data), None
                return None, _response(404), None
            if "/contributors" in url:
                return [], _response(200, []), None
            return None, _response(404), None

        checker = self._checker()
        with patch.object(checker.http, "get_json", side_effect=fake_get_json):
            with patch.object(checker.http, "get_text", return_value=(codeowners, _response(200, text=codeowners), None)):
                with patch.object(checker, "check_openssf_scorecard", return_value={
                    "available": True, "score": 8.9, "date": "2026-07-15",
                    "commit": "abc", "weak_checks": [], "check_count": 1, "error": None,
                }):
                    result = checker.check_github_repository("o", "r")

        self.assertTrue(result["available"])
        self.assertEqual(result["github_star"], 100)
        self.assertEqual(result["last_commit"], "2026-07-15")
        self.assertIsNone(result["last_release"])
        self.assertEqual(result["maintainer_count"], 2)
        self.assertEqual(result["maintainer_count_method"], "codeowners")
        self.assertEqual(result["openssf_score"], 8.9)

    def test_github_404(self):
        checker = self._checker()
        with patch.object(checker.http, "get_json", return_value=(None, _response(404), None)):
            result = checker.check_github_repository("missing", "repo")
        self.assertFalse(result["available"])
        self.assertTrue(any(e["code"] == "not_found" for e in result["errors"]))

    def test_github_rate_limit(self):
        checker = self._checker()
        resp = _response(403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "999"})
        with patch.object(checker.http, "get_json", return_value=(None, resp, None)):
            result = checker.check_github_repository("o", "r")
        self.assertTrue(any(e["code"] == "rate_limit" for e in result["errors"]))

    def test_release_404_is_ok(self):
        # covered in test_github_ok_response via last_release is None
        self.test_github_ok_response()

    def test_empty_repo_commits(self):
        repo_json = {
            "stargazers_count": 0, "forks_count": 0, "default_branch": "main",
            "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
            "pushed_at": None, "archived": False, "fork": False,
            "license": None, "html_url": "https://github.com/o/r",
            "owner": {"login": "o"}, "description": "",
        }

        def fake_get_json(url, **kwargs):
            if url.endswith("/repos/o/empty"):
                return repo_json, _response(200, repo_json), None
            if "/commits" in url:
                return None, _response(409), None
            if "/releases/latest" in url:
                return None, _response(404), None
            if "/contents/" in url:
                return None, _response(404), None
            if "/contributors" in url:
                return [], _response(200, []), None
            return None, _response(404), None

        checker = self._checker()
        with patch.object(checker.http, "get_json", side_effect=fake_get_json):
            with patch.object(checker, "check_openssf_scorecard", return_value={
                "available": False, "score": None, "date": None, "commit": None,
                "weak_checks": [], "check_count": 0, "error": "scorecard result not available",
            }):
                result = checker.check_github_repository("o", "empty")
        self.assertTrue(result["available"])
        self.assertIsNone(result["last_commit"])
        self.assertTrue(any("no commits" in i["detail"] for i in result["issues"]))


class TestOpenSSF(unittest.TestCase):
    def test_openssf_ok(self):
        payload = {
            "score": 8.9,
            "date": "2026-07-15",
            "commit": "abc",
            "checks": [
                {"name": "Maintained", "score": 10, "reason": "ok", "documentation": {"url": "https://example"}},
                {"name": "Signed-Releases", "score": 2, "reason": "weak", "documentation": {"url": "https://example"}},
            ],
        }
        checker = RepositoryChecker(now=FIXED_NOW)
        with patch.object(checker.http, "get_json", return_value=(payload, _response(200, payload), None)):
            result = checker.check_openssf_scorecard("o", "r")
        self.assertTrue(result["available"])
        self.assertEqual(result["score"], 8.9)
        self.assertEqual(len(result["weak_checks"]), 1)
        self.assertEqual(result["weak_checks"][0]["name"], "Signed-Releases")

    def test_openssf_missing(self):
        checker = RepositoryChecker(now=FIXED_NOW)
        with patch.object(checker.http, "get_json", return_value=(None, _response(404), None)):
            result = checker.check_openssf_scorecard("o", "r")
        self.assertFalse(result["available"])
        self.assertIsNone(result["score"])
        self.assertIn("not available", result["error"])


class TestTrustScoreAndVerdict(unittest.TestCase):
    def test_deterministic(self):
        kwargs = dict(
            archived=False,
            last_commit="2026-07-01",
            last_release="2026-06-01",
            maintainer_count=3,
            maintainer_count_method="codeowners",
            stars=100,
            openssf_score=8.0,
            openssf_available=True,
            revision_pinned=True,
            hash_verified=True,
            signature_status="verified",
            signature_verified=True,
            has_license=True,
            has_readme=True,
            has_codeowners=True,
            issues=[],
            now=FIXED_NOW,
        )
        a = calculate_trust_score(**kwargs)
        b = calculate_trust_score(**kwargs)
        self.assertEqual(a, b)

    def test_critical_blocks(self):
        result = calculate_trust_score(
            issues=[{"type": "hash", "severity": "critical", "detail": "mismatch"}],
            now=FIXED_NOW,
            openssf_available=True,
            openssf_score=9.0,
            revision_pinned=True,
            hash_verified=False,
            archived=False,
            has_license=True,
            has_readme=True,
        )
        self.assertEqual(result["verdict"], "BLOCK")

    def test_low_confidence_conditional(self):
        result = calculate_trust_score(issues=[], now=FIXED_NOW, partial_data=True)
        self.assertEqual(result["verdict"], "WARNING")

    def test_provenance_rules(self):
        ok, status = evaluate_provenance(
            revision_pinned=True, hash_verified=True,
            signature_verified=False, signature_status="not_found",
        )
        self.assertTrue(ok)
        self.assertEqual(status, "partial")


class TestPartialFailureAndJSON(unittest.TestCase):
    def test_partial_result_on_openssf_failure(self):
        repo_json = {
            "stargazers_count": 5, "forks_count": 1, "default_branch": "main",
            "created_at": "2024-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
            "pushed_at": "2026-01-01T00:00:00Z", "archived": False, "fork": False,
            "license": {"spdx_id": "Apache-2.0"}, "html_url": "https://github.com/o/r",
            "owner": {"login": "o"}, "description": "x",
        }
        commits = [{"commit": {"committer": {"date": "2026-01-01T00:00:00Z"}, "author": {}}}]

        def fake_get_json(url, **kwargs):
            if url.endswith("/repos/o/r"):
                return repo_json, _response(200, repo_json), None
            if "/commits" in url:
                return commits, _response(200, commits), None
            if "/releases/latest" in url:
                return None, _response(404), None
            if "/contents/" in url:
                return None, _response(404), None
            if "/contributors" in url:
                return [{"login": "alice", "contributions": 20, "type": "User"}], _response(200), None
            return None, _response(404), None

        checker = RepositoryChecker(now=FIXED_NOW)
        with patch.object(checker.http, "get_json", side_effect=fake_get_json):
            with patch.object(checker, "check_openssf_scorecard", return_value={
                "available": False, "score": None, "date": None, "commit": None,
                "weak_checks": [], "check_count": 0, "error": "scorecard result not available",
            }):
                result = checker.check_github_repository("o", "r")
        self.assertTrue(result["available"])
        self.assertEqual(result["github_star"], 5)
        self.assertIsNone(result["openssf_score"])

    def test_json_serializable_end_to_end(self):
        with patch.object(RepositoryChecker, "check_github_repository") as gh:
            gh.return_value = {
                "available": True,
                "issues": [],
                "errors": [],
                "github_star": 1,
                "github_fork": 0,
                "last_commit": "2026-07-01",
                "last_release": None,
                "maintainer_count": None,
                "maintainer_count_method": "unknown",
                "openssf_score": None,
                "repository": {"provider": "github", "owner": "o", "name": "r",
                               "default_branch": "main", "created_at": "2020-01-01",
                               "updated_at": "2026-07-01", "archived": False,
                               "fork": False, "license": "MIT"},
                "openssf": {"available": False, "score": None, "weak_checks": []},
                "release_assets": [],
                "has_description": True,
            }
            result = check_repository("https://github.com/o/r", timeout=1.0)
        json.dumps(result, ensure_ascii=False)
        self.assertIn("trust_score", result)
        self.assertIn("verdict", result)
        self.assertIn(result["verdict"], ("ALLOW", "WARNING", "BLOCK"))


class TestGitPlusAndClassify(unittest.TestCase):
    def test_git_plus_sha_pinned(self):
        sha = "b" * 40
        d = detect_target_type(f"git+https://github.com/owner/repo.git@{sha}")
        self.assertEqual(d["type"], "github")
        self.assertEqual(d["revision"], sha)
        from aibom_guardian.repository_checker import _classify_revision
        rtype, pinned = _classify_revision(sha)
        self.assertTrue(pinned)
        self.assertEqual(rtype, "commit")


if __name__ == "__main__":
    unittest.main()
