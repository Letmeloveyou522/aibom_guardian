"""
tests/test_mcp_repository_tool.py
-----------------------------------
MCP-layer tests for check_repo_trust.
Network calls are mocked via repository_checker.check_repository.

If the optional ``mcp`` package is not installed, a lightweight FastMCP
stub is injected so tool wrappers can still be unit-tested.
"""

from __future__ import annotations

import json
import sys
import types
import unittest
from unittest.mock import patch


def _install_mcp_stub_if_needed() -> bool:
    """Return True when a stub was installed."""
    try:
        import mcp.server.fastmcp  # noqa: F401
        return False
    except ImportError:
        pass

    class _Tool:
        def __init__(self, name: str, fn):
            self.name = name
            self.fn = fn

    class _ToolManager:
        def __init__(self):
            self._tools = {}

        def add_tool(self, fn, name=None):
            tool_name = name or fn.__name__
            self._tools[tool_name] = _Tool(tool_name, fn)
            return fn

        def list_tools(self):
            return list(self._tools.values())

    class FastMCP:
        def __init__(self, name: str):
            self.name = name
            self._tool_manager = _ToolManager()

        def tool(self, *args, **kwargs):
            def decorator(fn):
                self._tool_manager.add_tool(fn)
                return fn

            if args and callable(args[0]) and not kwargs:
                return decorator(args[0])
            return decorator

        def run(self):
            return None

    mcp_mod = types.ModuleType("mcp")
    server_mod = types.ModuleType("mcp.server")
    fastmcp_mod = types.ModuleType("mcp.server.fastmcp")
    fastmcp_mod.FastMCP = FastMCP
    server_mod.fastmcp = fastmcp_mod
    mcp_mod.server = server_mod
    sys.modules["mcp"] = mcp_mod
    sys.modules["mcp.server"] = server_mod
    sys.modules["mcp.server.fastmcp"] = fastmcp_mod
    return True


_STUBBED = _install_mcp_stub_if_needed()

import mcp_server  # noqa: E402
from mcp_server import (  # noqa: E402
    build_repository_check_summary,
    check_license,
    check_package,
    check_repo_trust,
    mcp,
    validate_check_repo_trust_inputs,
)


def _sample_result(**overrides):
    base = {
        "target": {
            "input": "https://github.com/pallets/flask",
            "type": "github",
            "normalized": "pallets/flask",
        },
        "github_star": 100,
        "github_fork": 10,
        "last_commit": "2026-07-01",
        "last_release": "2026-06-01",
        "maintainer_count": 2,
        "maintainer_count_method": "codeowners",
        "openssf_score": 8.0,
        "provenance": False,
        "signature": False,
        "signature_verified": False,
        "trust_score": 65,
        "verdict": "WARNING",
        "repository": {"provider": "github", "owner": "pallets", "name": "flask"},
        "openssf": {"available": True, "score": 8.0, "weak_checks": []},
        "provenance_detail": {
            "status": "unknown",
            "requested_revision": None,
            "resolved_revision": None,
            "revision_type": None,
            "revision_pinned": False,
            "version_pinned": False,
            "hash_verified": None,
            "signature_status": "not_found",
        },
        "dataset": {"checked": False, "missing_fields": []},
        "score_breakdown": {
            "repository_health": 15,
            "openssf": 24,
            "provenance": 0,
            "transparency": 10,
            "confidence": 0.8,
        },
        "issues": [
            {
                "type": "signature",
                "severity": "medium",
                "detail": "no signature found",
                "evidence": None,
                "recommendation": "verify a signed release or Sigstore bundle",
            }
        ],
        "errors": [],
    }
    base.update(overrides)
    return base


class TestToolRegistration(unittest.TestCase):
    def test_check_repo_trust_registered(self):
        tools = mcp._tool_manager.list_tools()
        names = {t.name for t in tools}
        self.assertIn("check_repo_trust", names)

    def test_existing_tools_still_registered(self):
        tools = mcp._tool_manager.list_tools()
        names = {t.name for t in tools}
        self.assertIn("check_package", names)
        self.assertIn("check_license", names)
        self.assertTrue(callable(check_package))
        self.assertTrue(callable(check_license))


class TestCheckRepoTrustMCP(unittest.TestCase):
    def test_github_target(self):
        sample = _sample_result()
        with patch.object(mcp_server, "check_repository", return_value=sample) as mocked:
            result = check_repo_trust("https://github.com/pallets/flask")
        mocked.assert_called_once()
        self.assertTrue(result["success"])
        self.assertEqual(result["tool"], "check_repo_trust")
        self.assertEqual(result["trust_score"], 65)
        self.assertEqual(result["verdict"], "WARNING")
        self.assertIn("summary", result)

    def test_pypi_versioned_target(self):
        sample = _sample_result(
            target={
                "input": "requests==2.31.0",
                "type": "pypi",
                "normalized": "requests",
            },
            provenance_detail={
                "status": "unknown",
                "revision_pinned": False,
                "version_pinned": True,
                "hash_verified": None,
                "signature_status": "not_found",
            },
        )
        with patch.object(mcp_server, "check_repository", return_value=sample) as mocked:
            result = check_repo_trust("requests==2.31.0")
        args, kwargs = mocked.call_args
        self.assertEqual(args[0], "requests==2.31.0")
        self.assertEqual(kwargs.get("target_type"), "auto")
        self.assertEqual(result["target"]["type"], "pypi")

    def test_target_type_passed(self):
        sample = _sample_result()
        with patch.object(mcp_server, "check_repository", return_value=sample) as mocked:
            check_repo_trust("pallets/flask", target_type="github")
        _, kwargs = mocked.call_args
        self.assertEqual(kwargs["target_type"], "github")

    def test_revision_passed(self):
        sample = _sample_result()
        sha = "a" * 40
        with patch.object(mcp_server, "check_repository", return_value=sample) as mocked:
            check_repo_trust(
                "https://github.com/pallets/flask",
                target_type="github",
                revision=sha,
            )
        _, kwargs = mocked.call_args
        self.assertEqual(kwargs["revision"], sha)

    def test_local_file_and_hash_passed(self):
        sample = _sample_result()
        digest = "b" * 64
        with patch.object(mcp_server, "check_repository", return_value=sample) as mocked:
            check_repo_trust(
                "requests==2.31.0",
                target_type="pypi",
                local_file="C:/tmp/requests-2.31.0-py3-none-any.whl",
                expected_sha256=digest,
            )
        _, kwargs = mocked.call_args
        self.assertEqual(
            kwargs["local_file"],
            "C:/tmp/requests-2.31.0-py3-none-any.whl",
        )
        self.assertEqual(kwargs["expected_sha256"], digest)

    def test_empty_target_error(self):
        result = check_repo_trust("   ")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["type"], "invalid_input")
        self.assertIn("empty", result["error"]["detail"])

    def test_invalid_target_type_error(self):
        result = check_repo_trust("pallets/flask", target_type="bitbucket")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["type"], "invalid_target_type")

    def test_call_args_exact(self):
        sample = _sample_result()
        with patch.object(mcp_server, "check_repository", return_value=sample) as mocked:
            check_repo_trust(
                "  requests==2.31.0  ",
                target_type="PyPI",
                revision=None,
                local_file=None,
                expected_sha256=None,
            )
        mocked.assert_called_once_with(
            "requests==2.31.0",
            target_type="pypi",
            revision=None,
            local_file=None,
            expected_sha256=None,
        )

    def test_result_fields_preserved(self):
        sample = _sample_result()
        with patch.object(mcp_server, "check_repository", return_value=sample):
            result = check_repo_trust("https://github.com/pallets/flask")
        self.assertEqual(result["openssf_score"], 8.0)
        self.assertEqual(result["issues"], sample["issues"])
        self.assertEqual(result["score_breakdown"], sample["score_breakdown"])
        self.assertIn("summary", result)
        self.assertTrue(result["success"])

    def test_summary_field_created(self):
        sample = _sample_result(
            provenance_detail={
                "status": "unknown",
                "revision_pinned": False,
                "version_pinned": True,
                "hash_verified": None,
                "signature_status": "not_found",
            },
            issues=[],
        )
        with patch.object(mcp_server, "check_repository", return_value=sample):
            result = check_repo_trust("requests==2.31.0")
        summary = result["summary"]
        self.assertEqual(summary["verdict"], "WARNING")
        self.assertEqual(summary["trust_score"], 65)
        self.assertIn("main_reason", summary)
        self.assertIn("recommended_action", summary)

    def test_critical_issue_summary(self):
        sample = _sample_result(
            verdict="BLOCK",
            trust_score=20,
            issues=[{
                "type": "hash",
                "severity": "critical",
                "detail": "local file SHA-256 does not match the published digest",
                "evidence": None,
                "recommendation": "do not use this artifact",
            }],
        )
        summary = build_repository_check_summary(sample)
        self.assertIn("does not match", summary["main_reason"])
        self.assertEqual(summary["recommended_action"], "do not use this artifact")

    def test_ambiguous_target_result(self):
        sample = _sample_result(
            target={
                "input": "owner/repo",
                "type": "ambiguous",
                "normalized": "owner/repo",
            },
            verdict="WARNING",
            issues=[{
                "type": "repository",
                "severity": "medium",
                "detail": "ambiguous_target: owner/repo could be GitHub or Hugging Face",
                "evidence": "owner/repo",
                "recommendation": "set target_type to github, hf_model, or hf_dataset",
            }],
        )
        with patch.object(mcp_server, "check_repository", return_value=sample):
            result = check_repo_trust("owner/repo")
        self.assertEqual(result["target"]["type"], "ambiguous")
        self.assertIn("ambiguous", result["summary"]["main_reason"].lower())

    def test_internal_exception_structured(self):
        with patch.object(
            mcp_server,
            "check_repository",
            side_effect=RuntimeError("boom"),
        ):
            result = check_repo_trust("https://github.com/pallets/flask")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["type"], "internal_error")
        self.assertNotIn("boom", result["error"]["detail"])
        self.assertNotIn("Traceback", json.dumps(result))

    def test_json_serializable(self):
        sample = _sample_result()
        with patch.object(mcp_server, "check_repository", return_value=sample):
            result = check_repo_trust("https://github.com/pallets/flask")
        json.dumps(result, ensure_ascii=False)

    def test_validation_helper_rejects_non_string_target(self):
        normalized, error = validate_check_repo_trust_inputs(123)
        self.assertIsNone(normalized)
        self.assertEqual(error["error"]["type"], "invalid_input")


if __name__ == "__main__":
    unittest.main()
