"""
tests/test_mcp_package_model.py
-----------------------------------
MCP-layer tests for check_package (OSV None contract) and check_model
(scan_report models[] schema).

Network is mocked; no Hub/OSV calls leave the process.
"""

from __future__ import annotations

import importlib
import json
import sys
import types
import unittest
from unittest.mock import patch


def _install_mcp_stub_if_needed() -> bool:
    # import_module rather than a plain import: this is a probe, and an
    # unused-import warning on a deliberate availability check is noise that
    # trains people to ignore the linter.
    try:
        importlib.import_module("mcp.server.fastmcp")
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


_install_mcp_stub_if_needed()

from aibom_guard import mcp_server  # noqa: E402
from aibom_guard.mcp_server import (  # noqa: E402
    _vulns_to_issues,
    check_model,
    check_package,
    mcp,
)


class TestToolRegistration(unittest.TestCase):
    def test_check_model_is_registered(self):
        names = {t.name for t in mcp._tool_manager.list_tools()}
        self.assertIn("check_model", names)
        self.assertIn("check_package", names)


class TestVulnsToIssuesContract(unittest.TestCase):
    def test_none_stays_none(self):
        """OSV failure must not become an empty list."""
        self.assertIsNone(_vulns_to_issues(None))

    def test_empty_list_stays_empty(self):
        self.assertEqual(_vulns_to_issues([]), [])

    def test_preserves_cvss_score_and_aliases(self):
        issues = _vulns_to_issues([{
            "id": "GHSA-x",
            "severity": "medium",
            "summary": "leak",
            "detail": "proxy leak",
            "cvss_score": 5.3,
            "aliases": ["PYSEC-1"],
        }])
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["cvss_score"], 5.3)
        self.assertEqual(issues[0]["aliases"], ["PYSEC-1"])
        self.assertEqual(issues[0]["detail"], "proxy leak")

    def test_cli_and_mcp_share_one_adapter(self):
        """
        Identity, not equality. Two adapters that merely behave the same today
        are what this guards against - the CLI and MCP verdicts only match if
        both feed score_engine input built by the same code.
        """
        from aibom_guard import _adapters, scanner

        self.assertIs(scanner._vulns_to_issues, _adapters._vulns_to_issues)
        self.assertIs(mcp_server._vulns_to_issues, _adapters._vulns_to_issues)
        self.assertIs(scanner._build_check_result, _adapters._build_check_result)
        self.assertIs(mcp_server._build_check_result, _adapters._build_check_result)


class TestCheckPackageOsvNone(unittest.TestCase):
    def test_osv_none_yields_warning_and_low_confidence(self):
        """
        query_vulnerabilities returning None must become issues=None for
        score_engine, never []. Verdict WARNING, osv_unverified true.
        """
        with patch.object(mcp_server, "query_vulnerabilities", return_value=None), \
             patch.object(mcp_server, "resolve_license", return_value={
                 "license": "MIT", "source": "pypi:license_expression",
                 "version": "2.28.0", "unverified": False, "error": None}):
            result = check_package("requests", "2.28.0")

        self.assertTrue(result["success"])
        self.assertIsNone(result["vulnerabilities"])
        self.assertTrue(result["osv_unverified"])
        self.assertEqual(result["verdict"], "WARNING")
        self.assertLess(result["confidence"], 0.5)
        self.assertEqual(result["license_status"], "ALLOWED")

    def test_osv_empty_list_is_verified_clean(self):
        with patch.object(mcp_server, "query_vulnerabilities", return_value=[]), \
             patch.object(mcp_server, "resolve_license", return_value={
                 "license": "MIT", "source": "pypi:license_expression",
                 "version": "2.28.0", "unverified": False, "error": None}):
            result = check_package("requests", "2.34.2")

        self.assertEqual(result["vulnerabilities"], [])
        self.assertFalse(result["osv_unverified"])
        self.assertGreaterEqual(result["confidence"], 0.5)

    def test_osv_findings_preserve_cvss_in_scoring_path(self):
        vulns = [{
            "id": "GHSA-x",
            "severity": "unknown",
            "summary": "x",
            "detail": "x",
            "cvss_score": 9.8,
            "aliases": ["CVE-1"],
        }]
        with patch.object(mcp_server, "query_vulnerabilities", return_value=vulns), \
             patch.object(mcp_server, "resolve_license", return_value={
                 "license": "MIT", "source": "pypi:license_expression",
                 "version": "2.28.0", "unverified": False, "error": None}):
            result = check_package("requests", "2.28.0")

        self.assertEqual(result["vulnerabilities"], vulns)
        self.assertFalse(result["osv_unverified"])
        # Critical-ish via CVSS fallback should lower the score below clean.
        self.assertLess(result["trust_score"], 100)


class TestCheckModelMCP(unittest.TestCase):
    def _sample_model_report(self):
        return {
            "model_id": "org/demo-model",
            "url": "https://huggingface.co/org/demo-model",
            "commit_sha": "abc123",
            "license": "apache-2.0",
            "license_name": "apache-2.0",
            "license_status": "ALLOWED",
            "license_family": "permissive",
            "license_reason": "OSI-approved",
            "issues": [],
            "model_card": {"present": True, "completeness": 80},
            "file_formats": {"safetensors": ["model.safetensors"], "pickle": []},
            "risk_score": 90,
            "verdict": "ALLOW",
            "hard_block": False,
            "hard_block_reasons": [],
            "score_breakdown": {},
            "confidence": 0.85,
        }

    def test_check_model_returns_scan_report_models_shape(self):
        sample = self._sample_model_report()
        with patch.object(mcp_server, "scan_model", return_value=sample) as mocked:
            result = check_model("org/demo-model")

        mocked.assert_called_once_with("org/demo-model", max_pickle_size_mb=0)
        self.assertTrue(result["success"])
        self.assertEqual(result["tool"], "check_model")
        # scan_report.json models[] fields must be present.
        for key in (
            "model_id", "license_status", "verdict", "risk_score",
            "issues", "model_card", "confidence", "commit_sha",
        ):
            self.assertIn(key, result)
        self.assertEqual(result["model_id"], "org/demo-model")
        self.assertEqual(result["verdict"], "ALLOW")

    def test_check_model_passes_pickle_budget(self):
        sample = self._sample_model_report()
        with patch.object(mcp_server, "scan_model", return_value=sample) as mocked:
            check_model("org/demo-model", max_pickle_size_mb=64)
        mocked.assert_called_once_with("org/demo-model", max_pickle_size_mb=64)

    def test_check_model_none_is_structured_error(self):
        with patch.object(mcp_server, "scan_model", return_value=None):
            result = check_model("org/missing")
        self.assertFalse(result["success"])
        self.assertEqual(result["tool"], "check_model")
        self.assertEqual(result["error"]["type"], "analysis_error")

    def test_check_model_rejects_empty_ref(self):
        result = check_model("   ")
        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["type"], "invalid_input")

    def test_models_entry_is_json_serialisable(self):
        sample = self._sample_model_report()
        with patch.object(mcp_server, "scan_model", return_value=sample):
            result = check_model("org/demo-model")
        json.dumps(result)  # must not raise
        # Compatible with wrapping into the scan_report document.
        document = {"packages": [], "models": [result], "unscanned": []}
        self.assertEqual(document["models"][0]["model_id"], "org/demo-model")


if __name__ == "__main__":
    unittest.main()
