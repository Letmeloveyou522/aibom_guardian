"""
stdio MCP carries JSON-RPC over stdout, so anything else printed there lands
inside a message the client is parsing.

These drive the MCP tools through their failure paths - where a print is
tempting - and assert stdout stays empty. The failures must still be
reported, so the second class checks they reach logging.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import sys
import types
import unittest
from unittest.mock import patch

import requests


def _install_mcp_stub_if_needed() -> bool:
    try:
        importlib.import_module("mcp.server.fastmcp")
        return False
    except ImportError:
        pass

    class _Tool:
        def __init__(self, name, fn):
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
        def __init__(self, name):
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

from aibom_guard import mcp_server, osv_client  # noqa: E402

_LICENSE_OK = {
    "license": "MIT",
    "source": "pypi:license_expression",
    "version": "2.28.0",
    "unverified": False,
    "error": None,
}


@contextlib.contextmanager
def captured_stdout():
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        yield buffer


class TestMcpToolsDoNotWriteToStdout(unittest.TestCase):
    def assert_silent(self, buffer, tool: str):
        written = buffer.getvalue()
        self.assertEqual(
            written,
            "",
            f"{tool} wrote {len(written)} bytes to stdout; on stdio MCP that "
            f"goes into the JSON-RPC stream. Use logging instead.\n"
            f"---\n{written}",
        )

    def test_check_package_is_silent_when_osv_fails(self):
        """The regression this file exists for."""
        def explode(*args, **kwargs):
            raise requests.exceptions.ConnectionError("simulated network failure")

        with patch.object(osv_client.requests, "post", explode), \
             patch.object(mcp_server, "resolve_license", return_value=_LICENSE_OK):
            with captured_stdout() as buffer:
                result = mcp_server.check_package("requests", "2.28.0")

        # The answer itself must still be the "unverified" one, not a clean pass.
        self.assertIsNone(result["vulnerabilities"])
        self.assertTrue(result["osv_unverified"])
        self.assert_silent(buffer, "check_package")

    def test_check_package_is_silent_when_osv_returns_junk(self):
        response = types.SimpleNamespace(
            status_code=200,
            json=lambda: (_ for _ in ()).throw(ValueError("not json")),
            raise_for_status=lambda: None,
        )
        with patch.object(osv_client.requests, "post", return_value=response), \
             patch.object(mcp_server, "resolve_license", return_value=_LICENSE_OK):
            with captured_stdout() as buffer:
                mcp_server.check_package("requests", "2.28.0")

        self.assert_silent(buffer, "check_package")

    def test_check_model_is_silent_when_the_model_cannot_be_read(self):
        from aibom_guard import scanner

        def explode(*args, **kwargs):
            raise RuntimeError("simulated hub failure")

        with patch.object(scanner, "check_model", explode), \
             patch.object(scanner, "HAS_MODEL_CHECKER", True):
            with captured_stdout() as buffer:
                mcp_server.check_model("org/does-not-exist")

        self.assert_silent(buffer, "check_model")

    def test_check_model_is_silent_when_model_checker_is_missing(self):
        from aibom_guard import scanner

        with patch.object(scanner, "HAS_MODEL_CHECKER", False):
            with captured_stdout() as buffer:
                mcp_server.check_model("org/whatever")

        self.assert_silent(buffer, "check_model")

    def test_check_license_is_silent(self):
        with captured_stdout() as buffer:
            result = mcp_server.check_license("MIT")
        self.assert_silent(buffer, "check_license")
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get("status"), "ALLOWED")


class TestFailuresAreStillReported(unittest.TestCase):
    """
    Silence on stdout must not become silence altogether - that would trade a
    protocol bug for an invisible failure, which is worse.
    """

    def test_osv_failure_is_logged(self):
        def explode(*args, **kwargs):
            raise requests.exceptions.ConnectionError("simulated network failure")

        with patch.object(osv_client.requests, "post", explode):
            with self.assertLogs("aibom_guard.osv_client", level="WARNING") as logs:
                result = osv_client.query_vulnerabilities("requests", "2.28.0")

        self.assertIsNone(result)
        self.assertTrue(any("OSV query failed" in line for line in logs.output))

    def test_unreadable_model_is_logged(self):
        from aibom_guard import scanner

        def explode(*args, **kwargs):
            raise RuntimeError("simulated hub failure")

        with patch.object(scanner, "check_model", explode), \
             patch.object(scanner, "HAS_MODEL_CHECKER", True):
            with self.assertLogs("aibom_guard.scanner", level="ERROR") as logs:
                report = scanner.scan_model("org/does-not-exist")

        self.assertIsNone(report)
        self.assertTrue(any("could not read model" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()
