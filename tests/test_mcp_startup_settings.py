"""Use a fresh interpreter: other tests can already have imported FastMCP."""
import os
from pathlib import Path
import subprocess
import sys


def test_startup_resolves_lifespan_without_warning():
    env = os.environ.copy()
    env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
    result = subprocess.run(
        [sys.executable, '-W', 'error', '-c',
         'import aibom_guardian.mcp_server as s; '
         'assert s.FastMCPSettings.__pydantic_complete__; '
         'assert s.mcp.settings.lifespan is None'],
        env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ''
