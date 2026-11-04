"""Exercise the README's offline demo as a user-facing command."""

import json
from pathlib import Path
import subprocess
import sys


def test_readme_offline_demo_runs_all_scenarios():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "examples/demo_scenarios.py", "--compact"],
        cwd=root, capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout.split("--- JSON ---\n", 1)[1].splitlines()[0])
    assert document["mode"] == "offline"
    assert len(document["scenarios"]) == 4
    assert "[ok] scenario assertions passed" in result.stdout
