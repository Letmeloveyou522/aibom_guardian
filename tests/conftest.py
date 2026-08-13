"""
Shared pytest configuration.

The package under test lives in src/aibom_guard, so it is not importable from
the repository root. `pythonpath = ["src"]` in pyproject.toml normally handles
that, but this also covers running pytest from inside tests/, or with an older
pytest that does not support the pythonpath option.
"""

import os
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# license_checker downloads the SPDX and Blue Oak lists on first use and
# caches them. Point that cache at a trimmed fixture pair so the suite never
# reaches the network and never depends on the developer's real cache.
#
# The fixtures hold only the identifiers these tests assert on - see
# tests/fixtures/README.md for how to regenerate them.
os.environ["AIBOM_GUARD_CACHE"] = str(Path(__file__).resolve().parent / "fixtures")
