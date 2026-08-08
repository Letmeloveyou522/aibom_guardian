"""
Shared pytest configuration.

The modules under test live at the repository root, one directory up from
here. `pythonpath = ["."]` in pyproject.toml normally handles that, but this
also covers running pytest from inside tests/, or with an older pytest that
does not support the pythonpath option.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# license_checker downloads the SPDX and Blue Oak lists on first use and
# caches them. Point that cache at a trimmed fixture pair so the suite never
# reaches the network and never depends on the developer's real cache.
#
# The fixtures hold only the identifiers these tests assert on - see
# tests/fixtures/README.md for how to regenerate them.
os.environ["AIBOM_GUARD_CACHE"] = str(Path(__file__).resolve().parent / "fixtures")
