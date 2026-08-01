"""
Shared pytest configuration.

The modules under test live at the repository root, one directory up from
here. `pythonpath = ["."]` in pyproject.toml normally handles that, but this
also covers running pytest from inside tests/, or with an older pytest that
does not support the pythonpath option.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
