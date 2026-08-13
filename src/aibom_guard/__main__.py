"""``python -m aibom_guard <requirements.txt>`` - same as the aibom-guard script."""

import sys

from .scanner import main

if __name__ == "__main__":
    sys.exit(main())
