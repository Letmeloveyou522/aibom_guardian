"""``python -m aibom_guardian <requirements.txt>`` - same as the aibom-guardian script."""

import sys

from .scanner import main

if __name__ == "__main__":
    sys.exit(main())
