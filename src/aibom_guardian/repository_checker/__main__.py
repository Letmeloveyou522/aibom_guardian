"""``python -m aibom_guardian.repository_checker <target>``.

A package needs this file; ``-m`` cannot execute a package directory itself.
"""

import sys

from ._cli import main

if __name__ == "__main__":
    sys.exit(main())
