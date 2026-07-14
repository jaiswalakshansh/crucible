"""Make ``src`` importable during local test runs without installing the package.

CI installs the package (``pip install -e``), so this is only a convenience for
running ``pytest`` straight from a clone.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
