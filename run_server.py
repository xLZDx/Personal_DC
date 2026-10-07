from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.environ.setdefault("PERSONAL_DC_HOME", str(ROOT))
os.environ.setdefault("PERSONAL_DC_TRANSPORT", "stdio")

from personal_dc.server import main

if __name__ == "__main__":
    main()
