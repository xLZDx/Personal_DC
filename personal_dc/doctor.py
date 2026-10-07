from __future__ import annotations

import json
import shutil
import sys

from . import __version__
from .policy import Policy
from .projects import describe_projects


def check() -> dict:
    policy = Policy()
    return {
        "ok": True,
        "version": __version__,
        "python": sys.version.split()[0],
        "git": shutil.which("git"),
        "allowed_roots": [
            {"path": str(root), "exists": root.exists()}
            for root in policy.allowed_roots
        ],
        "projects": describe_projects(),
    }


def main() -> None:
    print(json.dumps(check(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
