"""Write npm lockfile fixtures under data/org/lockfiles."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from hydrashield.universe import APPLICATIONS, lockfile_payload  # noqa: E402


def main() -> None:
    out = ROOT / "data" / "org" / "lockfiles"
    out.mkdir(parents=True, exist_ok=True)
    for app in APPLICATIONS:
        payload = lockfile_payload(app)
        path = out / f"{app['slug']}.package-lock.json"
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(path)


if __name__ == "__main__":
    main()
