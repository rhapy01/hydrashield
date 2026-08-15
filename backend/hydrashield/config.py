"""Runtime settings. HydraDB is mandatory — the product does not run a local graph."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    hydradb_url: str
    hydradb_token: str
    hydradb_namespace: str
    hydradb_graph: str
    hydradb_cell: str
    hydradb_timeout: float
    auto_ingest: bool
    hydradb_retries: int

    @classmethod
    def load(cls) -> Settings:
        root = Path(__file__).resolve().parents[2]
        return cls(
            data_dir=Path(os.environ.get("DATA_DIR", root / "data")),
            hydradb_url=os.environ.get("HYDRADB_URL", "http://127.0.0.1:8443").rstrip("/"),
            hydradb_token=os.environ.get("HYDRADB_TOKEN", "local-development-token-32-bytes"),
            hydradb_namespace=os.environ.get("HYDRADB_NAMESPACE", "default"),
            hydradb_graph=os.environ.get("HYDRADB_GRAPH", "default"),
            hydradb_cell=os.environ.get("HYDRADB_CELL", "cell-0"),
            hydradb_timeout=float(os.environ.get("HYDRADB_TIMEOUT", "45")),
            auto_ingest=_flag("AUTO_INGEST", True),
            hydradb_retries=int(os.environ.get("HYDRADB_RETRIES", "4")),
        )
