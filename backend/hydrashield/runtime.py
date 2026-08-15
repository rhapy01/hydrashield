"""Process runtime. Every vertex, edge, and traversal lives in HydraDB."""

from __future__ import annotations

import logging
import threading
from typing import Any

from .analyze import Analyzer
from .config import Settings
from .hydradb import HydraDB, HydraDBError
from .ingest import Ingestor
from .schema import IdAllocator

log = logging.getLogger("hydrashield")


class Runtime:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.hydra: HydraDB | None = None
        self.ids = IdAllocator()
        self.ingested = False
        self.error: str | None = None
        self.lock = threading.RLock()
        self.last_result: dict[str, Any] | None = None
        self.last_ingest: dict[str, Any] | None = None

    def connect(self) -> HydraDB:
        if self.hydra and self.hydra.ready():
            self.error = None
            return self.hydra
        if self.hydra:
            try:
                self.hydra.close()
            except Exception:
                pass
            self.hydra = None
        url = self.settings.hydradb_url
        if not url:
            raise HydraDBError("HYDRADB_URL is empty — HydraShield cannot run without HydraDB")
        client = HydraDB(
            url,
            self.settings.hydradb_token,
            namespace=self.settings.hydradb_namespace,
            graph=self.settings.hydradb_graph,
            cell=self.settings.hydradb_cell,
            timeout=self.settings.hydradb_timeout,
            retries=self.settings.hydradb_retries,
        )
        if not client.ready():
            client.close()
            raise HydraDBError(f"HydraDB is not ready at {url}")
        self.hydra = client
        self.error = None
        return client

    def ingest(self) -> dict[str, Any]:
        with self.lock:
            db = self.connect()
            ingestor = Ingestor(db, self.settings.data_dir, self.ids)
            stats = ingestor.ingest()
            self.ingested = True
            payload = {
                **stats,
                "engine": "hydradb",
                "hydradb": True,
            }
            self.last_ingest = payload
            log.info("ingested %s vertices / %s edges into HydraDB", stats["vertices"], stats["edges"])
            return payload

    def ensure(self) -> HydraDB:
        db = self.connect()
        if not self.ingested:
            self.ingest()
            db = self.connect()
        return db

    def analyze(self, **kwargs: Any) -> dict[str, Any]:
        db = self.ensure()
        analyzer = Analyzer(db, self.ids.dump())
        result = analyzer.analyze(**kwargs)
        result["engine"] = "hydradb"
        self.last_result = result
        return result

    def health(self) -> dict[str, Any]:
        try:
            db = self.connect()
            ready = db.ready()
        except HydraDBError as exc:
            self.error = str(exc)
            ready = False
        return {
            "ok": ready and self.ingested,
            "engine": "hydradb",
            "hydradb": ready,
            "ingested": self.ingested,
            "error": self.error,
            "require_hydradb": True,
        }

    def add_lockfile(self, parsed: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        db = self.ensure()
        with self.lock:
            return Ingestor(db, self.settings.data_dir, self.ids).add_lockfile(parsed, **kwargs)
