"""HydraShield HTTP API. HydraDB is the only graph engine."""

from __future__ import annotations

import json
import logging
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from .analyze import Analyzer
from .config import Settings
from .hydradb import HydraDBError
from .lockfiles import parse_lockfile
from .reports import markdown_report
from .runtime import Runtime
from .universe import INCIDENT, ORG

log = logging.getLogger("hydrashield")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

settings = Settings.load()
runtime = Runtime(settings)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if settings.auto_ingest:
        for attempt in range(40):
            try:
                runtime.ingest()
                break
            except HydraDBError as exc:
                log.warning("HydraDB not ready (%s/40): %s", attempt + 1, exc)
                time.sleep(5)
    yield
    if runtime.hydra:
        runtime.hydra.close()


app = FastAPI(
    title="HydraShield",
    version="1.0.0",
    description="Supply-chain blast radius on HydraDB. Every vertex and traversal is OpenCypher.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    package: str = Field(default=INCIDENT["package"])
    version: str = Field(default=INCIDENT["version"])
    start_ts: int | None = None
    end_ts: int | None = None
    safe_version: str | None = None


def _hydra(exc: HydraDBError) -> HTTPException:
    return HTTPException(
        status_code=503,
        detail=f"HydraDB required: {exc}. Start graph-node (docker compose up hydradb) and retry ingest.",
    )


@app.get("/api/health")
def health() -> dict[str, Any]:
    body = runtime.health()
    body["org"] = ORG
    body["incident"] = INCIDENT["slug"]
    return body


@app.post("/api/ingest")
def ingest() -> dict[str, Any]:
    try:
        return {"ok": True, **runtime.ingest()}
    except HydraDBError as exc:
        raise _hydra(exc) from exc


@app.get("/api/incident")
def incident() -> dict[str, Any]:
    return {"org": ORG, "incident": INCIDENT, "engine": "hydradb"}


@app.get("/api/packages")
def packages() -> dict[str, Any]:
    try:
        db = runtime.ensure()
        return {"packages": db.list_packages()}
    except HydraDBError as exc:
        raise _hydra(exc) from exc


@app.get("/api/versions")
def versions(name: str | None = Query(default=None)) -> dict[str, Any]:
    try:
        db = runtime.ensure()
        return {"versions": db.list_versions(name)}
    except HydraDBError as exc:
        raise _hydra(exc) from exc


@app.post("/api/analyze")
def analyze(body: AnalyzeRequest) -> dict[str, Any]:
    try:
        return runtime.analyze(
            package=body.package,
            version=body.version,
            start_ts=body.start_ts,
            end_ts=body.end_ts,
            safe_version=body.safe_version,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HydraDBError as exc:
        raise _hydra(exc) from exc


@app.get("/api/analyze/report")
def report(
    package: str = INCIDENT["package"],
    version: str = INCIDENT["version"],
    start_ts: int | None = None,
    end_ts: int | None = None,
) -> PlainTextResponse:
    try:
        result = runtime.analyze(package=package, version=version, start_ts=start_ts, end_ts=end_ts)
    except HydraDBError as exc:
        raise _hydra(exc) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return PlainTextResponse(markdown_report(result), media_type="text/markdown")


@app.get("/api/services/{name}/evidence")
def evidence(name: str) -> dict[str, Any]:
    try:
        db = runtime.ensure()
        return Analyzer(db, runtime.ids.dump()).evidence(name)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except HydraDBError as exc:
        raise _hydra(exc) from exc


@app.post("/api/lockfiles")
async def upload_lockfile(file: UploadFile = File(...)) -> dict[str, Any]:
    raw = await file.read()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Lockfile must be JSON (npm lockfile v2/v3)") from exc
    parsed = parse_lockfile(payload)
    try:
        written = runtime.add_lockfile(parsed)
    except HydraDBError as exc:
        raise _hydra(exc) from exc
    return {"ok": True, "engine": "hydradb", **written}
