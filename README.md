# HydraShield

**Incident response for dependency graphs. Know your blast radius before the compromise spreads.**

HydraShield is a Track 2A (supply-chain blast radius) project for [Hack Hydra](https://hackhydra.hydradb.com/). It uses the [HydraDB](https://github.com/hydra-db/hydradb) open-source graph database as the system of record for npm package versions, lockfile snapshots, services, maintainers, publishing infrastructure, and typosquat neighborhoods.

> Demo premise: Package `signal-bus@2.4.1` was compromised at 09:00. Which of VantaPay’s services were exposed by 09:06, why, and what should we upgrade first?

This is not “does this lockfile contain package X?” A scanner can answer that. HydraShield answers a graph question: **did this service resolve the compromised version during the exact window it was malicious, through which dependency path, and what else in the ecosystem became reachable from the same maintainer or CI identity?**

## What it does

1. Ingests a curated npm universe plus 28 VantaPay application lockfiles.
2. Writes labeled vertices and typed edges into HydraDB.
3. Marks `signal-bus@2.4.1` as live from 09:00–09:06 UTC on 2026-05-14.
4. Runs snapshot-consistent OpenCypher (and native `algo.SPpaths` / `algo.SSpaths`) to compute:
   - time-qualified reverse exposure of internal services
   - exact dependency paths for evidence
   - ecosystem reverse dependents
   - shared maintainers and GitHub Actions OIDC publishing infra
   - Levenshtein typosquat neighborhood (`signel-bus`, `signal-buss`, …)
5. Ranks services and emits a remediation sequence that upgrades the compromised package first, then reviews same-maintainer packages.

## Why HydraDB

HydraDB is not a cache sitting under a SQL model. The product’s central action is a **time-aware transitive traversal with explainable paths**.

| Capability used | Where |
|---|---|
| Object-store-backed durable graph + integer vertex ids | Ingest of packages, versions, lockfiles, services |
| OpenCypher `MATCH` with bounded variable-length `DEPENDS_ON*1..6` | Ecosystem reverse closure |
| Directed one-type hops `Service-[:RUNS]->Application-[:HAS_LOCKFILE]->Lockfile-[:RESOLVES]->PackageVersion` | Org exposure |
| `WHERE lock.resolved_at >= $t0 AND lock.resolved_at <= $t1` | Temporal window (the 09:00–09:06 question) |
| `algo.SPpaths` | Evidence path between a direct dependency and the compromised version |
| `algo.SSpaths` | Reverse paths out of the compromised node |
| Causal bookmarks + optional `strong` consistency on the first read | Report does not mix topology from two snapshots |
| `UNWIND` / `MERGE` batches | Idempotent ingest |

Without HydraDB the product does not run. `/api/analyze` and `/api/ingest` return HTTP 503. There is no in-memory graph, no SQL stand-in, and no cached copy of the blast radius.

HydraDB’s OpenCypher subset is strict (one relationship type per hop, bounded variable-length paths, integer ids, `UNWIND` for batches). The schema in `backend/hydrashield/schema.py` is written against that subset on purpose.

## Quick start

### Prerequisites

- Docker Desktop (HydraDB ships as `ghcr.io/hydra-db/hydradb`)
- Python 3.11+ and Node 20+ if you run the API/UI on the host

### One-command demo

```bash
mkdir -p hydradb-data/store hydradb-data/cache
docker compose up --build
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). The API waits for HydraDB, ingests the graph, then the UI runs **Analyze**.

### Live demo (no local Docker)

This machine does not need Docker. GitHub Actions runs HydraDB, the API, and the UI, then publishes a Cloudflare URL for ~90 minutes.

1. Open the **Actions** tab → **Live demo** → **Run workflow**
2. Open the run, wait until **Open public tunnel** finishes
3. The URL is in the job summary (`https://….trycloudflare.com`)

Re-run the workflow whenever you need a fresh URL.

If the image cannot write the bind-mounted store on Windows, run the containers as root (compose already does not remap UID) and confirm `hydradb-data/store` exists.

### Host process (HydraDB in Docker only)

```bash
docker compose up hydradb
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
pytest -q
set PYTHONPATH=.
uvicorn hydrashield.main:app --reload --port 8000

cd ..\frontend
npm install
npm run dev
```

Then `POST /api/ingest` from the UI button **Ingest + analyze**.

### Tests (no HydraDB required)

Use a virtualenv. A global Python with unrelated pytest plugins (for example `web3`) can break collection.

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pytest -q
```

These cover lockfile parsing, temporal window membership, path evidence, ranking, typosquats, and remediation set-cover.

## Demo script (≈3 minutes)

1. Open the incident workspace. The alert is already `signal-bus@2.4.1` at 09:00.
2. Click **Ingest + analyze**. KPIs show exposed services, P0 count, ecosystem dependents, and the 360s window.
3. The radial graph is the reverse-closure: compromised version at the center, package path in blue, VantaPay services on the outer ring.
4. Click `checkout-api`. Evidence expands: `checkout-api → payments-core@12.0.0 → event-router@0.9.3 → signal-bus@2.4.1`.
5. Point at the neighborhood strip: `logger-pretty` / `config-merge` share maintainer `mara-okonkwo` and GitHub Actions OIDC; `signel-bus` is a typosquat.
6. Click **Generate remediation plan**. First action: upgrade `signal-bus@2.4.2`, which clears every time-window hit. Then rotate CI/npm credentials and block typosquats.
7. Open the Cypher drawer. The query that produced the headline is HydraDB OpenCypher, not a fixture lookup.

Services that locked **before** 09:00 (`ledger-worker` on `2.4.0`) or **after** the yank (`webhook-relay` on `2.4.2`) are correctly absent from the exposed list. That is the temporal argument.

## Repository layout

```
backend/hydrashield/   FastAPI, HydraDB HTTP client, ingest, Cypher analysis
backend/tests/         Ranking, lockfile, temporal, typosquat tests
frontend/              Incident workspace (Vite + React)
data/org/lockfiles/    npm lockfile v3 fixtures for VantaPay
docker-compose.yml     HydraDB + API + UI
```

## Graph model

```
(Service)-[:RUNS]->(Application)-[:HAS_LOCKFILE]->(LockfileSnapshot)-[:RESOLVES]->(PackageVersion)
(Package)-[:HAS_RELEASE]->(PackageVersion)-[:DEPENDS_ON]->(PackageVersion)
(Package)-[:MAINTAINED_BY]->(Maintainer)
(Package)-[:PUBLISHED_VIA]->(Infrastructure)
(Package)-[:SIMILAR_NAME_TO]->(Package)
(PackageVersion)-[:COMPROMISED_IN]->(IncidentWindow)
```

Vertex ids are integers (HydraDB requirement). Names, versions, criticality, and unix timestamps are properties.

## Scope (intentional)

- npm only, curated registry snapshot, one org (VantaPay, 28 apps)
- One deterministic compromise (`signal-bus@2.4.1`, 09:00–09:06)
- No malware detection, no live npm crawl, no PyPI

The May 2026 TanStack-class incident (malicious artifacts published within six minutes of a CI breach) is the *shape* of the demo, not a replay of those package names.

## How HydraDB is used (submission form)

HydraDB stores the supply-chain graph and executes every blast-radius query. The API is a thin planner: it binds the compromised `PackageVersion` id, runs OpenCypher / path procedures with a pinned snapshot, then ranks the returned services. If you unplug HydraDB, ingest and analyze return HTTP 503. The UI is not sitting on a parallel in-memory graph.

## License and attribution

- HydraShield: [MIT](LICENSE)
- HydraDB: AGPL-3.0, used as a running service via `ghcr.io/hydra-db/hydradb` — see [hydra-db/hydradb](https://github.com/hydra-db/hydradb)
- Demo packages and the VantaPay org are fictional fixtures

## Team notes

Work on this repository starts on or after 12 August 2026, per Hack Hydra rules.
