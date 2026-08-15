# HydraShield — judge notes (Hack Hydra Track 2A)

**One sentence:** When `signal-bus@2.4.1` is live for six minutes, HydraDB tells VantaPay which services resolved that exact version *in that window*, through which path, and what to upgrade first.

HydraDB is the product. Unplug `graph-node` and ingest/analyze return HTTP 503. There is no in-memory graph.

## 3-minute demo

| Time | Beat |
|---|---|
| 0:00 | Problem: scanners grep lockfiles. Worms publish and yank in minutes. Grep has no time. |
| 0:25 | Open the UI. Headline is the track question. HydraDB pill is live. |
| 0:40 | KPIs: exposed in-window vs contained vs scanner over-flags. Read the yellow contrast strip. |
| 1:10 | Click **Contained**. `ledger-worker` pinned `2.4.0` at 08:41. `webhook-relay` got `2.4.2` at 09:12. Both would light up a name grep. HydraDB keeps them out. |
| 1:40 | Click **Exposed** → `checkout-api`. Path: `checkout-api → payments-core@12.0.0 → event-router@0.9.3 → signal-bus@2.4.1`. Graph highlights that path. Paths come from `algo.MSpaths` / `algo.SPpaths`. |
| 2:10 | Neighborhood: shared maintainer, GitHub Actions OIDC next-hop (worm republish surface), typosquats (`signel-bus`). |
| 2:30 | **Containment plan**: upgrade `signal-bus@2.4.2` first (clears every in-window hit), rotate OIDC/npm tokens, block typosquats. |
| 2:45 | Open the Cypher drawer. `direct_lockfile_hits` is the 09:00–09:06 query. `ms_paths` is the batch evidence procedure. |

## What HydraDB does that SQL/vectors cannot

| Query | Procedure / Cypher |
|---|---|
| Compromised version | `MATCH (v:PackageVersion)` · `consistency: strong` |
| In-window org exposure | `Service-[:RUNS]->Application-[:HAS_LOCKFILE]->Lockfile-[:RESOLVES]->PackageVersion` + `WHERE lock.resolved_at` |
| Evidence paths | `algo.MSpaths` (batch) then `algo.SPpaths` / 1-hop `MATCH` |
| Reverse dependents | `algo.SSpaths` incoming on `DEPENDS_ON` |
| Shared maintainer / OIDC | `MAINTAINED_BY`, `PUBLISHED_VIA` diamonds |
| Typosquats | `SIMILAR_NAME_TO` |
| Writes | `UNWIND` + `MERGE (n {id}) SET n:Label, …` and one-hop `CREATE` edges |

## Submission form (paste)

**Problem:** After an npm compromise, defenders cannot answer “which of our services resolved the malicious version while it was live?” Lockfile grep has no time and no path.

**What we built:** HydraShield, an incident workspace over a HydraDB graph of packages, lockfile snapshots, services, maintainers, publishing infra, and typosquats.

**How HydraDB is used:** It is the only graph. Ingest writes integer-id vertices and typed edges. Analyze is a planner that binds the compromised `PackageVersion` id and runs OpenCypher plus `algo.SPpaths` / `MSpaths` / `SSpaths` against one snapshot. Without HydraDB the product does not run.

**Tech stack:** HydraDB (`ghcr.io/hydra-db/hydradb`), FastAPI, React, npm lockfile v3 fixtures, GitHub Actions live demo.
