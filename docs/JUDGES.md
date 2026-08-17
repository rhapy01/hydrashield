# HydraShield — judge notes (Hack Hydra Track 2A)

**One sentence:** When `signal-bus@2.4.1` is live for six minutes, HydraDB tells VantaPay which services resolved that exact version *in that window*, through which path, and what to upgrade first.

HydraDB is the product. Unplug `graph-node` and ingest/analyze return HTTP 503. There is no in-memory graph.

**Always-on demo:** [https://rhapy01-hydrashield.fly.dev](https://rhapy01-hydrashield.fly.dev)

## 3-minute demo

| Time | Beat |
|---|---|
| 0:00 | Problem: scanners grep lockfiles. Worms publish and yank in minutes. Grep has no time. |
| 0:20 | Open the UI. Home is HydraShield, not VantaPay. Click **Open sample** on the demo ticket. (`?open=1` skips home.) |
| 0:35 | Hit **Replay 360s**. Clock runs 09:00→09:06. Nodes light as CI lockfiles resolve. Read the ticking exposed / P0 counts. |
| 1:10 | Click **If yanked at +2m**. `checkout-api` is still clean. Waiting three extra minutes is what put P0 checkout in the blast. |
| 1:35 | Click **Contained**. `ledger-worker` pinned `2.4.0` at 08:41. `webhook-relay` got `2.4.2` at 09:12. Both would light up a name grep. |
| 2:00 | Click **Exposed** → `checkout-api`. Path from a `PINS` hop, then `algo.MSpaths` on `PackageVersion.slug`. |
| 2:15 | **Complete blast radius**: three rings — org in-window, ecosystem reverse dependents (`algo.SSpaths`), adjacent identity/typosquat. HAS_RELEASE strip: `2.4.0` clean → `2.4.1` introduced → `2.4.2` patched. |
| 2:35 | **Containment plan**: upgrade `signal-bus@2.4.2` first, rotate OIDC/npm tokens, block typosquats. |
| 2:50 | Cypher drawer: `direct_lockfile_hits`, `lockfile_pins`, `package_releases`, `ms_paths`. |

Recording keys (when not focused in an input): **Space** play/pause, **2** yank +2m, **C** Contained (`ledger-worker`), **E** Exposed (`checkout-api`), **P** plan, **Esc** full window. **HydraDB in 60s** in the top bar opens the story page.

## What HydraDB does that SQL/vectors cannot

| Query | Procedure / Cypher |
|---|---|
| Compromised version | `PackageVersion-[:COMPROMISED_IN]->IncidentWindow` then `MATCH (v:PackageVersion)` · `consistency: strong` |
| In-window org exposure | `Service-[:RUNS]->Application-[:HAS_LOCKFILE]->Lockfile-[:RESOLVES]->PackageVersion` + `WHERE lock.resolved_at` |
| Evidence paths | `Lockfile-[:PINS]->` then `algo.MSpaths` on `PackageVersion.slug` (batch) then `algo.SPpaths` / 1-hop `MATCH` |
| Introducing version | `Package-[:HAS_RELEASE]->PackageVersion` |
| Reverse dependents | `algo.SSpaths` incoming on `DEPENDS_ON` |
| Shared maintainer / OIDC | `MAINTAINED_BY`, `PUBLISHED_VIA` diamonds |
| Typosquats | `SIMILAR_NAME_TO` |
| Writes | `UNWIND` + `MERGE (n {id}) SET n:Label, …` and one-hop `CREATE` edges |

## Submission form (paste)

**Problem:** After an npm compromise, defenders cannot answer the Track 2A questions: which services are transitively exposed, which version introduced it, who resolved it while it was live, who shares maintainer/infra, nearby typosquats, and the complete blast radius. Lockfile grep has no time, no path, and no rings.

**What we built:** HydraShield, an incident desk over HydraDB. Time is a 360-second replay plus a counterfactual yank (+2m saves P0 checkout). Completeness is three rings (org in-window, ecosystem reverse dependents, adjacent identity/typosquat) plus the HAS_RELEASE that introduced the worm. Evidence paths start at `Lockfile-[:PINS]`, not a flattened lockfile 1-hop.

**How HydraDB is used:** It is the only graph. Ingest writes integer-id vertices and typed edges. Analyze binds the compromised `PackageVersion` id and runs OpenCypher plus `algo.MSpaths` / `SPpaths` / `SSpaths` against one snapshot. Unplug HydraDB and ingest/analyze return HTTP 503.

**Tech stack:** HydraDB (`ghcr.io/hydra-db/hydradb`), FastAPI, React, npm lockfile v3 fixtures. Always-on at https://rhapy01-hydrashield.fly.dev
