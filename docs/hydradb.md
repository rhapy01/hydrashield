# How HydraDB is used

HydraShield does not have a local graph. HydraDB is the product.

| Step | Where it runs |
|---|---|
| Ingest of packages, versions, lockfiles, services, maintainers, infra | `UNWIND` / `MERGE` writes to HydraDB |
| Compromised version lookup | `MATCH (v:PackageVersion) WHERE v.name = $name` with `consistency: strong` |
| Incident window | `PackageVersion-[:COMPROMISED_IN]->IncidentWindow` |
| Introducing version | `Package-[:HAS_RELEASE]->PackageVersion` |
| Time-window exposure | `Service-[:RUNS]->Application-[:HAS_LOCKFILE]->Lockfile-[:RESOLVES]->PackageVersion` + `WHERE lock.resolved_at` |
| Direct pins | `LockfileSnapshot-[:PINS]->PackageVersion` |
| Scanner contrast | Same hop chain without the time predicate (`package_pins`) |
| Reverse ecosystem closure | `algo.SSpaths` incoming on `DEPENDS_ON` |
| Evidence paths | `PINS` then `CALL algo.MSpaths` on `PackageVersion.slug`, then `algo.SPpaths` / 1-hop `MATCH` still on HydraDB |
| Shared maintainers / infra / typosquats | `MAINTAINED_BY`, `PUBLISHED_VIA`, `SIMILAR_NAME_TO` |
| Fleet inventory | `MATCH (svc:Service)-[:IN_ORG]->(c:Catalog {id: 0})` |
| Uploaded lockfiles | Same `MERGE` path into HydraDB |

If HydraDB is down, the API returns **503**. The UI cannot invent a blast radius.
