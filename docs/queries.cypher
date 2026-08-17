-- HydraShield showcase queries.
-- These run against HydraDB's OpenCypher subset: one relationship type
-- per hop, bounded variable-length paths, integer vertex ids.

-- Which version sits in the incident window
MATCH (v:PackageVersion)-[:COMPROMISED_IN]->(w:IncidentWindow)
WHERE v.name = $name AND v.version = $version
RETURN w.start_ts AS start_ts, w.end_ts AS end_ts, w.advisory AS advisory

-- Which version introduced the compromise (HAS_RELEASE)
MATCH (p:Package)-[:HAS_RELEASE]->(v:PackageVersion)
WHERE p.name = $name
RETURN v.version AS version, v.published_at AS published_at,
       v.compromised AS compromised, v.yanked AS yanked

-- Compromised version
MATCH (v:PackageVersion)
WHERE v.name = $name AND v.version = $version
RETURN v.id AS id, v.name AS name, v.version AS version,
       v.published_at AS published_at, v.compromised AS compromised

-- Time-qualified org exposure (the 09:00–09:06 question)
MATCH (svc:Service)-[:RUNS]->(app:Application)-[:HAS_LOCKFILE]->(lock:LockfileSnapshot)
      -[:RESOLVES]->(bad:PackageVersion {id: $bad})
WHERE lock.resolved_at >= $t0 AND lock.resolved_at <= $t1
RETURN svc.name AS name, svc.criticality AS criticality,
       lock.resolved_at AS resolved_at

-- Ecosystem reverse closure
MATCH (other:PackageVersion)-[:DEPENDS_ON*1..6]->(bad:PackageVersion {id: $bad})
RETURN other.name AS name, other.version AS version

-- Shared maintainers
MATCH (pkg:Package)-[:MAINTAINED_BY]->(m:Maintainer)<-[:MAINTAINED_BY]-(other:Package)
WHERE pkg.name = $name
RETURN other.name AS name, m.npm_user AS npm_user

-- Shared publishing infrastructure
MATCH (pkg:Package)-[:PUBLISHED_VIA]->(inf:Infrastructure)<-[:PUBLISHED_VIA]-(other:Package)
WHERE pkg.name = $name
RETURN other.name AS name, inf.name AS infra

-- Typosquat neighborhood
MATCH (pkg:Package)-[:SIMILAR_NAME_TO]->(other:Package)
WHERE pkg.name = $name
RETURN other.name AS name

-- Direct package.json pins (evidence path sources)
MATCH (lock:LockfileSnapshot {id: $lock})-[:PINS]->(pv:PackageVersion)
RETURN pv.id AS id, pv.name AS name, pv.version AS version

-- Evidence path (native GraphBLAS-backed batch procedure)
CALL algo.MSpaths({
  sourceLabel: 'PackageVersion',
  sourceProperty: 'slug',
  sourceValues: $sources,
  targetLabel: 'PackageVersion',
  targetProperty: 'slug',
  targetValues: $targets,
  pairwise: false,
  relTypes: ['DEPENDS_ON'],
  relDirection: 'outgoing',
  maxLen: 6,
  pathCount: 3,
  resultLimit: 120
})
YIELD path
RETURN path

-- Evidence path (single pair)
CALL algo.SPpaths({
  sourceNode: $source,
  targetNode: $target,
  relTypes: ['DEPENDS_ON'],
  relDirection: 'outgoing',
  maxLen: 6,
  pathCount: 3
})
YIELD path
RETURN path

-- Reverse paths from the compromised node
CALL algo.SSpaths({
  sourceNode: $source,
  relTypes: ['DEPENDS_ON'],
  relDirection: 'incoming',
  maxLen: 4,
  pathCount: 12
})
YIELD path
RETURN path
