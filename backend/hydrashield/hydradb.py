"""HydraDB HTTP client implementing GraphStore.

Retries transient failures, chains causal bookmarks, and logs every Cypher
statement so the UI can show exactly what ran on the remote engine.
"""

from __future__ import annotations

import time
from typing import Any

import httpx


class HydraDBError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


def unwrap(cell: Any) -> Any:
    if cell is None:
        return None
    if isinstance(cell, dict) and "type" in cell:
        kind = cell["type"]
        value = cell.get("value")
        if kind in {"vertex_id", "integer", "signed_integer", "float", "boolean", "string"}:
            return value
        if kind == "null":
            return None
        if kind == "list":
            return [unwrap(item) for item in (value or [])]
        if kind == "path":
            return value
        return value
    return cell


def _admin_url(query_url: str) -> str:
    if ":8443" in query_url:
        return query_url.replace(":8443", ":9090")
    return query_url.rsplit(":", 1)[0] + ":9090"


class HydraDB:
    engine = "hydradb"

    def __init__(
        self,
        url: str,
        token: str,
        *,
        namespace: str = "default",
        graph: str = "default",
        cell: str = "cell-0",
        timeout: float = 45.0,
        retries: int = 3,
    ) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.namespace = namespace
        self.graph = graph
        self.cell = cell
        self.retries = max(1, retries)
        self.bookmark: str | None = None
        self.query_log: list[dict[str, Any]] = []
        self._vertex_cache: dict[int, dict[str, Any]] = {}
        self._client = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def ready(self) -> bool:
        try:
            response = httpx.get(f"{_admin_url(self.url)}/readyz", timeout=3.0)
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    def query(
        self,
        cypher: str,
        parameters: dict[str, Any] | None = None,
        *,
        consistency: str = "causal",
        timeout_ms: int = 30_000,
        log_name: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "cell_id": self.cell,
            "query": cypher,
            "parameters": parameters or {},
            "consistency": consistency,
            "timeout_ms": timeout_ms,
        }
        last_error: Exception | None = None
        for attempt in range(self.retries):
            if self.bookmark:
                payload["bookmark"] = self.bookmark
            try:
                response = self._client.post(
                    f"{self.url}/v1/graphs/{self.graph}/query",
                    headers={
                        "Authorization": f"Bearer {self.token}",
                        "X-Graph-Namespace": self.namespace,
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
            except httpx.HTTPError as exc:
                last_error = HydraDBError(f"HydraDB unreachable: {exc}")
                time.sleep(0.4 * (attempt + 1))
                continue
            if response.status_code >= 500:
                last_error = HydraDBError(
                    f"HydraDB query failed ({response.status_code}): {response.text[:800]}",
                    status=response.status_code,
                    body=response.text,
                )
                time.sleep(0.4 * (attempt + 1))
                continue
            if response.status_code >= 400:
                raise HydraDBError(
                    f"HydraDB query failed ({response.status_code}): {response.text[:800]}",
                    status=response.status_code,
                    body=response.text,
                )
            data = response.json()
            bookmark = data.get("bookmark")
            if bookmark:
                self.bookmark = bookmark
            if log_name:
                self.query_log.append(
                    {
                        "name": log_name,
                        "cypher": cypher,
                        "parameters": parameters or {},
                        "row_count": len(data.get("rows") or []),
                        "engine": self.engine,
                    }
                )
            return data
        assert last_error is not None
        raise last_error

    def rows(self, cypher: str, parameters: dict[str, Any] | None = None, **kwargs: Any) -> list[dict[str, Any]]:
        data = self.query(cypher, parameters, **kwargs)
        columns: list[str] = data.get("columns") or []
        out: list[dict[str, Any]] = []
        for raw in data.get("rows") or []:
            out.append({col: unwrap(cell) for col, cell in zip(columns, raw)})
        return out

    def execute(self, cypher: str, parameters: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
        return self.query(cypher, parameters, **kwargs)

    def merge_vertices(self, label: str, rows: list[dict[str, Any]], set_clause: str = "") -> int:
        """HydraDB vertex upsert: UNWIND / MERGE by id / SET label+properties."""
        del set_clause
        if not rows:
            return 0
        keys = [k for k in rows[0] if k != "vertex"]
        assignments = ", ".join([f"n:{label}", *[f"n.{k} = row.{k}" for k in keys]])
        cypher = f"UNWIND $rows AS row MERGE (n {{id: row.vertex}}) SET {assignments}"
        for chunk in _chunks(rows, 40):
            self.execute(cypher, {"rows": chunk})
        return len(rows)

    def merge_edges(
        self,
        rel: str,
        rows: list[dict[str, Any]],
        source_label: str = "",
        destination_label: str = "",
    ) -> int:
        """HydraDB edge writes: one-hop CREATE by integer id, or labeled MATCH CREATE."""
        if not rows:
            return 0
        create_q = (
            "UNWIND $rows AS row "
            f"CREATE (s {{id: row.source}})-[:{rel}]->(d {{id: row.destination}})"
        )
        try:
            for chunk in _chunks(rows, 40):
                self.execute(create_q, {"rows": chunk})
            return len(rows)
        except HydraDBError:
            if not source_label or not destination_label:
                raise
        match_q = (
            "UNWIND $rows AS row "
            f"MATCH (s:{source_label} {{id: row.source}}), "
            f"(d:{destination_label} {{id: row.destination}}) "
            f"CREATE (s)-[:{rel}]->(d)"
        )
        for chunk in _chunks(rows, 40):
            self.execute(match_q, {"rows": chunk})
        return len(rows)

    def find_version(self, name: str, version: str) -> dict[str, Any] | None:
        rows = self.rows(
            "MATCH (v:PackageVersion) WHERE v.name = $name AND v.version = $version "
            "RETURN v.id AS id, v.name AS name, v.version AS version, "
            "v.published_at AS published_at, v.compromised AS compromised, v.yanked AS yanked",
            {"name": name, "version": version},
            consistency="strong",
            log_name="compromised_version",
        )
        return rows[0] if rows else None

    def lockfile_hits(self, bad_id: int, t0: int, t1: int) -> list[dict[str, Any]]:
        return self.rows(
            "MATCH (svc:Service)-[:RUNS]->(app:Application)-[:HAS_LOCKFILE]->(lock:LockfileSnapshot)"
            "-[:RESOLVES]->(bad:PackageVersion {id: $bad}) "
            "WHERE lock.resolved_at >= $t0 AND lock.resolved_at <= $t1 "
            "RETURN svc.id AS service_id, svc.name AS name, svc.env AS env, "
            "svc.criticality AS criticality, svc.team AS team, "
            "svc.deployed_at AS deployed_at, app.name AS application, "
            "lock.id AS lock_id, lock.resolved_at AS resolved_at, lock.commit AS commit",
            {"bad": bad_id, "t0": t0, "t1": t1},
            log_name="direct_lockfile_hits",
        )

    def package_pins(self, name: str) -> list[dict[str, Any]]:
        """Every org lockfile that resolves any version of a package — time and version included."""
        return self.rows(
            "MATCH (svc:Service)-[:RUNS]->(app:Application)-[:HAS_LOCKFILE]->(lock:LockfileSnapshot)"
            "-[:RESOLVES]->(pv:PackageVersion) "
            "WHERE pv.name = $name "
            "RETURN svc.id AS service_id, svc.name AS name, svc.env AS env, "
            "svc.criticality AS criticality, svc.team AS team, app.name AS application, "
            "lock.id AS lock_id, lock.resolved_at AS resolved_at, "
            "pv.id AS version_id, pv.version AS version",
            {"name": name},
            log_name="package_pins",
        )

    def many_shortest_paths(
        self, sources: list[int], target: int, rel: str, max_len: int = 6
    ) -> dict[int, list[int]]:
        """Batch evidence paths via algo.MSpaths (one snapshot, no client fan-out).

        HydraDB resolves MSpaths through a property index. Vertex `id` is not
        that index — `slug` (`name@version`) is, matching the documented
        sourceLabel/sourceProperty/sourceValues shape.
        """
        unique = [int(s) for s in dict.fromkeys(sources) if int(s) != int(target)]
        out: dict[int, list[int]] = {}
        if not unique:
            return out
        slug_of, _id_of = self._version_slugs(unique + [int(target)])
        source_slugs = [slug_of[s] for s in unique if s in slug_of]
        target_slug = slug_of.get(int(target))
        rows: list[dict[str, Any]] = []
        cypher = (
            "CALL algo.MSpaths({"
            "sourceLabel: 'PackageVersion', sourceProperty: 'slug', sourceValues: $sources, "
            "targetLabel: 'PackageVersion', targetProperty: 'slug', targetValues: $targets, "
            "pairwise: false, "
            f"relTypes: ['{rel}'], relDirection: 'outgoing', maxLen: {int(max_len)}, "
            "pathCount: 3, resultLimit: 120}) "
            "YIELD path RETURN path"
        )
        params: dict[str, Any] = {"sources": source_slugs, "targets": [target_slug] if target_slug else []}
        try:
            if source_slugs and target_slug:
                logged = False
                for chunk in _chunks(source_slugs, 16):
                    rows.extend(
                        self.rows(
                            cypher,
                            {"sources": chunk, "targets": [target_slug]},
                            log_name="ms_paths" if not logged else None,
                            timeout_ms=60_000,
                        )
                    )
                    logged = True
                if not logged:
                    self.query_log.append(
                        {
                            "name": "ms_paths",
                            "cypher": cypher,
                            "parameters": params,
                            "row_count": 0,
                            "engine": self.engine,
                        }
                    )
        except HydraDBError as exc:
            self.query_log.append(
                {
                    "name": "ms_paths",
                    "cypher": cypher,
                    "parameters": {**params, "error": str(exc)[:500]},
                    "row_count": 0,
                    "engine": self.engine,
                }
            )
            rows = []
        grouped: dict[int, list[list[int]]] = {}
        for row in rows:
            ids = _path_ids(row.get("path"))
            if len(ids) < 2:
                continue
            grouped.setdefault(ids[0], []).append(ids)
        for src, paths in grouped.items():
            best = self._best_named_path(paths)
            if best:
                out[src] = best
        missing = [s for s in unique if s not in out]
        for src in missing:
            path = self.shortest_path(src, target, rel, max_len)
            if path:
                out[src] = path
        return out

    def _version_slugs(self, ids: list[int]) -> tuple[dict[int, str], dict[str, int]]:
        unique_ids = list(dict.fromkeys(int(i) for i in ids))
        rows: list[dict[str, Any]] = []
        try:
            rows = self.rows(
                "UNWIND $ids AS vid MATCH (v:PackageVersion {id: vid}) "
                "RETURN v.id AS id, v.slug AS slug, v.name AS name, v.version AS version",
                {"ids": unique_ids},
            )
        except HydraDBError:
            for vid in unique_ids:
                rows.extend(
                    self.rows(
                        "MATCH (v:PackageVersion {id: $id}) "
                        "RETURN v.id AS id, v.slug AS slug, v.name AS name, v.version AS version",
                        {"id": vid},
                    )
                )
        slug_of: dict[int, str] = {}
        id_of: dict[str, int] = {}
        for row in rows:
            vid = int(row["id"])
            slug = row.get("slug") or (
                f"{row.get('name')}@{row.get('version')}" if row.get("name") else None
            )
            if not slug:
                continue
            slug_of[vid] = str(slug)
            id_of[str(slug)] = vid
        return slug_of, id_of

    def _best_named_path(self, paths: list[list[int]]) -> list[int]:
        named: list[list[tuple[str, int]]] = []
        for path in paths:
            hops: list[tuple[str, int]] = []
            for vid in path:
                node = self.vertex(vid) or {}
                hops.append((str(node.get("name") or ""), int(vid)))
            if hops:
                named.append(hops)
        if not named:
            return []
        best = min(named, key=lambda path: (len(path), [name for name, _vid in path]))
        return [vid for _name, vid in best]

    def reverse_dependents(self, bad_id: int, max_len: int = 6) -> list[dict[str, Any]]:
        try:
            rows = self.rows(
                "CALL algo.SSpaths({sourceNode: $source, "
                "relTypes: ['DEPENDS_ON'], relDirection: 'incoming', "
                f"maxLen: {int(max_len)}, pathCount: 64}}) "
                "YIELD path RETURN path",
                {"source": bad_id},
                log_name="reverse_dependents",
            )
        except HydraDBError:
            rows = []
        found: dict[int, dict[str, Any]] = {}
        for row in rows:
            for vid in _path_ids(row.get("path")):
                if vid != bad_id and vid not in found:
                    node = self.vertex(vid) or {"id": vid}
                    found[vid] = node
        if found:
            return list(found.values())
        seen = {bad_id}
        frontier = [bad_id]
        out: list[dict[str, Any]] = []
        for _ in range(max_len):
            nxt: list[int] = []
            for vid in frontier:
                for nb in self.neighbors(vid, "DEPENDS_ON", incoming=True):
                    nid = int(nb["id"])
                    if nid in seen:
                        continue
                    seen.add(nid)
                    nxt.append(nid)
                    out.append(nb)
            frontier = nxt
            if not frontier:
                break
        return out

    def shared_maintainers(self, package: str) -> list[dict[str, Any]]:
        return self.rows(
            "MATCH (pkg:Package)-[:MAINTAINED_BY]->(m:Maintainer)<-[:MAINTAINED_BY]-(other:Package) "
            "WHERE pkg.name = $name "
            "RETURN other.name AS name, m.name AS maintainer, m.npm_user AS npm_user, other.id AS id",
            {"name": package},
            log_name="shared_maintainers",
        )

    def shared_infra(self, package: str) -> list[dict[str, Any]]:
        return self.rows(
            "MATCH (pkg:Package)-[:PUBLISHED_VIA]->(inf:Infrastructure)<-[:PUBLISHED_VIA]-(other:Package) "
            "WHERE pkg.name = $name "
            "RETURN other.name AS name, inf.name AS infra, inf.slug AS infra_slug, other.id AS id",
            {"name": package},
            log_name="shared_infra",
        )

    def typosquats(self, package: str) -> list[dict[str, Any]]:
        return self.rows(
            "MATCH (pkg:Package)-[:SIMILAR_NAME_TO]->(other:Package) "
            "WHERE pkg.name = $name "
            "RETURN other.name AS name, other.id AS id, other.downloads AS downloads",
            {"name": package},
            log_name="typosquats",
        )

    def shortest_path(self, source: int, target: int, rel: str, max_len: int = 6) -> list[int]:
        try:
            rows = self.rows(
                "CALL algo.SPpaths({sourceNode: $source, targetNode: $target, "
                f"relTypes: ['{rel}'], relDirection: 'outgoing', maxLen: {int(max_len)}, pathCount: 3}}) "
                "YIELD path RETURN path",
                {"source": source, "target": target},
                log_name="sp_path" if not any(item.get("name") == "sp_path" for item in self.query_log) else None,
            )
        except HydraDBError:
            return []
        paths = [_path_ids(row.get("path")) for row in rows]
        paths = [path for path in paths if len(path) >= 2]
        if not paths:
            return []
        return self._best_named_path(paths)

    def neighbors(self, vid: int, rel: str, *, incoming: bool = False) -> list[dict[str, Any]]:
        if incoming:
            cypher = (
                f"MATCH (d {{id: $id}})<-[:{rel}]-(s) "
                "RETURN s.id AS id, s.name AS name, s.version AS version, s.kind AS kind"
            )
        else:
            cypher = (
                f"MATCH (s {{id: $id}})-[:{rel}]->(d) "
                "RETURN d.id AS id, d.name AS name, d.version AS version, d.kind AS kind"
            )
        return self.rows(cypher, {"id": vid})

    def lockfile_resolves(self, lock_id: int) -> list[dict[str, Any]]:
        return self.lockfiles_resolves([lock_id]).get(int(lock_id), [])

    def lockfile_pins(self, lock_id: int) -> list[dict[str, Any]]:
        """Direct package.json pins — evidence paths start here, not at a transitive 1-hop."""
        return self.lockfiles_pins([lock_id]).get(int(lock_id), [])

    def lockfiles_resolves(self, lock_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
        return self._lockfile_map(lock_ids, "RESOLVES", "lockfile_resolves")

    def lockfiles_pins(self, lock_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
        return self._lockfile_map(lock_ids, "PINS", "lockfile_pins")

    def _lockfile_map(self, lock_ids: list[int], rel: str, log_name: str) -> dict[int, list[dict[str, Any]]]:
        ids = list(dict.fromkeys(int(i) for i in lock_ids))
        out: dict[int, list[dict[str, Any]]] = {lid: [] for lid in ids}
        if not ids:
            return out
        cypher = (
            "UNWIND $locks AS lock_id "
            f"MATCH (lock:LockfileSnapshot {{id: lock_id}})-[:{rel}]->(pv:PackageVersion) "
            "RETURN lock.id AS lock_id, pv.id AS id, pv.name AS name, pv.version AS version"
        )
        try:
            rows = self.rows(cypher, {"locks": ids}, log_name=log_name)
        except HydraDBError:
            rows = []
            for i, lid in enumerate(ids):
                rows.extend(
                    [
                        {**row, "lock_id": lid}
                        for row in self.rows(
                            f"MATCH (lock:LockfileSnapshot {{id: $lock}})-[:{rel}]->(pv:PackageVersion) "
                            "RETURN pv.id AS id, pv.name AS name, pv.version AS version",
                            {"lock": lid},
                            log_name=log_name if i == 0 else None,
                        )
                    ]
                )
        for row in rows:
            lid = int(row.get("lock_id") or 0)
            if lid in out:
                out[lid].append(row)
        return out

    def list_services(self) -> list[dict[str, Any]]:
        return self.rows(
            "MATCH (svc:Service)-[:IN_ORG]->(c:Catalog {id: 0}) "
            "RETURN svc.id AS id, svc.name AS name, svc.env AS env, "
            "svc.criticality AS criticality, svc.team AS team, svc.deployed_at AS deployed_at",
            log_name="services",
        )

    def list_packages(self) -> list[dict[str, Any]]:
        return self.rows(
            "MATCH (p:Package) RETURN p.id AS id, p.name AS name, p.downloads AS downloads, p.repo AS repo",
            log_name="packages",
        )

    def package_releases(self, name: str) -> list[dict[str, Any]]:
        """HAS_RELEASE walk — which version introduced the compromise."""
        rows = self.rows(
            "MATCH (p:Package)-[:HAS_RELEASE]->(v:PackageVersion) "
            "WHERE p.name = $name "
            "RETURN v.id AS id, v.name AS name, v.version AS version, "
            "v.published_at AS published_at, v.compromised AS compromised, v.yanked AS yanked",
            {"name": name},
            log_name="package_releases",
        )
        return sorted(rows, key=lambda row: (int(row.get("published_at") or 0), str(row.get("version") or "")))

    def incident_window(self, name: str, version: str) -> dict[str, Any] | None:
        rows = self.rows(
            "MATCH (v:PackageVersion)-[:COMPROMISED_IN]->(w:IncidentWindow) "
            "WHERE v.name = $name AND v.version = $version "
            "RETURN w.slug AS slug, w.name AS title, w.start_ts AS start_ts, "
            "w.end_ts AS end_ts, w.advisory AS advisory, v.id AS version_id",
            {"name": name, "version": version},
            log_name="compromised_in",
        )
        return rows[0] if rows else None

    def list_versions(self, name: str | None = None) -> list[dict[str, Any]]:
        if name:
            return self.rows(
                "MATCH (v:PackageVersion) WHERE v.name = $name "
                "RETURN v.id AS id, v.name AS name, v.version AS version, "
                "v.published_at AS published_at, v.compromised AS compromised",
                {"name": name},
                log_name="versions",
            )
        return self.rows(
            "MATCH (v:PackageVersion) "
            "RETURN v.id AS id, v.name AS name, v.version AS version, "
            "v.published_at AS published_at, v.compromised AS compromised",
            log_name="versions",
        )

    def vertex(self, vid: int) -> dict[str, Any] | None:
        key = int(vid)
        if key in self._vertex_cache:
            return self._vertex_cache[key]
        rows = self.rows(
            "MATCH (n {id: $id}) RETURN n.id AS id, n.name AS name, n.version AS version, "
            "n.kind AS kind, n.env AS env, n.criticality AS criticality",
            {"id": key},
        )
        node = rows[0] if rows else None
        if node:
            self._vertex_cache[key] = node
        return node


def _chunks(rows: list[Any], size: int):
    for i in range(0, len(rows), size):
        yield rows[i : i + size]


def _path_ids(path: Any) -> list[int]:
    if path is None:
        return []
    if isinstance(path, dict):
        nodes = path.get("nodes") or path.get("vertices") or []
        ids: list[int] = []
        for node in nodes:
            if isinstance(node, dict):
                value = node.get("id") or node.get("value")
                if isinstance(value, dict):
                    value = value.get("value")
                if value is not None:
                    ids.append(int(value))
            elif isinstance(node, int):
                ids.append(node)
        return ids
    if isinstance(path, list):
        out = []
        for item in path:
            if isinstance(item, int):
                out.append(item)
            elif isinstance(item, dict) and "id" in item:
                out.append(int(item["id"]))
        return out
    return []
