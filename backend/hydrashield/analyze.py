"""Blast-radius analysis. Topology, paths, and fleet state all come from HydraDB."""

from __future__ import annotations

from typing import Any

from . import universe as U
from .graph import GraphStore
from .blast import build_blast
from .ranking import rank_services
from .remediation import remediation_plan
from .replay import build_replay
from .schema import REL


def _dedupe(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    seen: set[Any] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        value = row.get(key)
        if value in seen:
            continue
        seen.add(value)
        out.append(row)
    return out


def _unique_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, Any, Any]] = set()
    out: list[dict[str, Any]] = []
    for edge in edges:
        key = (edge["source"], edge["target"], edge["rel"])
        if key in seen:
            continue
        seen.add(key)
        out.append(edge)
    return out


def _latest_pin(pins: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for row in pins:
        name = str(row.get("name") or "")
        if not name:
            continue
        prev = latest.get(name)
        if prev is None or int(row.get("resolved_at") or 0) >= int(prev.get("resolved_at") or 0):
            latest[name] = row
    return latest


def _why_contained(pin: dict[str, Any] | None, bad_version: str, t0: int, t1: int) -> str:
    if not pin:
        return "no_pin"
    resolved = int(pin.get("resolved_at") or 0)
    version = str(pin.get("version") or "")
    if resolved < t0:
        return "before_window"
    if resolved > t1:
        return "after_yank"
    if version != bad_version:
        return "other_version"
    return "outside_window"


class Analyzer:
    def __init__(self, store: GraphStore, id_map: dict[str, int] | None = None) -> None:
        self.store = store
        self.id_map = id_map or {}

    def analyze(
        self,
        *,
        package: str | None = None,
        version: str | None = None,
        start_ts: int | None = None,
        end_ts: int | None = None,
        safe_version: str | None = None,
    ) -> dict[str, Any]:
        inc = U.INCIDENT
        package = package or inc["package"]
        version = version or inc["version"]
        start_ts = start_ts if start_ts is not None else inc["published_ts"]
        end_ts = end_ts if end_ts is not None else inc["yanked_ts"]
        if start_ts > end_ts:
            raise ValueError("start_ts must be <= end_ts")
        window_len = max(end_ts - start_ts, 1)
        safe_version = safe_version or inc["safe_version"]

        self.store.query_log = []
        bad = self.store.find_version(package, version)
        if not bad:
            raise LookupError(f"PackageVersion {package}@{version} is not in the graph")
        bad_id = int(bad["id"])

        hits = self.store.lockfile_hits(bad_id, start_ts, end_ts)
        pins = self.store.package_pins(package)
        reverse = self.store.reverse_dependents(bad_id)
        maintainers = self.store.shared_maintainers(package)
        infra = self.store.shared_infra(package)
        typos = self.store.typosquats(package)
        fleet = self.store.list_services()
        releases = self.store.package_releases(package)

        lock_candidates: dict[int, list[int]] = {}
        all_sources: list[int] = []
        for hit in hits:
            lock_id = int(hit["lock_id"])
            if lock_id in lock_candidates:
                continue
            resolved = self.store.lockfile_resolves(lock_id)
            ids = [int(row["id"]) for row in resolved if row.get("id") is not None]
            candidates = [vid for vid in ids if vid != bad_id] or ([bad_id] if bad_id in ids else ids)
            lock_candidates[lock_id] = candidates
            all_sources.extend(candidates)
        batched_paths = self.store.many_shortest_paths(all_sources, bad_id, REL["depends_on"], 6)

        exposed: list[dict[str, Any]] = []
        graph_nodes: dict[int, dict[str, Any]] = {
            bad_id: {
                "id": bad_id,
                "label": f"{package}@{version}",
                "kind": "compromised",
                "name": package,
                "version": version,
            }
        }
        graph_edges: list[dict[str, Any]] = []

        for hit in hits:
            lock_id = int(hit["lock_id"])
            path_ids = self._pick_path(lock_candidates.get(lock_id) or [], bad_id, batched_paths)
            path = []
            for vid in path_ids:
                node = self.store.vertex(vid) or {}
                name = str(node.get("name") or "")
                ver = str(node.get("version") or "")
                if name:
                    path.append({"name": name, "version": ver, "id": vid})
                    graph_nodes[vid] = {
                        "id": vid,
                        "label": f"{name}@{ver}" if ver else name,
                        "kind": "package" if vid != bad_id else "compromised",
                        "name": name,
                        "version": ver,
                    }
            if not path:
                node = self.store.vertex(bad_id) or bad
                path = [{"name": str(node.get("name") or package), "version": str(node.get("version") or version), "id": bad_id}]
                path_ids = [bad_id]

            svc_id = int(hit["service_id"])
            graph_nodes[svc_id] = {
                "id": svc_id,
                "label": hit["name"],
                "kind": "service",
                "name": hit["name"],
                "criticality": hit["criticality"],
                "env": hit["env"],
            }
            if path_ids:
                graph_edges.append({"source": svc_id, "target": path_ids[0], "rel": "EXPOSES"})
                for src, dst in zip(path_ids, path_ids[1:]):
                    graph_edges.append({"source": src, "target": dst, "rel": REL["depends_on"]})

            resolved_at = int(hit["resolved_at"])
            overlap = min(end_ts, resolved_at) - start_ts if start_ts <= resolved_at <= end_ts else 0
            depth = max(len(path) - 1, 1) if path else 1
            exposed.append(
                {
                    "id": svc_id,
                    "name": hit["name"],
                    "application": hit["application"],
                    "env": hit["env"],
                    "criticality": hit["criticality"],
                    "team": hit["team"],
                    "deployed_at": hit["deployed_at"],
                    "resolved_at": resolved_at,
                    "commit": hit.get("commit") or "",
                    "depth": depth,
                    "direct_pin": bool(path and path[0].get("name") == package),
                    "window_overlap_s": max(overlap, 1),
                    "window_len_s": window_len,
                    "path": path,
                    "path_packages": [hop["name"] for hop in path],
                }
            )

        ranked = rank_services(exposed)
        unique_maintainers = _dedupe(maintainers, "name")
        unique_infra = _dedupe(infra, "name")
        unique_typos = _dedupe(typos, "name")
        shared_pkgs = [row["name"] for row in unique_maintainers if row["name"] != package]
        oidc = [row for row in unique_infra if "oidc" in str(row.get("infra_slug") or row.get("infra") or "").lower()]
        plan = remediation_plan(
            compromised_package=package,
            safe_version=safe_version,
            exposed=ranked,
            shared_maintainer_packages=shared_pkgs,
            typosquats=[row["name"] for row in unique_typos],
        )

        reverse_nodes = []
        for row in reverse:
            vid = int(row["id"])
            reverse_nodes.append(row)
            if vid not in graph_nodes:
                graph_nodes[vid] = {
                    "id": vid,
                    "label": f"{row.get('name')}@{row.get('version')}",
                    "kind": "ecosystem",
                    "name": row.get("name"),
                    "version": row.get("version"),
                }
            graph_edges.append({"source": vid, "target": bad_id, "rel": REL["depends_on"]})

        exposed_names = {row["name"] for row in ranked}
        pin_by_service = _latest_pin(pins)
        scanner_name = {row["name"] for row in pins}
        scanner_version = {row["name"] for row in pins if str(row.get("version")) == version}
        fleet_rows = []
        contained: list[dict[str, Any]] = []
        for svc in fleet:
            name = svc.get("name")
            hit = next((row for row in ranked if row["name"] == name), None)
            pin = pin_by_service.get(name)
            why = _why_contained(pin, version, start_ts, end_ts) if not hit else "exposed"
            row = {
                **svc,
                "exposed": name in exposed_names,
                "score": hit["score"] if hit else 0,
                "depth": hit["depth"] if hit else None,
                "resolved_at": hit["resolved_at"] if hit else (pin or {}).get("resolved_at"),
                "pinned_version": (pin or {}).get("version"),
                "why": why,
            }
            fleet_rows.append(row)
            if not hit:
                contained.append(row)
        fleet_rows.sort(key=lambda item: (-int(item.get("exposed") or 0), -(item.get("score") or 0), item.get("name") or ""))
        contained.sort(key=lambda item: (item.get("why") or "", item.get("name") or ""))
        false_positives = sorted(scanner_name - exposed_names)

        timeline = sorted(
            [
                {
                    "at": row["resolved_at"],
                    "kind": "lockfile",
                    "label": f"{row['name']} resolved {package}@{version}",
                    "service": row["name"],
                    "severity": row["criticality"],
                }
                for row in ranked
            ],
            key=lambda item: int(item["at"]),
        )
        timeline.insert(0, {"at": start_ts, "kind": "publish", "label": f"{package}@{version} published", "severity": "P0"})
        timeline.append({"at": end_ts, "kind": "yank", "label": f"{package}@{version} yanked", "severity": "ok"})

        production = [row for row in ranked if row["env"] == "production"]
        p0 = [row for row in ranked if row["criticality"] == "P0"]
        briefing = (
            f"{len(ranked)} VantaPay services resolved {package}@{version} while it was live "
            f"({window_len}s). {len(p0)} of those are P0 production. "
            f"A name grep of lockfiles would also flag {len(false_positives)} services that "
            f"never resolved the malicious version in-window — including pins before 09:00 and after the yank."
        )
        return {
            "engine": "hydradb",
            "briefing": briefing,
            "contrast": {
                "scanner_name_hits": len(scanner_name),
                "scanner_version_hits": len(scanner_version),
                "hydrashield_exposed": len(ranked),
                "false_positives": false_positives,
                "why": "Lockfile grep has no time. HydraDB matches Service→Lockfile→PackageVersion only where lock.resolved_at sits inside the publish/yank window.",
            },
            "contained": contained,
            "next_hop": {
                "reason": "Packages that publish through the same GitHub Actions OIDC identity the worm reused.",
                "packages": oidc,
            },
            "incident": {
                **inc,
                "package": package,
                "version": version,
                "safe_version": safe_version,
                "start_ts": start_ts,
                "end_ts": end_ts,
            },
            "compromised": bad,
            "summary": {
                "services_total": len(fleet_rows),
                "services_exposed": len(ranked),
                "services_safe": max(len(fleet_rows) - len(ranked), 0),
                "production_exposed": len(production),
                "p0_exposed": len(p0),
                "ecosystem_dependents": len(reverse_nodes),
                "shared_maintainers": len({row.get("maintainer") for row in unique_maintainers}),
                "typosquats": len(unique_typos),
                "window_seconds": window_len,
                "scanner_false_positives": len(false_positives),
            },
            "exposed": ranked,
            "fleet": fleet_rows,
            "timeline": timeline,
            "ecosystem": reverse_nodes,
            "maintainers": unique_maintainers,
            "infrastructure": unique_infra,
            "typosquats": unique_typos,
            "remediation": plan,
            "graph": {"nodes": list(graph_nodes.values()), "edges": _unique_edges(graph_edges)},
            "replay": build_replay(ranked, t0=start_ts, t1=end_ts),
            "blast": build_blast(
                package=package,
                version=version,
                safe_version=safe_version,
                ranked=ranked,
                reverse=reverse_nodes,
                maintainers=unique_maintainers,
                infra=unique_infra,
                typos=unique_typos,
                releases=releases,
                t0=start_ts,
                t1=end_ts,
            ),
            "queries": list(self.store.query_log),
        }

    def _pick_path(
        self, candidates: list[int], bad_id: int, batched: dict[int, list[int]]
    ) -> list[int]:
        best: list[int] = []
        for src in candidates:
            path = batched.get(src) or []
            if not path:
                path = self._hydra_bfs(src, bad_id, REL["depends_on"], 6)
            if path and (not best or len(path) < len(best)):
                best = path
        if not best and bad_id in candidates:
            return [bad_id]
        return best

    def _evidence_path(self, lock_id: int, bad_id: int) -> list[int]:
        resolved = self.store.lockfile_resolves(lock_id)
        ids = [int(row["id"]) for row in resolved if row.get("id") is not None]
        candidates = [vid for vid in ids if vid != bad_id] or ([bad_id] if bad_id in ids else ids)
        batched = self.store.many_shortest_paths(candidates, bad_id, REL["depends_on"], 6)
        return self._pick_path(candidates, bad_id, batched)

    def _hydra_bfs(self, source: int, target: int, rel: str, max_len: int) -> list[int]:
        """1-hop MATCH walk on HydraDB when algo.SPpaths does not return a path."""
        if source == target:
            return [source]
        queue: list[list[int]] = [[source]]
        seen = {source}
        while queue:
            path = queue.pop(0)
            if len(path) - 1 >= max_len:
                continue
            for nbr in self.store.neighbors(path[-1], rel, incoming=False):
                nxt = int(nbr["id"])
                if nxt in seen:
                    continue
                seen.add(nxt)
                nxt_path = path + [nxt]
                if nxt == target:
                    return nxt_path
                queue.append(nxt_path)
        return []

    def evidence(self, service_name: str, **kwargs: Any) -> dict[str, Any]:
        result = self.analyze(**kwargs)
        match = next((row for row in result["exposed"] if row["name"] == service_name), None)
        if not match:
            raise LookupError(f"{service_name} was not exposed in the incident window")
        return {"service": match, "incident": result["incident"], "engine": result["engine"], "queries": result["queries"]}
