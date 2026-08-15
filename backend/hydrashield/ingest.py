"""Write vertices and typed edges into a GraphStore from the curated universe."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import universe as U
from .graph import GraphStore
from .lockfiles import parse_lockfile
from .schema import CATALOG, LABELS, REL, IdAllocator


def _resolved_ts(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value:
        raw = value.strip()
        if raw.endswith("Z") and raw.count("T") == 1:
            try:
                return U.parse_iso(raw[:19] + "Z")
            except ValueError:
                pass
        try:
            return int(raw)
        except ValueError:
            pass
    return U.INCIDENT["published_ts"] + 90


class Ingestor:
    def __init__(self, store: GraphStore, data_dir: Path | None = None, ids: IdAllocator | None = None) -> None:
        self.store = store
        self.data_dir = data_dir
        self.ids = ids or IdAllocator()
        self.stats: dict[str, int] = {"vertices": 0, "edges": 0}

    def ingest(self) -> dict[str, Any]:
        self._upsert_catalog()
        self._upsert_maintainers()
        self._upsert_infra()
        self._upsert_packages()
        self._upsert_versions()
        self._upsert_incident()
        self._upsert_apps_and_lockfiles()
        self._upsert_services()
        self._edges_releases()
        self._edges_depends()
        self._edges_ownership()
        self._edges_lockfiles()
        self._edges_maintainers_infra()
        self._edges_typosquat()
        self._edges_compromised()
        return {
            "org": U.ORG,
            "incident": U.INCIDENT,
            "vertices": self.stats["vertices"],
            "edges": self.stats["edges"],
            "engine": getattr(self.store, "engine", "unknown"),
            "ids": self.ids.dump(),
        }

    def _vertices(self, label: str, rows: list[dict[str, Any]], set_clause: str) -> None:
        if not rows:
            return
        self.store.merge_vertices(label, rows, set_clause)
        self.stats["vertices"] += len(rows)

    def _edges(self, rel: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        self.store.merge_edges(rel, rows)
        self.stats["edges"] += len(rows)

    def _upsert_catalog(self) -> None:
        self._vertices(
            LABELS["catalog"],
            [{"vertex": CATALOG, "name": U.ORG["name"], "slug": U.ORG["slug"], "kind": "catalog"}],
            "n.name = row.name, n.slug = row.slug, n.kind = row.kind",
        )

    def _upsert_maintainers(self) -> None:
        rows = [
            {
                "vertex": self.ids.get("maintainer", item["slug"]),
                "name": item["name"],
                "slug": item["slug"],
                "npm_user": item["npm_user"],
                "email": item["email"],
                "kind": "maintainer",
            }
            for item in U.MAINTAINERS
        ]
        self._vertices(
            LABELS["maintainer"],
            rows,
            "n.name = row.name, n.slug = row.slug, n.npm_user = row.npm_user, n.email = row.email, n.kind = row.kind",
        )

    def _upsert_infra(self) -> None:
        rows = [
            {
                "vertex": self.ids.get("infra", item["slug"]),
                "name": item["name"],
                "slug": item["slug"],
                "infra_kind": item["kind"],
                "kind": "infra",
            }
            for item in U.INFRA
        ]
        self._vertices(
            LABELS["infra"],
            rows,
            "n.name = row.name, n.slug = row.slug, n.infra_kind = row.infra_kind, n.kind = row.kind",
        )

    def _upsert_packages(self) -> None:
        rows = []
        for name in U.package_names():
            meta = U.PACKAGE_META.get(name, U.DEFAULT_META)
            downloads = next((weekly for pkg, _v, _t, _y, _c, weekly in U.PACKAGE_RELEASES if pkg == name), 0)
            rows.append(
                {
                    "vertex": self.ids.get("package", name),
                    "name": name,
                    "slug": name,
                    "description": meta.get("description") or name,
                    "repo": meta.get("repo") or "",
                    "downloads": downloads,
                    "ecosystem": "npm",
                    "kind": "package",
                }
            )
        self._vertices(
            LABELS["package"],
            rows,
            "n.name = row.name, n.slug = row.slug, n.description = row.description, "
            "n.repo = row.repo, n.downloads = row.downloads, n.ecosystem = row.ecosystem, n.kind = row.kind",
        )

    def _upsert_versions(self) -> None:
        rows = []
        for name, version, published_ts, yanked, compromised, _downloads in U.PACKAGE_RELEASES:
            key = f"{name}@{version}"
            rows.append(
                {
                    "vertex": self.ids.get("version", key),
                    "name": name,
                    "version": version,
                    "slug": key,
                    "published_at": published_ts,
                    "yanked": yanked,
                    "compromised": compromised,
                    "kind": "version",
                }
            )
        self._vertices(
            LABELS["version"],
            rows,
            "n.name = row.name, n.version = row.version, n.slug = row.slug, "
            "n.published_at = row.published_at, n.yanked = row.yanked, "
            "n.compromised = row.compromised, n.kind = row.kind",
        )

    def _upsert_incident(self) -> None:
        inc = U.INCIDENT
        self._vertices(
            LABELS["incident"],
            [
                {
                    "vertex": self.ids.get("incident", inc["slug"]),
                    "name": inc["title"],
                    "slug": inc["slug"],
                    "package": inc["package"],
                    "version": inc["version"],
                    "start_ts": inc["published_ts"],
                    "end_ts": inc["yanked_ts"],
                    "advisory": inc["advisory"],
                    "kind": "incident",
                }
            ],
            "n.name = row.name, n.slug = row.slug, n.package = row.package, n.version = row.version, "
            "n.start_ts = row.start_ts, n.end_ts = row.end_ts, n.advisory = row.advisory, n.kind = row.kind",
        )

    def lockfile_docs(self) -> list[dict[str, Any]]:
        docs: list[dict[str, Any]] = []
        lock_dir = self.data_dir / "org" / "lockfiles" if self.data_dir else None
        if lock_dir and lock_dir.exists():
            for path in sorted(lock_dir.glob("*.json")):
                docs.append(parse_lockfile(json.loads(path.read_text(encoding="utf-8"))))
            if docs:
                return docs
        for app in U.APPLICATIONS:
            parsed = parse_lockfile(U.lockfile_payload(app))
            parsed["filename"] = f"{app['slug']}.package-lock.json"
            docs.append(parsed)
        return docs

    def _upsert_apps_and_lockfiles(self) -> None:
        app_rows = []
        lock_rows = []
        for app in U.APPLICATIONS:
            app_rows.append(
                {
                    "vertex": self.ids.get("application", app["slug"]),
                    "name": app["slug"],
                    "slug": app["slug"],
                    "repo": app["repo"],
                    "kind": "application",
                }
            )
            lock_rows.append(
                {
                    "vertex": self.ids.get("lockfile", app["slug"]),
                    "name": app["slug"],
                    "slug": app["slug"],
                    "resolved_at": U.parse_iso(app["resolved_at"]),
                    "commit": app["commit"],
                    "kind": "lockfile",
                }
            )
        self._vertices(
            LABELS["application"],
            app_rows,
            "n.name = row.name, n.slug = row.slug, n.repo = row.repo, n.kind = row.kind",
        )
        self._vertices(
            LABELS["lockfile"],
            lock_rows,
            "n.name = row.name, n.slug = row.slug, n.resolved_at = row.resolved_at, "
            "n.commit = row.commit, n.kind = row.kind",
        )

    def _upsert_services(self) -> None:
        rows = [
            {
                "vertex": self.ids.get("service", svc["slug"]),
                "name": svc["slug"],
                "slug": svc["slug"],
                "env": svc["env"],
                "criticality": svc["criticality"],
                "team": svc["team"],
                "deployed_at": U.parse_iso(svc["deployed_at"]),
                "kind": "service",
            }
            for svc in U.SERVICES
        ]
        self._vertices(
            LABELS["service"],
            rows,
            "n.name = row.name, n.slug = row.slug, n.env = row.env, n.criticality = row.criticality, "
            "n.team = row.team, n.deployed_at = row.deployed_at, n.kind = row.kind",
        )

    def _edges_releases(self) -> None:
        rows = [
            {
                "source": self.ids.lookup("package", name),
                "destination": self.ids.lookup("version", f"{name}@{version}"),
                "rel": self.ids.get("edge", f"rel:{name}@{version}"),
            }
            for name, version, *_rest in U.PACKAGE_RELEASES
        ]
        self._edges(REL["has_release"], rows)

    def _edges_depends(self) -> None:
        rows = [
            {
                "source": self.ids.lookup("version", f"{frm_n}@{frm_v}"),
                "destination": self.ids.lookup("version", f"{to_n}@{to_v}"),
                "rel": self.ids.get("edge", f"dep:{frm_n}@{frm_v}->{to_n}@{to_v}"),
            }
            for frm_n, frm_v, to_n, to_v in U.DEPENDENCIES
        ]
        self._edges(REL["depends_on"], rows)

    def _edges_ownership(self) -> None:
        run_rows = [
            {
                "source": self.ids.lookup("service", svc["slug"]),
                "destination": self.ids.lookup("application", svc["app"]),
                "rel": self.ids.get("edge", f"runs:{svc['slug']}"),
            }
            for svc in U.SERVICES
        ]
        org_rows = [
            {
                "source": self.ids.lookup("service", svc["slug"]),
                "destination": CATALOG,
                "rel": self.ids.get("edge", f"org:{svc['slug']}"),
            }
            for svc in U.SERVICES
        ]
        lock_rows = [
            {
                "source": self.ids.lookup("application", app["slug"]),
                "destination": self.ids.lookup("lockfile", app["slug"]),
                "rel": self.ids.get("edge", f"lock:{app['slug']}"),
            }
            for app in U.APPLICATIONS
        ]
        self._edges(REL["runs"], run_rows)
        self._edges(REL["has_lockfile"], lock_rows)
        self._edges(REL["in_org"], org_rows)

    def _edges_lockfiles(self) -> None:
        docs = {doc["name"]: doc for doc in self.lockfile_docs()}
        rows = []
        for app in U.APPLICATIONS:
            parsed = docs.get(app["slug"])
            flattened = (
                [(item["name"], item["version"]) for item in parsed["packages"]]
                if parsed
                else U.resolve_tree(app["direct"], pin_signal=app.get("pin_signal"))
            )
            lock_id = self.ids.lookup("lockfile", app["slug"])
            for name, version in flattened:
                key = f"{name}@{version}"
                try:
                    dest = self.ids.lookup("version", key)
                except KeyError:
                    dest = self.ids.get("version", key)
                rows.append(
                    {
                        "source": lock_id,
                        "destination": dest,
                        "rel": self.ids.get("edge", f"res:{app['slug']}:{key}"),
                    }
                )
        self._edges(REL["resolves"], rows)

    def _edges_maintainers_infra(self) -> None:
        maint_rows = []
        infra_rows = []
        for name in U.package_names():
            meta = U.PACKAGE_META.get(name, U.DEFAULT_META)
            maint = meta.get("maintainer") or "evan-brooks"
            maint_rows.append(
                {
                    "source": self.ids.lookup("package", name),
                    "destination": self.ids.lookup("maintainer", maint),
                    "rel": self.ids.get("edge", f"mnt:{name}"),
                }
            )
            for infra in meta.get("infra") or ["npmjs-registry"]:
                infra_rows.append(
                    {
                        "source": self.ids.lookup("package", name),
                        "destination": self.ids.lookup("infra", infra),
                        "rel": self.ids.get("edge", f"inf:{name}:{infra}"),
                    }
                )
        self._edges(REL["maintained_by"], maint_rows)
        self._edges(REL["published_via"], infra_rows)

    def _edges_typosquat(self) -> None:
        rows = [
            {
                "source": self.ids.lookup("package", left),
                "destination": self.ids.lookup("package", right),
                "rel": self.ids.get("edge", f"typo:{left}->{right}:{dist}"),
            }
            for left, right, dist in U.typosquat_pairs()
        ]
        self._edges(REL["similar_name_to"], rows)

    def _edges_compromised(self) -> None:
        inc = U.INCIDENT
        self._edges(
            REL["compromised_in"],
            [
                {
                    "source": self.ids.lookup("version", f"{inc['package']}@{inc['version']}"),
                    "destination": self.ids.lookup("incident", inc["slug"]),
                    "rel": self.ids.get("edge", "compromised"),
                }
            ],
        )

    def add_lockfile(
        self,
        parsed: dict[str, Any],
        *,
        env: str = "production",
        criticality: str = "P2",
        team: str = "imported",
    ) -> dict[str, Any]:
        name = str(parsed.get("name") or "imported-app")
        resolved_at = _resolved_ts(parsed.get("resolved_at"))
        avid = self.ids.get("application", name)
        lvid = self.ids.get("lockfile", name)
        svid = self.ids.get("service", name)
        self._vertices(
            LABELS["application"],
            [{"vertex": avid, "name": name, "slug": name, "repo": "", "kind": "application"}],
            "n.name = row.name, n.slug = row.slug, n.repo = row.repo, n.kind = row.kind",
        )
        self._vertices(
            LABELS["lockfile"],
            [{"vertex": lvid, "name": name, "slug": name, "resolved_at": resolved_at, "commit": parsed.get("commit") or "upload", "kind": "lockfile"}],
            "n.name = row.name, n.slug = row.slug, n.resolved_at = row.resolved_at, n.commit = row.commit, n.kind = row.kind",
        )
        self._vertices(
            LABELS["service"],
            [{"vertex": svid, "name": name, "slug": name, "env": env, "criticality": criticality, "team": team, "deployed_at": resolved_at, "kind": "service"}],
            "n.name = row.name, n.slug = row.slug, n.env = row.env, n.criticality = row.criticality, n.team = row.team, n.deployed_at = row.deployed_at, n.kind = row.kind",
        )
        self._edges(REL["runs"], [{"source": svid, "destination": avid, "rel": self.ids.get("edge", f"runs:{name}")}])
        self._edges(REL["has_lockfile"], [{"source": avid, "destination": lvid, "rel": self.ids.get("edge", f"lock:{name}")}])
        self._edges(REL["in_org"], [{"source": svid, "destination": CATALOG, "rel": self.ids.get("edge", f"org:{name}")}])
        res_rows = []
        for item in parsed.get("packages") or []:
            key = f"{item['name']}@{item['version']}"
            try:
                dest = self.ids.lookup("version", key)
            except KeyError:
                dest = self.ids.get("version", key)
                self._vertices(
                    LABELS["version"],
                    [{"vertex": dest, "name": item["name"], "version": item["version"], "slug": key, "published_at": resolved_at, "yanked": False, "compromised": False, "kind": "version"}],
                    "n.name = row.name, n.version = row.version, n.slug = row.slug, n.published_at = row.published_at, n.yanked = row.yanked, n.compromised = row.compromised, n.kind = row.kind",
                )
            res_rows.append({"source": lvid, "destination": dest, "rel": self.ids.get("edge", f"res:{name}:{key}")})
        self._edges(REL["resolves"], res_rows)
        return {"name": name, "resolved_at": resolved_at, "packages": len(res_rows)}
