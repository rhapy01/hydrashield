"""Parse npm lockfile v2/v3 JSON into resolved package versions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_lockfile(payload: dict[str, Any]) -> dict[str, Any]:
    name = payload.get("name") or payload.get("packages", {}).get("", {}).get("name") or "unknown"
    resolved_at = payload.get("resolved_at") or payload.get("hydrashield_resolved_at")
    packages: list[dict[str, str]] = []
    direct: dict[str, str] = {}

    root = payload.get("packages", {}).get("") or {}
    deps = root.get("dependencies") or payload.get("dependencies") or {}
    if isinstance(deps, dict):
        for dep_name, spec in deps.items():
            if isinstance(spec, str):
                direct[dep_name] = spec
            elif isinstance(spec, dict) and spec.get("version"):
                direct[dep_name] = str(spec["version"])

    if "packages" in payload and isinstance(payload["packages"], dict):
        for key, meta in payload["packages"].items():
            if key == "" or not isinstance(meta, dict):
                continue
            pkg_name = meta.get("name")
            if not pkg_name:
                pkg_name = key.replace("node_modules/", "").split("node_modules/")[-1]
            version = str(meta.get("version") or "")
            if pkg_name and version:
                packages.append({"name": pkg_name, "version": version})
    elif "dependencies" in payload and isinstance(payload["dependencies"], dict):
        _walk_v1(payload["dependencies"], packages)

    # de-dupe
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for item in packages:
        pair = (item["name"], item["version"])
        if pair in seen:
            continue
        seen.add(pair)
        unique.append(item)

    return {
        "name": name,
        "resolved_at": resolved_at,
        "direct": direct,
        "packages": unique,
        "commit": payload.get("commit") or "",
    }


def _walk_v1(deps: dict[str, Any], out: list[dict[str, str]]) -> None:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        version = str(meta.get("version") or "")
        if version:
            out.append({"name": name, "version": version})
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _walk_v1(nested, out)


def load_lockfile(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    parsed = parse_lockfile(payload)
    parsed["path"] = str(path)
    parsed["filename"] = path.name
    if not parsed.get("resolved_at"):
        parsed["resolved_at"] = None
    return parsed
