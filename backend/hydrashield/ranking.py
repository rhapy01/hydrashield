"""Severity ranking for exposed services.

The score is a weighted mix of production criticality, environment,
dependency depth, and whether the lockfile pinned the compromised
version itself (versus only a transitive ancestor).
"""

from __future__ import annotations

from typing import Any


CRITICALITY = {"P0": 1.0, "P1": 0.72, "P2": 0.42, "P3": 0.18}
ENV = {"production": 1.0, "staging": 0.38, "dev": 0.12}


def exposure_score(
    *,
    criticality: str,
    env: str,
    depth: int,
    max_depth: int = 8,
    direct_pin: bool = False,
    window_overlap_s: int = 0,
    window_len_s: int = 360,
) -> float:
    crit = CRITICALITY.get(criticality, 0.3)
    environment = ENV.get(env, 0.2)
    depth_term = 1.0 - min(max(depth, 0), max_depth) / max_depth
    pin_term = 1.0 if direct_pin else 0.55
    if window_len_s <= 0:
        temporal = 1.0
    else:
        temporal = min(1.0, max(window_overlap_s, 0) / window_len_s)
        temporal = 0.65 + 0.35 * temporal
    score = (
        0.38 * crit
        + 0.24 * environment
        + 0.18 * depth_term
        + 0.12 * pin_term
        + 0.08 * temporal
    )
    return round(min(1.0, max(0.0, score)), 4)


def rank_services(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for row in rows:
        score = exposure_score(
            criticality=str(row.get("criticality") or "P3"),
            env=str(row.get("env") or "dev"),
            depth=int(row.get("depth") or 1),
            direct_pin=bool(row.get("direct_pin")),
            window_overlap_s=int(row.get("window_overlap_s") or 0),
            window_len_s=int(row.get("window_len_s") or 360),
        )
        item = dict(row)
        item["score"] = score
        ranked.append(item)
    ranked.sort(key=lambda item: (-item["score"], item.get("depth", 99), item.get("name", "")))
    return ranked
