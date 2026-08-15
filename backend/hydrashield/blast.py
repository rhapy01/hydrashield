"""Complete blast radius as three rings plus the introducing version.

Track 2A is not “is package X in the lockfile.” It is six graph questions.
HydraShield answers them as one object: which release introduced the worm,
who in the org resolved it while it was live, who in the ecosystem depends
on it, and who sits one identity/name hop away.
"""

from __future__ import annotations

from typing import Any


def classify_release(
    row: dict[str, Any],
    *,
    bad_version: str,
    safe_version: str,
    t0: int,
    t1: int,
) -> str:
    version = str(row.get("version") or "")
    published = int(row.get("published_at") or 0)
    compromised = bool(row.get("compromised"))
    if version == bad_version or compromised:
        return "introduced"
    if version == safe_version or published > t1:
        return "patched"
    if published and published < t0:
        return "prior_clean"
    return "other"


def build_blast(
    *,
    package: str,
    version: str,
    safe_version: str,
    ranked: list[dict[str, Any]],
    reverse: list[dict[str, Any]],
    maintainers: list[dict[str, Any]],
    infra: list[dict[str, Any]],
    typos: list[dict[str, Any]],
    releases: list[dict[str, Any]],
    t0: int,
    t1: int,
) -> dict[str, Any]:
    classified = []
    for row in sorted(releases, key=lambda item: (int(item.get("published_at") or 0), str(item.get("version") or ""))):
        role = classify_release(row, bad_version=version, safe_version=safe_version, t0=t0, t1=t1)
        classified.append({**row, "role": role})
    introduced = next((row for row in classified if row["role"] == "introduced"), None)
    prior = next((row for row in classified if row["role"] == "prior_clean"), None)
    patched = next((row for row in classified if row["role"] == "patched"), None)

    org_names = [row["name"] for row in ranked]
    eco_names = []
    seen_eco: set[str] = set()
    for row in reverse:
        label = f"{row.get('name')}@{row.get('version')}" if row.get("version") else str(row.get("name") or "")
        if not label or label in seen_eco:
            continue
        seen_eco.add(label)
        eco_names.append(label)

    maint_names = [row["name"] for row in maintainers if row.get("name") and row["name"] != package]
    infra_names = [row["name"] for row in infra if row.get("name") and row["name"] != package]
    typo_names = [row["name"] for row in typos if row.get("name")]
    adjacent = list(dict.fromkeys([*maint_names, *infra_names, *typo_names]))

    return {
        "introducing": {
            "package": package,
            "version": version,
            "safe_version": safe_version,
            "why": (
                f"{package}@{version} is the first compromised HAS_RELEASE."
                + (f" Prior {package}@{prior['version']} is clean." if prior else "")
                + (f" {package}@{patched['version']} is the post-yank rebuild." if patched else "")
            ),
            "releases": classified,
            "introduced": introduced,
        },
        "rings": {
            "org": {
                "label": "Org · in-window",
                "count": len(org_names),
                "names": org_names,
                "why": "Service → Lockfile → PackageVersion with lock.resolved_at inside the publish/yank window.",
            },
            "ecosystem": {
                "label": "Ecosystem · reverse dependents",
                "count": len(eco_names),
                "names": eco_names,
                "why": "algo.SSpaths incoming on DEPENDS_ON from the compromised PackageVersion.",
            },
            "adjacent": {
                "label": "Adjacent · identity / typosquat",
                "count": len(adjacent),
                "names": adjacent,
                "maintainers": maint_names,
                "infra": infra_names,
                "typosquats": typo_names,
                "why": "MAINTAINED_BY and PUBLISHED_VIA diamonds plus SIMILAR_NAME_TO. Not hit yet — the worm’s next hop.",
            },
        },
        "answers": [
            {
                "q": "Which internal services are transitively exposed?",
                "a": f"{len(org_names)} VantaPay services, ranked by criticality and path depth.",
            },
            {
                "q": "Which version introduced the vulnerability?",
                "a": f"{package}@{version} on HAS_RELEASE. Earlier releases are clean; {safe_version} is the patch.",
            },
            {
                "q": "Which applications resolved it while it was live?",
                "a": ", ".join(org_names[:8]) + ("…" if len(org_names) > 8 else ""),
            },
            {
                "q": "Which packages share maintainers or infrastructure?",
                "a": ", ".join(list(dict.fromkeys([*maint_names, *infra_names]))[:8]) or "None in this snapshot.",
            },
            {
                "q": "Are there likely typosquat packages nearby?",
                "a": ", ".join(typo_names) or "None in this snapshot.",
            },
            {
                "q": "What is the complete blast radius?",
                "a": (
                    f"{len(org_names)} org services in-window, "
                    f"{len(eco_names)} ecosystem dependents, "
                    f"{len(adjacent)} adjacent next-hop packages."
                ),
            },
        ],
    }
