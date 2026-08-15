"""Turn ranked exposure into an ordered upgrade plan.

The interesting move is collapsing many service hits into the fewest
package-version upgrades that remove the compromised node from each
lockfile's resolved graph.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def residual_after(exposed: list[dict[str, Any]], upgraded: set[str]) -> list[dict[str, Any]]:
    remaining = []
    for row in exposed:
        path_packages = set(row.get("path_packages") or [])
        if path_packages & upgraded:
            continue
        remaining.append(row)
    return remaining


def remediation_plan(
    *,
    compromised_package: str,
    safe_version: str,
    exposed: list[dict[str, Any]],
    shared_maintainer_packages: list[str],
    typosquats: list[str],
) -> dict[str, Any]:
    """Greedy set-cover over path packages, starting at the compromised node."""
    steps: list[dict[str, Any]] = []
    remaining = list(exposed)
    upgraded: set[str] = set()

    first_cover = residual_after(remaining, {compromised_package})
    steps.append(
        {
            "action": "upgrade",
            "package": compromised_package,
            "to_version": safe_version,
            "reason": "Removes the compromised version from every lockfile that still resolves it.",
            "services_fixed": len(remaining) - len(first_cover),
            "residual": len(first_cover),
        }
    )
    remaining = first_cover
    upgraded.add(compromised_package)

    # If anything is still exposed (shouldn't be if every path contains the
    # compromised package), cover the most frequent ancestor next.
    while remaining:
        counts: dict[str, int] = defaultdict(int)
        for row in remaining:
            for name in row.get("path_packages") or []:
                if name not in upgraded:
                    counts[name] += 1
        if not counts:
            break
        nxt = max(counts, key=lambda name: counts[name])
        after = residual_after(remaining, upgraded | {nxt})
        steps.append(
            {
                "action": "upgrade",
                "package": nxt,
                "to_version": "latest-safe",
                "reason": "Shared ancestor still pulling a stale transitive edge.",
                "services_fixed": len(remaining) - len(after),
                "residual": len(after),
            }
        )
        remaining = after
        upgraded.add(nxt)

    review = [
        {
            "action": "review",
            "package": name,
            "reason": "Shares a maintainer or publishing pipeline with the compromised package.",
        }
        for name in shared_maintainer_packages
        if name != compromised_package
    ]
    block = [
        {
            "action": "block",
            "package": name,
            "reason": "Name is within typosquat distance of the compromised package.",
        }
        for name in typosquats
    ]
    rotate = {
        "action": "rotate_credentials",
        "reason": "Assume npm tokens and CI OIDC identity used to publish 2.4.1 are burned.",
    }
    return {
        "summary": (
            f"Upgrade {compromised_package}@{safe_version} first. "
            f"That clears {steps[0]['services_fixed']} services in one change."
        ),
        "steps": steps,
        "review": review,
        "block": block,
        "rotate": rotate,
        "residual_services": [row.get("name") for row in remaining],
    }
