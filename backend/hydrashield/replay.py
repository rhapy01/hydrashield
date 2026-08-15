"""360-second incident replay from HydraDB lockfile timestamps.

Frames and counterfactual yanks are derived from Service→Lockfile→PackageVersion
hits HydraDB already returned. The planner does not invent topology.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def clock(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime("%H:%M:%S")


def build_replay(
    ranked: list[dict[str, Any]],
    *,
    t0: int,
    t1: int,
) -> dict[str, Any]:
    hits = sorted(ranked, key=lambda row: int(row.get("resolved_at") or t0))
    stamps = sorted({t0, t1, *[int(row["resolved_at"]) for row in hits if t0 <= int(row["resolved_at"]) <= t1]})
    frames: list[dict[str, Any]] = []
    for at in stamps:
        live = [row for row in hits if int(row["resolved_at"]) <= at]
        arrived = [row["name"] for row in hits if int(row["resolved_at"]) == at]
        p0 = [row for row in live if row.get("criticality") == "P0"]
        frames.append(
            {
                "at": at,
                "offset_s": at - t0,
                "clock": clock(at),
                "exposed_count": len(live),
                "p0_count": len(p0),
                "new": arrived,
                "exposed_names": [row["name"] for row in live],
            }
        )

    delay_cost: list[dict[str, Any]] = []
    for minutes in (1, 2, 3, 4, 5, 6):
        yank = t0 + minutes * 60
        if yank > t1:
            yank = t1
        still = [row for row in hits if int(row["resolved_at"]) <= yank]
        saved = [row for row in hits if int(row["resolved_at"]) > yank]
        delay_cost.append(
            {
                "minutes": minutes,
                "yank_at": yank,
                "clock": clock(yank),
                "exposed": len(still),
                "saved": len(saved),
                "saved_p0": [row["name"] for row in saved if row.get("criticality") == "P0"],
                "saved_names": [row["name"] for row in saved],
            }
        )
        if yank == t1:
            break

    actual = frames[-1]["exposed_count"] if frames else 0
    at_two = next((row for row in delay_cost if row["minutes"] == 2), delay_cost[0] if delay_cost else None)
    headline = ""
    if at_two:
        extra = actual - int(at_two["exposed"])
        p0s = at_two["saved_p0"]
        headline = (
            f"If the registry yanked at {at_two['clock']} instead of {clock(t1)}, "
            f"{extra} services would still be clean"
            + (f", including P0 {', '.join(p0s)}." if p0s else ".")
        )

    return {
        "t0": t0,
        "t1": t1,
        "duration_s": t1 - t0,
        "frames": frames,
        "delay_cost": delay_cost,
        "headline": headline,
    }
