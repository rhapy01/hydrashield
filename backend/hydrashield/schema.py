"""Integer id spaces and OpenCypher-facing labels/relationships.

HydraDB matches vertices on integer `id`. Human names live in properties.
Relationship types are singular: HydraDB allows exactly one type per hop.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# Vertex id ranges. HydraDB ids are non-negative integers.
PACKAGE = 1_000_000
VERSION = 2_000_000
APPLICATION = 3_000_000
SERVICE = 4_000_000
MAINTAINER = 5_000_000
LOCKFILE = 6_000_000
INCIDENT = 7_000_000
INFRA = 8_000_000
EDGE = 9_000_000
CATALOG = 0

LABELS = {
    "package": "Package",
    "version": "PackageVersion",
    "application": "Application",
    "service": "Service",
    "maintainer": "Maintainer",
    "lockfile": "LockfileSnapshot",
    "incident": "IncidentWindow",
    "infra": "Infrastructure",
    "catalog": "Catalog",
}

REL = {
    "has_release": "HAS_RELEASE",
    "depends_on": "DEPENDS_ON",
    "resolves": "RESOLVES",
    "has_lockfile": "HAS_LOCKFILE",
    "runs": "RUNS",
    "maintained_by": "MAINTAINED_BY",
    "published_via": "PUBLISHED_VIA",
    "similar_name_to": "SIMILAR_NAME_TO",
    "compromised_in": "COMPROMISED_IN",
    "in_org": "IN_ORG",
}


@dataclass
class IdAllocator:
    counters: dict[str, int] = field(
        default_factory=lambda: {
            "package": 0,
            "version": 0,
            "application": 0,
            "service": 0,
            "maintainer": 0,
            "lockfile": 0,
            "incident": 0,
            "infra": 0,
            "edge": 0,
        }
    )
    keys: dict[str, int] = field(default_factory=dict)

    def get(self, kind: str, key: str) -> int:
        cache_key = f"{kind}:{key}"
        if cache_key in self.keys:
            return self.keys[cache_key]
        bases = {
            "package": PACKAGE,
            "version": VERSION,
            "application": APPLICATION,
            "service": SERVICE,
            "maintainer": MAINTAINER,
            "lockfile": LOCKFILE,
            "incident": INCIDENT,
            "infra": INFRA,
            "edge": EDGE,
        }
        self.counters[kind] += 1
        vid = bases[kind] + self.counters[kind]
        self.keys[cache_key] = vid
        return vid

    def lookup(self, kind: str, key: str) -> int:
        return self.keys[f"{kind}:{key}"]

    def dump(self) -> dict[str, int]:
        return dict(self.keys)
