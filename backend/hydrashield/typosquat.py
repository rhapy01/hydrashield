"""Levenshtein neighborhood used to seed SIMILAR_NAME_TO edges."""

from __future__ import annotations


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(ins, delete, sub))
        prev = curr
    return prev[-1]


def is_typosquat(candidate: str, popular: str, *, max_distance: int = 2) -> bool:
    left = candidate.lower().replace("_", "-")
    right = popular.lower().replace("_", "-")
    if left == right:
        return False
    if right in left and len(left) - len(right) <= 2:
        return True
    if left.replace("-", "") == right.replace("-", ""):
        return True
    return levenshtein(left, right) <= max_distance


def neighborhood(names: list[str], target: str, *, max_distance: int = 2) -> list[tuple[str, int]]:
    hits: list[tuple[str, int]] = []
    for name in names:
        if name == target:
            continue
        if is_typosquat(name, target, max_distance=max_distance):
            hits.append((name, levenshtein(name.lower(), target.lower())))
    hits.sort(key=lambda item: (item[1], item[0]))
    return hits
