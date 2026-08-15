from hydrashield.lockfiles import parse_lockfile
from hydrashield.ranking import exposure_score, rank_services
from hydrashield.remediation import remediation_plan
from hydrashield.typosquat import is_typosquat, levenshtein, neighborhood
from hydrashield.universe import (
    APPLICATIONS,
    INCIDENT,
    SERVICES,
    lockfile_payload,
    parse_iso,
    path_to,
    resolve_tree,
    shortest_depth,
)


def test_levenshtein_typosquats() -> None:
    assert levenshtein("signal-bus", "signel-bus") == 1
    assert is_typosquat("signel-bus", "signal-bus")
    assert is_typosquat("signalbus", "signal-bus")
    assert not is_typosquat("express", "signal-bus")
    names = ["signal-bus", "signel-bus", "express", "signal-buss"]
    hits = neighborhood(names, "signal-bus")
    assert {name for name, _dist in hits} == {"signel-bus", "signal-buss"}


def test_lockfile_parser_flattens_v3() -> None:
    payload = lockfile_payload(next(app for app in APPLICATIONS if app["slug"] == "checkout-api"))
    parsed = parse_lockfile(payload)
    assert parsed["name"] == "checkout-api"
    names = {(item["name"], item["version"]) for item in parsed["packages"]}
    assert ("signal-bus", "2.4.1") in names
    assert ("payments-core", "12.0.0") in names
    assert parsed["direct"]["payments-core"] == "12.0.0"


def test_pre_window_lockfile_pins_safe_version() -> None:
    payload = lockfile_payload(next(app for app in APPLICATIONS if app["slug"] == "ledger-worker"))
    parsed = parse_lockfile(payload)
    names = {(item["name"], item["version"]) for item in parsed["packages"]}
    assert ("signal-bus", "2.4.0") in names
    assert ("signal-bus", "2.4.1") not in names


def test_post_yank_pin_uses_patched_release() -> None:
    tree = resolve_tree({"event-router": "0.9.3"}, pin_signal="2.4.2")
    assert ("signal-bus", "2.4.2") in tree
    assert ("signal-bus", "2.4.1") not in tree


def test_path_explains_checkout_api() -> None:
    app = next(item for item in APPLICATIONS if item["slug"] == "checkout-api")
    path = path_to(app["direct"], ("signal-bus", "2.4.1"))
    assert path[0][0] == "payments-core"
    assert path[-1] == ("signal-bus", "2.4.1")
    assert shortest_depth(app["direct"], ("signal-bus", "2.4.1")) >= 2


def test_temporal_window_splits_fleet() -> None:
    start = INCIDENT["published_ts"]
    end = INCIDENT["yanked_ts"]
    in_window = []
    for app in APPLICATIONS:
        resolved = parse_iso(app["resolved_at"])
        tree = resolve_tree(app["direct"], pin_signal=app.get("pin_signal"))
        if start <= resolved <= end and ("signal-bus", "2.4.1") in tree:
            in_window.append(app["slug"])
    assert "checkout-api" in in_window
    assert "ledger-worker" not in in_window
    assert "webhook-relay" not in in_window
    assert "docs-site" not in in_window
    assert len(in_window) >= 12


def test_ranking_puts_p0_prod_first() -> None:
    rows = rank_services(
        [
            {"name": "docs", "criticality": "P3", "env": "production", "depth": 1, "direct_pin": True},
            {"name": "checkout-api", "criticality": "P0", "env": "production", "depth": 3, "direct_pin": False},
            {"name": "playground", "criticality": "P0", "env": "dev", "depth": 1, "direct_pin": True},
        ]
    )
    assert rows[0]["name"] == "checkout-api"
    assert exposure_score(criticality="P0", env="production", depth=2) > exposure_score(
        criticality="P2", env="staging", depth=2
    )


def test_remediation_clears_all_when_root_upgraded() -> None:
    exposed = [
        {"name": "a", "path_packages": ["payments-core", "signal-bus"]},
        {"name": "b", "path_packages": ["analytics-sdk", "signal-bus"]},
    ]
    plan = remediation_plan(
        compromised_package="signal-bus",
        safe_version="2.4.2",
        exposed=exposed,
        shared_maintainer_packages=["logger-pretty"],
        typosquats=["signel-bus"],
    )
    assert plan["steps"][0]["services_fixed"] == 2
    assert plan["residual_services"] == []
    assert plan["review"][0]["package"] == "logger-pretty"


def test_name_grep_is_not_the_blast_radius() -> None:
    start = INCIDENT["published_ts"]
    end = INCIDENT["yanked_ts"]
    named = []
    windowed = []
    for app in APPLICATIONS:
        resolved = parse_iso(app["resolved_at"])
        tree = resolve_tree(app["direct"], pin_signal=app.get("pin_signal"))
        if any(name == "signal-bus" for name, _version in tree):
            named.append(app["slug"])
        if start <= resolved <= end and ("signal-bus", "2.4.1") in tree:
            windowed.append(app["slug"])
    assert "ledger-worker" in named
    assert "ledger-worker" not in windowed
    assert "webhook-relay" in named
    assert "webhook-relay" not in windowed
    assert "checkout-api" in windowed
    assert len(named) > len(windowed)


def test_contained_reasons() -> None:
    from hydrashield.analyze import _why_contained

    t0, t1 = INCIDENT["published_ts"], INCIDENT["yanked_ts"]
    assert _why_contained({"version": "2.4.0", "resolved_at": t0 - 60}, "2.4.1", t0, t1) == "before_window"
    assert _why_contained({"version": "2.4.2", "resolved_at": t1 + 60}, "2.4.1", t0, t1) == "after_yank"
    assert _why_contained(None, "2.4.1", t0, t1) == "no_pin"
