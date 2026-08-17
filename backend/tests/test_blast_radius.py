from hydrashield.analyze import pin_first_sources, prefer_evidence_path
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


def test_evidence_starts_at_package_json_pin() -> None:
    """Flattened RESOLVES includes telemetry-kit; PINS must win so checkout isn't a 1-hop lie."""
    telemetry, payments, express, bad = 11, 22, 33, 99
    assert pin_first_sources([payments, express], [telemetry, payments, express, bad], bad) == [payments, express]
    assert pin_first_sources([], [telemetry, bad], bad) == [telemetry, bad]


def test_equal_length_paths_prefer_stable_names() -> None:
    telemetry = [("payments-core", 1), ("telemetry-kit", 2), ("signal-bus", 3)]
    router = [("payments-core", 1), ("event-router", 4), ("signal-bus", 3)]
    assert prefer_evidence_path([telemetry, router]) == [1, 4, 3]


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


def test_replay_delay_costs_p0s() -> None:
    from hydrashield.replay import build_replay

    t0, t1 = INCIDENT["published_ts"], INCIDENT["yanked_ts"]
    ranked = []
    for app in APPLICATIONS:
        resolved = parse_iso(app["resolved_at"])
        tree = resolve_tree(app["direct"], pin_signal=app.get("pin_signal"))
        if t0 <= resolved <= t1 and ("signal-bus", "2.4.1") in tree:
            crit = "P0" if app["slug"] in {
                "checkout-api",
                "payments-gateway",
                "fraud-service",
                "web-app",
                "payouts-api",
            } else "P2"
            ranked.append({"name": app["slug"], "resolved_at": resolved, "criticality": crit})
    replay = build_replay(ranked, t0=t0, t1=t1)
    assert replay["frames"][0]["at"] == t0
    assert replay["frames"][0]["exposed_count"] == 0
    assert replay["frames"][-1]["exposed_count"] == len(ranked)
    two = next(row for row in replay["delay_cost"] if row["minutes"] == 2)
    three = next(row for row in replay["delay_cost"] if row["minutes"] == 3)
    six = next(row for row in replay["delay_cost"] if row["minutes"] == 6)
    assert six["exposed"] > two["exposed"]
    assert "checkout-api" in two["saved_names"]
    assert "checkout-api" not in three["saved_names"]
    assert six["saved"] == 0
    assert replay["headline"]


def test_blast_rings_and_introducing_version() -> None:
    from hydrashield.blast import build_blast, classify_release

    t0, t1 = INCIDENT["published_ts"], INCIDENT["yanked_ts"]
    assert (
        classify_release(
            {"version": "2.4.1", "compromised": True, "published_at": t0},
            bad_version="2.4.1",
            safe_version="2.4.2",
            t0=t0,
            t1=t1,
        )
        == "introduced"
    )
    assert (
        classify_release(
            {"version": "2.4.0", "compromised": False, "published_at": t0 - 86400},
            bad_version="2.4.1",
            safe_version="2.4.2",
            t0=t0,
            t1=t1,
        )
        == "prior_clean"
    )
    blast = build_blast(
        package="signal-bus",
        version="2.4.1",
        safe_version="2.4.2",
        ranked=[{"name": "checkout-api"}, {"name": "fraud-service"}],
        reverse=[{"name": "event-router", "version": "0.9.3"}, {"name": "telemetry-kit", "version": "3.1.0"}],
        maintainers=[{"name": "react-signal-hooks"}, {"name": "signal-bus"}],
        infra=[{"name": "queue-pulse"}],
        typos=[{"name": "signel-bus"}],
        releases=[
            {"version": "2.4.0", "published_at": t0 - 86400, "compromised": False},
            {"version": "2.4.1", "published_at": t0, "compromised": True},
            {"version": "2.4.2", "published_at": t1 + 120, "compromised": False},
        ],
        t0=t0,
        t1=t1,
    )
    assert blast["introducing"]["version"] == "2.4.1"
    assert [row["role"] for row in blast["introducing"]["releases"]] == ["prior_clean", "introduced", "patched"]
    assert blast["rings"]["org"]["count"] == 2
    assert blast["rings"]["ecosystem"]["count"] == 2
    assert "signel-bus" in blast["rings"]["adjacent"]["names"]
    assert "checkout-api" not in blast["rings"]["adjacent"]["names"]
    assert len(blast["answers"]) == 6
    assert "2.4.1" in blast["answers"][1]["a"]


def test_report_includes_track_answers() -> None:
    from hydrashield.blast import build_blast
    from hydrashield.reports import markdown_report

    t0, t1 = INCIDENT["published_ts"], INCIDENT["yanked_ts"]
    blast = build_blast(
        package="signal-bus",
        version="2.4.1",
        safe_version="2.4.2",
        ranked=[{"name": "checkout-api"}],
        reverse=[{"name": "event-router", "version": "0.9.3"}],
        maintainers=[{"name": "react-signal-hooks"}],
        infra=[{"name": "queue-pulse"}],
        typos=[{"name": "signel-bus"}],
        releases=[{"version": "2.4.1", "published_at": t0, "compromised": True}],
        t0=t0,
        t1=t1,
    )
    text = markdown_report(
        {
            "engine": "hydradb",
            "incident": {**INCIDENT, "start_ts": t0, "end_ts": t1},
            "summary": {
                "window_seconds": 360,
                "services_exposed": 1,
                "services_total": 2,
                "p0_exposed": 1,
                "production_exposed": 1,
                "ecosystem_dependents": 1,
                "typosquats": 1,
            },
            "blast": blast,
            "exposed": [],
            "remediation": {"summary": "", "steps": []},
        }
    )
    assert "Track 2A answers" in text
    assert "Introducing version" in text
    assert "signel-bus" in text
    assert "Which version introduced" in text


def test_contained_reasons() -> None:
    from hydrashield.analyze import _why_contained, compact_query_log

    t0, t1 = INCIDENT["published_ts"], INCIDENT["yanked_ts"]
    assert _why_contained({"version": "2.4.0", "resolved_at": t0 - 60}, "2.4.1", t0, t1) == "before_window"
    assert _why_contained({"version": "2.4.2", "resolved_at": t1 + 60}, "2.4.1", t0, t1) == "after_yank"
    assert _why_contained(None, "2.4.1", t0, t1) == "no_pin"
    names = [row["name"] for row in compact_query_log(
        [
            {"name": "neighbors", "cypher": "x"},
            {"name": "lockfile_pins", "cypher": "a"},
            {"name": "lockfile_pins", "cypher": "b"},
            {"name": "ms_paths", "cypher": "m"},
            {"name": "services", "cypher": "s"},
        ]
    )]
    assert "neighbors" not in names
    assert names[0] == "lockfile_pins"
    assert names.count("lockfile_pins") == 1
    assert "ms_paths" in names


def test_path_engine_does_not_claim_failed_ms() -> None:
    from hydrashield.analyze import _path_engine

    assert _path_engine([{"name": "ms_paths", "row_count": 4, "parameters": {}}]) == "ms_paths"
    assert _path_engine([{"name": "ms_paths", "row_count": 0, "parameters": {"error": "400"}}]) == "sp_path"
    assert _path_engine([{"name": "sp_path", "row_count": 1, "parameters": {}}]) == "sp_path"
