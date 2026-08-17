"""Camera-script contract. If this fails, the 3-minute demo is a lie."""

from hydrashield.lockfiles import parse_lockfile
from hydrashield.replay import build_replay
from hydrashield.universe import APPLICATIONS, INCIDENT, SERVICES, lockfile_payload, parse_iso, path_to, resolve_tree


def _app(slug: str) -> dict:
    return next(item for item in APPLICATIONS if item["slug"] == slug)


def test_checkout_path_is_the_payments_core_story() -> None:
    app = _app("checkout-api")
    path = path_to(app["direct"], ("signal-bus", "2.4.1"))
    names = [name for name, _version in path]
    assert names[0] == "payments-core"
    assert "event-router" in names
    assert names[-1] == "signal-bus"
    parsed = parse_lockfile(lockfile_payload(app))
    assert "payments-core" in parsed["direct"]
    assert "telemetry-kit" not in parsed["direct"]
    assert any(item["name"] == "telemetry-kit" for item in parsed["packages"])


def test_plus_two_minutes_saves_checkout() -> None:
    t0, t1 = INCIDENT["published_ts"], INCIDENT["yanked_ts"]
    checkout_at = parse_iso(_app("checkout-api")["resolved_at"])
    assert t0 < checkout_at <= t1
    assert checkout_at > t0 + 120
    ranked = []
    for app in APPLICATIONS:
        resolved = parse_iso(app["resolved_at"])
        tree = resolve_tree(app["direct"], pin_signal=app.get("pin_signal"))
        if t0 <= resolved <= t1 and ("signal-bus", "2.4.1") in tree:
            ranked.append({"name": app["slug"], "resolved_at": resolved, "criticality": "P0"})
    two = next(row for row in build_replay(ranked, t0=t0, t1=t1)["delay_cost"] if row["minutes"] == 2)
    assert "checkout-api" in two["saved_names"]


def test_scanner_false_positives_are_ledger_and_webhook() -> None:
    t0, t1 = INCIDENT["published_ts"], INCIDENT["yanked_ts"]
    ledger = parse_iso(_app("ledger-worker")["resolved_at"])
    webhook = parse_iso(_app("webhook-relay")["resolved_at"])
    assert ledger < t0
    assert webhook > t1
    assert ("signal-bus", "2.4.0") in resolve_tree(_app("ledger-worker")["direct"], pin_signal=_app("ledger-worker").get("pin_signal"))
    assert ("signal-bus", "2.4.2") in resolve_tree(_app("webhook-relay")["direct"], pin_signal=_app("webhook-relay").get("pin_signal"))


def test_fleet_is_an_org_not_a_toy() -> None:
    assert len(APPLICATIONS) >= 24
    assert len(SERVICES) >= 24
    p0_prod = [row for row in SERVICES if row["criticality"] == "P0" and row["env"] == "production"]
    assert any(row["slug"] == "checkout-api" for row in p0_prod)
    assert len(p0_prod) >= 4
