"""Curated npm universe + VantaPay org snapshot for a deterministic demo.

Incident: signal-bus@2.4.1 was published at 09:00 UTC on 2026-05-14 and
yanked at 09:06. The worm reused a GitHub Actions OIDC identity — the same
shape as the May 2026 TanStack-class npm compromises.

Lockfiles are npm lockfile v3. Ingestion parses them; HydraDB stores the
resulting graph. Do not expand this into a live registry crawl for the MVP.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .typosquat import neighborhood


def ts(hour: int, minute: int, second: int = 0) -> int:
    return int(datetime(2026, 5, 14, hour, minute, second, tzinfo=timezone.utc).timestamp())


def iso(hour: int, minute: int, second: int = 0) -> str:
    return datetime(2026, 5, 14, hour, minute, second, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


INCIDENT = {
    "slug": "INC-2026-0514-SIGNAL-BUS",
    "title": "signal-bus@2.4.1 npm compromise",
    "package": "signal-bus",
    "version": "2.4.1",
    "safe_version": "2.4.2",
    "previous_version": "2.4.0",
    "published_at": iso(9, 0, 0),
    "published_ts": ts(9, 0, 0),
    "yanked_at": iso(9, 6, 0),
    "yanked_ts": ts(9, 6, 0),
    "advisory": (
        "Maintainer GitHub Actions OIDC token reused to publish signal-bus@2.4.1. "
        "The tarball drops a postinstall worm that harvests npm tokens and "
        "republishes downstream packages. Window: 09:00–09:06 UTC."
    ),
}

ORG = {
    "name": "VantaPay",
    "slug": "vantapay",
    "description": "Card issuing and merchant payments platform",
}

MAINTAINERS = [
    {"slug": "mara-okonkwo", "name": "Mara Okonkwo", "npm_user": "mara-okonkwo", "email": "mara@signal-labs.dev"},
    {"slug": "signal-release-bot", "name": "signal-labs-ci", "npm_user": "signal-release-bot", "email": "ci@signal-labs.dev"},
    {"slug": "nami-cho", "name": "Nami Cho", "npm_user": "nami-cho", "email": "nami@telemetry.dev"},
    {"slug": "evan-brooks", "name": "Evan Brooks", "npm_user": "evan-brooks", "email": "evan@paykit.dev"},
    {"slug": "linh-pham", "name": "Linh Pham", "npm_user": "linh-pham", "email": "linh@fraudlabs.io"},
    {"slug": "typo-actor", "name": "pkg-mirror", "npm_user": "pkg-mirror", "email": "noreply@mirror.invalid"},
]

INFRA = [
    {"slug": "github-actions-oidc", "name": "GitHub Actions OIDC → npm", "kind": "ci"},
    {"slug": "npmjs-registry", "name": "registry.npmjs.org", "kind": "registry"},
    {"slug": "circleci-npm", "name": "CircleCI npm publish", "kind": "ci"},
]

# (name, version, published_ts, yanked, compromised, weekly_downloads)
PACKAGE_RELEASES: list[tuple[str, str, int, bool, bool, int]] = [
    ("signal-bus", "2.3.0", ts(8, 0, 0) - 86400 * 40, False, False, 1_800_000),
    ("signal-bus", "2.4.0", ts(8, 0, 0) - 86400 * 12, False, False, 1_800_000),
    ("signal-bus", "2.4.1", ts(9, 0, 0), True, True, 1_800_000),
    ("signal-bus", "2.4.2", ts(9, 8, 0), False, False, 1_800_000),
    ("telemetry-kit", "3.0.4", ts(8, 0, 0) - 86400 * 20, False, False, 420_000),
    ("telemetry-kit", "3.1.0", ts(8, 10, 0), False, False, 420_000),
    ("event-router", "0.9.2", ts(8, 0, 0) - 86400 * 9, False, False, 210_000),
    ("event-router", "0.9.3", ts(8, 12, 0), False, False, 210_000),
    ("react-signal-hooks", "2.0.8", ts(8, 0, 0) - 86400 * 15, False, False, 95_000),
    ("react-signal-hooks", "2.1.0", ts(8, 20, 0), False, False, 95_000),
    ("queue-pulse", "4.1.9", ts(8, 0, 0) - 86400 * 18, False, False, 77_000),
    ("queue-pulse", "4.2.0", ts(8, 15, 0), False, False, 77_000),
    ("ws-presence", "1.2.1", ts(8, 0, 0) - 86400 * 30, False, False, 40_000),
    ("ws-presence", "1.3.0", ts(8, 18, 0), False, False, 40_000),
    ("analytics-sdk", "8.2.3", ts(8, 0, 0) - 86400 * 8, False, False, 160_000),
    ("analytics-sdk", "8.2.4", ts(8, 30, 0), False, False, 160_000),
    ("payments-core", "11.9.0", ts(8, 0, 0) - 86400 * 14, False, False, 12_000),
    ("payments-core", "12.0.0", ts(8, 40, 0), False, False, 12_000),
    ("checkout-ui", "1.8.4", ts(8, 0, 0) - 86400 * 11, False, False, 8_000),
    ("checkout-ui", "1.9.0", ts(8, 45, 0), False, False, 8_000),
    ("notify-dispatch", "1.3.2", ts(8, 0, 0) - 86400 * 6, False, False, 9_000),
    ("notify-dispatch", "1.4.0", ts(8, 50, 0), False, False, 9_000),
    ("fraud-rules", "6.0.2", ts(8, 0, 0) - 86400 * 21, False, False, 6_500),
    ("fraud-rules", "6.1.0", ts(8, 33, 0), False, False, 6_500),
    ("risk-engine", "2.9.1", ts(8, 0, 0) - 86400 * 10, False, False, 4_000),
    ("risk-engine", "3.0.0", ts(8, 48, 0), False, False, 4_000),
    ("admin-kit", "4.0.0", ts(8, 0, 0) - 86400 * 4, False, False, 2_200),
    ("dashboard-kit", "2.0.1", ts(8, 52, 0), False, False, 1_800),
    ("mobile-bridge", "0.8.2", ts(8, 44, 0), False, False, 3_100),
    ("ledger-lib", "5.3.0", ts(8, 0, 0) - 86400 * 21, False, False, 2_400),
    ("ledger-lib", "5.4.0", ts(8, 0, 0) - 86400 * 7, False, False, 2_400),
    ("logger-pretty", "1.8.2", ts(8, 0, 0) - 86400 * 3, False, False, 310_000),
    ("config-merge", "0.4.1", ts(8, 0, 0) - 86400 * 16, False, False, 88_000),
    ("express", "4.19.2", ts(8, 0, 0) - 86400 * 60, False, False, 32_000_000),
    ("react", "18.3.1", ts(8, 0, 0) - 86400 * 90, False, False, 20_000_000),
    ("zod", "3.23.8", ts(8, 0, 0) - 86400 * 40, False, False, 8_000_000),
    ("pino", "9.2.0", ts(8, 0, 0) - 86400 * 25, False, False, 4_000_000),
    ("lodash", "4.17.21", ts(8, 0, 0) - 86400 * 400, False, False, 40_000_000),
    ("pg", "8.12.0", ts(8, 0, 0) - 86400 * 50, False, False, 5_000_000),
    ("ioredis", "5.4.1", ts(8, 0, 0) - 86400 * 35, False, False, 3_000_000),
    ("fastify", "4.28.1", ts(8, 0, 0) - 86400 * 28, False, False, 2_800_000),
    ("next", "14.2.5", ts(8, 0, 0) - 86400 * 22, False, False, 7_000_000),
    ("signel-bus", "2.4.1", ts(9, 1, 12), False, False, 40),
    ("signal-buss", "2.4.0", ts(8, 0, 0) - 86400 * 2, False, False, 18),
    ("signalbus", "1.0.0", ts(8, 0, 0) - 86400 * 80, False, False, 9),
    ("signal-bsu", "2.3.9", ts(9, 3, 40), False, False, 6),
]

PACKAGE_META: dict[str, dict[str, Any]] = {
    "signal-bus": {
        "description": "Tiny in-process event bus used across Node services",
        "maintainer": "mara-okonkwo",
        "infra": ["github-actions-oidc", "npmjs-registry"],
        "repo": "github.com/signal-labs/signal-bus",
    },
    "logger-pretty": {
        "description": "Pretty stdout formatter",
        "maintainer": "mara-okonkwo",
        "infra": ["github-actions-oidc", "npmjs-registry"],
        "repo": "github.com/signal-labs/logger-pretty",
    },
    "config-merge": {
        "description": "Deep-merge for 12-factor config",
        "maintainer": "mara-okonkwo",
        "infra": ["github-actions-oidc", "npmjs-registry"],
        "repo": "github.com/signal-labs/config-merge",
    },
    "telemetry-kit": {
        "description": "OpenTelemetry helpers for Node",
        "maintainer": "nami-cho",
        "infra": ["github-actions-oidc", "npmjs-registry"],
        "repo": "github.com/signal-labs/telemetry-kit",
    },
    "event-router": {
        "description": "Partitioned in-process event router",
        "maintainer": "evan-brooks",
        "infra": ["npmjs-registry"],
        "repo": "github.com/paykit/event-router",
    },
    "react-signal-hooks": {
        "description": "React bindings for signal-bus",
        "maintainer": "nami-cho",
        "infra": ["github-actions-oidc", "npmjs-registry"],
        "repo": "github.com/signal-labs/react-signal-hooks",
    },
    "queue-pulse": {
        "description": "Backoff + pulse queue",
        "maintainer": "linh-pham",
        "infra": ["circleci-npm", "npmjs-registry"],
        "repo": "github.com/fraudlabs/queue-pulse",
    },
    "ws-presence": {
        "description": "Websocket presence fanout",
        "maintainer": "evan-brooks",
        "infra": ["npmjs-registry"],
        "repo": "github.com/paykit/ws-presence",
    },
    "analytics-sdk": {
        "description": "Product analytics client",
        "maintainer": "nami-cho",
        "infra": ["npmjs-registry"],
        "repo": "github.com/telemetry-dev/analytics-sdk",
    },
    "payments-core": {
        "description": "VantaPay shared payments library",
        "maintainer": "evan-brooks",
        "infra": ["github-actions-oidc", "npmjs-registry"],
        "repo": "github.com/vantapay/payments-core",
    },
    "checkout-ui": {
        "description": "Hosted checkout widgets",
        "maintainer": "evan-brooks",
        "infra": ["github-actions-oidc", "npmjs-registry"],
        "repo": "github.com/vantapay/checkout-ui",
    },
    "notify-dispatch": {
        "description": "Notification routing",
        "maintainer": "evan-brooks",
        "infra": ["npmjs-registry"],
        "repo": "github.com/vantapay/notify-dispatch",
    },
    "fraud-rules": {
        "description": "Rule evaluation for fraud",
        "maintainer": "linh-pham",
        "infra": ["circleci-npm", "npmjs-registry"],
        "repo": "github.com/fraudlabs/fraud-rules",
    },
    "risk-engine": {
        "description": "Scoring engine",
        "maintainer": "linh-pham",
        "infra": ["circleci-npm", "npmjs-registry"],
        "repo": "github.com/fraudlabs/risk-engine",
    },
    "signel-bus": {
        "description": "Unofficial fork / likely typosquat",
        "maintainer": "typo-actor",
        "infra": ["npmjs-registry"],
        "repo": "",
    },
    "signal-buss": {
        "description": "Likely typosquat of signal-bus",
        "maintainer": "typo-actor",
        "infra": ["npmjs-registry"],
        "repo": "",
    },
    "signalbus": {
        "description": "Unscoped name collision",
        "maintainer": "typo-actor",
        "infra": ["npmjs-registry"],
        "repo": "",
    },
    "signal-bsu": {
        "description": "Transposed-letter typosquat published during the window",
        "maintainer": "typo-actor",
        "infra": ["npmjs-registry"],
        "repo": "",
    },
}

DEFAULT_META = {
    "description": "",
    "maintainer": "evan-brooks",
    "infra": ["npmjs-registry"],
    "repo": "",
}

# from_name, from_ver, to_name, to_ver
DEPENDENCIES: list[tuple[str, str, str, str]] = [
    # trees that resolve onto the compromised 2.4.1
    ("telemetry-kit", "3.1.0", "signal-bus", "2.4.1"),
    ("event-router", "0.9.3", "signal-bus", "2.4.1"),
    ("react-signal-hooks", "2.1.0", "signal-bus", "2.4.1"),
    ("queue-pulse", "4.2.0", "signal-bus", "2.4.1"),
    ("ws-presence", "1.3.0", "signal-bus", "2.4.1"),
    ("analytics-sdk", "8.2.4", "telemetry-kit", "3.1.0"),
    ("payments-core", "12.0.0", "event-router", "0.9.3"),
    ("payments-core", "12.0.0", "telemetry-kit", "3.1.0"),
    ("checkout-ui", "1.9.0", "analytics-sdk", "8.2.4"),
    ("checkout-ui", "1.9.0", "react-signal-hooks", "2.1.0"),
    ("notify-dispatch", "1.4.0", "event-router", "0.9.3"),
    ("notify-dispatch", "1.4.0", "ws-presence", "1.3.0"),
    ("fraud-rules", "6.1.0", "queue-pulse", "4.2.0"),
    ("risk-engine", "3.0.0", "fraud-rules", "6.1.0"),
    ("risk-engine", "3.0.0", "payments-core", "12.0.0"),
    ("admin-kit", "4.0.0", "analytics-sdk", "8.2.4"),
    ("dashboard-kit", "2.0.1", "admin-kit", "4.0.0"),
    ("dashboard-kit", "2.0.1", "checkout-ui", "1.9.0"),
    ("mobile-bridge", "0.8.2", "react-signal-hooks", "2.1.0"),
    ("ledger-lib", "5.3.0", "payments-core", "11.9.0"),
    ("ledger-lib", "5.4.0", "payments-core", "12.0.0"),
    # pre-window trees pin 2.4.0
    ("telemetry-kit", "3.0.4", "signal-bus", "2.4.0"),
    ("event-router", "0.9.2", "signal-bus", "2.4.0"),
    ("react-signal-hooks", "2.0.8", "signal-bus", "2.4.0"),
    ("queue-pulse", "4.1.9", "signal-bus", "2.4.0"),
    ("ws-presence", "1.2.1", "signal-bus", "2.4.0"),
    ("analytics-sdk", "8.2.3", "telemetry-kit", "3.0.4"),
    ("payments-core", "11.9.0", "event-router", "0.9.2"),
    ("payments-core", "11.9.0", "telemetry-kit", "3.0.4"),
    ("checkout-ui", "1.8.4", "analytics-sdk", "8.2.3"),
    ("notify-dispatch", "1.3.2", "event-router", "0.9.2"),
    ("fraud-rules", "6.0.2", "queue-pulse", "4.1.9"),
    ("risk-engine", "2.9.1", "fraud-rules", "6.0.2"),
    ("risk-engine", "2.9.1", "payments-core", "11.9.0"),
    # noise
    ("payments-core", "12.0.0", "zod", "3.23.8"),
    ("payments-core", "12.0.0", "pino", "9.2.0"),
    ("analytics-sdk", "8.2.4", "zod", "3.23.8"),
    ("checkout-ui", "1.9.0", "react", "18.3.1"),
    ("admin-kit", "4.0.0", "react", "18.3.1"),
    ("mobile-bridge", "0.8.2", "react", "18.3.1"),
]

# Direct dependencies for each application (package.json style).
APPLICATIONS: list[dict[str, Any]] = [
    {
        "slug": "checkout-api",
        "repo": "github.com/vantapay/checkout-api",
        "direct": {"payments-core": "12.0.0", "express": "4.19.2", "pino": "9.2.0", "logger-pretty": "1.8.2"},
        "resolved_at": iso(9, 2, 11),
        "commit": "c0a1c4e",
    },
    {
        "slug": "payments-gateway",
        "repo": "github.com/vantapay/payments-gateway",
        "direct": {"payments-core": "12.0.0", "fastify": "4.28.1", "ioredis": "5.4.1"},
        "resolved_at": iso(9, 3, 4),
        "commit": "91b22aa",
    },
    {
        "slug": "fraud-service",
        "repo": "github.com/vantapay/fraud-service",
        "direct": {"risk-engine": "3.0.0", "fraud-rules": "6.1.0", "fastify": "4.28.1"},
        "resolved_at": iso(9, 2, 47),
        "commit": "f4e1901",
    },
    {
        "slug": "web-app",
        "repo": "github.com/vantapay/web-app",
        "direct": {"checkout-ui": "1.9.0", "next": "14.2.5", "react": "18.3.1", "analytics-sdk": "8.2.4"},
        "resolved_at": iso(9, 4, 22),
        "commit": "bb17e02",
    },
    {
        "slug": "ledger-worker",
        "repo": "github.com/vantapay/ledger-worker",
        "direct": {"ledger-lib": "5.3.0", "payments-core": "11.9.0", "pg": "8.12.0", "pino": "9.2.0"},
        "resolved_at": iso(8, 41, 0),
        "commit": "aa00910",
    },
    {
        "slug": "mobile-bff",
        "repo": "github.com/vantapay/mobile-bff",
        "direct": {"mobile-bridge": "0.8.2", "payments-core": "12.0.0", "express": "4.19.2"},
        "resolved_at": iso(9, 5, 18),
        "commit": "d33c91f",
    },
    {
        "slug": "notify-service",
        "repo": "github.com/vantapay/notify-service",
        "direct": {"notify-dispatch": "1.4.0", "express": "4.19.2", "pino": "9.2.0"},
        "resolved_at": iso(9, 3, 51),
        "commit": "e81ab04",
    },
    {
        "slug": "risk-api",
        "repo": "github.com/vantapay/risk-api",
        "direct": {"risk-engine": "2.9.1", "fastify": "4.28.1"},
        "resolved_at": iso(8, 12, 0),
        "commit": "11c0ff0",
    },
    {
        "slug": "settlement-worker",
        "repo": "github.com/vantapay/settlement-worker",
        "direct": {"payments-core": "11.9.0", "pg": "8.12.0"},
        "resolved_at": iso(7, 55, 0),
        "commit": "50f11e2",
    },
    {
        "slug": "card-tokenizer",
        "repo": "github.com/vantapay/card-tokenizer",
        "direct": {"fastify": "4.28.1", "zod": "3.23.8", "pino": "9.2.0"},
        "resolved_at": iso(8, 30, 0),
        "commit": "99a1b2c",
    },
    {
        "slug": "admin-console",
        "repo": "github.com/vantapay/admin-console",
        "direct": {"dashboard-kit": "2.0.1", "admin-kit": "4.0.0", "react": "18.3.1"},
        "resolved_at": iso(9, 5, 40),
        "commit": "cafe012",
    },
    {
        "slug": "analytics-pipeline",
        "repo": "github.com/vantapay/analytics-pipeline",
        "direct": {"analytics-sdk": "8.2.4", "pino": "9.2.0", "pg": "8.12.0"},
        "resolved_at": iso(9, 1, 33),
        "commit": "0ff1ce0",
    },
    {
        "slug": "webhook-relay",
        "repo": "github.com/vantapay/webhook-relay",
        "direct": {"event-router": "0.9.3", "fastify": "4.28.1"},
        "resolved_at": iso(9, 12, 0),
        "commit": "postyank",
        "overrides": {("signal-bus",): "2.4.2", ("event-router",): "0.9.3"},
        "pin_signal": "2.4.2",
    },
    {
        "slug": "docs-site",
        "repo": "github.com/vantapay/docs-site",
        "direct": {"next": "14.2.5", "react": "18.3.1"},
        "resolved_at": iso(8, 0, 0),
        "commit": "docs001",
    },
    {
        "slug": "status-page",
        "repo": "github.com/vantapay/status-page",
        "direct": {"react": "18.3.1", "next": "14.2.5"},
        "resolved_at": iso(6, 0, 0),
        "commit": "stat001",
    },
    {
        "slug": "invoice-pdf",
        "repo": "github.com/vantapay/invoice-pdf",
        "direct": {"payments-core": "12.0.0", "pino": "9.2.0"},
        "resolved_at": iso(9, 4, 55),
        "commit": "inv0091",
    },
    {
        "slug": "fx-quote",
        "repo": "github.com/vantapay/fx-quote",
        "direct": {"payments-core": "12.0.0", "ioredis": "5.4.1", "fastify": "4.28.1"},
        "resolved_at": iso(9, 2, 30),
        "commit": "fx00aa1",
    },
    {
        "slug": "payouts-api",
        "repo": "github.com/vantapay/payouts-api",
        "direct": {"payments-core": "12.0.0", "ledger-lib": "5.4.0", "express": "4.19.2"},
        "resolved_at": iso(9, 3, 40),
        "commit": "pay0ut1",
    },
    {
        "slug": "identity-api",
        "repo": "github.com/vantapay/identity-api",
        "direct": {"fastify": "4.28.1", "pg": "8.12.0", "zod": "3.23.8", "pino": "9.2.0"},
        "resolved_at": iso(8, 20, 0),
        "commit": "id00001",
    },
    {
        "slug": "audit-log",
        "repo": "github.com/vantapay/audit-log",
        "direct": {"telemetry-kit": "3.1.0", "pino": "9.2.0", "pg": "8.12.0"},
        "resolved_at": iso(9, 4, 8),
        "commit": "aud1t01",
    },
    {
        "slug": "merchant-portal",
        "repo": "github.com/vantapay/merchant-portal",
        "direct": {"checkout-ui": "1.9.0", "dashboard-kit": "2.0.1", "next": "14.2.5"},
        "resolved_at": iso(9, 5, 50),
        "commit": "merch01",
    },
    {
        "slug": "recon-worker",
        "repo": "github.com/vantapay/recon-worker",
        "direct": {"ledger-lib": "5.3.0", "payments-core": "11.9.0", "pg": "8.12.0", "pino": "9.2.0"},
        "resolved_at": iso(8, 5, 0),
        "commit": "recon01",
    },
    {
        "slug": "checkout-staging",
        "repo": "github.com/vantapay/checkout-api",
        "direct": {"payments-core": "12.0.0", "express": "4.19.2", "pino": "9.2.0"},
        "resolved_at": iso(9, 2, 20),
        "commit": "c0a1c4e",
    },
    {
        "slug": "web-staging",
        "repo": "github.com/vantapay/web-app",
        "direct": {"checkout-ui": "1.9.0", "next": "14.2.5", "react": "18.3.1"},
        "resolved_at": iso(9, 4, 1),
        "commit": "bb17e02",
    },
    {
        "slug": "fraud-staging",
        "repo": "github.com/vantapay/fraud-service",
        "direct": {"risk-engine": "2.9.1", "fastify": "4.28.1"},
        "resolved_at": iso(8, 50, 0),
        "commit": "oldf4e1",
    },
    {
        "slug": "playground",
        "repo": "github.com/vantapay/playground",
        "direct": {"payments-core": "12.0.0", "express": "4.19.2"},
        "resolved_at": iso(9, 20, 0),
        "commit": "play002",
        "pin_signal": "2.4.2",
    },
    {
        "slug": "storybook",
        "repo": "github.com/vantapay/design-system",
        "direct": {"react": "18.3.1", "next": "14.2.5"},
        "resolved_at": iso(7, 0, 0),
        "commit": "ds0007",
    },
    {
        "slug": "loadtest-harness",
        "repo": "github.com/vantapay/loadtest",
        "direct": {"payments-core": "12.0.0", "analytics-sdk": "8.2.4", "pino": "9.2.0"},
        "resolved_at": iso(9, 5, 2),
        "commit": "lt0005",
    },
]

SERVICES: list[dict[str, Any]] = [
    {"slug": "checkout-api", "app": "checkout-api", "env": "production", "criticality": "P0", "team": "checkout", "deployed_at": iso(9, 3, 40)},
    {"slug": "payments-gateway", "app": "payments-gateway", "env": "production", "criticality": "P0", "team": "payments", "deployed_at": iso(9, 4, 10)},
    {"slug": "fraud-service", "app": "fraud-service", "env": "production", "criticality": "P0", "team": "risk", "deployed_at": iso(9, 3, 55)},
    {"slug": "web-app", "app": "web-app", "env": "production", "criticality": "P0", "team": "frontend", "deployed_at": iso(9, 5, 10)},
    {"slug": "ledger-worker", "app": "ledger-worker", "env": "production", "criticality": "P0", "team": "ledger", "deployed_at": iso(8, 50, 0)},
    {"slug": "payouts-api", "app": "payouts-api", "env": "production", "criticality": "P0", "team": "payments", "deployed_at": iso(9, 4, 30)},
    {"slug": "identity-api", "app": "identity-api", "env": "production", "criticality": "P0", "team": "identity", "deployed_at": iso(8, 40, 0)},
    {"slug": "mobile-bff", "app": "mobile-bff", "env": "production", "criticality": "P1", "team": "mobile", "deployed_at": iso(9, 5, 50)},
    {"slug": "notify-service", "app": "notify-service", "env": "production", "criticality": "P1", "team": "comms", "deployed_at": iso(9, 4, 20)},
    {"slug": "risk-api", "app": "risk-api", "env": "production", "criticality": "P1", "team": "risk", "deployed_at": iso(8, 22, 0)},
    {"slug": "settlement-worker", "app": "settlement-worker", "env": "production", "criticality": "P1", "team": "ledger", "deployed_at": iso(8, 10, 0)},
    {"slug": "card-tokenizer", "app": "card-tokenizer", "env": "production", "criticality": "P1", "team": "pci", "deployed_at": iso(8, 45, 0)},
    {"slug": "fx-quote", "app": "fx-quote", "env": "production", "criticality": "P1", "team": "trading", "deployed_at": iso(9, 3, 15)},
    {"slug": "audit-log", "app": "audit-log", "env": "production", "criticality": "P1", "team": "security", "deployed_at": iso(9, 4, 40)},
    {"slug": "merchant-portal", "app": "merchant-portal", "env": "production", "criticality": "P1", "team": "frontend", "deployed_at": iso(9, 5, 58)},
    {"slug": "recon-worker", "app": "recon-worker", "env": "production", "criticality": "P1", "team": "ledger", "deployed_at": iso(8, 15, 0)},
    {"slug": "admin-console", "app": "admin-console", "env": "production", "criticality": "P2", "team": "internal-tools", "deployed_at": iso(9, 5, 55)},
    {"slug": "analytics-pipeline", "app": "analytics-pipeline", "env": "production", "criticality": "P2", "team": "data", "deployed_at": iso(9, 2, 10)},
    {"slug": "webhook-relay", "app": "webhook-relay", "env": "production", "criticality": "P2", "team": "integrations", "deployed_at": iso(9, 18, 0)},
    {"slug": "invoice-pdf", "app": "invoice-pdf", "env": "production", "criticality": "P2", "team": "billing", "deployed_at": iso(9, 5, 20)},
    {"slug": "docs-site", "app": "docs-site", "env": "production", "criticality": "P3", "team": "dx", "deployed_at": iso(8, 10, 0)},
    {"slug": "status-page", "app": "status-page", "env": "production", "criticality": "P3", "team": "dx", "deployed_at": iso(6, 30, 0)},
    {"slug": "checkout-staging", "app": "checkout-staging", "env": "staging", "criticality": "P2", "team": "checkout", "deployed_at": iso(9, 2, 50)},
    {"slug": "web-staging", "app": "web-staging", "env": "staging", "criticality": "P2", "team": "frontend", "deployed_at": iso(9, 4, 30)},
    {"slug": "fraud-staging", "app": "fraud-staging", "env": "staging", "criticality": "P2", "team": "risk", "deployed_at": iso(8, 55, 0)},
    {"slug": "playground", "app": "playground", "env": "dev", "criticality": "P3", "team": "dx", "deployed_at": iso(9, 22, 0)},
    {"slug": "storybook", "app": "storybook", "env": "dev", "criticality": "P3", "team": "frontend", "deployed_at": iso(7, 30, 0)},
    {"slug": "loadtest-harness", "app": "loadtest-harness", "env": "dev", "criticality": "P3", "team": "sre", "deployed_at": iso(9, 5, 30)},
]


def dep_index() -> dict[tuple[str, str], list[tuple[str, str]]]:
    index: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for frm_n, frm_v, to_n, to_v in DEPENDENCIES:
        index.setdefault((frm_n, frm_v), []).append((to_n, to_v))
    return index


def resolve_tree(direct: dict[str, str], *, pin_signal: str | None = None) -> list[tuple[str, str]]:
    """Flatten direct deps through DEPENDENCIES. Optional pin replaces signal-bus."""
    index = dep_index()
    seen: set[tuple[str, str]] = set()
    stack = list(direct.items())
    while stack:
        name, version = stack.pop()
        if name == "signal-bus" and pin_signal:
            version = pin_signal
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        for child in index.get(key, []):
            child_name, child_ver = child
            if child_name == "signal-bus" and pin_signal:
                child_ver = pin_signal
            stack.append((child_name, child_ver))
    return sorted(seen)


def shortest_depth(direct: dict[str, str], target: tuple[str, str], *, pin_signal: str | None = None) -> int | None:
    index = dep_index()
    queue: list[tuple[str, str, int]] = [(n, v, 1) for n, v in direct.items()]
    seen: set[tuple[str, str]] = set()
    while queue:
        name, version, depth = queue.pop(0)
        if name == "signal-bus" and pin_signal:
            version = pin_signal
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        if key == target:
            return depth
        for child_n, child_v in index.get(key, []):
            if child_n == "signal-bus" and pin_signal:
                child_v = pin_signal
            queue.append((child_n, child_v, depth + 1))
    return None


def path_to(direct: dict[str, str], target: tuple[str, str], *, pin_signal: str | None = None) -> list[tuple[str, str]]:
    index = dep_index()
    queue: list[tuple[str, str, list[tuple[str, str]]]] = [(n, v, [(n, v)]) for n, v in direct.items()]
    seen: set[tuple[str, str]] = set()
    while queue:
        name, version, path = queue.pop(0)
        if name == "signal-bus" and pin_signal:
            version = pin_signal
            path = path[:-1] + [(name, version)]
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)
        if key == target:
            return path
        for child_n, child_v in index.get(key, []):
            if child_n == "signal-bus" and pin_signal:
                child_v = pin_signal
            queue.append((child_n, child_v, path + [(child_n, child_v)]))
    return []


def package_names() -> list[str]:
    return sorted({row[0] for row in PACKAGE_RELEASES})


def typosquat_pairs() -> list[tuple[str, str, int]]:
    names = package_names()
    pairs: list[tuple[str, str, int]] = []
    popular = ["signal-bus", "telemetry-kit", "payments-core", "express", "react", "lodash"]
    for target in popular:
        for name, dist in neighborhood(names, target):
            pairs.append((target, name, dist))
    return pairs


def lockfile_payload(app: dict[str, Any]) -> dict[str, Any]:
    pin = app.get("pin_signal")
    flattened = resolve_tree(app["direct"], pin_signal=pin)
    packages: dict[str, Any] = {
        "": {
            "name": app["slug"],
            "dependencies": dict(app["direct"]),
        }
    }
    for name, version in flattened:
        packages[f"node_modules/{name}"] = {"version": version, "name": name}
    return {
        "name": app["slug"],
        "lockfileVersion": 3,
        "resolved_at": app["resolved_at"],
        "commit": app["commit"],
        "packages": packages,
    }


def parse_iso(value: str) -> int:
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
