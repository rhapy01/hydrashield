#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/hydradb-data/store" "$ROOT/hydradb-data/cache"
cd "$ROOT"
docker compose up --build
