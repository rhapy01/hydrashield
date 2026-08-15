# VantaPay lockfile snapshot

npm lockfile v3 fixtures generated from `backend/hydrashield/universe.py`.

Regenerate:

```bash
cd backend
python -m hydrashield.write_fixtures
```

`resolved_at` is a HydraShield extension so ingest can intersect lockfile time with the incident window without guessing from git history.
