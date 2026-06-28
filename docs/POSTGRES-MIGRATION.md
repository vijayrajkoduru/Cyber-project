# SQLite → Postgres Migration

**Status:** foundation shipped (`tools/_core/db.py`); cutover is a staged,
reversible follow-up. SQLite remains the default and current production backend
— nothing changes until `DATABASE_URL` is set.

## Why
SQLite serialises writes and can't replicate — the ceiling for a multi-tenant
SaaS. Postgres gives concurrent writes, managed backups, and HA.

## What's already in place
- `tools/_core/db.py` — one connection factory + paramstyle helper (`q()`).
  - `DATABASE_URL` unset → `sqlite3` (WAL + foreign_keys), identical to today.
  - `DATABASE_URL=postgresql://…` → `psycopg` (lazily imported).
- The factory means each call site migrates with a two-line change (see the
  module docstring).

## Cutover plan (staged, reversible)
1. **Provision** managed Postgres (RDS / Cloud SQL / Supabase). Keep it private.
2. **Add the driver:** `psycopg[binary]>=3.2` to `requirements.txt`; rebuild.
3. **Migrate call sites** to `get_conn()/q()`. Sites (from `grep -rn sqlite3.connect`):
   - `tools/auth/_db.py` (users/auth — do first, highest value)
   - `tools/credentials/_vault.py`
   - `tools/consent/consent_log.py`
   - `tools/_audit.py`
   - `endpoints/account.py`, `endpoints/ops_console.py` (read-only `?mode=ro`)
4. **Translate schema:** create tables in Postgres. SQLite-isms to fix:
   - `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL PRIMARY KEY`
   - `INSERT OR REPLACE` / `INSERT OR IGNORE` → `INSERT … ON CONFLICT … DO …`
   - datetime text columns → `TIMESTAMPTZ` (or keep TEXT initially)
5. **Copy data:** `pgloader sqlite:///path/users.db postgresql://…` (handles
   type mapping), or a small Python ETL per table for full control.
6. **Dual-read verify:** point a staging backend at Postgres; compare row
   counts + spot-check auth/login, scan history, audit log, vault read.
7. **Flip:** set `DATABASE_URL` in prod `.env`, `docker compose up -d`.
   Rollback = unset `DATABASE_URL` (SQLite file is untouched until you retire it).

## After cutover
- Move backups to `pg_dump` (managed-provider automated snapshots preferred).
- For multi-instance scale, move the rate-limit counter
  (`tools/_core/ratelimit.py`) to Redis so the window is shared.
