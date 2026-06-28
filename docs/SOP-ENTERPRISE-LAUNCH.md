# SOP — Enterprise Features, Deploy & Launch

**Scope:** how to ship the `feat/enterprise-main` work to production, go live for
sales, and run day-to-day. Pairs with `ROTATE-SECRETS.md`, `POSTGRES-MIGRATION.md`,
`SECURITY-DEBT.md`, and `EVERYDAY-TODO.md`.

- **Production:** https://app.vulnuslab.com → Cloudflare → VPS `root@187.127.162.231`
- **Repo:** github.com/vijayrajkoduru/Cyber-project
- **Branch with the new work:** `feat/enterprise-main`

---

## 0. What was built (enterprise set, no SSO)
| Feature | Who it's for | Notes |
|---|---|---|
| MFA / 2FA (TOTP) | every customer | enroll in Account → Two-Factor; required at login when on |
| Email verification | every customer | welcome email + verify link sent at signup |
| Welcome email (with plan) | every customer | sent on registration |
| Organizations / Teams + RBAC | team/business customers | roles: owner > admin > member |
| Audit log | **admins only** | who-did-what incl. each scan (`scan.run`) |
| Metrics (`/api/metrics`) | ops/you | Prometheus scrape |
| ~~API keys~~ | removed per product decision |

> **Not built:** per-module access control ("buy one module → use only that
> module"). Access is currently **plan-based**. Decide before selling per-module.

---

## 1. Release procedure (branch → main)
```bash
# review the PR first:
#   https://github.com/vijayrajkoduru/Cyber-project/compare/main...feat/enterprise-main
git checkout main && git pull
git merge feat/enterprise-main
git push origin main
```
Do this from a clean tree. Resolve any conflicts, re-run the test suite (§5).

## 2. Deploy to the VPS
```bash
ssh root@187.127.162.231
cd ~/Cyber-project && git pull
# REQUIRED — new dependency (pyotp) → rebuild, not just restart:
docker compose build --no-cache backend && docker compose up -d
docker compose logs -f backend     # wait for "Uvicorn running", Ctrl+C
```
**New env vars** (set in `.env` before/with deploy):
- `APP_BASE_URL=https://app.vulnuslab.com`  (used in email links)
- Email: `EMAIL_PROVIDER=zeptomail`, `EMAIL_API_KEY=...`, `EMAIL_FROM=...`, `EMAIL_REPLY_TO=...`
- Optional: `SENTRY_DSN` (error tracking), `RATE_LIMIT_PER_MIN` (default 120)

DB schema migrates itself: new tables/columns are idempotent `CREATE/ALTER … IF
NOT EXISTS`, applied on first DB use. No manual migration step.

## 3. Post-deploy verification
```bash
curl -s https://app.vulnuslab.com/api/health   | head   # tools_loaded > 0
curl -s https://app.vulnuslab.com/api/metrics  | head   # must NOT be 404
./scripts/preflight_launch.sh                            # GO / NO-GO
```
Manual UI smoke: log in → **Account** → enroll MFA → log out → log in with the
2FA code. Register a test user → confirm the welcome email arrives → click the
verify link. Then delete the test user.

## 4. Go-live checklist (before taking money)
Run `./scripts/go_live.sh` on the VPS (deploy + vault key + backups + preflight),
then confirm the two things no script can:
1. **Revoke** the old leaked keys at each provider (`ROTATE-SECRETS.md`)
2. **One real live payment end-to-end + a refund**

Also: `POSTGRES_PASSWORD` is a strong value (not `vlpass`); backups cron installed.

## 5. Testing
```bash
# full suite (needs a Postgres for the enterprise tests; others run anywhere):
DATABASE_URL=postgresql+psycopg2://USER:PW@HOST:5432/DB JWT_SECRET=x \
  python -m pytest tests/ -q
```
Enterprise tests skip cleanly if `DATABASE_URL` is unset. CI gates on pytest +
pip-audit (see `.github/workflows/ci.yml`).

## 6. Daily / weekly ops
See `EVERYDAY-TODO.md`. Key items:
- Morning: open the dashboard; if off, run the SSH health one-liner.
- Backups: `scripts/backup_db.sh` runs daily via cron — confirm a recent
  `~/backups/*.dump`, and test a restore periodically.
- Watch `/api/health` (tools_failed) and `/api/metrics` (latency/errors). Point
  an uptime monitor (UptimeRobot) at `/api/health`.
- Audit trail: admins view it in **Account → Audit Log** (or `GET /api/audit/log`).

## 7. Rollback
- Code: `git revert <merge>` + redeploy, or redeploy the previous image.
- DB: restore the latest `pg_dump` (see `EVERYDAY-TODO.md` §6) — schema changes
  are additive, so rollback rarely needs a DB restore.
- `.env`: `rotate_keys.sh`/`go_live.sh` back up `.env` to `.env.bak.<ts>` before
  edits — `cp` it back and restart.

## 8. Known issues
- **`red_team_admin` quarantined** (`/api/health` → tools_failed). Superadmin-only,
  auto-isolated, zero customer impact. It imports `red_team_ops` (gitignored /
  local-only). Fix on the VPS: ship `red_team_ops/` in the image, or
  `rm endpoints/red_team_admin.py` + rebuild if unused.

---
_Last updated: 2026-06-28. Owner: VulnusLab._
