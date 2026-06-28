# VulnusLab — Daily Operations Checklist

**Production URLs**
- Dashboard: https://app.vulnuslab.com
- Landing page: https://vulnuslab.com
- VPS: `root@187.127.162.231`
- Repo: https://github.com/vijayrajkoduru/Cyber-project

**Login**
- Username: `ADMIN`
- Password: (the one you set in `.env` on VPS — keep it in your password manager)

---

## 1. Morning Health Check (30 seconds)

Open https://app.vulnuslab.com in a browser.
- Page loads + you can log in → all good, you're done.
- Page doesn't load → SSH in and run the one-liner below.

---

## 2. SSH One-Liner (Run If Anything Looks Off)

```bash
ssh root@187.127.162.231
```

Once in, run this single command — shows containers + disk + user count:

```bash
cd ~/Cyber-project && \
echo "=== CONTAINERS ===" && docker compose ps && \
echo "=== DISK ===" && df -h / && \
echo "=== USERS ===" && docker exec vulnuslab_postgres psql -U vluser -d vulnuslab -c "SELECT username, plan, created_at FROM users;" && \
echo "=== BACKEND LAST 20 LINES ===" && docker compose logs --tail 20 backend
```

**What to look for:**
- All containers status: `Up` (good) / `Exited` or `Restarting` (bad)
- Disk `Use%` under 80% (good) / over 80% (clean up)
- Backend logs: no `RuntimeError`, no repeated `ERROR` lines

---

## 3. Restart If A Container Is Down

```bash
cd ~/Cyber-project
docker compose up -d
```

If still down after that:

```bash
docker compose down
docker compose up -d
docker compose logs -f backend
```

Press `Ctrl+C` to exit logs once you see `Uvicorn running on http://0.0.0.0:8000`.

---

## 4. Disk Cleanup (Run Weekly Or When Over 80%)

```bash
docker image prune -f
docker builder prune -f --keep-storage 2gb
docker container prune -f
df -h /
```

---

## 5. Deploy New Code (After Pushing From Laptop)

On your laptop first:
```powershell
cd C:\Users\vijay\OneDrive\Desktop\kali\Cyber-project
git push origin main
```

Then on VPS:
```bash
cd ~/Cyber-project
git pull
docker compose build --no-cache backend frontend
docker compose up -d
docker compose logs -f backend
```

Wait until you see `Uvicorn running on http://0.0.0.0:8000`, then `Ctrl+C`.

**For landing-page changes:** Build locally and drag `landing-page/build/` to Netlify — no SSH needed.

---

## 6. Daily Database Backup (Run Every Morning)

The user DB and scan history live in **PostgreSQL** (`vulnuslab_postgres`
container, volume `cyber-project_pg_data`). **If the VPS dies, you lose
everything.** Back it up daily with `pg_dump`:

```bash
mkdir -p ~/backups
docker exec vulnuslab_postgres pg_dump -U vluser -Fc vulnuslab \
  > ~/backups/vulnuslab-$(date +%Y%m%d-%H%M).dump
ls -lh ~/backups/
```

The installed cron job (`/root/backup-vulnuslab.sh`, source
`scripts/backup-vulnuslab.sh`) does this automatically at 3 AM daily.

**Optional — keep only last 14 days of backups:**
```bash
find ~/backups -name "vulnuslab-*.dump" -mtime +14 -delete
```

**To restore from a backup (only if something broke):**
```bash
docker compose stop backend
docker exec -i vulnuslab_postgres \
  pg_restore -U vluser -d vulnuslab --clean --if-exists \
  < ~/backups/vulnuslab-YYYYMMDD-HHMM.dump
docker compose start backend
```

See `BACKUP-RESTORE.md` for the full guide.

---

## 7. Quick Functional Test (Run After Any Deploy)

1. Open https://app.vulnuslab.com → log in as `ADMIN`
2. Run a scan on `http://testphp.vulnweb.com`
3. Check that XSS Scanner shows **CRITICAL**
4. Check that SQL Injection shows **CRITICAL**
5. Generate a PDF report — should download

If all four work, the deploy is healthy.

---

## 8. SSL Certificate Check (Monthly)

Let's Encrypt certs auto-renew via certbot, but verify monthly:

```bash
certbot certificates
```

Look for `VALID: XX days` — if under 30 days and not renewing, run:
```bash
certbot renew
docker compose restart frontend
```

---

## 9. Weekly Tasks (Every Monday)

- [ ] Check user count: `docker exec vulnuslab_postgres psql -U vluser -d vulnuslab -c "SELECT COUNT(*) FROM users;"`
- [ ] Check scan count: `docker exec vulnuslab_postgres psql -U vluser -d vulnuslab -c "SELECT COUNT(*) FROM scan_usage;"`
- [ ] Disk usage trend: `df -h /`
- [ ] Test register + login with a brand-new test account, then delete it
- [ ] Pull latest from git even if you didn't push (in case team pushed): `cd ~/Cyber-project && git pull`

---

## 10. Emergency — Dashboard Completely Dead

```bash
# Step 1: see what's running
cd ~/Cyber-project
docker compose ps

# Step 2: hard restart
docker compose down
docker compose up -d

# Step 3: if backend won't start, check env file
cat .env | grep -E '^(JWT_SECRET|ADMIN_PASSWORD|CORS_ORIGINS)='
# All three must be present and non-empty

# Step 4: full rebuild (slowest, last resort)
docker compose build --no-cache backend frontend
docker compose up -d
docker compose logs -f backend
```

---

## 11. Reset ADMIN Password (If Forgotten)

```bash
# 1. Set new password in .env
nano ~/Cyber-project/.env
# Edit the line: ADMIN_PASSWORD=NewStrongPasswordHere

# 2. Delete existing ADMIN row from DB
docker exec vulnuslab_postgres psql -U vluser -d vulnuslab -c "DELETE FROM users WHERE username='ADMIN';"

# 3. Restart backend — it will reseed ADMIN with the new password
docker compose restart backend
docker compose logs -f backend
```

---

## Notes

- **Never commit `.env`** to git — it has secrets. It's in `.gitignore` already.
- **Never share your `JWT_SECRET`** — anyone with it can forge admin tokens.
- The `ADMIN_PASSWORD` env var only takes effect when the ADMIN user does NOT exist in the DB. Section 11 covers rotating it.
- If you change the env vars, you must `docker compose restart backend` for them to take effect.
