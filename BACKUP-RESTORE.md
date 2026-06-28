# Backup & Restore Guide — VulnusLab

Your customer database (users, scans, subscriptions, trial timers) lives in
**PostgreSQL**, inside the `vulnuslab_postgres` container (data on the Docker
volume `cyber-project_pg_data`). This file documents everything about backing
it up and restoring it.

> **Migrated to Postgres (full cutover).** Backups are now `pg_dump` archives
> (`*.dump`), **not** SQLite `.db` files. Any old `users-*.db` files are SQLite
> dumps from before the cutover and can no longer be restored with these steps.

**Important:** GitHub backs up your CODE only. It does NOT back up your
database. Code can be re-deployed; customer data cannot be recreated.

---

## Current Backup Setup

| Item | Value |
|---|---|
| Backup script | `/root/backup-vulnuslab.sh` (source: `scripts/backup-vulnuslab.sh`) |
| Backup folder | `/root/backups/` |
| Schedule | Daily at 3:00 AM (cron) |
| Retention | 14 days (older auto-deleted) |
| Log file | `/root/backups/backup.log` |
| File pattern | `vulnuslab-YYYYMMDD-HHMM.dump` |
| DB container | `vulnuslab_postgres` (user `vluser`, db `vulnuslab`) |
| Format | `pg_dump -Fc` (custom, compressed, restorable with `pg_restore`) |

---

## 1. Daily Backups (Already Set Up)

The cron job runs automatically at 3 AM every day. You don't need to do anything.

**To verify backups are still happening:**

```bash
# SSH into VPS first
ssh root@187.127.162.231

# Check backup folder
ls -lh ~/backups/

# Read the log
tail ~/backups/backup.log

# Check cron is scheduled
crontab -l
```

You should see a fresh `.dump` file dated today (or yesterday before 3 AM).

---

## 2. Manual Backup (Run Anytime)

To create an immediate backup outside the schedule:

```bash
ssh root@187.127.162.231
~/backup-vulnuslab.sh
ls -lh ~/backups/
```

A new file with current timestamp appears.

**One-liner if the script isn't installed yet:**

```bash
docker exec vulnuslab_postgres pg_dump -U vluser -Fc vulnuslab \
  > ~/backups/vulnuslab-$(date +%Y%m%d-%H%M).dump
```

---

## 3. RESTORE — Only Run if Disaster Strikes

**DESTRUCTIVE COMMANDS — these overwrite your live database.** Only run when
actually needed.

### Step 1: Find which backup to restore

```bash
ssh root@187.127.162.231
ls -lh ~/backups/
```

You'll see files like:
```
vulnuslab-20260628-0300.dump   (180K)
vulnuslab-20260627-0300.dump   (172K)
vulnuslab-20260626-0300.dump   (160K)
```

Pick the most recent **healthy** backup (before whatever broke happened).

### Step 2: Stop the backend (leave Postgres running)

The backend holds open connections; stopping it lets `pg_restore` drop and
recreate tables cleanly. Postgres itself must stay up to receive the restore.

```bash
cd ~/Cyber-project
docker compose stop backend
```

### Step 3: Restore the backup

Replace `vulnuslab-YYYYMMDD-HHMM.dump` with the actual filename you chose.
`--clean --if-exists` drops the existing tables first so the restore is a clean
overwrite (no leftover rows):

```bash
docker exec -i vulnuslab_postgres \
  pg_restore -U vluser -d vulnuslab --clean --if-exists \
  < ~/backups/vulnuslab-YYYYMMDD-HHMM.dump
```

**Example with real filename:**
```bash
docker exec -i vulnuslab_postgres \
  pg_restore -U vluser -d vulnuslab --clean --if-exists \
  < ~/backups/vulnuslab-20260628-0300.dump
```

### Step 4: Restart the backend

```bash
docker compose start backend
docker compose logs -f backend
```

Wait for `Uvicorn running on http://0.0.0.0:8000` → Ctrl+C.

### Step 5: Verify users are back

```bash
docker exec vulnuslab_postgres psql -U vluser -d vulnuslab \
  -c "SELECT username, plan, created_at FROM users;"
```

You should see your users listed. Done.

---

## 4. Full Disaster Recovery (VPS Died)

If the entire VPS is destroyed:

### Step 1: Provision a new VPS
- Order a new server (same provider, Ubuntu 22.04+ recommended)
- SSH in as root

### Step 2: Install Docker + git
```bash
apt update && apt install -y docker.io docker-compose-plugin git
```

### Step 3: Clone the repo
```bash
git clone https://github.com/vijayrajkoduru/Cyber-project.git
cd Cyber-project
```

### Step 4: Restore .env file
The `.env` file is NOT in git (it has secrets). You'll need to recreate it.
See `.env.example` in the repo for the full list of required keys:

```bash
cat > .env <<'EOF'
JWT_SECRET=<paste your saved JWT_SECRET — generate new if lost>
ADMIN_PASSWORD=<your admin password>
POSTGRES_PASSWORD=<the DB password — must match what your dump expects>
CORS_ORIGINS=https://app.vulnuslab.com,https://vulnuslab.com
LEMONSQUEEZY_API_KEY=<from LS dashboard>
LEMONSQUEEZY_STORE_ID=<from LS dashboard>
LEMONSQUEEZY_VARIANT_ID=<from LS dashboard>
LEMONSQUEEZY_WEBHOOK_SECRET=<from LS dashboard>
VIRUSTOTAL_KEY=your_actual_key
ABUSEIPDB_KEY=your_abuseipdb_key
EOF
```

### Step 5: Deploy the app
```bash
chmod +x deploy.sh
./deploy.sh
```

This starts Postgres and runs the Alembic migrations to create an empty schema.

### Step 6: Restore the latest backup
You need a copy of the most recent `vulnuslab-*.dump` file. If you set up
off-VPS backups (GitHub private repo, S3, etc.), pull from there. Otherwise,
the data is gone.

```bash
# Place the dump at /root/backups/vulnuslab-XXXX.dump, then:
mkdir -p /root/backups
docker compose stop backend
docker exec -i vulnuslab_postgres \
  pg_restore -U vluser -d vulnuslab --clean --if-exists \
  < /root/backups/vulnuslab-XXXX.dump
docker compose start backend
```

### Step 7: Re-set up the daily backup cron
```bash
cp ~/Cyber-project/scripts/backup-vulnuslab.sh /root/backup-vulnuslab.sh
chmod +x /root/backup-vulnuslab.sh
(crontab -l 2>/dev/null | grep -v "backup-vulnuslab.sh"; \
  echo "0 3 * * * /root/backup-vulnuslab.sh") | crontab -
```

### Step 8: Point DNS to new IP
Update the Cloudflare `app` A record to the new VPS IP.

---

## 5. Off-VPS Backup (Strongly Recommended)

Local backups on the VPS protect against accidental data loss. But if the VPS
disk dies entirely, local backups die with it.

For real safety, copy backups OFF the VPS daily.

### Option A: Push to a private GitHub repo

```bash
# One-time setup on VPS
mkdir -p /root/db-backups-git
cd /root/db-backups-git
git init
git remote add origin git@github.com:vijayrajkoduru/vulnuslab-db-backups.git
# (Create that private repo on GitHub first, add VPS's SSH key as deploy key)

# Add this to backup-vulnuslab.sh AFTER the find/delete line:
cp /root/backups/vulnuslab-$DATE.dump /root/db-backups-git/
cd /root/db-backups-git
git add . && git commit -m "Backup $DATE" 2>/dev/null && git push 2>/dev/null || true
```

### Option B: Push to AWS S3 / Backblaze B2

```bash
# Install aws-cli once:  apt install -y awscli  &&  aws configure

# Add to backup script:
aws s3 cp /root/backups/vulnuslab-$DATE.dump s3://vulnuslab-backups/
```

### Option C: Email yourself a copy daily

```bash
# Install mutt:  apt install -y mutt
# Add to backup script:
echo "Daily backup attached" | mutt -s "VulnusLab Backup $DATE" \
  -a "/root/backups/vulnuslab-$DATE.dump" -- support@vulnuslab.com
```

---

## 6. Backup Sizes — What to Expect

`pg_dump -Fc` output is gzip-compressed, so dumps stay small.

| Users | Approximate dump size |
|---|---|
| 0 | ~4 KB (just ADMIN row) |
| 10 | ~20 KB |
| 100 | ~200 KB |
| 1000 | ~2 MB |
| 10,000 | ~20 MB |

If your dump suddenly jumps in size (e.g., 200 KB → 50 MB overnight),
something's wrong — likely scan history blowing up. Investigate before backups
eat your disk.

---

## 7. Common Tasks

### Check database size
```bash
docker exec vulnuslab_postgres psql -U vluser -d vulnuslab \
  -c "SELECT pg_size_pretty(pg_database_size('vulnuslab'));"
```

### Count users
```bash
docker exec vulnuslab_postgres psql -U vluser -d vulnuslab \
  -c "SELECT COUNT(*) FROM users;"
```

### Count scans
```bash
docker exec vulnuslab_postgres psql -U vluser -d vulnuslab \
  -c "SELECT COUNT(*) FROM scan_usage;"
```

### Open an interactive SQL shell
```bash
docker exec -it vulnuslab_postgres psql -U vluser -d vulnuslab
```

### List the tables
```bash
docker exec vulnuslab_postgres psql -U vluser -d vulnuslab -c "\dt"
```

### View latest backups
```bash
ls -lht ~/backups/ | head -10
```

### Free disk space if backups folder gets full
```bash
# Manually delete backups older than 7 days
find ~/backups -name "vulnuslab-*.dump" -mtime +7 -delete
```

---

## 8. If Backups Stop Running

Diagnosis:

```bash
# 1. Check the log — is there a recent entry?
tail -20 ~/backups/backup.log

# 2. Run the script manually — does it work?
~/backup-vulnuslab.sh

# 3. Is the Postgres container up?
docker ps --filter name=vulnuslab_postgres

# 4. Check cron is still scheduled
crontab -l

# 5. Check cron service is running
systemctl status cron

# 6. View cron logs for errors
grep CRON /var/log/syslog | tail -20
```

If the script works manually but cron isn't firing, restart cron:
```bash
systemctl restart cron
```
