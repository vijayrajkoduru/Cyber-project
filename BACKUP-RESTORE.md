# Backup & Restore Guide — VulnusLab

Your customer database (users, scans, subscriptions, trial timers) lives in the Docker volume `cyber-project_scan_data` on the VPS. This file documents everything about backing it up and restoring it.

**⚠️ Important:** GitHub backs up your CODE only. It does NOT back up your database. Code can be re-deployed; customer data cannot be recreated.

---

## Current Backup Setup

| Item | Value |
|---|---|
| Backup script | `/root/backup-vulnuslab.sh` |
| Backup folder | `/root/backups/` |
| Schedule | Daily at 3:00 AM (cron) |
| Retention | 14 days (older auto-deleted) |
| Log file | `/root/backups/backup.log` |
| File pattern | `users-YYYYMMDD-HHMM.db` |

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

You should see a fresh `.db` file dated today (or yesterday before 3 AM).

---

## 2. Manual Backup (Run Anytime)

To create an immediate backup outside the schedule:

```bash
ssh root@187.127.162.231
~/backup-vulnuslab.sh
ls -lh ~/backups/
```

A new file with current timestamp appears.

---

## 3. RESTORE — Only Run if Disaster Strikes

⚠️ **DESTRUCTIVE COMMANDS — these overwrite your live database.** Only run when actually needed.

### Step 1: Find which backup to restore

```bash
ssh root@187.127.162.231
ls -lh ~/backups/
```

You'll see files like:
```
users-20260511-1108.db   (88K)
users-20260511-1930.db   (172K)
users-20260512-0300.db   (180K)
```

Pick the most recent **healthy** backup (before whatever broke happened).

### Step 2: Stop the running containers

```bash
cd ~/Cyber-project
docker compose down
```

### Step 3: Restore the backup

Replace `users-YYYYMMDD-HHMM.db` with the actual filename you chose:

```bash
docker run --rm \
  -v cyber-project_scan_data:/data \
  -v /root/backups:/backup \
  alpine sh -c "cp /backup/users-YYYYMMDD-HHMM.db /data/users.db"
```

**Example with real filename:**
```bash
docker run --rm \
  -v cyber-project_scan_data:/data \
  -v /root/backups:/backup \
  alpine sh -c "cp /backup/users-20260512-0300.db /data/users.db"
```

### Step 4: Restart containers

```bash
docker compose up -d
docker compose logs -f backend
```

Wait for `Uvicorn running on http://0.0.0.0:8000` → Ctrl+C.

### Step 5: Verify users are back

```bash
docker exec oscp_backend sqlite3 /app/data/users.db "SELECT username, plan, created_at FROM users;"
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
The `.env` file is NOT in git (it has secrets). You'll need to recreate it:

```bash
cat > .env <<'EOF'
JWT_SECRET=<paste your saved JWT_SECRET — generate new if lost>
ADMIN_PASSWORD=<your admin password>
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

### Step 6: Restore the latest backup
You need a copy of the most recent `users-*.db` file. If you set up off-VPS backups (GitHub private repo, S3, etc.), pull from there. Otherwise, the data is gone.

```bash
# Place users.db at /root/backups/users-XXXX.db, then:
docker compose down
docker run --rm \
  -v cyber-project_scan_data:/data \
  -v /root/backups:/backup \
  alpine sh -c "cp /backup/users-XXXX.db /data/users.db"
docker compose up -d
```

### Step 7: Re-set up the daily backup cron
```bash
cat > ~/backup-vulnuslab.sh <<'EOF'
#!/bin/bash
set -e
BACKUP_DIR="/root/backups"
DATE=$(date +%Y%m%d-%H%M)
mkdir -p "$BACKUP_DIR"
docker run --rm \
  -v cyber-project_scan_data:/data \
  -v "$BACKUP_DIR":/backup \
  alpine sh -c "cp /data/users.db /backup/users-$DATE.db"
find "$BACKUP_DIR" -name "users-*.db" -mtime +14 -delete 2>/dev/null
SIZE=$(ls -lh "$BACKUP_DIR/users-$DATE.db" | awk '{print $5}')
echo "[$(date)] Backup OK: users-$DATE.db ($SIZE)" >> "$BACKUP_DIR/backup.log"
EOF
chmod +x ~/backup-vulnuslab.sh
(crontab -l 2>/dev/null | grep -v "backup-vulnuslab.sh"; echo "0 3 * * * /root/backup-vulnuslab.sh") | crontab -
```

### Step 8: Point DNS to new IP
Update the Cloudflare `app` A record to the new VPS IP.

---

## 5. Off-VPS Backup (Strongly Recommended)

Local backups on the VPS protect against accidental data loss. But if the VPS disk dies entirely, local backups die with it.

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
cp /root/backups/users-$DATE.db /root/db-backups-git/
cd /root/db-backups-git
git add . && git commit -m "Backup $DATE" 2>/dev/null && git push 2>/dev/null || true
```

### Option B: Push to AWS S3 / Backblaze B2

```bash
# Install aws-cli once:  apt install -y awscli  &&  aws configure

# Add to backup script:
aws s3 cp /root/backups/users-$DATE.db s3://vulnuslab-backups/
```

### Option C: Email yourself a copy daily

```bash
# Install mutt:  apt install -y mutt
# Add to backup script:
echo "Daily backup attached" | mutt -s "VulnusLab Backup $DATE" -a "/root/backups/users-$DATE.db" -- support@vulnuslab.com
```

---

## 6. Backup Sizes — What to Expect

| Users | Approximate DB size |
|---|---|
| 0 | ~80 KB (just ADMIN row) |
| 10 | ~200 KB |
| 100 | ~2 MB |
| 1000 | ~20 MB |
| 10,000 | ~150 MB |

If your DB suddenly jumps in size (e.g., 1 MB → 100 MB overnight), something's wrong — likely scan history blowing up. Investigate before backups eat your disk.

---

## 7. Common Tasks

### Check current DB size
```bash
docker exec oscp_backend ls -lh /app/data/users.db
```

### Count users
```bash
docker exec oscp_backend sqlite3 /app/data/users.db "SELECT COUNT(*) FROM users;"
```

### Count scans
```bash
docker exec oscp_backend sqlite3 /app/data/users.db "SELECT COUNT(*) FROM scans;"
```

### View latest backups
```bash
ls -lht ~/backups/ | head -10
```

### Free disk space if backups folder gets full
```bash
# Manually delete backups older than 7 days
find ~/backups -name "users-*.db" -mtime +7 -delete
```

---

## 8. If Backups Stop Running

Diagnosis:

```bash
# 1. Check the log — is there a recent entry?
tail -20 ~/backups/backup.log

# 2. Run the script manually — does it work?
~/backup-vulnuslab.sh

# 3. Check cron is still scheduled
crontab -l

# 4. Check cron service is running
systemctl status cron

# 5. View cron logs for errors
grep CRON /var/log/syslog | tail -20
```

If the script works manually but cron isn't firing, restart cron:
```bash
systemctl restart cron
```
