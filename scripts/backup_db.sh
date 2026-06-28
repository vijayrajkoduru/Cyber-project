#!/usr/bin/env bash
# Automated database backup with integrity check + retention.
#
# Replaces the manual "run this every morning" step in EVERYDAY-TODO.md.
# Cron-ready and idempotent. Backs up the SQLite DB out of the docker volume,
# verifies it (PRAGMA integrity_check), compresses it, prunes old copies, and
# (optionally) pushes off-box so a dead VPS does not mean total data loss.
#
# Install as a daily cron job:
#   crontab -e
#   15 3 * * *  /root/Cyber-project/scripts/backup_db.sh >> /var/log/vl-backup.log 2>&1
#
# Off-site (recommended — survives VPS loss). Set in the environment/cron:
#   BACKUP_REMOTE="s3://my-bucket/vulnuslab"     # requires awscli, OR
#   BACKUP_REMOTE="user@host:/srv/backups/vl"    # requires ssh/scp
set -euo pipefail

VOLUME="${BACKUP_VOLUME:-cyber-project_scan_data}"
DB_NAME="${BACKUP_DB_NAME:-users.db}"
DEST="${BACKUP_DEST:-$HOME/backups}"
RETAIN_DAYS="${BACKUP_RETAIN_DAYS:-14}"
REMOTE="${BACKUP_REMOTE:-}"
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$DEST"
RAW="$DEST/${DB_NAME%.db}-$STAMP.db"

echo "[$(date -Is)] backup start: volume=$VOLUME db=$DB_NAME -> $RAW"

# 1. Copy the live DB out of the docker volume (no container needed).
docker run --rm -v "$VOLUME":/data -v "$DEST":/backup alpine \
  sh -c "cp /data/$DB_NAME /backup/$(basename "$RAW")"

# 2. Integrity-check the copy before we trust it. A corrupt backup is worse
#    than no backup because it hides the problem until restore day.
if command -v sqlite3 >/dev/null 2>&1; then
  RESULT="$(sqlite3 "$RAW" 'PRAGMA integrity_check;' 2>&1 || true)"
else
  RESULT="$(docker run --rm -v "$DEST":/backup alpine \
    sh -c "apk add --no-cache sqlite >/dev/null 2>&1; sqlite3 /backup/$(basename "$RAW") 'PRAGMA integrity_check;'" 2>&1 || true)"
fi
if [ "$RESULT" != "ok" ]; then
  echo "[$(date -Is)] FATAL: integrity_check failed -> '$RESULT' — removing bad copy"
  rm -f "$RAW"
  exit 1
fi
echo "[$(date -Is)] integrity_check: ok"

# 3. Compress.
gzip -f "$RAW"
ARCHIVE="$RAW.gz"
echo "[$(date -Is)] compressed: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

# 4. Off-site copy (optional but recommended).
if [ -n "$REMOTE" ]; then
  case "$REMOTE" in
    s3://*) aws s3 cp "$ARCHIVE" "$REMOTE/" && echo "[$(date -Is)] pushed to $REMOTE" ;;
    *)      scp -q "$ARCHIVE" "$REMOTE/" && echo "[$(date -Is)] pushed to $REMOTE" ;;
  esac
fi

# 5. Retention — prune local copies older than N days.
find "$DEST" -name "${DB_NAME%.db}-*.db.gz" -mtime +"$RETAIN_DAYS" -print -delete \
  | sed "s/^/[$(date -Is)] pruned: /" || true

echo "[$(date -Is)] backup done. local copies: $(find "$DEST" -name "${DB_NAME%.db}-*.db.gz" | wc -l)"
