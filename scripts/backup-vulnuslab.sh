#!/bin/bash
# Daily Postgres backup for VulnusLab.
#
# Dumps the `vulnuslab` database out of the `vulnuslab_postgres` container
# using pg_dump's custom format (-Fc: compressed + restorable with pg_restore),
# keeps 14 days of history locally, copies each dump OFFSITE (so a dead/hacked/
# suspended VPS does not take the backups with it), and appends a one-line
# result to backup.log.
#
# Install on the VPS as /root/backup-vulnuslab.sh and schedule via cron:
#   cp scripts/backup-vulnuslab.sh /root/backup-vulnuslab.sh
#   chmod +x /root/backup-vulnuslab.sh
#   (crontab -l 2>/dev/null | grep -v backup-vulnuslab.sh; \
#     echo "0 3 * * * /root/backup-vulnuslab.sh") | crontab -
#
# ── Offsite setup (one time) ────────────────────────────────────────────────
# Offsite upload uses rclone so it works with Backblaze B2 (cheapest), AWS S3,
# Google Drive, etc. Backblaze B2 is recommended (~$6/TB/month, generous free
# tier). One-time setup on the VPS:
#   1. apt install -y rclone           # or: curl https://rclone.org/install.sh | bash
#   2. rclone config                   # create a remote, e.g. name it "offsite"
#   3. Set OFFSITE_REMOTE below (or export it in the crontab line), e.g.:
#        OFFSITE_REMOTE="offsite:vulnuslab-backups"
# If OFFSITE_REMOTE is empty or rclone is missing, the local backup still runs
# and the script logs a LOUD warning so you notice offsite is not protected yet.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/root/backups}"
PG_CONTAINER="${PG_CONTAINER:-vulnuslab_postgres}"
DB_USER="${DB_USER:-vluser}"
DB_NAME="${DB_NAME:-vulnuslab}"
RETAIN_DAYS="${RETAIN_DAYS:-14}"

# Offsite target as an rclone remote path, e.g. "offsite:vulnuslab-backups".
# Leave empty to disable offsite (NOT recommended in production).
OFFSITE_REMOTE="${OFFSITE_REMOTE:-}"

DATE=$(date +%Y%m%d-%H%M)
OUT="$BACKUP_DIR/vulnuslab-$DATE.dump"
LOG="$BACKUP_DIR/backup.log"
mkdir -p "$BACKUP_DIR"

# Dump to a temp file first so a failed pg_dump never leaves a half-written
# .dump that looks like a valid backup.
docker exec "$PG_CONTAINER" pg_dump -U "$DB_USER" -Fc "$DB_NAME" > "$OUT.tmp"
mv "$OUT.tmp" "$OUT"

# Prune LOCAL backups older than the retention window.
find "$BACKUP_DIR" -name "vulnuslab-*.dump" -mtime "+$RETAIN_DAYS" -delete 2>/dev/null || true

SIZE=$(ls -lh "$OUT" | awk '{print $5}')
echo "[$(date)] Backup OK (local): $(basename "$OUT") ($SIZE)" >> "$LOG"

# ── Offsite copy ────────────────────────────────────────────────────────────
# Guarded so an offsite failure never makes a good local backup look failed.
# `set -e` is relaxed inside this block; each step logs its own outcome.
if [ -z "$OFFSITE_REMOTE" ]; then
  echo "[$(date)] WARNING: OFFSITE_REMOTE not set — backup is LOCAL ONLY. If this VPS dies you lose everything. See setup notes at top of this script." >> "$LOG"
elif ! command -v rclone >/dev/null 2>&1; then
  echo "[$(date)] WARNING: rclone not installed — cannot copy offsite. Backup is LOCAL ONLY. Run: apt install -y rclone" >> "$LOG"
else
  if rclone copy "$OUT" "$OFFSITE_REMOTE" --no-traverse 2>>"$LOG"; then
    echo "[$(date)] Offsite OK: $(basename "$OUT") -> $OFFSITE_REMOTE" >> "$LOG"
    # Prune OFFSITE copies older than the retention window to match local.
    if ! rclone delete "$OFFSITE_REMOTE" --min-age "${RETAIN_DAYS}d" --include "vulnuslab-*.dump" 2>>"$LOG"; then
      echo "[$(date)] WARNING: offsite prune failed (non-fatal) for $OFFSITE_REMOTE" >> "$LOG"
    fi
  else
    echo "[$(date)] ERROR: offsite copy FAILED for $(basename "$OUT") -> $OFFSITE_REMOTE. Local backup is fine; offsite is NOT protected. Check rclone config/credentials." >> "$LOG"
  fi
fi
