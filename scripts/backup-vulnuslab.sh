#!/bin/bash
# Daily Postgres backup for VulnusLab.
#
# Dumps the `vulnuslab` database out of the `vulnuslab_postgres` container
# using pg_dump's custom format (-Fc: compressed + restorable with pg_restore),
# keeps 14 days of history, and appends a one-line result to backup.log.
#
# Install on the VPS as /root/backup-vulnuslab.sh and schedule via cron:
#   cp scripts/backup-vulnuslab.sh /root/backup-vulnuslab.sh
#   chmod +x /root/backup-vulnuslab.sh
#   (crontab -l 2>/dev/null | grep -v backup-vulnuslab.sh; \
#     echo "0 3 * * * /root/backup-vulnuslab.sh") | crontab -
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/root/backups}"
PG_CONTAINER="${PG_CONTAINER:-vulnuslab_postgres}"
DB_USER="${DB_USER:-vluser}"
DB_NAME="${DB_NAME:-vulnuslab}"
RETAIN_DAYS="${RETAIN_DAYS:-14}"

DATE=$(date +%Y%m%d-%H%M)
OUT="$BACKUP_DIR/vulnuslab-$DATE.dump"
mkdir -p "$BACKUP_DIR"

# Dump to a temp file first so a failed pg_dump never leaves a half-written
# .dump that looks like a valid backup.
docker exec "$PG_CONTAINER" pg_dump -U "$DB_USER" -Fc "$DB_NAME" > "$OUT.tmp"
mv "$OUT.tmp" "$OUT"

# Prune backups older than the retention window.
find "$BACKUP_DIR" -name "vulnuslab-*.dump" -mtime "+$RETAIN_DAYS" -delete 2>/dev/null || true

SIZE=$(ls -lh "$OUT" | awk '{print $5}')
echo "[$(date)] Backup OK: $(basename "$OUT") ($SIZE)" >> "$BACKUP_DIR/backup.log"
