#!/usr/bin/env bash
#
# maintenance-upgrade.sh — finish the Kali upgrade (Docker + kept-back packages)
# and reboot into the new kernel. Run in a maintenance window, as root.
#
#   sudo bash /root/Cyber-project/scripts/maintenance-upgrade.sh
#
# What it does, in order:
#   1. Backs up the Postgres database to /root/backups/pg-<timestamp>.sql.gz
#   2. apt upgrade (now includes Docker, which was held during the live session)
#   3. apt autoremove + clean
#   4. Waits for the app to come back after the Docker daemon restart
#   5. Asks for confirmation, then reboots into the new kernel
#
# The containers use `restart: unless-stopped`, so they come back on their own
# after both the Docker daemon restart (step 2) and the reboot (step 5).
# Expect a short outage (seconds) while the Docker daemon restarts.

set -uo pipefail

COMPOSE_DIR="/root/Cyber-project"
BACKUP_DIR="/root/backups"
PG_CONTAINER="vulnuslab_postgres"
PG_USER="vluser"
PG_DB="vulnuslab"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="/var/log/vulnuslab-maintenance-$TS.log"

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

if [[ $EUID -ne 0 ]]; then
  echo "Must run as root: sudo bash $0"; exit 1
fi

log "=== VulnusLab maintenance upgrade started ==="

# ── 1. Database backup ───────────────────────────────────────────────
mkdir -p "$BACKUP_DIR"
PG_BACKUP="$BACKUP_DIR/pg-$TS.sql.gz"
log "Backing up Postgres ($PG_DB) -> $PG_BACKUP"
if docker exec "$PG_CONTAINER" pg_dump -U "$PG_USER" "$PG_DB" | gzip > "$PG_BACKUP"; then
  log "DB backup OK ($(du -h "$PG_BACKUP" | cut -f1))"
else
  log "ERROR: DB backup failed — ABORTING before any upgrade."
  exit 1
fi

# ── 2. Package upgrade (Docker now included) ─────────────────────────
log "apt-get update"
apt-get update -q >>"$LOG" 2>&1
log "apt-get full-upgrade (Docker daemon will restart; containers auto-recover)"
NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive \
  apt-get full-upgrade -y \
  -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" \
  >>"$LOG" 2>&1
UPGRADE_RC=$?
if [[ $UPGRADE_RC -ne 0 ]]; then
  log "WARNING: apt full-upgrade exit code $UPGRADE_RC — review $LOG before rebooting."
fi

# ── 3. Cleanup ───────────────────────────────────────────────────────
log "apt-get autoremove + clean"
apt-get autoremove -y >>"$LOG" 2>&1
apt-get clean       >>"$LOG" 2>&1

# ── 4. Wait for the app to recover after the Docker restart ──────────
log "Waiting for backend health (up to 120s)..."
ok=0
for i in $(seq 1 24); do
  code=$(curl -s -m5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/api/health || true)
  if [[ "$code" == "200" ]]; then ok=1; log "Backend healthy after ${i}x5s"; break; fi
  sleep 5
done
[[ $ok -eq 1 ]] || log "WARNING: backend not healthy yet — check 'docker ps' and $LOG."

log "Remaining upgradable packages: $(apt list --upgradable 2>/dev/null | grep -c upgradable)"
REBOOT_FLAG="no"; [[ -f /var/run/reboot-required ]] && REBOOT_FLAG="YES"
log "Reboot required flag: $REBOOT_FLAG"

# ── 5. Confirmed reboot ──────────────────────────────────────────────
echo
echo "Upgrade + cleanup complete. DB backup: $PG_BACKUP   Log: $LOG"
echo "A reboot activates the new kernel. Containers restart automatically (unless-stopped)."
read -r -p "Reboot now? type 'yes' to reboot, anything else to skip: " ans
if [[ "$ans" == "yes" ]]; then
  log "Rebooting now."
  sync
  reboot
else
  log "Reboot skipped by operator. Run 'sudo reboot' later to activate the new kernel."
  echo "Skipped reboot. Run 'sudo reboot' during your window to finish."
fi
