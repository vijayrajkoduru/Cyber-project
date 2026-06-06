#!/usr/bin/env bash
# backup_recon.sh — snapshot the Recon module so it can be restored later.
#
# Saves THREE things:
#   1. tar.gz of tools/recon/ + endpoints/recon_*.py + tools/recon/_targeting.py
#   2. git tag `recon-stable-YYYYMMDD-HHMMSS` on current HEAD
#   3. log entry to .recon_backups/backups.log
#
# Run when Recon is in a known-good state (after a clean PDF / passing scan).
# Restore with `./scripts/restore_recon.sh`.
#
# Backup is module-only: does NOT touch vuln, webapp, mobile, password etc.
# Use this when you want a Recon-specific safety net independent of the
# global ./rollback.sh (which restores everything).

set -e
cd "$(dirname "$0")/.."

C_BLUE='\033[1;34m'; C_GREEN='\033[1;32m'; C_YELLOW='\033[1;33m'; C_DIM='\033[2m'; C_RST='\033[0m'
say()  { printf "${C_BLUE}[recon-backup]${C_RST} %s\n" "$1"; }
ok()   { printf "${C_GREEN}${C_RST} %s\n" "$1"; }
warn() { printf "${C_YELLOW}!${C_RST} %s\n" "$1"; }

BACKUP_DIR=".recon_backups"
mkdir -p "$BACKUP_DIR"

TS=$(date +%Y%m%d-%H%M%S)
LABEL="${1:-}"
ARCHIVE_NAME="recon-$TS${LABEL:+-$LABEL}.tar.gz"
ARCHIVE_PATH="$BACKUP_DIR/$ARCHIVE_NAME"
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "no-git")
GIT_TAG="recon-stable-$TS"

# ── 1. Tar the Recon code + helpers ─────────────────────────────
say "snapshotting Recon module..."
tar -czf "$ARCHIVE_PATH" \
    tools/recon \
    endpoints/recon_orchestrator.py \
    endpoints/recon_flow.py \
    endpoints/recon_flow_advanced.py \
    endpoints/recon_prime.py \
    2>/dev/null || warn "some files missing (continuing)"

SIZE=$(du -h "$ARCHIVE_PATH" | cut -f1)
FILE_COUNT=$(tar -tzf "$ARCHIVE_PATH" | wc -l)
ok "saved $ARCHIVE_PATH ($SIZE, $FILE_COUNT files)"

# ── 2. Git tag the current HEAD ─────────────────────────────────
if git rev-parse HEAD >/dev/null 2>&1; then
    git tag "$GIT_TAG" >/dev/null 2>&1 || warn "git tag '$GIT_TAG' already exists"
    # Move floating `recon-stable` to current HEAD too
    git tag -f recon-stable >/dev/null 2>&1 || true
    ok "git: HEAD ($GIT_SHA) tagged as 'recon-stable' + '$GIT_TAG'"
fi

# ── 3. Log entry ────────────────────────────────────────────────
LOG="$BACKUP_DIR/backups.log"
{
    echo "$TS  archive=$ARCHIVE_NAME  git=$GIT_SHA  tag=$GIT_TAG  files=$FILE_COUNT  size=$SIZE  msg=$(git log -1 --pretty=%s 2>/dev/null | head -c 80)"
} >> "$LOG"

# Keep last 100 log entries
tail -n 100 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"

# Prune old archives — keep last 10
ls -t "$BACKUP_DIR"/recon-*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm

echo ""
ok "Recon backup complete."
echo ""
echo "  Archive : $ARCHIVE_PATH"
echo "  Git tag : $GIT_TAG"
echo "  Restore : ./scripts/restore_recon.sh"
echo ""
