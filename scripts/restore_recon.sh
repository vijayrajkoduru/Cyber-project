#!/usr/bin/env bash
# restore_recon.sh — restore Recon module from a backup.
#
# Usage:
#   ./scripts/restore_recon.sh              # restore latest backup
#   ./scripts/restore_recon.sh list         # show available backups
#   ./scripts/restore_recon.sh <archive>    # restore a specific archive
#   ./scripts/restore_recon.sh git          # restore from git tag 'recon-stable'
#
# What it does:
#   1. Backs up CURRENT recon to .recon_backups/pre-restore-<ts>.tar.gz
#      (so if the restore is wrong, you can un-restore)
#   2. Extracts the chosen backup over tools/recon/ + endpoints/recon_*.py
#   3. Reminds you to rebuild backend: ./redeploy.sh backend
#
# This restores ONLY the Recon module. Other modules (vuln, webapp, password,
# mobile etc.) are untouched.

set -e
cd "$(dirname "$0")/.."

C_BLUE='\033[1;34m'; C_GREEN='\033[1;32m'; C_RED='\033[1;31m'; C_YELLOW='\033[1;33m'; C_DIM='\033[2m'; C_RST='\033[0m'
say()  { printf "${C_BLUE}[recon-restore]${C_RST} %s\n" "$1"; }
ok()   { printf "${C_GREEN}${C_RST} %s\n" "$1"; }
err()  { printf "${C_RED}${C_RST} %s\n" "$1"; }
warn() { printf "${C_YELLOW}!${C_RST} %s\n" "$1"; }

BACKUP_DIR=".recon_backups"

# ── list mode ───────────────────────────────────────────────────
if [ "$1" = "list" ]; then
    echo "Available Recon backups:"
    if [ -d "$BACKUP_DIR" ] && [ -n "$(ls -A "$BACKUP_DIR"/recon-*.tar.gz 2>/dev/null)" ]; then
        printf "${C_DIM}%-40s %-10s %s${C_RST}\n" "Archive" "Size" "Files"
        for f in $(ls -t "$BACKUP_DIR"/recon-*.tar.gz 2>/dev/null); do
            size=$(du -h "$f" | cut -f1)
            files=$(tar -tzf "$f" 2>/dev/null | wc -l)
            printf "  %-40s %-10s %s\n" "$(basename $f)" "$size" "$files"
        done
    else
        echo "  (none yet — run ./scripts/backup_recon.sh first)"
    fi
    echo ""
    echo "Recon git tags:"
    git tag -l 'recon-stable*' --sort=-creatordate | head -10 | sed 's/^/  /'
    exit 0
fi

# ── git mode — restore from `recon-stable` tag ──────────────────
if [ "$1" = "git" ]; then
    TARGET_TAG="${2:-recon-stable}"
    if ! git rev-parse "$TARGET_TAG" >/dev/null 2>&1; then
        err "Git tag '$TARGET_TAG' not found"
        echo ""
        echo "Available tags:"
        git tag -l 'recon-stable*' --sort=-creatordate | head -10 | sed 's/^/  /'
        exit 1
    fi
    TARGET_SHA=$(git rev-parse --short "$TARGET_TAG")
    warn "About to restore Recon from git tag '$TARGET_TAG' ($TARGET_SHA)"
    echo "    Files affected: tools/recon/* + endpoints/recon_*.py"
    echo ""
    if [ "${VL_RESTORE_AUTO:-0}" != "1" ]; then
        read -r -p "Proceed? (yes/no): " CONFIRM
        [ "$CONFIRM" != "yes" ] && { echo "Aborted."; exit 0; }
    fi
    # Save pre-restore snapshot first
    ./scripts/backup_recon.sh pre-restore >/dev/null 2>&1 || warn "pre-restore snapshot failed (continuing)"
    say "git: checking out Recon files from $TARGET_TAG..."
    git checkout "$TARGET_TAG" -- tools/recon endpoints/recon_orchestrator.py endpoints/recon_flow.py endpoints/recon_flow_advanced.py endpoints/recon_prime.py 2>/dev/null
    ok "restored Recon files from $TARGET_TAG"
    echo ""
    echo "Next: ./redeploy.sh backend"
    exit 0
fi

# ── archive mode (default: latest, or specific archive) ─────────
if [ -n "$1" ]; then
    # If user passed a path or filename
    if [ -f "$1" ]; then
        ARCHIVE="$1"
    elif [ -f "$BACKUP_DIR/$1" ]; then
        ARCHIVE="$BACKUP_DIR/$1"
    else
        err "Backup '$1' not found"
        echo "  Try: ./scripts/restore_recon.sh list"
        exit 1
    fi
else
    # Default: latest
    ARCHIVE=$(ls -t "$BACKUP_DIR"/recon-*.tar.gz 2>/dev/null | head -1 || true)
    if [ -z "$ARCHIVE" ]; then
        err "No Recon backups found in $BACKUP_DIR"
        echo "  Create one first: ./scripts/backup_recon.sh"
        exit 1
    fi
fi

# Skip pre-restore backups when picking 'latest' default — those are auto-saves
# from previous restores, not real snapshots.
if [ -z "$1" ] && echo "$ARCHIVE" | grep -q "pre-restore"; then
    ARCHIVE=$(ls -t "$BACKUP_DIR"/recon-*.tar.gz 2>/dev/null | grep -v "pre-restore" | head -1 || true)
    [ -z "$ARCHIVE" ] && { err "No non-pre-restore backups found"; exit 1; }
fi

SIZE=$(du -h "$ARCHIVE" | cut -f1)
FILES=$(tar -tzf "$ARCHIVE" | wc -l)

warn "About to restore Recon from:"
echo "    Archive: $ARCHIVE"
echo "    Size   : $SIZE  ($FILES files)"
echo "    Affects: tools/recon/* + endpoints/recon_*.py (other modules untouched)"
echo ""
if [ "${VL_RESTORE_AUTO:-0}" != "1" ]; then
    read -r -p "Proceed? (yes/no): " CONFIRM
    [ "$CONFIRM" != "yes" ] && { echo "Aborted."; exit 0; }
fi

# ── 1. Save current state as pre-restore ────────────────────────
say "saving current Recon as pre-restore snapshot..."
./scripts/backup_recon.sh pre-restore >/dev/null 2>&1 || warn "pre-restore snapshot failed (continuing)"

# ── 2. Extract ──────────────────────────────────────────────────
say "extracting $ARCHIVE..."
tar -xzf "$ARCHIVE" -C .
ok "Recon files restored from $ARCHIVE"

echo ""
echo "  Next steps:"
echo "    1. Rebuild backend     : ./redeploy.sh backend"
echo "    2. Verify scanner count: docker exec vulnuslab_backend python -c \"from main import app; print(sum(1 for r in app.routes if hasattr(r,'path') and r.path.startswith('/api/recon/')))\""
echo "    3. Re-scan to confirm  : scan a known target via dashboard"
echo ""
echo "  Undo this restore:"
echo "    ./scripts/restore_recon.sh \$(ls -t .recon_backups/recon-*-pre-restore.tar.gz | head -1)"
echo ""
