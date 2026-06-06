#!/usr/bin/env bash
# rollback.sh — restore the last known-good state.
#
# Usage:
#   ./rollback.sh            # restore last snapshot (the 'stable' tag)
#   ./rollback.sh list       # show available snapshots
#   ./rollback.sh <tag>      # restore a specific snapshot (e.g. stable-20260606-143012)
#   ./rollback.sh code-only  # restore git only (no docker rebuild)
#
# What it does:
#   1. git reset --hard <tag>      → code returns to that point
#   2. docker tag :stable :latest  → containers restart on saved image
#   3. docker compose up -d        → live in ~10 seconds
#   4. health check                → confirm restore worked
#
# This is your panic button. If something breaks badly, run it.

set -e
cd "$(dirname "$0")"

C_BLUE='\033[1;34m'; C_GREEN='\033[1;32m'; C_RED='\033[1;31m'; C_YELLOW='\033[1;33m'; C_DIM='\033[2m'; C_RST='\033[0m'
say()  { printf "${C_BLUE}[rollback]${C_RST} %s\n" "$1"; }
ok()   { printf "${C_GREEN}${C_RST} %s\n" "$1"; }
err()  { printf "${C_RED}${C_RST} %s\n" "$1"; }
warn() { printf "${C_YELLOW}!${C_RST} %s\n" "$1"; }

SNAP_DIR=".safety"
SNAP_LOG="$SNAP_DIR/snapshots.log"

# ─── list mode ────────────────────────────────────────────────────
if [ "$1" = "list" ]; then
    echo "Available snapshots:"
    if [ -f "$SNAP_LOG" ]; then
        printf "${C_DIM}%-20s %-12s %s${C_RST}\n" "Timestamp" "Git SHA" "Commit"
        tac "$SNAP_LOG" | head -20 | while IFS= read -r line; do
            ts=$(echo "$line"   | awk '{print $1}')
            sha=$(echo "$line"  | grep -oE 'git=[a-f0-9]+'    | cut -d= -f2)
            msg=$(echo "$line"  | sed 's/.*msg=//')
            printf "  %-20s %-12s %s\n" "$ts" "$sha" "$msg"
        done
    else
        echo "  (no snapshots taken yet)"
    fi
    echo ""
    echo "Git tags:"
    git tag -l 'stable*' --sort=-creatordate | head -10 | sed 's/^/  /'
    exit 0
fi

# ─── pick the target tag ─────────────────────────────────────────
TARGET="${1:-stable}"
CODE_ONLY=0
[ "$1" = "code-only" ] && { TARGET="stable"; CODE_ONLY=1; }

if ! git rev-parse "$TARGET" >/dev/null 2>&1; then
    err "Snapshot tag '$TARGET' not found"
    echo ""
    echo "Available snapshots:"
    git tag -l 'stable*' --sort=-creatordate | head -10 | sed 's/^/  /'
    exit 1
fi

TARGET_SHA=$(git rev-parse --short "$TARGET")
CURRENT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

# ─── confirm ──────────────────────────────────────────────────────
echo ""
warn "About to ROLLBACK:"
echo "    Current HEAD : $CURRENT_SHA  ($(git log -1 --pretty=%s 2>/dev/null))"
echo "    Restore to   : $TARGET_SHA  ($(git log -1 --pretty=%s "$TARGET" 2>/dev/null)) [tag: $TARGET]"
echo ""

# Auto-confirm when invoked from redeploy.sh (env var set), otherwise prompt.
if [ "${VL_ROLLBACK_AUTO:-0}" != "1" ]; then
    read -r -p "Proceed with rollback? (yes/no): " CONFIRM
    if [ "$CONFIRM" != "yes" ]; then
        echo "Aborted."
        exit 0
    fi
fi

# ─── 1. Save current state as 'pre-rollback' so user can UN-rollback ─
PRE_TAG="pre-rollback-$(date +%Y%m%d-%H%M%S)"
git tag "$PRE_TAG" "$CURRENT_SHA" 2>/dev/null || true
ok "saved current state as tag '$PRE_TAG' (use './rollback.sh $PRE_TAG' to undo)"

# ─── 2. Git reset ────────────────────────────────────────────────
say "git: resetting code to $TARGET_SHA..."
# Stash any uncommitted edits so they don't block the reset.
git stash push -u -m "rollback-stash-$(date +%s)" >/dev/null 2>&1 || true
git reset --hard "$TARGET" >/dev/null
ok "code restored to $TARGET_SHA"

# ─── 3. Docker image restore (skip if --code-only) ──────────────
if [ "$CODE_ONLY" = "1" ]; then
    say "skipping docker rebuild (code-only mode)"
    echo ""
    ok "ROLLBACK COMPLETE (code-only)"
    echo "    Run './redeploy.sh all' if you also need a rebuild."
    exit 0
fi

if ! docker info >/dev/null 2>&1; then
    warn "docker not available — code rolled back, containers NOT restored"
    exit 0
fi

restore_image() {
    local image="$1"
    if docker image inspect "$image:stable" >/dev/null 2>&1; then
        docker tag "$image:stable" "$image:latest"
        ok "$image: restored from :stable -> :latest"
    else
        warn "$image:stable not found — will rebuild from rolled-back code"
        return 1
    fi
}

say "docker: restoring images from :stable tags..."
RESTORE_OK=1
restore_image vulnuslab_backend  || RESTORE_OK=0
restore_image vulnuslab_frontend || RESTORE_OK=0

say "docker: restarting containers..."
docker compose up -d >/dev/null 2>&1 || {
    err "docker compose up failed — investigate manually"
    exit 1
}

# ─── 4. Health verify ────────────────────────────────────────────
say "health: waiting for backend (max 60s)..."
HEALTH_OK=0
for i in $(seq 1 30); do
    if curl -fsS http://localhost:8000/api/health >/dev/null 2>&1; then
        HEALTH_OK=1
        break
    fi
    sleep 2
done

echo ""
if [ "$HEALTH_OK" = "1" ]; then
    ok "ROLLBACK COMPLETE — backend healthy on $TARGET_SHA"
else
    err "ROLLBACK partially complete — backend NOT healthy after restore"
    echo "    Check logs: docker logs vulnuslab_backend --tail 50"
fi
echo ""
echo "  Undo this rollback (if needed):  ./rollback.sh $PRE_TAG"
echo "  Snapshot history:                 ./rollback.sh list"
