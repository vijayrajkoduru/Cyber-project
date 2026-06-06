#!/usr/bin/env bash
# safety_snapshot.sh — capture a known-good restore point.
# Runs automatically from redeploy.sh BEFORE every deploy, but can also be
# invoked manually after a successful scan to lock in the current state.
#
# What it captures:
#   1. git tag       — `stable-YYYYMMDD-HHMMSS` on current HEAD
#   2. docker images — re-tag :latest -> :stable + :stable-<ts>
#   3. snapshot log  — appends a one-liner to .safety/snapshots.log
#
# Idempotent: safe to run multiple times in a row.
# Non-destructive: ONLY adds tags. Never deletes anything.

set -e
cd "$(dirname "$0")/.."

SNAP_DIR=".safety"
SNAP_LOG="$SNAP_DIR/snapshots.log"
mkdir -p "$SNAP_DIR"

TS=$(date +%Y%m%d-%H%M%S)
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "no-git")
GIT_TAG="stable-$TS"

# ─── 1. Git tag the current HEAD ─────────────────────────────────
# Move the floating `stable` tag to current HEAD, AND create a dated tag
# so we keep a history of every snapshot (in case 'stable' moves and we
# need to go further back).
if git rev-parse HEAD >/dev/null 2>&1; then
    git tag -f stable >/dev/null 2>&1 || true
    git tag "$GIT_TAG" >/dev/null 2>&1 || true
    echo "  [snap] git: HEAD ($GIT_SHA) tagged as 'stable' + '$GIT_TAG'"
else
    echo "  [snap] git: skipped (not a git repo or no HEAD)"
fi

# ─── 2. Docker image snapshots ────────────────────────────────────
# Only snapshot if Docker daemon reachable + image exists. The :stable
# tag is what rollback.sh restores to. The dated tag is rotated history.
snap_image() {
    local image="$1"
    if docker image inspect "$image:latest" >/dev/null 2>&1; then
        docker tag "$image:latest" "$image:stable"
        docker tag "$image:latest" "$image:stable-$TS"
        echo "  [snap] docker: $image:latest -> $image:stable + :stable-$TS"
    else
        echo "  [snap] docker: $image:latest not found (skipping)"
    fi
}

if docker info >/dev/null 2>&1; then
    snap_image "cyber-project-backend"
    snap_image "cyber-project-frontend"
    # Prune old dated snapshots — keep the last 5 only so we don't fill disk.
    for img in cyber-project-backend cyber-project-frontend; do
        docker images --format '{{.Repository}}:{{.Tag}}' \
            | grep -E "^${img}:stable-[0-9]" \
            | sort -r \
            | tail -n +6 \
            | xargs -r -n1 docker rmi >/dev/null 2>&1 || true
    done
else
    echo "  [snap] docker: daemon not reachable (skipping image snapshot)"
fi

# ─── 3. Append to snapshot log ────────────────────────────────────
{
    echo "$TS  git=$GIT_SHA  tag=$GIT_TAG  msg=$(git log -1 --pretty=%s 2>/dev/null || echo unknown)"
} >> "$SNAP_LOG"

# Keep last 50 log entries
if [ -f "$SNAP_LOG" ]; then
    tail -n 50 "$SNAP_LOG" > "$SNAP_LOG.tmp" && mv "$SNAP_LOG.tmp" "$SNAP_LOG"
fi

echo "  [snap] saved restore point: $TS (use './rollback.sh' to restore)"
