#!/usr/bin/env bash
# VL-FOUNDRY Layer 23 — Deployment + Verification.
#
# One command wraps the 5-phase deploy sequence + logs the result.
# Designed to run ON THE VPS, not locally.
#
# Usage:
#   ./scripts/deploy.sh <module>
#   VL_TOKEN='...' ./scripts/deploy.sh osint   # full auth'd verification
#
# Exits non-zero on any gate failure. Logs to /var/log/vl-foundry-deploys.log
# if writable; otherwise to ./vl-foundry-deploys.log in repo root.

set -u
MODULE="${1:?usage: deploy.sh <module>}"
LOG_PATH="/var/log/vl-foundry-deploys.log"
[ -w "$(dirname $LOG_PATH)" ] || LOG_PATH="./vl-foundry-deploys.log"

log() {
  local stamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "[$stamp] $*" | tee -a "$LOG_PATH"
}

fail() {
  log "FAIL gate=$1 module=$MODULE commit=$(git rev-parse --short HEAD 2>/dev/null || echo '?')"
  echo ""
  echo "  Deployment aborted at gate $1."
  echo "  Rollback:"
  echo "    git reset --hard HEAD~1"
  echo "    git push --force-with-lease origin main"
  echo "    docker compose build --no-cache backend frontend && docker compose up -d"
  exit 1
}

echo "═══════════════════════════════════════════════════════════════"
echo "  VL-FOUNDRY Layer 23 deploy — module: $MODULE"
echo "  Log: $LOG_PATH"
echo "═══════════════════════════════════════════════════════════════"
log "START module=$MODULE pwd=$(pwd)"

# ─── Phase 1 — Pull ───────────────────────────────────────────
echo ""
echo "  [1/5] git pull ..."
PULL_OUTPUT=$(git pull 2>&1) || fail "git_pull"
COMMIT=$(git rev-parse --short HEAD)
echo "$PULL_OUTPUT" | tail -3
log "PHASE1 git_pull commit=$COMMIT ok"

# ─── Phase 2 — Install pre-commit hook (idempotent) ───────────
echo ""
echo "  [2/5] python scripts/install_hooks.py ..."
python scripts/install_hooks.py 2>&1 | tail -3 || fail "install_hooks"
log "PHASE2 install_hooks ok"

# ─── Phase 3 — Rebuild Docker ─────────────────────────────────
echo ""
echo "  [3/5] docker compose build --no-cache backend frontend ..."
BUILD_START=$(date +%s)
docker compose build --no-cache backend frontend 2>&1 | tail -10 || fail "docker_build"
BUILD_DUR=$(( $(date +%s) - BUILD_START ))
log "PHASE3 docker_build duration=${BUILD_DUR}s ok"

echo ""
echo "  [3.5/5] docker compose up -d ..."
docker compose up -d 2>&1 | tail -10 || fail "docker_up"
# Give the backend healthcheck a few seconds to register
sleep 5
log "PHASE3.5 docker_up ok"

# ─── Phase 4 — Public smoke test (no token) ──────────────────
echo ""
echo "  [4/5] ./scripts/smoke_test.sh $MODULE  (public probes) ..."
./scripts/smoke_test.sh "$MODULE" || fail "smoke_public"
log "PHASE4 smoke_public ok"

# ─── Phase 5 — Authenticated smoke test ──────────────────────
if [ -z "${VL_TOKEN:-}" ]; then
  echo ""
  echo "  [5/5] Auth'd smoke test SKIPPED — VL_TOKEN not set"
  echo ""
  echo "  To do full verification:"
  echo "    export VL_TOKEN='<from browser localStorage.cyberToken>'"
  echo "    ./scripts/deploy.sh $MODULE"
  log "PHASE5 smoke_authed SKIPPED no_token"
  echo ""
  echo "   PARTIAL DEPLOY — gates 1-4 green, gate 5 skipped"
  exit 0
fi

echo ""
echo "  [5/5] ./scripts/smoke_test.sh $MODULE  (with token) ..."
./scripts/smoke_test.sh "$MODULE" || fail "smoke_authed"
log "PHASE5 smoke_authed ok"

# ─── Done ─────────────────────────────────────────────────────
echo ""
echo "───────────────────────────────────────────────────────────────"
echo "  DEPLOY SUCCESSFUL — $MODULE on commit $COMMIT"
echo "  Backend live at: $(docker compose port backend 8000 2>/dev/null || echo 'localhost:8000')"
echo "  Frontend live at: https://app.vulnuslab.com"
echo "═══════════════════════════════════════════════════════════════"
log "DONE module=$MODULE commit=$COMMIT all_green"
