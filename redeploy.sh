#!/usr/bin/env bash
# VulnusLab — single command after any edit.
# Usage:  ./redeploy.sh [frontend|backend|nginx|all|verify]
#         ./redeploy.sh                    # smart auto-detect (uses git diff)
#
# SAFETY NET (2026-06-06):
#   Every deploy auto-snapshots state BEFORE touching anything. If the
#   backend fails its health check after rebuild, we AUTO-ROLLBACK to the
#   last known-good docker image. You won't end up stuck with a dead site.
#
#   Override the safety net:  VL_SAFETY_OFF=1 ./redeploy.sh
#   Manual restore anytime:   ./rollback.sh
set -e
cd "$(dirname "$0")"

C_BLUE='\033[1;34m'; C_GREEN='\033[1;32m'; C_RED='\033[1;31m'; C_YELLOW='\033[1;33m'; C_DIM='\033[2m'; C_RST='\033[0m'
say() { printf "${C_BLUE}[%s]${C_RST} %s\n" "$1" "$2"; }
ok()  { printf "${C_GREEN}${C_RST} %s\n" "$1"; }
err() { printf "${C_RED}${C_RST} %s\n" "$1"; }
warn(){ printf "${C_YELLOW}!${C_RST} %s\n" "$1"; }

# ─── Pre-deploy safety snapshot ───────────────────────────────────
# Locks in the current state as the rollback target. Runs ONCE per
# redeploy invocation, before any rebuild. Skips on `verify` (no-op).
SAFETY_DONE=0
safety_snapshot_once() {
  [ "$SAFETY_DONE" = "1" ] && return 0
  [ "${VL_SAFETY_OFF:-0}" = "1" ] && { warn "safety net disabled by VL_SAFETY_OFF=1"; SAFETY_DONE=1; return 0; }
  if [ -x scripts/safety_snapshot.sh ]; then
    say safety "snapshotting current state as restore point..."
    scripts/safety_snapshot.sh || warn "snapshot failed (deploy continues, but rollback may not work)"
  fi
  SAFETY_DONE=1
}

# ─── Auto-rollback on failed health ───────────────────────────────
# Called when backend doesn't become healthy after rebuild. Restores
# the previous :stable docker image + restarts containers. No git reset
# because the user might want to inspect the failing code.
auto_rollback_backend() {
  [ "${VL_SAFETY_OFF:-0}" = "1" ] && { err "safety net OFF — leaving backend in failed state"; return 1; }
  warn "AUTO-ROLLBACK: backend unhealthy, restoring previous :stable image..."
  if ! docker image inspect cyber-project-backend:stable >/dev/null 2>&1; then
    err "no cyber-project-backend:stable image exists — first deploy or snapshot missing. Run: docker compose up -d (manual recovery)"
    return 1
  fi
  docker tag cyber-project-backend:stable cyber-project-backend:latest
  docker compose up -d backend >/dev/null 2>&1
  for i in $(seq 1 30); do
    if curl -fsS http://localhost:8000/api/health >/dev/null 2>&1; then
      ok "ROLLED BACK: backend healthy again on previous image"
      warn "Your new code is still on disk — check logs to fix, then re-run ./redeploy.sh"
      return 0
    fi
    sleep 2
  done
  err "AUTO-ROLLBACK FAILED: even previous image not healthy. Manual intervention required."
  return 1
}

build_frontend() {
  safety_snapshot_once
  say frontend "preflight syntax check..."
  ./preflight.sh || return 1
  say frontend "building React bundle (~30s)..."
  docker compose build frontend
  docker compose up -d frontend
  sleep 2
  local hash=$(docker exec vulnuslab_frontend grep -oE 'main\.[a-f0-9]+\.js' /usr/share/nginx/html/index.html | head -1)
  ok "frontend live: $hash"
}

build_backend() {
  safety_snapshot_once
  say backend "rebuilding Python image (~60s)..."
  docker compose build backend
  docker compose up -d backend
  say backend "waiting for health..."
  for i in $(seq 1 30); do
    curl -fsS http://localhost:8000/api/health >/dev/null 2>&1 && { ok "backend healthy"; return; }
    sleep 2
  done
  err "backend did not become healthy in 60s — check: docker logs vulnuslab_backend --tail 50"
  auto_rollback_backend || true
  return 1
}

reload_nginx() {
  say nginx "validating + reloading config..."
  docker exec vulnuslab_frontend nginx -t
  docker exec vulnuslab_frontend nginx -s reload
  ok "nginx reloaded"
}

verify() {
  printf "\n${C_BLUE}═══ VERIFICATION ═══${C_RST}\n"
  local c_hash p_hash
  c_hash=$(docker exec vulnuslab_frontend grep -oE 'main\.[a-f0-9]+\.js' /usr/share/nginx/html/index.html 2>/dev/null | head -1)
  p_hash=$(curl -sS "https://app.vulnuslab.com/?cb=$(date +%s)" 2>/dev/null | grep -oE 'main\.[a-f0-9]+\.js' | head -1)
  echo "  Frontend bundle:"
  echo "    container : $c_hash"
  echo "    public URL: $p_hash"
  [ "$c_hash" = "$p_hash" ] && ok "frontend in sync" || err "frontend OUT OF SYNC — check nginx + cache"

  # ── Content-marker check (cache-bust catch) ──────────────────
  # Hash-match alone can fool you when the index.html points at a
  # main.HASH.js bundle that was rebuilt but somehow lost a feature
  # mid-merge. Grep for expected strings inside the served bundle so
  # we catch silent regressions loud.
  echo ""
  echo "  Bundle content markers (PDF v4 + UI options form):"
  local markers=("INSUFFICIENT SCAN" "PARTIAL SCAN" "BASELINE SCAN")
  local marker_fail=0
  for m in "${markers[@]}"; do
    local hits
    hits=$(docker exec vulnuslab_frontend sh -c "grep -lF '$m' /usr/share/nginx/html/static/js/*.js 2>/dev/null | wc -l")
    if [ "$hits" -gt 0 ]; then
      ok "  marker '$m' present"
    else
      err "  marker '$m' MISSING — bundle is stale, rebuild without cache"
      marker_fail=1
    fi
  done
  if [ "$marker_fail" -gt 0 ]; then
    echo -e "${C_DIM}    Fix: docker compose build --no-cache frontend && docker compose up -d frontend${C_RST}"
  fi

  echo ""
  echo "  Backend:"
  if curl -fsS http://localhost:8000/api/health >/dev/null 2>&1; then ok "health OK"; else err "health FAILED"; fi

  echo ""
  echo "  Endpoints registered:"
  docker exec vulnuslab_backend python -c "
from main import app
def n(pfx): return sum(1 for r in app.routes if hasattr(r,'path') and r.path.startswith(pfx))
print(f'    /api/recon/*  : {n(\"/api/recon/\")}')
print(f'    /api/vuln/*   : {n(\"/api/vuln/\")}')
print(f'    /api/webapp/* : {n(\"/api/webapp/\")}')
print(f'    /api/mobile_* : {n(\"/api/mobile_\")}')
" 2>&1 | sed 's/^/  /'

  echo ""
  echo "  Containers:"
  docker compose ps --format "table {{.Service}}\t{{.Status}}" 2>/dev/null | head -10 | sed 's/^/    /'
  echo ""
  echo -e "${C_DIM}  → After any rebuild, hard-refresh browser: Ctrl+Shift+R (or Incognito)${C_RST}"
}

auto_detect() {
  local changed
  changed=$(git diff --name-only HEAD 2>/dev/null; git status --porcelain 2>/dev/null | awk '{print $2}')
  local fe=$(echo "$changed" | grep -E "^(src/|public/|package|Dockerfile\.frontend|nginx\.conf|extra_nginx_conf/)" | head -1)
  local be=$(echo "$changed" | grep -E "^(main\.py|tools/[^_]|endpoints/|profiles/|requirements|Dockerfile$)" | head -1)
  local ng=$(echo "$changed" | grep -E "^(nginx\.conf|extra_nginx_conf/)" | head -1)
  [ -n "$be" ] && { say auto "backend code changed → rebuild"; build_backend; }
  [ -n "$fe" ] && { say auto "frontend code changed → rebuild"; build_frontend; }
  [ -n "$ng" ] && [ -z "$fe" ] && { say auto "nginx config changed → reload"; reload_nginx; }
  [ -z "$be" ] && [ -z "$fe" ] && say auto "no tracked changes detected (use 'all' to force full rebuild)"
}

case "${1:-auto}" in
  frontend|fe|f) build_frontend ;;
  backend|be|b)  build_backend ;;
  nginx|n)       reload_nginx ;;
  all|a)         build_backend; build_frontend ;;
  verify|v)      ;;
  auto)          auto_detect ;;
  *) echo "Usage: $0 [frontend|backend|nginx|all|verify|auto]"; exit 1 ;;
esac

verify
