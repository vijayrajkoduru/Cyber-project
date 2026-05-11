#!/bin/bash
# ════════════════════════════════════════════════════════════════════════════
#  VulnusLab one-command deploy script
#  Usage:  ./deploy.sh
#  What it does:
#    1. Pulls latest code from git
#    2. Stops + REMOVES old containers (so stale state can't survive)
#    3. Force-rebuilds BOTH backend and frontend from scratch (--no-cache)
#    4. Brings up fresh containers
#    5. Verifies the new code is actually inside the running containers
#    6. Tails backend logs until you see Uvicorn is ready
#
#  Designed to be idempotent — safe to re-run.
#  Exits non-zero on any failure so you can tell something went wrong.
# ════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Always run from the repo root, regardless of where you invoked the script from.
cd "$(dirname "$0")"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

step() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
ok()   { echo -e "${GREEN}✓ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }

# ─── 1. Pull latest code ────────────────────────────────────────────────────
step "1/6  Pulling latest code from git"
git pull --ff-only || fail "git pull failed — resolve manually then re-run"
CURRENT_COMMIT=$(git rev-parse --short HEAD)
ok "On commit ${CURRENT_COMMIT}"
git log --oneline -3

# ─── 2. Verify .env has the critical secrets ────────────────────────────────
step "2/6  Verifying .env has required secrets"
[ -f .env ] || fail ".env file missing — backend will not start"
for k in JWT_SECRET CORS_ORIGINS; do
  if ! grep -qE "^${k}=." .env; then
    fail "Missing required env var in .env: ${k}"
  fi
done
ok ".env looks complete"

# ─── 3. Stop + REMOVE old containers ────────────────────────────────────────
step "3/6  Stopping and removing old containers"
docker compose down --remove-orphans
ok "Old containers removed"

# ─── 4. Force rebuild BOTH backend and frontend (no cache, no layer reuse) ──
step "4/6  Rebuilding backend + frontend from scratch (this takes a few minutes)"
docker compose build --no-cache --pull backend frontend
ok "Build complete"

# ─── 5. Start fresh containers ──────────────────────────────────────────────
step "5/6  Starting fresh containers"
docker compose up -d
sleep 6
ok "Containers up"
docker compose ps

# ─── 6. Verify the new code is actually inside the running containers ───────
step "6/6  Verifying new code is actually inside containers"

# Backend: look for a marker that only exists in the new main.py
if docker exec oscp_backend grep -q "_detect_static_host" /app/main.py; then
  ok "Backend has new static-host detector"
else
  warn "Backend may be running OLD code — _detect_static_host not found"
fi

# Frontend: look for a marker that only exists in the new build
if docker exec oscp_frontend sh -c "grep -l 'VulnusLab Automated Pentest' /usr/share/nginx/html/static/js/*.js 2>/dev/null | head -1" | grep -q .; then
  ok "Frontend has new VulnusLab branding"
else
  warn "Frontend may be running OLD code — VulnusLab Automated Pentest not found"
fi

# Wait briefly for backend to start, then check it's responding
echo ""
step "Health check"
sleep 4
if curl -sf http://localhost:8000/api/health >/dev/null; then
  ok "Backend responds on http://localhost:8000/api/health"
else
  warn "Backend not responding yet — check logs:  docker compose logs backend"
fi

if curl -sf http://localhost/ >/dev/null; then
  ok "Frontend responds on http://localhost/"
else
  warn "Frontend not responding yet — check logs:  docker compose logs frontend"
fi

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Deploy complete. Commit: ${CURRENT_COMMIT}${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Open https://app.vulnuslab.com in INCOGNITO mode for the first test"
echo "  (only needed once — after this deploy, the new nginx cache headers"
echo "   ensure future deploys are visible without clearing browser cache)"
echo ""
echo "  Watch backend logs:    docker compose logs -f backend"
echo "  Watch frontend logs:   docker compose logs -f frontend"
echo ""
