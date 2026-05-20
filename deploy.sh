#!/usr/bin/env bash
# deploy.sh [frontend|backend|nginx|all]
# Safely deploys with auto-rollback if smoke test fails.
set -u
WHAT="${1:-all}"
SNAPSHOT=$(git stash create 2>/dev/null || echo "")
HEAD=$(git rev-parse HEAD)

echo "── pre-flight check ──"
./check.sh || { echo "Refusing to deploy: system is not healthy NOW. Fix first."; exit 1; }

echo ""
echo "── deploying [$WHAT] ──"
case "$WHAT" in
  nginx)
    docker exec vulnuslab_frontend nginx -t || { echo "nginx config broken — abort"; exit 2; }
    docker exec vulnuslab_frontend nginx -s reload
    ;;
  backend)
    docker compose restart backend
    ;;
  frontend)
    docker compose up -d --build --force-recreate frontend
    ;;
  all)
    docker compose up -d --build
    ;;
  *)
    echo "usage: $0 [frontend|backend|nginx|all]"; exit 1
    ;;
esac

echo ""
echo "── post-flight check (waiting 12s for stabilization) ──"
sleep 12
if ./check.sh; then
  echo "✓ Deploy successful — committing if changes present"
  git add -A && git commit -m "deploy: $WHAT ($(date '+%Y-%m-%d %H:%M'))" 2>&1 | tail -1
else
  echo ""
  echo "✗ Deploy BROKE the system — rolling back to $HEAD"
  git reset --hard "$HEAD"
  [ -n "$SNAPSHOT" ] && git stash apply "$SNAPSHOT" 2>/dev/null
  docker compose up -d --build
  sleep 8
  ./check.sh
fi
