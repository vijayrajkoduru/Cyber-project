#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
echo "═══ FULL REVERT (login + backend + db + nginx) ═══"

docker compose stop frontend backend 2>/dev/null

# Restore images
docker tag cyber-project-backend:kali-backend-good      cyber-project-backend:latest 2>/dev/null
docker tag cyber-project-frontend:dashboard-login-good  cyber-project-frontend:latest 2>/dev/null

# Restore git source
if [ -f .safe-fallback-commit ]; then
  COMMIT=$(cat .safe-fallback-commit)
  git stash push -m "auto-stash-$(date +%s)" 2>/dev/null
  git checkout "$COMMIT" -- . 2>/dev/null
  echo "✓ source reverted to $COMMIT"
fi

# Restore users.db
if [ -f .login_backups/users.db.good ]; then
  cp .login_backups/users.db.good users.db 2>/dev/null
  cp .login_backups/users.db.good data/users.db 2>/dev/null
  echo "✓ users.db restored"
fi

# Restore nginx
if [ -f .login_backups/nginx.conf.good ]; then
  cp .login_backups/nginx.conf.good nginx.conf
  echo "✓ nginx.conf restored"
fi

docker compose up -d backend
sleep 90
if docker exec vulnuslab_backend curl -fsS http://localhost:8000/api/health >/dev/null 2>&1; then
  echo "✓ Kali backend ONLINE"
  docker compose up -d frontend
  sleep 10
  echo "✓ Dashboard login restored"
  docker compose ps
else
  echo "✗ Revert failed"
  docker logs vulnuslab_backend --tail 20
fi
