#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
if ! docker exec vulnuslab_backend curl -fsS http://localhost:8000/api/health >/dev/null 2>&1; then
  echo "Cannot snapshot — backend is currently unhealthy. Fix first."
  exit 1
fi
docker tag cyber-project-backend:latest  cyber-project-backend:kali-backend-good
docker tag cyber-project-backend:latest  cyber-project-backend:dashboard-login-good
docker tag cyber-project-frontend:latest cyber-project-frontend:dashboard-login-good
git rev-parse HEAD > .safe-fallback-commit
echo "Snapshotted current healthy state"
echo "commit: $(cat .safe-fallback-commit)"
echo "If anything breaks next: ./revert-to-good.sh"
