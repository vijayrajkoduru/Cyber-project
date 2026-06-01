#!/usr/bin/env bash
set -euo pipefail
echo "=== 1. Stop frontend ==="
docker compose stop frontend || true
echo "=== 2. Force-remove frontend image ==="
docker image rm cyber-project-frontend cyber-project-frontend:latest 2>/dev/null || true
echo "=== 3. Prune ALL build cache ==="
docker builder prune -af
docker buildx prune -af 2>/dev/null || true
echo "=== 4. Bust webpack contenthash ==="
TS=$(date +%s)
echo "export const CACHE_BUSTER = \"$TS\";" > src/.cache-buster.js
echo "    bust token: $TS"
echo "=== 5. Rebuild without BuildKit, no cache, with pull ==="
DOCKER_BUILDKIT=0 docker compose build --no-cache --pull frontend
echo "=== 6. Restart frontend ==="
docker compose up -d frontend
sleep 10
echo "=== 7. Verify f.detail in bundle ==="
HITS=$(docker exec cyber_project_frontend sh -c 'grep -o "f\.detail" /usr/share/nginx/html/static/js/main.*.js 2>/dev/null | wc -l' || echo 0)
if [ "$HITS" -gt 0 ]; then
    echo "PASS — bundle contains f.detail ($HITS occurrences)"
else
    echo "FAIL — bundle has 0 f.detail occurrences"
    exit 1
fi
docker exec cyber_project_frontend sh -c 'ls /usr/share/nginx/html/static/js/main.*.js'
echo "Done. Hard-refresh browser (Ctrl-Shift-R)."
