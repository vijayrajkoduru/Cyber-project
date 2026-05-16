#!/bin/bash
# Nightly VAULT sync — invoked by cron at 03:00 UTC.
set -euo pipefail
PROJECT_DIR="/root/Cyber-project"
echo ""
echo "=== VAULT nightly sync @ $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
cd "${PROJECT_DIR}"
docker compose exec -T backend python3 -c "
from tools._core.vault import nightly_sync
r = nightly_sync()
print(f'users:  {len(r[\"users\"])}')
print(f'tools:  {len(r[\"tools\"])}')
print(f'db:     {r[\"db\"] is not None}')
print(f'errors: {len(r[\"errors\"])}')
"
echo "=== done @ $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
