#!/bin/bash
# Start / stop the throwaway Postgres the backend test suite needs.
#
# tests/conftest.py defaults DATABASE_URL to localhost:55432, so pytest needs
# a Postgres there. This wraps docker-compose.test.yml.
#
#   scripts/test-db.sh up     # start the test DB and wait until it's ready
#   scripts/test-db.sh down   # stop and remove it
#   scripts/test-db.sh        # (no arg) same as `up`
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE_FILE="docker-compose.test.yml"

case "${1:-up}" in
  up)
    docker compose -f "$COMPOSE_FILE" up -d --wait
    echo "Test Postgres ready on localhost:55432 — run: pytest"
    ;;
  down)
    docker compose -f "$COMPOSE_FILE" down
    ;;
  *)
    echo "usage: $0 [up|down]" >&2
    exit 2
    ;;
esac
