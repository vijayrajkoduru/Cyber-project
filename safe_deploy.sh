#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
ACTION="${1:-b}"
G='\033[1;32m'; R='\033[1;31m'; X='\033[0m'
snapshot() { docker tag cyber-project-$1:latest cyber-project-$1:last-good 2>/dev/null; }
revert()   { docker tag cyber-project-$1:last-good cyber-project-$1:latest 2>/dev/null; docker compose up -d $1; }
wait_healthy() {
  for i in $(seq 1 45); do
    curl -fsS http://localhost:8000/api/health >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
deploy() {
  snapshot "$1"
  docker compose build "$1"
  docker compose up -d "$1"
  if [ "$1" = "backend" ]; then
    wait_healthy && { printf "${G}✓ deployed${X}\n"; return; } || { printf "${R}✗ reverting${X}\n"; revert "$1"; wait_healthy; return 1; }
  else
    sleep 10
    docker ps | grep -q "vulnuslab_$1.*Up" && printf "${G}✓ deployed${X}\n" || { printf "${R}✗ reverting${X}\n"; revert "$1"; }
  fi
}
case "$ACTION" in
  b|backend) deploy backend ;;
  f|frontend) deploy frontend ;;
  all) deploy backend && deploy frontend ;;
esac
docker compose ps
