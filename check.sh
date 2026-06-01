#!/usr/bin/env bash
# check.sh — verify deployment is healthy in <10s.
# Run this BEFORE and AFTER any change. If anything fails, don't proceed.
set -u
PASS=0; FAIL=0
t() {
  d="$1"; c="$2"; e="$3"
  if eval "$c" 2>&1 | grep -qE "$e"; then echo "  $d"; PASS=$((PASS+1))
  else echo "  $d"; FAIL=$((FAIL+1)); fi
}
echo "── healthcheck $(date '+%H:%M:%S') ──"
t "yaml parses"        "docker compose config --quiet && echo PARSE_OK"              "PARSE_OK"
t "backend healthy"    "docker inspect --format='{{.State.Health.Status}}' vulnuslab_backend"  "healthy"
t "frontend up"        "docker compose ps frontend"                                "Up"
t "/api/health direct" "curl -sf -m 5 http://localhost:8000/api/health 2>/dev/null || docker exec vulnuslab_backend curl -sf http://localhost:8000/api/health" "ok"
t "/api/health proxy"  "curl -sf -m 5 http://localhost/api/health"                 "ok"
t "/api/auth/login"    "curl -sf -m 10 -X POST http://localhost/api/auth/login -H 'Content-Type: application/json' -d '{\"username\":\"ADMIN\",\"password\":\"VL-cf5330aa\"}'" "access_token"
t "frontend index"     "curl -sI -m 5 http://localhost/"                           "200|301|302"
echo "── $PASS passed, $FAIL failed ──"
[ $FAIL -eq 0 ] && echo "HEALTHY" || echo "NOT HEALTHY — investigate before changing anything"
exit $FAIL
