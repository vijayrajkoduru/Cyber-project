#!/usr/bin/env bash
# check.sh — verify deployment is healthy in <10s.
# Run this BEFORE and AFTER any change. If anything fails, don't proceed.
#
# Setup (once): add the current ADMIN password to the git-ignored .env file:
#   VL_ADMIN_PASSWORD=your-admin-password
# or export it for one run:  VL_ADMIN_PASSWORD='...' ./check.sh
# Update it whenever the ADMIN password changes.
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
# Login smoke test. The ADMIN password is NEVER stored in the repo: it comes from
# the VL_ADMIN_PASSWORD environment variable, or from VL_ADMIN_PASSWORD=... in the
# git-ignored .env next to this script. .env is read as plain text (never
# `source`d) and the password is piped to curl on stdin, so it never appears in a
# command line / `ps` output. Unset -> the check is SKIPPED (not failed).
SKIP=0
login_check() {
  local pw="${VL_ADMIN_PASSWORD:-}"
  if [ -z "$pw" ] && [ -f "$(dirname "$0")/.env" ]; then
    pw=$(grep -m1 -E '^[[:space:]]*VL_ADMIN_PASSWORD=' "$(dirname "$0")/.env" | cut -d= -f2- \
         | sed -E 's/^[[:space:]]+|[[:space:]]+$//g; s/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/')
  fi
  if [ -z "$pw" ]; then
    echo "  /api/auth/login  SKIPPED — set VL_ADMIN_PASSWORD in .env (see check.sh header)"
    SKIP=$((SKIP+1)); return
  fi
  local code
  code=$(VL_USER="${VL_ADMIN_USER:-koduru}" VL_PW="$pw" python3 -c 'import json,os,sys; sys.stdout.write(json.dumps({"username":os.environ["VL_USER"],"password":os.environ["VL_PW"]}))' \
         | curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST http://localhost/api/auth/login \
                -H 'Content-Type: application/json' --data-binary @-)
  if [ "$code" = "200" ]; then echo "  /api/auth/login"; PASS=$((PASS+1))
  else echo "  /api/auth/login  (HTTP $code — wrong VL_ADMIN_PASSWORD?)"; FAIL=$((FAIL+1)); fi
}
login_check
t "frontend index"     "curl -sI -m 5 http://localhost/"                           "200|301|302"
SKIPMSG=""; [ "$SKIP" -gt 0 ] && SKIPMSG=", $SKIP skipped"
echo "── $PASS passed, $FAIL failed$SKIPMSG ──"
[ $FAIL -eq 0 ] && echo "HEALTHY" || echo "NOT HEALTHY — investigate before changing anything"
exit $FAIL
