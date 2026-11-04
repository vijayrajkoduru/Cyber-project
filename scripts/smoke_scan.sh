#!/usr/bin/env bash
# smoke_scan.sh -- post-deploy behavioral smoke of the SCAN path, not just
# /api/health. Catches a scan endpoint that boots fine but 500s on use
# (exactly the _resolve_underscore failure). Exits non-zero on any failure
# so safe_deploy can auto-revert.
#
# Credentials come from the environment -- NEVER hardcode them here:
#   SMOKE_USER / SMOKE_PASS   smoke account (read from .env or ops secret)
#   SMOKE_BASE                default http://localhost:8000
#   SMOKE_LAB                 default http://lab_dvwa
# If SMOKE_PASS is unset the script auto-loads VL_SMOKE_USER/VL_SMOKE_PASS
# from ./.env when present, else skips with a clear notice (non-fatal).
set -u
BASE="${SMOKE_BASE:-http://localhost:8000}"
LAB="${SMOKE_LAB:-http://lab_dvwa}"
U="${SMOKE_USER:-${VL_SMOKE_USER:-}}"
P="${SMOKE_PASS:-${VL_SMOKE_PASS:-}}"
if [ -z "$P" ] && [ -f ./.env ]; then
    U="${U:-$(sed -n 's/^VL_SMOKE_USER=//p' ./.env | head -1)}"
    P="$(sed -n 's/^VL_SMOKE_PASS=//p' ./.env | head -1)"
fi
G='\033[1;32m'; R='\033[1;31m'; X='\033[0m'
ok=0; bad=0
pass(){ printf "  ${G}PASS${X} %s\n" "$1"; ok=$((ok+1)); }
fail(){ printf "  ${R}FAIL${X} %s\n" "$1"; bad=$((bad+1)); }

echo "-- scan smoke $(date '+%H:%M:%S') base=$BASE --"
if [ -z "$U" ] || [ -z "$P" ]; then
    echo "  SKIP: no smoke credentials (set VL_SMOKE_USER/VL_SMOKE_PASS in .env)"
    echo "-- skipped --"; exit 0
fi

TOK=$(curl -s -m 10 -X POST "$BASE/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"$U\",\"password\":\"$P\"}" \
      | sed -n 's/.*"access_token"[: ]*"\([^"]*\)".*/\1/p')
if [ -z "$TOK" ]; then fail "auth/login did not return a token"; echo "-- $ok passed, $bad failed --"; exit 1; fi
pass "auth/login issued a token"

# /api/scan/login against a practice lab (lab_* is authz-exempt). The
# reliability assertion: a STRUCTURED response, never a 5xx / crash.
RESP=$(curl -s -m 40 -o /tmp/vl_smoke_body.$$ -w '%{http_code}' \
        -X POST "$BASE/api/scan/login" \
        -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
        -d "{\"target\":\"$LAB\",\"auth_type\":\"form\",\"login_url\":\"/login.php\",\"username\":\"admin\",\"password\":\"password\"}")
BODY=$(cat /tmp/vl_smoke_body.$$ 2>/dev/null); rm -f /tmp/vl_smoke_body.$$
if [ "$RESP" -ge 500 ] 2>/dev/null; then
    fail "scan/login returned HTTP $RESP (server crash): $BODY"
elif echo "$BODY" | grep -q '"login_verified"\|"ok"'; then
    pass "scan/login returned a structured result (HTTP $RESP)"
else
    fail "scan/login HTTP $RESP but body is not a structured result: $BODY"
fi

echo "-- $ok passed, $bad failed --"
[ $bad -eq 0 ] && echo "SCAN SMOKE OK" || echo "SCAN SMOKE FAILED"
exit $bad
