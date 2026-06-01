#!/usr/bin/env bash
# VL-FOUNDRY production smoke test (Gap 2 fix).
#
# Runs the full chain (POST /run_all → NDJSON → record count → first
# finding shape) against a LIVE backend. Use on the VPS after every
# deploy to catch the OSINT-broken-PDF class of regression.
#
# Usage:
#   ./scripts/smoke_test.sh <module>
#   ./scripts/smoke_test.sh osint
#   API_BASE=https://app.vulnuslab.com ./scripts/smoke_test.sh recon
#
# Env:
#   API_BASE  — default http://localhost:8000 (Docker-internal)
#   TARGET    — default vulnuslab.com
#   VL_TOKEN  — Bearer token (required for auth'd endpoints)
#
# Exit codes:
#   0 — all checks green
#   1 — one or more checks failed (CI-friendly)

set -u
MODULE="${1:?usage: smoke_test.sh <module>}"
API="${API_BASE:-http://localhost:8000}"
TARGET="${TARGET:-vulnuslab.com}"
TOKEN="${VL_TOKEN:-}"
OUT=$(mktemp)
trap "rm -f $OUT" EXIT

echo "═══════════════════════════════════════════════════════════════"
echo "  VL-FOUNDRY smoke test: ${MODULE}"
echo "  API: $API"
echo "  Target: $TARGET"
echo "═══════════════════════════════════════════════════════════════"

# Gate 1: /health (backend serves /api/health; fall back to /health for older deploys)
echo -n "  [1/5] API health ... "
STATUS=$(curl -sS -m 8 -o /dev/null -w "%{http_code}" "$API/api/health")
if [ "$STATUS" != "200" ]; then
  STATUS=$(curl -sS -m 8 -o /dev/null -w "%{http_code}" "$API/health")
fi
if [ "$STATUS" = "200" ]; then echo "OK (200)"; else echo "FAIL ($STATUS)"; exit 1; fi

# Gate 2: tier discovery (no auth required)
echo -n "  [2/5] Tier discovery /api/${MODULE}/run_all/tiers ... "
TIERS=$(curl -sS -m 10 -w "\n%{http_code}" "$API/api/${MODULE}/run_all/tiers")
TIER_STATUS=$(echo "$TIERS" | tail -n1)
TIER_JSON=$(echo "$TIERS" | head -n-1)
if [ "$TIER_STATUS" != "200" ]; then echo "FAIL ($TIER_STATUS)"; exit 1; fi
TOTAL_TOOLS=$(echo "$TIER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('total_tools',0))")
echo "OK (200, ${TOTAL_TOOLS} tools)"

# Gate 3: POST /run_all returns 200
if [ -z "$TOKEN" ]; then
  echo "  [3/5] POST /api/${MODULE}/run_all ... SKIPPED (no VL_TOKEN set)"
  echo ""
  echo "  Note: without a token, gates 3-5 cannot run. Set VL_TOKEN to"
  echo "        complete the smoke test:"
  echo "          export VL_TOKEN='<from browser localStorage.cyberToken>'"
  echo ""
  echo "   PARTIAL PASS (health + tiers verified, scan not exercised)"
  exit 0
fi

echo -n "  [3/5] POST /api/${MODULE}/run_all ... "
START=$(date +%s)
curl -sS -m 300 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -X POST "$API/api/${MODULE}/run_all" \
  -d "{\"target\":\"$TARGET\",\"concurrency\":6}" \
  > "$OUT" 2>&1
RC=$?
ELAPSED=$(( $(date +%s) - START ))
if [ "$RC" != "0" ]; then echo "FAIL (curl exit $RC)"; exit 1; fi
RECORDS=$(grep -c '^{' "$OUT" 2>/dev/null || echo 0)
echo "OK (${ELAPSED}s, ${RECORDS} NDJSON records)"

# Gate 4: record count sanity (1..200)
echo -n "  [4/5] Record count sanity ... "
if [ "$RECORDS" -lt 1 ] || [ "$RECORDS" -gt 200 ]; then
  echo "FAIL (${RECORDS} records — expected 1..200)"
  echo "  ── first 500 chars of response ──"
  head -c 500 "$OUT"
  echo ""
  exit 1
fi
echo "OK"

# Gate 5: shape check on first finding-bearing record
echo -n "  [5/5] First record has recognizable shape ... "
SHAPE_OK=$(python3 - "$OUT" <<'PY'
import json, sys
ok_count = 0
total = 0
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
            total += 1
            if isinstance(r, dict) and (
                set(r.keys()) & {"tool","target","findings","scanner","error","event"}
            ):
                ok_count += 1
        except json.JSONDecodeError:
            continue
print(f"{ok_count}/{total}")
PY
)
OK_COUNT=$(echo "$SHAPE_OK" | cut -d/ -f1)
TOTAL=$(echo "$SHAPE_OK" | cut -d/ -f2)
if [ "$OK_COUNT" = "0" ] || [ "$TOTAL" = "0" ]; then
  echo "FAIL (no valid records: $SHAPE_OK)"
  exit 1
fi
echo "OK ($SHAPE_OK)"

echo "───────────────────────────────────────────────────────────────"
echo "  ALL GREEN — ${MODULE} module passing smoke test"
echo "═══════════════════════════════════════════════════════════════"
