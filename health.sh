#!/usr/bin/env bash
# Verifies: filesystem ↔ routes ↔ live response ↔ report path
set -u
cd "$(dirname "$0")"

C_GREEN='\033[1;32m'; C_RED='\033[1;31m'; C_YEL='\033[1;33m'; C_DIM='\033[2m'; C_RST='\033[0m'
ok()   { printf "${C_GREEN}${C_RST} %s\n" "$*"; }
fail() { printf "${C_RED}${C_RST} %s\n" "$*"; }
warn() { printf "${C_YEL}!${C_RST} %s\n" "$*"; }
hdr()  { printf "\n${C_DIM}─── %s ───${C_RST}\n" "$*"; }

BACKEND="http://localhost:8000"
TARGET="${TEST_TARGET:-example.com}"
EMAIL="${ADMIN_EMAIL:-awsvijju5@gmail.com}"
declare -A SEC_NAMES=(
  [1]="Passive Footprint" [2]="DNS Recon" [3]="Subdomain Enumeration"
  [4]="OSINT / Public Records" [5]="Web App Recon" [6]="Cloud Asset Discovery"
  [7]="Email / People Intel" [8]="Threat Intel / Reputation" [9]="Network / Infrastructure"
  [10]="Code Repo / Secret Leak" [11]="Dark Web / Breach Intel" [12]="Mobile / IoT Discovery"
  [13]="AI/LLM-assisted Recon"
)

# ─── AUTH ─────────────────────────────────────────────────────
if [ -z "${TOKEN:-}" ]; then
  if [ -z "${ADMIN_PASS:-}" ]; then
    read -s -p "Admin password for $EMAIL: " ADMIN_PASS; echo
  fi
  TOKEN=$(curl -sS -X POST "$BACKEND/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$ADMIN_PASS\"}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token') or d.get('token',''))" 2>/dev/null)
  [ -z "$TOKEN" ] && { fail "login failed for $EMAIL"; exit 1; }
fi
ok "logged in"

# ─── 1. FILESYSTEM ────────────────────────────────────────────
hdr "1. Filesystem inventory"
declare -A FS_COUNT
TOTAL_FS=0
declare -A TOOL_TIER
for d in tools/recon/tier*_*/; do
  tier=$(basename "$d" | sed -E 's/tier([0-9]+)_.*/\1/')
  c=0
  for f in "$d"*.py; do
    n=$(basename "$f" .py)
    [ "$n" = "__init__" ] && continue
    TOOL_TIER["$n"]="$tier"
    c=$((c+1))
  done
  FS_COUNT[$tier]=$c
  TOTAL_FS=$((TOTAL_FS+c))
done
ok "scanner files on disk: $TOTAL_FS"

# ─── 2. BACKEND ROUTES ────────────────────────────────────────
hdr "2. Routes registered in FastAPI"
ROUTES=$(docker exec vulnuslab_backend python3 -c "
from main import app
for r in sorted(set(r.path for r in app.routes if hasattr(r,'path') and r.path.startswith('/api/recon/'))):
    print(r)
" 2>/dev/null)
ROUTE_COUNT=$(echo "$ROUTES" | grep -c '^/api/recon/')
ok "registered: $ROUTE_COUNT"

# ─── 3. CROSS-REFERENCE: file vs route ────────────────────────
hdr "3. File vs route mismatch"
MISSING=()
for tool in "${!TOOL_TIER[@]}"; do
  if ! echo "$ROUTES" | grep -qE "^/api/recon/${tool}/?$"; then
    MISSING+=("§${TOOL_TIER[$tool]} → $tool")
  fi
done
if [ ${#MISSING[@]} -eq 0 ]; then
  ok "all $TOTAL_FS scanners have a registered route"
else
  fail "${#MISSING[@]} scanners NOT wired:"
  printf "    %s\n" "${MISSING[@]}" | sort
fi

# ─── 4. BACKEND LOAD ERRORS ───────────────────────────────────
hdr "4. Autoloader errors at boot"
ERR=$(docker logs vulnuslab_backend 2>&1 | grep -iE "load.*fail|ImportError|cannot import|attribute.*error" | grep -i recon | tail -10 || true)
if [ -z "$ERR" ]; then
  ok "no scanner-load errors in backend logs"
else
  warn "backend logs report load issues:"
  echo "$ERR" | sed 's/^/    /'
fi

# ─── 5. PER-SECTION LIVE TEST (1 tool per section) ────────────
hdr "5. Live test — 1 tool per section vs $TARGET (10s each)"
declare -A SEC_STATUS
declare -A SEC_PROBE
for tier in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  # Pick the first tool in this tier
  probe=""
  for tool in "${!TOOL_TIER[@]}"; do
    if [ "${TOOL_TIER[$tool]}" = "$tier" ]; then
      probe="$tool"; break
    fi
  done
  SEC_PROBE[$tier]=$probe
  if [ -z "$probe" ]; then
    SEC_STATUS[$tier]="NO_TOOLS"; continue
  fi
  resp=$(curl -sS -o /tmp/h_$$ -w "%{http_code}|%{time_total}" -m 12 \
    -X POST "$BACKEND/api/recon/$probe" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"target\":\"$TARGET\"}" 2>/dev/null || echo "000|0")
  code="${resp%%|*}"
  tt="${resp#*|}"
  case "$code" in
    200) SEC_STATUS[$tier]="OK ${tt}s" ;;
    401|403) SEC_STATUS[$tier]="AUTH_FAIL" ;;
    404) SEC_STATUS[$tier]="ROUTE_404" ;;
    500|502) SEC_STATUS[$tier]="HTTP_$code" ;;
    000) SEC_STATUS[$tier]="TIMEOUT" ;;
    *) SEC_STATUS[$tier]="HTTP_$code" ;;
  esac
done
rm -f /tmp/h_$$

# ─── SECTION TABLE ────────────────────────────────────────────
hdr "Section summary"
printf "%-4s %-30s %-7s %-25s %s\n" "SEC" "NAME" "FILES" "PROBE" "STATUS"
printf "%-4s %-30s %-7s %-25s %s\n" "---" "------------------------------" "-----" "-------------------------" "------"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  st="${SEC_STATUS[$i]}"
  case "$st" in
    OK*)        c="$C_GREEN" ;;
    AUTH_FAIL*) c="$C_YEL"   ;;
    *)          c="$C_RED"   ;;
  esac
  printf "${c}%-4s %-30s %-7s %-25s %s${C_RST}\n" "$i" "${SEC_NAMES[$i]}" "${FS_COUNT[$i]}" "${SEC_PROBE[$i]}" "$st"
done

# ─── 6. REPORT GENERATION ────────────────────────────────────
hdr "6. Report generation (PDF)"
# The PDF is built client-side in App.js via jsPDF. Verify the function exists.
if grep -q "generateReconReport\|dlReconPDF\|jspdf" src/App.js; then
  ok "PDF generator wired in src/App.js"
else
  fail "PDF generator NOT found in src/App.js"
fi
# Check if backend has any report endpoint
if echo "$ROUTES" | grep -qi "report\|pdf"; then
  ok "backend report endpoint(s) registered"
else
  warn "no backend /report endpoint — PDF is client-side only (expected)"
fi

# ─── VERDICT ─────────────────────────────────────────────────
hdr "Verdict"
FAIL_CT=0
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  case "${SEC_STATUS[$i]}" in OK*) ;; *) FAIL_CT=$((FAIL_CT+1));; esac
done
echo "  Files on disk      : $TOTAL_FS"
echo "  Routes registered  : $ROUTE_COUNT"
echo "  Unwired scanners   : ${#MISSING[@]}"
echo "  Section probes OK  : $((13-FAIL_CT)) / 13"
echo
if [ ${#MISSING[@]} -eq 0 ] && [ $FAIL_CT -eq 0 ]; then
  ok "ALL SYSTEMS GO — every section is wired and responding"
else
  fail "Issues found — review sections 3-5 above"
fi
