#!/usr/bin/env bash
# VL-AUDIT — one-command dogfood audit
# Usage: ./scripts/vl_audit.sh <target> [--modules vuln,recon,webapp]
#
# Runs every (or selected) module against <target> via /api/<module>/run_all,
# saves NDJSON output per module under ./audit/<target>/<date>/, then writes
# a summary.md with finding counts per module.
#
# Auth:
#   - VL_TOKEN env var (preferred), OR
#   - first line of .env matching ^VL_TOKEN=
# Backend:
#   - VL_API env var (e.g. http://localhost:8000 or https://app.vulnuslab.com/api)
#   - defaults to http://localhost:8000

set -uo pipefail

TARGET="${1:-vulnuslab.com}"
shift || true

MODULES_DEFAULT="vuln,recon,webapp,cloud,k8s,osint,api_sec,ai_llm"
MODULES_ARG=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --modules) MODULES_ARG="$2"; shift 2 ;;
    --modules=*) MODULES_ARG="${1#*=}"; shift ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
MODULES="${MODULES_ARG:-$MODULES_DEFAULT}"

# Resolve token
if [[ -z "${VL_TOKEN:-}" ]] && [[ -f .env ]]; then
  VL_TOKEN="$(grep -m1 '^VL_TOKEN=' .env | cut -d= -f2- || true)"
fi
if [[ -z "${VL_TOKEN:-}" ]]; then
  echo "VL-AUDIT: VL_TOKEN not set in env or .env — aborting." >&2
  echo "         Set VL_TOKEN=<your-jwt> in .env or export VL_TOKEN=..." >&2
  exit 1
fi

VL_API="${VL_API:-http://localhost:8000}"
DATE="$(date +%Y-%m-%d)"
OUTDIR="./audit/${TARGET}/${DATE}"
mkdir -p "$OUTDIR"

echo "VL-AUDIT starting"
echo "  target  : $TARGET"
echo "  backend : $VL_API"
echo "  modules : $MODULES"
echo "  output  : $OUTDIR"
echo ""

# Per-module scan
IFS=',' read -ra MODULE_LIST <<< "$MODULES"
declare -A MODULE_RESULT_FILE
for m in "${MODULE_LIST[@]}"; do
  m="$(echo "$m" | tr -d ' ')"
  [[ -z "$m" ]] && continue
  out="$OUTDIR/${m}.ndjson"
  MODULE_RESULT_FILE[$m]="$out"
  echo "[$m] POST $VL_API/api/$m/run_all  target=$TARGET"
  http_code=$(curl -sS -o "$out" -w "%{http_code}" \
    -H "Authorization: Bearer $VL_TOKEN" \
    -H "Content-Type: application/json" \
    -X POST "$VL_API/api/$m/run_all" \
    -d "{\"target\":\"$TARGET\"}" \
    --max-time 600 || true)
  if [[ "$http_code" == "200" ]]; then
    n_events=$(wc -l < "$out" 2>/dev/null || echo 0)
    echo "[$m] OK  http=$http_code  events=$n_events  saved=$out"
  else
    echo "[$m] FAIL http=$http_code  see $out"
  fi
done

echo ""
echo "VL-AUDIT generating summary"

# Summary.md
SUMMARY="$OUTDIR/summary.md"
{
  echo "# VL-AUDIT — $TARGET"
  echo ""
  echo "**Date:** $DATE  "
  echo "**Backend:** $VL_API  "
  echo "**Modules run:** $MODULES  "
  echo ""
  echo "## Per-module finding rollup"
  echo ""
  echo "| Module | Events | CRITICAL | HIGH | MEDIUM | LOW | INFO | Notes |"
  echo "|--------|--------|----------|------|--------|-----|------|-------|"
} > "$SUMMARY"

for m in "${MODULE_LIST[@]}"; do
  m="$(echo "$m" | tr -d ' ')"
  [[ -z "$m" ]] && continue
  out="${MODULE_RESULT_FILE[$m]}"
  if [[ ! -s "$out" ]]; then
    echo "| $m | 0 | - | - | - | - | - | no output |" >> "$SUMMARY"
    continue
  fi
  # Each line is a JSON event. Count severity occurrences via grep.
  n=$(wc -l < "$out")
  c=$(grep -o '"severity":"CRITICAL"' "$out" | wc -l)
  h=$(grep -o '"severity":"HIGH"' "$out" | wc -l)
  med=$(grep -o '"severity":"MEDIUM"' "$out" | wc -l)
  l=$(grep -o '"severity":"LOW"' "$out" | wc -l)
  i=$(grep -o '"severity":"INFO"' "$out" | wc -l)
  notes=""
  if grep -q '"error"' "$out" 2>/dev/null; then notes="errors present"; fi
  echo "| $m | $n | $c | $h | $med | $l | $i | $notes |" >> "$SUMMARY"
done

{
  echo ""
  echo "## Files"
  echo ""
  for m in "${MODULE_LIST[@]}"; do
    m="$(echo "$m" | tr -d ' ')"
    [[ -z "$m" ]] && continue
    echo "- \`${MODULE_RESULT_FILE[$m]#./}\`"
  done
  echo ""
  echo "## Next steps"
  echo ""
  echo "1. Open the dashboard at \`$VL_API\` (or app.vulnuslab.com) and re-run the same modules to generate PDFs."
  echo "2. Save each PDF to \`$OUTDIR/<module>.pdf\`."
  echo "3. Grade each PDF against \`module_playbooks/pdf_industry_standard.md\` (% vs industry + numbered gaps)."
  echo "4. Compare findings to last audit at \`./audit/${TARGET}/<prev_date>/summary.md\` to spot drift."
} >> "$SUMMARY"

echo "VL-AUDIT done"
echo "  summary: $SUMMARY"
