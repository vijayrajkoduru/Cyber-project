#!/bin/bash
# VulnusLab multi-module smoke test — verifies every module's run_all/tiers
# endpoint responds. Complements existing smoke_test.sh (single-module deep
# probe) with breadth across all 30+ modules.
#
# Usage:
#   VULNUSLAB_TOKEN=<jwt> ./scripts/smoke_test_all_modules.sh [target]

URL="${VULNUSLAB_URL:-http://localhost:8000}"
TOKEN="${VULNUSLAB_TOKEN}"
TARGET="${1:-localhost}"

if [ -z "$TOKEN" ]; then
    echo "VULNUSLAB_TOKEN required."
    echo "Get a JWT via: curl -X POST -H 'Content-Type: application/json' \\"
    echo "  -d '{\"username\":\"ADMIN\",\"password\":\"<pass>\"}' $URL/api/auth/login"
    exit 2
fi

echo "Smoke test ALL modules: $URL  (target: $TARGET)"
echo ""

modules=$(curl -s "$URL/api/manifest" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for m in d.get('modules', []):
    if m.get('has_run_all'):
        print(m['slug'])
" 2>/dev/null)

ok=0; fail=0
for mod in $modules; do
    n=$(curl -s -H "Authorization: Bearer $TOKEN" \
        --max-time 5 \
        "$URL/api/$mod/run_all/tiers" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_tools',0))" 2>/dev/null)
    if [ -n "$n" ] && [ "$n" -gt 0 ]; then
        printf "   %-25s %s tools\n" "$mod" "$n"
        ok=$((ok+1))
    else
        printf "  %-25s NO RESPONSE\n" "$mod"
        fail=$((fail+1))
    fi
done

echo ""
echo "Result: $ok OK, $fail FAILED"
[ "$fail" -eq 0 ] && exit 0 || exit 1
