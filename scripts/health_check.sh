#!/bin/bash
# VulnusLab post-deploy health check.
# Verifies backend is healthy, autoloader picked up all modules,
# and key endpoints are reachable.
#
# Run on VPS after `docker compose build backend && docker compose up -d backend`.

set -e

URL="${VULNUSLAB_URL:-http://localhost:8000}"
echo "Health-checking $URL ..."
echo ""

# 1. Backend boot
echo "── Backend health ──"
health=$(curl -s "$URL/api/health" || echo "{}")
if [ -z "$health" ] || [ "$health" = "{}" ]; then
    echo "/api/health returned empty — backend not reachable"
    exit 1
fi
loaded=$(echo "$health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tools_loaded',0))")
failed=$(echo "$health" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('tools_failed',[])))")
healed=$(echo "$health" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('tools_healed',[])))")
echo "  tools_loaded: $loaded"
echo "  tools_failed: $failed"
echo "  tools_healed: $healed"

if [ "$failed" -ne 0 ]; then
    echo "Some tools failed to load. Inspect /api/health.tools_failed"
    echo "$health" | python3 -m json.tool | grep -A 50 tools_failed
    exit 1
fi

if [ "$loaded" -lt 500 ]; then
    echo " Only $loaded tools loaded (expected 700+). May still be booting."
fi

# 2. Module manifest
echo ""
echo "── Module catalogue (/api/manifest) ──"
manifest=$(curl -s "$URL/api/manifest" || echo "{}")
total_modules=$(echo "$manifest" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_modules',0))")
total_endpoints=$(echo "$manifest" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_endpoints',0))")
echo "  total_modules:   $total_modules"
echo "  total_endpoints: $total_endpoints"

if [ "$total_modules" -lt 25 ]; then
    echo " Only $total_modules modules registered (expected 30+)"
fi

# 3. Smoke-test 3 module run_all/tiers endpoints
echo ""
echo "── Smoke tests ──"
ok=0
for mod in recon vuln webapp network cloud apisec phishing; do
    n=$(curl -s "$URL/api/$mod/run_all/tiers" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_tools',0))" 2>/dev/null)
    if [ -n "$n" ] && [ "$n" -gt 0 ]; then
        echo "  /api/$mod/run_all/tiers → $n tools"
        ok=$((ok+1))
    else
        echo "  /api/$mod/run_all/tiers → no response"
    fi
done

if [ "$ok" -lt 5 ]; then
    echo "Fewer than 5 modules responded — likely degraded"
    exit 1
fi

echo ""
echo "Health check PASSED."
echo "  Run a full module scan via:"
echo "    python -m tools._cli scan vulnuslab.com --module recon"
