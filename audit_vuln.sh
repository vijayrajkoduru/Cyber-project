#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; D='\033[2m'; X='\033[0m'

declare -A FILE_CT REAL_CT STUB_CT
TOTAL=0; TOTAL_REAL=0; TOTAL_STUB=0
declare -A SEC=(
  [1]="Network Vuln" [2]="CVE Matching" [3]="Web Active (OWASP T10)"
  [4]="Authenticated Web" [5]="API Vuln (OWASP API T10)" [6]="Modern Protocol"
  [7]="SCA / SBOM" [8]="Container / Image" [9]="IaC / Cloud Config"
  [10]="Cloud-Native Runtime" [11]="CIS Hardening" [12]="Auth / Session"
  [13]="Supply Chain (SLSA)" [14]="AI / LLM" [15]="Wireless / IoT")

for d in tools/vuln/tier*_*/; do
  t=$(basename "$d" | sed -E 's/tier([0-9]+)_.*/\1/')
  for f in "$d"*.py; do
    n=$(basename "$f" .py); [ "$n" = "__init__" ] && continue
    TOTAL=$((TOTAL+1)); FILE_CT[$t]=$((${FILE_CT[$t]:-0}+1))
    if grep -qE 'scaffold|state\["scaffold"\]|"Scaffold:' "$f"; then
      STUB_CT[$t]=$((${STUB_CT[$t]:-0}+1)); TOTAL_STUB=$((TOTAL_STUB+1))
    else
      REAL_CT[$t]=$((${REAL_CT[$t]:-0}+1)); TOTAL_REAL=$((TOTAL_REAL+1))
    fi
  done
done

ROUTES=$(docker exec vulnuslab_backend python3 -c "
from main import app
for r in sorted(set(r.path for r in app.routes if hasattr(r,'path') and r.path.startswith('/api/vuln/'))):
    print(r)
" 2>/dev/null)
RT=$(echo "$ROUTES" | grep -c '^/api/vuln/')

DISPATCH=$(docker exec vulnuslab_backend python3 -c "
try:
    from endpoints.vuln_orchestrator import VULN_TOOLS_BY_TIER
    print(sum(len(v) for v in VULN_TOOLS_BY_TIER.values()))
except: print('?')
" 2>/dev/null)

printf "${D}═══════════════════════════════════════════════════════════${X}\n"
printf "  VULN AUDIT — files: %s · routes: %s · run_all: %s\n" "$TOTAL" "$RT" "$DISPATCH"
printf "${D}═══════════════════════════════════════════════════════════${X}\n\n"

printf "%-5s %-30s %-7s %-7s %-7s\n" "TIER" "SECTION" "FILES" "REAL" "STUB"
for t in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  f=${FILE_CT[$t]:-0}; r=${REAL_CT[$t]:-0}; s=${STUB_CT[$t]:-0}
  if [ $s -eq 0 ] && [ $r -gt 0 ]; then c=$G
  elif [ $r -eq 0 ]; then c=$R
  else c=$Y; fi
  printf "${c}§%-4s %-30s %-7s %-7s %-7s${X}\n" "$t" "${SEC[$t]}" "$f" "$r" "$s"
done

printf "\n${D}Q1. All %s tools working?${X}\n" "$TOTAL"
[ $TOTAL_STUB -eq 0 ] && printf "  ${G}✓ all real${X}\n" || printf "  ${R}✗ %s real | %s stubs${X}\n" "$TOTAL_REAL" "$TOTAL_STUB"

printf "${D}Q2. All wired?${X}\n  routes registered: %s\n" "$RT"
printf "${D}Q3. run_all dispatch:${X}\n  %s of %s\n" "$DISPATCH" "$TOTAL"
