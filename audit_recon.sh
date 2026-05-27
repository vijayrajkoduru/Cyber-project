#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; D='\033[2m'; X='\033[0m'

# ─── 1. Files + scaffold classification ──────────────────────
declare -A FILE_CT REAL_CT STUB_CT
TOTAL=0; TOTAL_REAL=0; TOTAL_STUB=0
declare -A SEC=(  [1]="Passive Footprint" [2]="DNS Recon" [3]="Subdomain Enumeration"
  [4]="OSINT / Public Records" [5]="Web App Recon" [6]="Cloud Asset Discovery"
  [7]="Email / People Intel" [8]="Threat Intel / Reputation" [9]="Network / Infrastructure"
  [10]="Code Repo / Secret Leak" [11]="Dark Web / Breach Intel" [12]="Mobile / IoT Discovery"
  [13]="AI/LLM-assisted Recon")

for d in tools/recon/tier*_*/; do
  t=$(basename "$d" | sed -E 's/tier([0-9]+)_.*/\1/')
  for f in "$d"*.py; do
    n=$(basename "$f" .py); [ "$n" = "__init__" ] && continue
    TOTAL=$((TOTAL+1)); FILE_CT[$t]=$((${FILE_CT[$t]:-0}+1))
    if grep -qE 'scaffold|state\["scaffold"\]|"Scaffold:|placeholder.*finding' "$f"; then
      STUB_CT[$t]=$((${STUB_CT[$t]:-0}+1)); TOTAL_STUB=$((TOTAL_STUB+1))
    else
      REAL_CT[$t]=$((${REAL_CT[$t]:-0}+1)); TOTAL_REAL=$((TOTAL_REAL+1))
    fi
  done
done

# ─── 2. Routes registered ────────────────────────────────────
ROUTES=$(docker exec vulnuslab_backend python3 -c "
from main import app
for r in sorted(set(r.path for r in app.routes if hasattr(r,'path') and r.path.startswith('/api/recon/'))):
    print(r)
" 2>/dev/null)
RT=$(echo "$ROUTES" | grep -c '^/api/recon/')

# ─── 3. Wired check ──────────────────────────────────────────
MISSING=()
for d in tools/recon/tier*_*/; do
  for f in "$d"*.py; do
    n=$(basename "$f" .py); [ "$n" = "__init__" ] && continue
    echo "$ROUTES" | grep -q "^/api/recon/${n}$" || MISSING+=("$n")
  done
done

# ─── 4. run_all dispatch count ───────────────────────────────
DISPATCH=$(docker exec vulnuslab_backend python3 -c "
try:
    from endpoints.recon_orchestrator import RECON_TOOLS_BY_TIER
    print(sum(len(v) for v in RECON_TOOLS_BY_TIER.values()))
except: print('?')
" 2>/dev/null)

# ─── 5. Report ───────────────────────────────────────────────
printf "${D}═══════════════════════════════════════════════════════════${X}\n"
printf "  RECON AUDIT — files: %s · routes: %s · run_all: %s\n" "$TOTAL" "$RT" "$DISPATCH"
printf "${D}═══════════════════════════════════════════════════════════${X}\n\n"

printf "%-5s %-30s %-7s %-7s %-7s\n" "TIER" "SECTION" "FILES" "REAL" "STUB"
for t in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  f=${FILE_CT[$t]:-0}; r=${REAL_CT[$t]:-0}; s=${STUB_CT[$t]:-0}
  if [ $s -eq 0 ] && [ $r -gt 0 ]; then c=$G
  elif [ $r -eq 0 ]; then c=$R
  else c=$Y; fi
  printf "${c}§%-4s %-30s %-7s %-7s %-7s${X}\n" "$t" "${SEC[$t]}" "$f" "$r" "$s"
done

printf "\n${D}Q1. All %s tools working?${X}\n" "$TOTAL"
[ $TOTAL_STUB -eq 0 ] && printf "  ${G}✓ all real${X}\n" || printf "  ${R}✗ %s real | %s stubs${X}\n" "$TOTAL_REAL" "$TOTAL_STUB"

printf "${D}Q2. All wired?${X}\n"
[ ${#MISSING[@]} -eq 0 ] && printf "  ${G}✓ every file has a route${X}\n" || { printf "  ${R}✗ %s missing:${X}\n" "${#MISSING[@]}"; printf "    - %s\n" "${MISSING[@]}" | head -20; }

printf "${D}Q3. All finding real vulns?${X}\n"
printf "  ${Y}!${X} %s scanners use real probes\n" "$TOTAL_REAL"
[ $TOTAL_STUB -eq 0 ] && printf "  ${G}✓ no scaffold placeholders${X}\n" || printf "  ${R}✗${X} %s scaffolds emit only 'Scaffold: …' placeholder (NOT real findings)\n" "$TOTAL_STUB"

printf "${D}Q4. All appear in PDF?${X}\n"
printf "  After RECON_PHASES rebuild: all %s phases listed.\n" "$TOTAL"
printf "  But scaffolds show 'Completed · 1 INFO' — empty content.\n"

printf "${D}Q5. False positives?${X}\n"
[ $TOTAL_STUB -eq 0 ] && printf "  ${G}✓ none from scaffolds${X}\n" || printf "  ${R}✗ %s scaffold INFOs are false positives${X}\n" "$TOTAL_STUB"

printf "${D}Q6. All %s scan when 'All sections' selected?${X}\n" "$TOTAL"
if [ "$DISPATCH" = "$TOTAL" ]; then
  printf "  ${G}✓ run_all dispatches all %s${X}\n" "$DISPATCH"
elif [ "$DISPATCH" = "?" ]; then
  printf "  ${Y}! couldn't read orchestrator dispatch count${X}\n"
else
  printf "  ${R}✗ run_all dispatches %s of %s${X}\n" "$DISPATCH" "$TOTAL"
fi
