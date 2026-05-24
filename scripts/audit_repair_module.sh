#!/usr/bin/env bash
# VL-FOUNDRY module audit + auto-repair.
#
# One command, finds + fixes the common AI-hallucination bugs:
#   - missing `def register(app)` at end of scanner file
#   - wrong keyword args (req=req, gather_fn=, scan_fn=, finding_rule=)
#   - Python syntax errors (saved as .ai_draft instead of .py)
#   - duplicate scanner files (e.g. tier_starter.py left after AI overwrote)
#   - missing @router.post decorators
#   - missing imports (ScanContext, run_scanner)
#
# Then rebuilds backend Docker + tests every endpoint.
#
# Usage:
#   ./scripts/audit_repair_module.sh <module>
#
# Example:
#   ./scripts/audit_repair_module.sh mobile

set -u
MODULE="${1:?usage: audit_repair_module.sh <module>}"
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || exit 1

echo "═══════════════════════════════════════════════════════════════"
echo "  VL-FOUNDRY audit + auto-repair: $MODULE"
echo "═══════════════════════════════════════════════════════════════"

# ─────────── PHASE 1: AUDIT ───────────

echo ""
echo "── PHASE 1: AUDIT ──"

# 1. Files present
echo ""
echo "[1.1] Scanner files on disk:"
files=$(find "tools/$MODULE" -name "*.py" ! -name "__init__.py" ! -name "*_starter.py" 2>/dev/null)
count=$(echo "$files" | grep -c . || echo 0)
echo "  Found: $count files"
echo "$files" | sed 's/^/    /'

# 2. Starter / duplicate cleanup candidates
echo ""
echo "[1.2] Stale / duplicate files to remove:"
stale=$(find "tools/$MODULE" -name "*_starter.py" -o -name "*.py.ai_draft" -o -name "*.py.bak" 2>/dev/null)
if [ -z "$stale" ]; then
  echo "  (none)"
else
  echo "$stale" | sed 's/^/  /'
fi

# 3. Syntax errors
echo ""
echo "[1.3] Python syntax check:"
syntax_errors=0
for f in $files; do
  if ! python3 -c "import ast; ast.parse(open('$f').read())" 2>/dev/null; then
    echo "  ❌ SYNTAX ERROR: $f"
    syntax_errors=$((syntax_errors+1))
  fi
done
[ "$syntax_errors" = "0" ] && echo "  ✅ all files parse"

# 4. Missing register(app)
echo ""
echo "[1.4] Missing def register(app):"
missing_reg=0
for f in $files; do
  if ! grep -qE "^def register|register\(app\):" "$f"; then
    echo "  ❌ NO register: $f"
    missing_reg=$((missing_reg+1))
  fi
done
[ "$missing_reg" = "0" ] && echo "  ✅ all files have register"

# 5. Wrong keyword args
echo ""
echo "[1.5] Wrong keyword args (run_scanner hallucinations):"
wrong_kw=$(grep -rln "gather_fn=\|scan_fn=\|req=req\|finding_rule=[A-Z]\|intel_field=\[\|flat_field=" "tools/$MODULE/" 2>/dev/null || true)
if [ -z "$wrong_kw" ]; then
  echo "  ✅ no wrong keyword args"
else
  echo "$wrong_kw" | sed 's/^/  ❌ /'
fi

# 6. Missing @router.post
echo ""
echo "[1.6] Missing @router.post decorator:"
missing_route=0
for f in $files; do
  if ! grep -q "@router.post" "$f"; then
    echo "  ❌ NO @router.post: $f"
    missing_route=$((missing_route+1))
  fi
done
[ "$missing_route" = "0" ] && echo "  ✅ all files have routes"

# 7. Missing critical imports
echo ""
echo "[1.7] Missing imports:"
missing_imp=0
for f in $files; do
  needs=""
  grep -q "ScanContext" "$f" && ! grep -q "from tools._framework import.*ScanContext\|import ScanContext" "$f" && needs="ScanContext "
  grep -q "run_scanner(" "$f" && ! grep -q "from tools._framework import.*run_scanner\|import run_scanner" "$f" && needs="${needs}run_scanner "
  if [ -n "$needs" ]; then
    echo "  ❌ $f needs: $needs"
    missing_imp=$((missing_imp+1))
  fi
done
[ "$missing_imp" = "0" ] && echo "  ✅ all imports present"

# ─────────── PHASE 2: AUTO-REPAIR ───────────

echo ""
echo "── PHASE 2: AUTO-REPAIR ──"

# Repair 2.1 — Delete stale files
if [ -n "$stale" ]; then
  echo ""
  echo "[2.1] Deleting stale files..."
  echo "$stale" | xargs -r rm -v
fi

# Repair 2.2 — Fix wrong keyword args (sed across all files)
echo ""
echo "[2.2] Fixing wrong keyword args..."
for f in $files; do
  before=$(md5sum "$f" 2>/dev/null | cut -d' ' -f1)
  sed -i \
    -e 's/gather_fn=/gather_func=/g' \
    -e 's/scan_fn=/gather_func=/g' \
    -e 's/req=req,\s*//g' \
    -e 's/,\s*req=req//g' \
    -e 's/finding_rule=\([A-Z_]\)/finding_rules=\1/g' \
    -e 's/intel_field=/intel_fields=/g' \
    -e 's/flat_field=/flat_field_keys=/g' \
    "$f"
  after=$(md5sum "$f" 2>/dev/null | cut -d' ' -f1)
  [ "$before" != "$after" ] && echo "  ✏️  patched: $f"
done

# Repair 2.3 — Inject missing register(app)
echo ""
echo "[2.3] Adding missing register(app)..."
for f in $files; do
  if ! grep -qE "^def register|register\(app\):" "$f"; then
    {
      echo ""
      echo ""
      echo "def register(app):"
      echo "    app.include_router(router)"
    } >> "$f"
    echo "  ➕ added register to: $f"
  fi
done

# Repair 2.4 — Re-validate syntax after edits
echo ""
echo "[2.4] Post-repair syntax check:"
post_errors=0
for f in $files; do
  if ! python3 -c "import ast; ast.parse(open('$f').read())" 2>&1 | head -3; then
    post_errors=$((post_errors+1))
  fi
done
[ "$post_errors" = "0" ] && echo "  ✅ all files still parse after repair"

# ─────────── PHASE 3: REBUILD + VERIFY ───────────

echo ""
echo "── PHASE 3: REBUILD + VERIFY ──"

echo ""
echo "[3.1] Touching files to bust Docker cache..."
find "tools/$MODULE" -name "*.py" -exec touch {} +

echo ""
echo "[3.2] Rebuilding backend (no-cache)..."
docker compose build --no-cache backend 2>&1 | tail -5

echo ""
echo "[3.3] Restarting backend..."
docker compose up -d backend
sleep 25

echo ""
echo "[3.4] Loaded ${MODULE} scanners:"
docker compose logs backend 2>&1 | grep -E "Loaded tool: tools.${MODULE}" | sort -u | wc -l
echo ""
docker compose logs backend 2>&1 | grep -E "Loaded tool: tools.${MODULE}|skipped.*${MODULE}|fail.*${MODULE}" | sort -u | tail -20

echo ""
echo "[3.5] Boot errors (last 90s):"
docker compose logs --since 90s backend 2>&1 | grep -iE "ERROR|Traceback|TypeError" | head -10 || echo "  ✅ no errors"

# Test every endpoint
echo ""
echo "[3.6] Testing each endpoint (no auth — looking for 401 = good):"
for f in $files; do
  name=$(basename "$f" .py)
  result=$(curl -sS -X POST "http://localhost:8000/api/${MODULE}/${name}" \
    -H "Content-Type: application/json" \
    -d '{"target":"signal.org"}' -m 10 2>&1 | head -c 80)
  case "$result" in
    *"Missing Authorization"*) echo "  ✅ $name (route alive)" ;;
    *"Not Found"*)             echo "  ❌ $name (404 — route not registered)" ;;
    *"Internal Server"*)       echo "  💥 $name (500 — scanner code error)" ;;
    *)                         echo "  ❓ $name: $result" ;;
  esac
done

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Audit + repair complete for ${MODULE}"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "If any 💥 500 errors remain, paste them:"
echo "  docker compose logs --since 90s backend 2>&1 | grep -A 8 'Traceback' | head -30"
