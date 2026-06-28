#!/usr/bin/env bash
# Launch preflight — run this right before flipping the switch for paid sales.
# Prints a green/red GO / NO-GO. Exit 0 = GO, non-zero = at least one blocker.
#
# Run on the VPS (needs docker access to the backend container) — the live
# HTTP checks also work from anywhere:
#   ./scripts/preflight_launch.sh                       # defaults below
#   BASE_URL=https://app.vulnuslab.com ./scripts/preflight_launch.sh
set -uo pipefail

BASE_URL="${BASE_URL:-https://app.vulnuslab.com}"
CONTAINER="${CONTAINER:-vulnuslab_backend}"
BACKUP_DIR="${BACKUP_DIR:-$HOME/backups}"

G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; D='\033[2m'; X='\033[0m'
BLOCKERS=0; WARNINGS=0

pass()  { printf "  ${G}PASS${X}  %s\n" "$1"; }
fail()  { printf "  ${R}FAIL${X}  %s\n" "$1"; BLOCKERS=$((BLOCKERS+1)); }
warn()  { printf "  ${Y}WARN${X}  %s\n" "$1"; WARNINGS=$((WARNINGS+1)); }
head()  { printf "\n${D}── %s${X}\n" "$1"; }

have_container() { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CONTAINER"; }
in_container()   { docker exec -i "$CONTAINER" "$@"; }

printf "${D}═══ VulnusLab Launch Preflight ═══${X}\n"
printf "${D}target: %s · container: %s${X}\n" "$BASE_URL" "$CONTAINER"

# ── Blocker 1: hardening deployed ───────────────────────────────────
head "1. Hardening deployed"
HCODE=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$BASE_URL/api/health" 2>/dev/null)
[ "$HCODE" = "200" ] && pass "/api/health -> 200" || fail "/api/health -> $HCODE (site down?)"
MCODE=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "$BASE_URL/api/metrics" 2>/dev/null)
if [ "$MCODE" = "200" ]; then pass "/api/metrics live (new code deployed)"
else fail "/api/metrics -> $MCODE — hardening NOT deployed (git pull + rebuild)"; fi
# rate-limit header proves the middleware is active
RLH=$(curl -s -m 10 -D - -o /dev/null "$BASE_URL/api/manifest" 2>/dev/null | grep -ic 'x-ratelimit-limit')
[ "$RLH" -ge 1 ] && pass "rate-limit middleware active (X-RateLimit-* header)" \
  || warn "no X-RateLimit header (rate limiting off or not deployed)"

# ── Blocker 2: secrets not placeholders ─────────────────────────────
head "2. Secrets configured (no placeholders)"
if have_container; then
  in_container python3 - <<'PY'
import os
markers=("your_actual_key_here","paste_new_token_here","your_token","<key>",
         "changeme","your_abuseipdb_key_here","rzp_test_","paste_new")
def ph(v): return bool(v) and any(m in v.lower() for m in markers)
# security-critical: a placeholder here BLOCKS launch
crit=["JWT_SECRET","RAZORPAY_KEY_ID","RAZORPAY_KEY_SECRET","RAZORPAY_WEBHOOK_SECRET",
      "ANTHROPIC_API_KEY","VAULT_KEY","CREDENTIAL_VAULT_MASTER_KEY"]
# optional integrations: a placeholder only DEGRADES features (warning)
opt=["VIRUSTOTAL_KEY","ABUSEIPDB_KEY","GITHUB_TOKEN","EMAIL_API_KEY"]
crit_bad=[k for k in crit if ph(os.getenv(k,""))]
crit_missing=[k for k in crit if not os.getenv(k)]
opt_bad=[k for k in opt if ph(os.getenv(k,""))]
print("CRIT_PLACEHOLDER:"+(",".join(crit_bad) if crit_bad else "none"))
print("CRIT_MISSING:"+(",".join(crit_missing) if crit_missing else "none"))
print("OPT_PLACEHOLDER:"+(",".join(opt_bad) if opt_bad else "none"))
print("RZP_MODE:"+("live" if os.getenv("RAZORPAY_KEY_ID","").startswith("rzp_live")
       else "test" if os.getenv("RAZORPAY_KEY_ID","").startswith("rzp_test") else "unset"))
PY
else
  warn "container '$CONTAINER' not running here — run this on the VPS for secret checks"
fi 2>/dev/null | while IFS= read -r line; do
  case "$line" in
    CRIT_PLACEHOLDER:none) pass "no placeholder in security-critical secrets" ;;
    CRIT_PLACEHOLDER:*)    fail "CRITICAL secrets are placeholders: ${line#CRIT_PLACEHOLDER:}" ;;
    CRIT_MISSING:none)     pass "all critical secrets present" ;;
    CRIT_MISSING:*)        fail "critical secrets missing: ${line#CRIT_MISSING:}" ;;
    OPT_PLACEHOLDER:none)  pass "optional integration keys configured" ;;
    OPT_PLACEHOLDER:*)     warn "optional integrations unset (feature-degrade only): ${line#OPT_PLACEHOLDER:}" ;;
    RZP_MODE:live)         pass "Razorpay in LIVE mode" ;;
    RZP_MODE:test)         warn "Razorpay in TEST mode — switch to live before selling" ;;
    RZP_MODE:unset)        fail "Razorpay key not set" ;;
    WARN*)                 warn "${line}" ;;
  esac
done
# NOTE: this proves keys are present + non-placeholder. It CANNOT prove the old
# leaked keys were revoked at the provider — verify that manually.
printf "  ${D}(reminder: confirm the OLD leaked keys are REVOKED at each provider)${X}\n"

# ── Blocker 3: payment endpoint reachable ───────────────────────────
head "3. Payment surface"
if have_container; then
  PAYROUTES=$(in_container python3 -c "
from main import app
print(sum(1 for r in app.routes if getattr(r,'path','').startswith('/api/') and any(s in r.path for s in ('pay','razor','billing','checkout','subscri'))))
" 2>/dev/null)
  [ "${PAYROUTES:-0}" -ge 1 ] && pass "$PAYROUTES payment route(s) registered" \
    || fail "no payment routes registered"
else
  warn "skip payment-route check (no container here)"
fi
printf "  ${D}(reminder: run ONE real live transaction end-to-end + a refund)${X}\n"

# ── Blocker 4: backups ──────────────────────────────────────────────
head "4. Backups"
[ -x "$(dirname "$0")/backup_db.sh" ] && pass "backup_db.sh present + executable" \
  || fail "scripts/backup_db.sh missing or not executable"
if crontab -l 2>/dev/null | grep -q 'backup_db.sh'; then pass "backup cron installed"
else warn "no backup cron found (crontab -e to add the daily job)"; fi
RECENT=$(find "$BACKUP_DIR" -name '*.db.gz' -mtime -2 2>/dev/null | wc -l)
[ "${RECENT:-0}" -ge 1 ] && pass "recent backup exists in $BACKUP_DIR (<48h)" \
  || warn "no backup <48h old in $BACKUP_DIR — run backup_db.sh + test a restore"

# ── Recommended (non-blocking) ──────────────────────────────────────
head "5. Recommended (non-blocking)"
for page in terms privacy refund; do
  PC=$(curl -s -m 10 -o /dev/null -w '%{http_code}' "${BASE_URL%/api*}/$page.html" 2>/dev/null)
  [ "$PC" = "200" ] && pass "/$page.html reachable" || warn "/$page.html -> $PC (link it at checkout)"
done

# ── Verdict ─────────────────────────────────────────────────────────
printf "\n${D}═══════════════════════════════════════${X}\n"
if [ "$BLOCKERS" -eq 0 ]; then
  printf "  ${G}GO${X} — 0 blockers, %s warning(s)\n" "$WARNINGS"
  exit 0
else
  printf "  ${R}NO-GO${X} — %s blocker(s), %s warning(s)\n" "$BLOCKERS" "$WARNINGS"
  exit 1
fi
