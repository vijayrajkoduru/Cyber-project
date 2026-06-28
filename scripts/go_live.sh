#!/usr/bin/env bash
# One-shot go-live for the production VPS. Idempotent — safe to re-run.
#
#   ssh root@<vps>
#   cd ~/Cyber-project && ./scripts/go_live.sh
#
# Fixes the deployable blockers automatically:
#   1. pulls latest code
#   2. generates a real CREDENTIAL_VAULT_MASTER_KEY *only if* it is still a
#      placeholder (never overwrites a real key — that would orphan vault data)
#   3. rebuilds + restarts the backend, waits for health
#   4. installs the daily backup cron (if missing) and takes one backup now
#   5. runs the launch preflight and prints GO / NO-GO
#
# It deliberately does NOT touch: provider-side key revocation, or the live
# payment test — those are printed as manual reminders at the end.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
ENV_FILE="$ROOT/.env"
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; D='\033[2m'; X='\033[0m'
step() { printf "\n${D}▶ %s${X}\n" "$1"; }

# ── 1. latest code ──────────────────────────────────────────────────
step "1/5 git pull"
git pull --ff-only || { printf "${R}git pull failed — resolve manually${X}\n"; exit 1; }

# ── 2. vault master key (guarded) ───────────────────────────────────
step "2/5 CREDENTIAL_VAULT_MASTER_KEY"
if [ ! -f "$ENV_FILE" ]; then
  printf "${R}.env not found at %s — create it first${X}\n" "$ENV_FILE"; exit 1
fi
CUR="$(grep -E '^CREDENTIAL_VAULT_MASTER_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
is_placeholder=0
case "$(printf '%s' "$CUR" | tr 'A-Z' 'a-z')" in
  ""|"<key>"|*changeme*|*placeholder*|*your_*|*paste_*) is_placeholder=1 ;;
esac
# A valid Fernet key is 44 url-safe base64 chars; anything shorter is bogus.
[ "${#CUR}" -lt 40 ] && is_placeholder=1
if [ "$is_placeholder" -eq 1 ]; then
  NEWKEY="$(openssl rand 32 | base64 | tr '+/' '-_')"   # urlsafe b64 -> valid Fernet key
  cp "$ENV_FILE" "$ENV_FILE.bak.$(date +%Y%m%d-%H%M%S)"
  if grep -qE '^CREDENTIAL_VAULT_MASTER_KEY=' "$ENV_FILE"; then
    sed -i "s|^CREDENTIAL_VAULT_MASTER_KEY=.*|CREDENTIAL_VAULT_MASTER_KEY=$NEWKEY|" "$ENV_FILE"
  else
    printf "\nCREDENTIAL_VAULT_MASTER_KEY=%s\n" "$NEWKEY" >> "$ENV_FILE"
  fi
  printf "${G}generated a real vault master key${X} (.env backed up)\n"
  printf "${Y}note: only safe because the old value was a placeholder. If the vault\n"
  printf "      already held data under a real key, restore the .bak and re-key per\n"
  printf "      docs/ROTATE-SECRETS.md instead.${X}\n"
else
  printf "${G}already a real key — left untouched${X}\n"
fi

# ── 3. deploy ───────────────────────────────────────────────────────
step "3/5 rebuild + restart backend"
docker compose build --no-cache backend
docker compose up -d
printf "${D}waiting for backend health...${X}\n"
ok=0
for _ in $(seq 1 30); do
  code="$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://localhost:8000/api/health 2>/dev/null || echo 000)"
  if [ "$code" = "200" ]; then ok=1; break; fi
  sleep 3
done
[ "$ok" = "1" ] && printf "${G}backend healthy${X}\n" || printf "${R}backend not healthy after 90s — check: docker compose logs backend${X}\n"

# ── 4. backups ──────────────────────────────────────────────────────
step "4/5 backups"
CRON_LINE="15 3 * * * $ROOT/scripts/backup_db.sh >> /var/log/vl-backup.log 2>&1"
if crontab -l 2>/dev/null | grep -q 'backup_db.sh'; then
  printf "${G}backup cron already installed${X}\n"
else
  ( crontab -l 2>/dev/null; echo "$CRON_LINE" ) | crontab -
  printf "${G}installed daily backup cron (03:15)${X}\n"
fi
"$ROOT/scripts/backup_db.sh" || printf "${Y}backup run reported an issue — check output above${X}\n"

# ── 5. preflight ────────────────────────────────────────────────────
step "5/5 launch preflight"
"$ROOT/scripts/preflight_launch.sh"; RC=$?

# ── manual reminders ────────────────────────────────────────────────
printf "\n${Y}MANUAL — a script cannot verify these:${X}\n"
printf "  • Confirm the OLD leaked keys are REVOKED at each provider\n"
printf "    (Razorpay, Anthropic, ZeptoMail, GitHub) — see docs/ROTATE-SECRETS.md\n"
printf "  • Run ONE real live transaction end-to-end, then refund it\n"
exit $RC
