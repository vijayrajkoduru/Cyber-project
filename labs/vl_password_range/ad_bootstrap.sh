#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# VulnusLab — Phase C Active Directory lab user seeder
# ─────────────────────────────────────────────────────────────────────
#
# Run via:
#     docker compose exec lab_pwd_ad bash /bootstrap.sh
#
# Requires:
#     - lab_pwd_ad container is healthy (Samba AD DC provisioned ~90s after first up)
#     - File is mounted at /bootstrap.sh (see docker-compose.yml volume)
#     - On the host, ensure executable:  chmod +x labs/vl_password_range/ad_bootstrap.sh
#
# Seeds five deterministic test users that exercise every Phase C scanner:
#
#   Administrator / VLrange_Admin_2026!   (Domain Admin — set by image at provision)
#   svc_mssql     / Password123           (kerberoastable, SPN MSSQLSvc/sql01.vlrange.local:1433)
#   svc_http      / Spring2024            (kerberoastable, SPN HTTP/web01.vlrange.local)
#   jbloggs       / NoPreAuth!            (AS-REP roastable — DONT_REQUIRE_PREAUTH UAC bit set)
#   regularuser   / regularuser           (standard domain user — no SPN, no flags)
#
# Idempotent: each samba-tool / ldbmodify step tolerates "already exists" errors.
# ─────────────────────────────────────────────────────────────────────

set -u

REALM="VLRANGE.LOCAL"
DOMAIN_DN="DC=vlrange,DC=local"
USERS_DN="CN=Users,${DOMAIN_DN}"

log()  { printf "[ad_bootstrap] %s\n" "$*"; }
warn() { printf "[ad_bootstrap] WARN: %s\n" "$*" >&2; }

# Wait until samba-tool is happy talking to the DC (max 60s)
log "Waiting for Samba AD DC to be ready..."
for i in $(seq 1 30); do
    if samba-tool domain info 127.0.0.1 >/dev/null 2>&1; then
        log "DC ready (took ${i}*2s)."
        break
    fi
    sleep 2
done

# ── 1. svc_mssql — kerberoastable via MSSQLSvc SPN ──────────────────
log "Creating svc_mssql..."
samba-tool user create svc_mssql 'Password123' \
    --given-name=Service --surname=MSSQL \
    --description="Kerberoastable test account (MSSQL)" \
    2>&1 | grep -v "already exists" || true

log "Adding SPN MSSQLSvc/sql01.vlrange.local:1433 to svc_mssql..."
samba-tool spn add MSSQLSvc/sql01.vlrange.local:1433 svc_mssql 2>&1 \
    | grep -v "already" || true

# ── 2. svc_http — kerberoastable via HTTP SPN ───────────────────────
log "Creating svc_http..."
samba-tool user create svc_http 'Spring2024' \
    --given-name=Service --surname=HTTP \
    --description="Kerberoastable test account (HTTP)" \
    2>&1 | grep -v "already exists" || true

log "Adding SPN HTTP/web01.vlrange.local to svc_http..."
samba-tool spn add HTTP/web01.vlrange.local svc_http 2>&1 \
    | grep -v "already" || true

# ── 3. jbloggs — AS-REP roastable (DONT_REQUIRE_PREAUTH) ────────────
log "Creating jbloggs..."
samba-tool user create jbloggs 'NoPreAuth!' \
    --given-name=Joe --surname=Bloggs \
    --description="AS-REP roastable test account" \
    2>&1 | grep -v "already exists" || true

log "Disabling password expiry on jbloggs..."
samba-tool user setexpiry jbloggs --noexpiry 2>&1 || true

# Set DONT_REQUIRE_PREAUTH (UAC bit 0x400000 = 4194304) via ldbmodify.
# Combined with the default NORMAL_ACCOUNT (0x200 = 512), userAccountControl
# should be 4194816 (0x400200).
log "Setting DONT_REQUIRE_PREAUTH UAC bit on jbloggs..."
LDIF_TMP=$(mktemp)
cat > "${LDIF_TMP}" <<LDIF
dn: CN=jbloggs,${USERS_DN}
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
LDIF
ldbmodify -H /var/lib/samba/private/sam.ldb "${LDIF_TMP}" 2>&1 || \
    warn "ldbmodify failed for jbloggs — DONT_REQUIRE_PREAUTH may not be set."
rm -f "${LDIF_TMP}"

# ── 4. regularuser — plain domain user ──────────────────────────────
log "Creating regularuser..."
samba-tool user create regularuser 'regularuser' \
    --given-name=Regular --surname=User \
    --description="Standard domain user — no SPN, no flags" \
    2>&1 | grep -v "already exists" || true

# ── Verification ────────────────────────────────────────────────────
log "Seeded users:"
samba-tool user list 2>/dev/null | grep -E "^(Administrator|svc_mssql|svc_http|jbloggs|regularuser)$" || \
    warn "samba-tool user list returned unexpected output."

log "Seeded SPNs (look for MSSQLSvc/ and HTTP/):"
samba-tool spn list svc_mssql 2>/dev/null || true
samba-tool spn list svc_http  2>/dev/null || true

log "Bootstrap complete."
