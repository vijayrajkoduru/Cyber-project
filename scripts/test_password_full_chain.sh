#!/usr/bin/env bash
#
# test_password_full_chain.sh
# End-to-end smoke test for the Password Attacks 19-scanner module
# + chaining engine, against the lab containers.
#
# Usage:
#   chmod +x scripts/test_password_full_chain.sh
#   ./scripts/test_password_full_chain.sh
#
# Env vars:
#   BACKEND_URL    default http://localhost:8000
#   BACKEND_JWT    optional bearer token; if unset, auth header is skipped
#   VERBOSE        set to 1 to echo each curl command

set -euo pipefail

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
BACKEND_JWT="${BACKEND_JWT:-}"
VERBOSE="${VERBOSE:-0}"
MAX_TIME=300

# -------------------------------------------------------------------
# Colors
# -------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_GREEN="\033[32m"
  C_RED="\033[31m"
  C_YELLOW="\033[33m"
  C_BLUE="\033[34m"
  C_BOLD="\033[1m"
  C_RESET="\033[0m"
else
  C_GREEN=""; C_RED=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

# -------------------------------------------------------------------
# Counters / state
# -------------------------------------------------------------------
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
FAILED_TESTS=()
SCRIPT_START_TS=$(date +%s)

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
print_header() {
  echo
  printf "%b%b== %s ==%b\n" "$C_BOLD" "$C_BLUE" "$1" "$C_RESET"
}

print_pass() {
  local name="$1" elapsed="$2" http="$3" detail="${4:-}"
  printf "%bPASS%b  %s  (%ss, HTTP %s)" "$C_GREEN" "$C_RESET" "$name" "$elapsed" "$http"
  [[ -n "$detail" ]] && printf "  %s" "$detail"
  echo
  TESTS_PASSED=$((TESTS_PASSED + 1))
}

print_fail() {
  local name="$1" elapsed="$2" http="$3" reason="$4"
  printf "%bFAIL%b  %s  (%ss, HTTP %s)  reason: %s\n" \
    "$C_RED" "$C_RESET" "$name" "$elapsed" "$http" "$reason"
  TESTS_FAILED=$((TESTS_FAILED + 1))
  FAILED_TESTS+=("$name :: $reason")
}

print_skip() {
  local name="$1" reason="$2"
  printf "%bSKIP%b  %s  reason: %s\n" "$C_YELLOW" "$C_RESET" "$name" "$reason"
  TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

print_info() {
  printf "       %s\n" "$1"
}

# Auth header builder (echoes flag pair or nothing)
auth_args=()
if [[ -n "$BACKEND_JWT" ]]; then
  auth_args=(-H "Authorization: Bearer ${BACKEND_JWT}")
fi

# api_post <path> <json_body>  ->  writes status to $LAST_HTTP, body to $LAST_BODY
api_post() {
  local path="$1" body="$2"
  local url="${BACKEND_URL}${path}"
  local tmp
  tmp=$(mktemp)
  if [[ "$VERBOSE" == "1" ]]; then
    echo "+ curl -sS --max-time ${MAX_TIME} -X POST '${url}' -H 'Content-Type: application/json' -d '${body}'"
  fi
  local http
  http=$(curl -sS --max-time "$MAX_TIME" \
    -o "$tmp" -w "%{http_code}" \
    -X POST "$url" \
    -H "Content-Type: application/json" \
    "${auth_args[@]}" \
    -d "$body" || echo "000")
  LAST_HTTP="$http"
  LAST_BODY=$(cat "$tmp")
  rm -f "$tmp"
}

# api_get <path>  ->  same conventions
api_get() {
  local path="$1"
  local url="${BACKEND_URL}${path}"
  local tmp
  tmp=$(mktemp)
  if [[ "$VERBOSE" == "1" ]]; then
    echo "+ curl -sS --max-time ${MAX_TIME} '${url}'"
  fi
  local http
  http=$(curl -sS --max-time "$MAX_TIME" \
    -o "$tmp" -w "%{http_code}" \
    "${auth_args[@]}" \
    "$url" || echo "000")
  LAST_HTTP="$http"
  LAST_BODY=$(cat "$tmp")
  rm -f "$tmp"
}

# json_ok <body>  -> 0 if parses, else dumps first 500 chars
json_ok() {
  local body="$1"
  if printf '%s' "$body" | jq empty >/dev/null 2>&1; then
    return 0
  fi
  printf "%b       Body is not valid JSON. First 500 chars:%b\n" "$C_RED" "$C_RESET"
  printf '%s\n' "${body:0:500}"
  return 1
}

# elapsed_since <start_ts>
elapsed_since() {
  local start="$1"
  local now
  now=$(date +%s)
  echo $((now - start))
}

# lab_running <container_name>
lab_running() {
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"
}

# -------------------------------------------------------------------
# Step 1 — Prereq checks
# -------------------------------------------------------------------
print_header "Prerequisite checks"

missing=()
for bin in curl jq docker; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    missing+=("$bin")
  fi
done
if (( ${#missing[@]} > 0 )); then
  printf "%bFATAL%b missing binaries: %s\n" "$C_RED" "$C_RESET" "${missing[*]}"
  exit 1
fi
print_info "curl, jq, docker present"

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx vulnuslab_backend; then
  printf "%bFATAL%b backend container 'vulnuslab_backend' is not running\n" "$C_RED" "$C_RESET"
  exit 1
fi
print_info "vulnuslab_backend container is running"

# -------------------------------------------------------------------
# Step 2 — Backend health
# -------------------------------------------------------------------
print_header "Backend health"

api_get "/api/health"
if [[ "$LAST_HTTP" != "200" ]]; then
  printf "%bFATAL%b /api/health returned HTTP %s\n" "$C_RED" "$C_RESET" "$LAST_HTTP"
  printf '%s\n' "${LAST_BODY:0:500}"
  exit 1
fi
print_info "/api/health OK"

# -------------------------------------------------------------------
# Step 3 — Lab inventory
# -------------------------------------------------------------------
print_header "Lab container inventory"

LAB_SSH=0; LAB_SMB=0; LAB_WEB=0; LAB_AD=0; LAB_OAUTH=0; LAB_SAML=0
lab_running lab_pwd_ssh   && LAB_SSH=1   || true
lab_running lab_pwd_smb   && LAB_SMB=1   || true
lab_running lab_pwd_web   && LAB_WEB=1   || true
lab_running lab_pwd_ad    && LAB_AD=1    || true
lab_running lab_pwd_oauth && LAB_OAUTH=1 || true
lab_running lab_pwd_saml  && LAB_SAML=1  || true

print_info "lab_pwd_ssh:   $([[ $LAB_SSH   == 1 ]] && echo up || echo down)"
print_info "lab_pwd_smb:   $([[ $LAB_SMB   == 1 ]] && echo up || echo down)"
print_info "lab_pwd_web:   $([[ $LAB_WEB   == 1 ]] && echo up || echo down)"
print_info "lab_pwd_ad:    $([[ $LAB_AD    == 1 ]] && echo up || echo down)"
print_info "lab_pwd_oauth: $([[ $LAB_OAUTH == 1 ]] && echo up || echo down)"
print_info "lab_pwd_saml:  $([[ $LAB_SAML  == 1 ]] && echo up || echo down)"

# -------------------------------------------------------------------
# Test 1 — Phase A: Hydra SSH against lab_pwd_ssh
# -------------------------------------------------------------------
print_header "Test 1 — hydra_ssh_spray vs lab_pwd_ssh"

T_NAME="Test 1 (hydra_ssh_spray)"
if (( LAB_SSH == 0 )); then
  print_skip "$T_NAME" "lab_pwd_ssh not running"
else
  T_START=$(date +%s)
  read -r -d '' BODY <<'JSON' || true
{
  "target": "lab_pwd_ssh",
  "options": {
    "port": 2222,
    "userlist": "admin",
    "passlist": "admin",
    "always_deep": true
  }
}
JSON
  api_post "/api/password/hydra_ssh_spray" "$BODY"
  T_ELAPSED=$(elapsed_since "$T_START")

  if [[ "$LAST_HTTP" != "200" ]]; then
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "non-200 response"
  elif ! json_ok "$LAST_BODY"; then
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "invalid JSON"
  else
    sev=$(jq -r '[.findings[]? | select(.severity=="MEDIUM" or .severity=="HIGH")] | length' <<<"$LAST_BODY")
    conf=$(jq -r '.raw_data.methodology_findings[0].confidence // "MISSING"' <<<"$LAST_BODY")
    chain_next_len=$(jq -r '(.raw_data.methodology_findings[0].chain_next // []) | length' <<<"$LAST_BODY")

    if (( sev >= 1 )) && [[ "$conf" == "CONFIRMED" ]] && (( chain_next_len >= 1 )); then
      print_pass "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" \
        "findings(M/H)=$sev confidence=$conf chain_next=$chain_next_len"
    else
      print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" \
        "expected findings(M/H)>=1 + CONFIRMED + chain_next>=1; got sev=$sev conf=$conf chain_next=$chain_next_len"
    fi
  fi
fi

# -------------------------------------------------------------------
# Test 2 — Phase B: Patator HTTP form vs lab_pwd_web
# -------------------------------------------------------------------
print_header "Test 2 — patator_http_form_brute vs lab_pwd_web"

T_NAME="Test 2 (patator_http_form_brute)"
if (( LAB_WEB == 0 )); then
  print_skip "$T_NAME" "lab_pwd_web not running"
else
  T_START=$(date +%s)
  read -r -d '' BODY <<'JSON' || true
{
  "target": "lab_pwd_web",
  "options": {
    "form_url": "http://lab_pwd_web:5000/login",
    "user_field": "username",
    "pass_field": "password",
    "fail_string": "Invalid credentials",
    "userlist": "admin",
    "passlist": "admin",
    "always_deep": true
  }
}
JSON
  api_post "/api/password/patator_http_form_brute" "$BODY"
  T_ELAPSED=$(elapsed_since "$T_START")

  if [[ "$LAST_HTTP" != "200" ]]; then
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "non-200 response"
  elif ! json_ok "$LAST_BODY"; then
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "invalid JSON"
  else
    confirmed=$(jq -r '
      [
        .findings[]? |
        select(
          ((.confidence // (.evidence.confidence // "")) == "CONFIRMED")
          and (((.username // .user // "") | ascii_downcase) == "admin")
        )
      ] | length
    ' <<<"$LAST_BODY")

    # Fallback: also accept methodology_findings[].confidence == CONFIRMED
    if (( confirmed == 0 )); then
      confirmed=$(jq -r '
        [.raw_data.methodology_findings[]? | select(.confidence=="CONFIRMED")] | length
      ' <<<"$LAST_BODY")
    fi

    if (( confirmed >= 1 )); then
      print_pass "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "confirmed_admin_creds=$confirmed"
    else
      print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" \
        "no CONFIRMED admin credential found in response"
    fi
  fi
fi

# -------------------------------------------------------------------
# Test 3 — Phase B: Medusa SMB vs lab_pwd_smb
# -------------------------------------------------------------------
print_header "Test 3 — medusa_smb_spray vs lab_pwd_smb"

T_NAME="Test 3 (medusa_smb_spray)"
if (( LAB_SMB == 0 )); then
  print_skip "$T_NAME" "lab_pwd_smb not running"
else
  T_START=$(date +%s)
  read -r -d '' BODY <<'JSON' || true
{
  "target": "lab_pwd_smb",
  "options": {
    "port": 445,
    "userlist": "admin",
    "passlist": "admin",
    "always_deep": true
  }
}
JSON
  api_post "/api/password/medusa_smb_spray" "$BODY"
  T_ELAPSED=$(elapsed_since "$T_START")

  if [[ "$LAST_HTTP" != "200" ]]; then
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "non-200 response"
  elif ! json_ok "$LAST_BODY"; then
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "invalid JSON"
  else
    confirmed=$(jq -r '
      [
        .findings[]? |
        select(((.confidence // (.evidence.confidence // "")) == "CONFIRMED"))
      ] | length
    ' <<<"$LAST_BODY")
    if (( confirmed == 0 )); then
      confirmed=$(jq -r '
        [.raw_data.methodology_findings[]? | select(.confidence=="CONFIRMED")] | length
      ' <<<"$LAST_BODY")
    fi

    if (( confirmed >= 1 )); then
      print_pass "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "confirmed_creds=$confirmed"
    else
      print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "no CONFIRMED credential found"
    fi
  fi
fi

# -------------------------------------------------------------------
# Test 4 — Phase C: chaining engine via run_all_buffered (AD lab)
# -------------------------------------------------------------------
print_header "Test 4 — chaining engine (ldap_brute -> kerberoast/asreproast/dcsync/bloodhound)"

T_NAME="Test 4 (chaining_ad)"
if (( LAB_AD == 0 )); then
  print_skip "$T_NAME" "AD lab not running"
else
  T_START=$(date +%s)
  read -r -d '' BODY <<'JSON' || true
{
  "target": "dc01.vlrange.local",
  "tiers": ["tier1_spray", "tier3_ad"],
  "options": {
    "userlist": "Administrator",
    "passlist": "VLrange_Admin_2026!",
    "domain": "vlrange.local",
    "dc_ip": "dc01.vlrange.local",
    "always_deep": true,
    "enable_chaining": true
  }
}
JSON
  api_post "/api/password/run_all_buffered" "$BODY"
  T_ELAPSED=$(elapsed_since "$T_START")

  if [[ "$LAST_HTTP" != "200" ]]; then
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "non-200 response"
  elif ! json_ok "$LAST_BODY"; then
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "invalid JSON"
  else
    chained=$(jq -r '.chain_summary.chained_scans // 0' <<<"$LAST_BODY")
    registered=$(jq -r '.chain_summary.registered_chain_scanners // [] | join(",")' <<<"$LAST_BODY")

    required=(kerberoast_audit asreproast_audit dcsync_audit bloodhound_audit)
    missing=()
    for r in "${required[@]}"; do
      if ! grep -q "$r" <<<"$registered"; then
        missing+=("$r")
      fi
    done

    kerb_findings=$(jq -r '
      [
        ( .chain_results.kerberoast_audit?.findings // [] ),
        ( .results.kerberoast_audit?.findings // [] ),
        ( .raw_data.chain_results.kerberoast_audit?.findings // [] )
      ] | add // [] | length
    ' <<<"$LAST_BODY")

    print_info "chain_summary: chained_scans=$chained  registered=[$registered]"
    print_info "kerberoast_audit findings: $kerb_findings"

    if (( chained > 0 )) && (( ${#missing[@]} == 0 )) && (( kerb_findings >= 1 )); then
      print_pass "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" \
        "chained=$chained kerb_findings=$kerb_findings"
    else
      reason="chained=$chained"
      (( ${#missing[@]} > 0 )) && reason+=" missing_registered=${missing[*]}"
      (( kerb_findings == 0 )) && reason+=" kerberoast_audit_findings=0"
      print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "$reason"
    fi
  fi
fi

# -------------------------------------------------------------------
# Test 5 — chain_registry health check (no labs needed)
# -------------------------------------------------------------------
print_header "Test 5 — chain_registry health check"

T_NAME="Test 5 (chain_registry_health)"
T_START=$(date +%s)
BODY='{"target":"localhost","options":{}}'
api_post "/api/password/run_all_buffered" "$BODY"
T_ELAPSED=$(elapsed_since "$T_START")

if [[ "$LAST_HTTP" != "200" ]]; then
  print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "non-200 response"
elif ! json_ok "$LAST_BODY"; then
  print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "invalid JSON"
else
  reg_count=$(jq -r '.chain_summary.registered_chain_scanners // [] | length' <<<"$LAST_BODY")
  reg_list=$(jq -r '.chain_summary.registered_chain_scanners // [] | join(",")' <<<"$LAST_BODY")
  expected=(kerberoast asreproast dcsync bloodhound jwt_forge session_predict oauth_token saml_signature)
  missing=()
  for e in "${expected[@]}"; do
    if ! grep -q "$e" <<<"$reg_list"; then
      missing+=("$e")
    fi
  done

  print_info "registered_chain_scanners ($reg_count): [$reg_list]"

  if (( reg_count >= 8 )) && (( ${#missing[@]} == 0 )); then
    print_pass "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "registered=$reg_count"
  else
    reason="registered=$reg_count"
    (( ${#missing[@]} > 0 )) && reason+=" missing=${missing[*]}"
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "$reason"
  fi
fi

# -------------------------------------------------------------------
# Test 6 — PDF v4 INSUFFICIENT detection (skipped_reason fires)
# -------------------------------------------------------------------
print_header "Test 6 — PDF v4 INSUFFICIENT (skipped_reason population)"

T_NAME="Test 6 (insufficient_detection)"
T_START=$(date +%s)
BODY='{"target":"localhost","options":{}}'
api_post "/api/password/run_all_buffered" "$BODY"
T_ELAPSED=$(elapsed_since "$T_START")

if [[ "$LAST_HTTP" != "200" ]]; then
  print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "non-200 response"
elif ! json_ok "$LAST_BODY"; then
  print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "invalid JSON"
else
  skipped=$(jq -r '
    [
      ( .results // {} | to_entries[] | select(.value.skipped_reason and .value.skipped_reason != "") ),
      ( .scanner_results // {} | to_entries[] | select(.value.skipped_reason and .value.skipped_reason != "") ),
      ( .raw_data.results // {} | to_entries[] | select(.value.skipped_reason and .value.skipped_reason != "") )
    ] | length
  ' <<<"$LAST_BODY")

  reasons=$(jq -r '
    [
      ( .results // {} | to_entries[] | .value.skipped_reason // empty ),
      ( .scanner_results // {} | to_entries[] | .value.skipped_reason // empty ),
      ( .raw_data.results // {} | to_entries[] | .value.skipped_reason // empty )
    ] | unique | join("|")
  ' <<<"$LAST_BODY")

  print_info "scanners_skipped=$skipped reasons=[$reasons]"

  if (( skipped >= 2 )); then
    print_pass "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" "skipped=$skipped"
  else
    print_fail "$T_NAME" "$T_ELAPSED" "$LAST_HTTP" \
      "expected >=2 scanners with skipped_reason; got $skipped"
  fi
fi

# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------
SCRIPT_ELAPSED=$(elapsed_since "$SCRIPT_START_TS")

echo
printf "%b%b== Summary ==%b\n" "$C_BOLD" "$C_BLUE" "$C_RESET"
printf "%bPASSED:%b  %d\n" "$C_GREEN"  "$C_RESET" "$TESTS_PASSED"
printf "%bFAILED:%b  %d\n" "$C_RED"    "$C_RESET" "$TESTS_FAILED"
printf "%bSKIPPED:%b %d\n" "$C_YELLOW" "$C_RESET" "$TESTS_SKIPPED"
printf "Total elapsed: %ds\n" "$SCRIPT_ELAPSED"

if (( TESTS_FAILED > 0 )); then
  echo
  printf "%bFailed tests:%b\n" "$C_RED" "$C_RESET"
  for f in "${FAILED_TESTS[@]}"; do
    printf "  - %s\n" "$f"
  done
  exit 1
fi

exit 0
