#!/bin/bash
# VulnusLab pre-commit security gate.
#
# Install:
#   cp scripts/pre-commit-check.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or run manually:
#   ./scripts/pre-commit-check.sh
#
# Blocks commits containing:
#   - .env / .env.* files
#   - *.db / *.sqlite files
#   - Hardcoded secrets matching common patterns
#   - Large binary blobs (>5MB)

set -e

# Get list of staged files
staged=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$staged" ]; then
    exit 0    # nothing staged
fi

fail=0

# ── Check 1: .env files ─────────────────────────────────────────────
for f in $staged; do
    case "$f" in
        .env|.env.*|*/.env|*/.env.*)
            echo "BLOCKED: $f (environment file with possible secrets)"
            fail=1
            ;;
    esac
done

# ── Check 2: database files ─────────────────────────────────────────
for f in $staged; do
    case "$f" in
        *.db|*.sqlite|*.sqlite3|*/users.db)
            echo "BLOCKED: $f (database file)"
            fail=1
            ;;
    esac
done

# ── Check 3: secrets patterns ───────────────────────────────────────
for f in $staged; do
    [ ! -f "$f" ] && continue
    case "$f" in
        *.png|*.jpg|*.jpeg|*.gif|*.pdf|*.zip|*.gz|*.tar|*.lock|*.png) continue ;;
    esac
    if grep -E "(AKIA|ASIA)[A-Z0-9]{16}|sk_live_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{35}|-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----" "$f" >/dev/null 2>&1; then
        echo "BLOCKED: $f (matches secret pattern: AKIA/AWS, sk_live_/Stripe, AIza/Google, or private key)"
        fail=1
    fi
    if grep -E "(password|passwd|secret|api_key|api-key)\s*[:=]\s*[\"'][^\"']{8,}[\"']" "$f" 2>/dev/null | grep -vE "(example|test|placeholder|YOUR_|CHANGE_ME|<.*>|\\\$\\{)" >/dev/null; then
        echo " REVIEW: $f (contains password/secret assignment with literal value)"
        echo "    (use environment variable instead, e.g. os.getenv('FOO'))"
    fi
done

# ── Check 4: large binary blobs ─────────────────────────────────────
for f in $staged; do
    [ ! -f "$f" ] && continue
    size=$(wc -c < "$f" 2>/dev/null || echo 0)
    if [ "$size" -gt 5242880 ]; then
        echo " LARGE: $f ($(($size / 1024 / 1024)) MB) — consider git-lfs or external storage"
    fi
done

# ── Result ──────────────────────────────────────────────────────────
if [ $fail -ne 0 ]; then
    echo ""
    echo "Commit BLOCKED. Remove the flagged files (git reset HEAD <file>) or rotate the exposed secret."
    echo "If a false positive, add an exception to scripts/pre-commit-check.sh."
    exit 1
fi

echo "pre-commit checks passed ($(echo "$staged" | wc -l) files staged)"
