"""HIBP Pwned Passwords k-anonymity check — playbook §1 #2.

Probe target is a password string passed as the `target`. Sends only the
first 5 chars of SHA-1 (k-anonymity) to HIBP; the API returns all hashes
matching that prefix and we check the remainder client-side. The actual
password never leaves the box.

Real probe, no API key required. Zero false positives — HIBP returns
exact appearance count from breach corpus.
"""
import asyncio
import hashlib
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 10

# Anything that looks like a domain (label.tld) or URL or email is NOT a
# password. The OSINT orchestrator passes the scan target (usually a domain)
# to every scanner; without this guard, HIBP hashes the domain string itself
# and reports it as "exposed" because common words like "example.com" appear
# in breach corpora as ACTUAL passwords used by other people.
_DOMAINISH = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_TLDS = {"com","net","org","co","io","ai","app","dev","me","us","uk","in",
          "de","fr","ca","au","jp","cn","ru","br","es","it","nl","gov","edu"}


def _looks_like_target_not_password(s: str) -> bool:
    if "://" in s or "@" in s:
        return True
    if _DOMAINISH.match(s):
        tld = s.rsplit(".", 1)[-1].lower()
        if tld in _TLDS:
            return True
    return False


def _do_scan(req: ScanRequest) -> dict:
    password = (req.target or "").strip()
    if not password:
        return standard_response(
            tool="hibp_passwords", target="(redacted)", findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty target — pass the password as the target string")

    if _looks_like_target_not_password(password):
        return standard_response(
            tool="hibp_passwords", target="(redacted)", findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason=("Target looks like a domain or URL, not a password. "
                            "This scanner requires an actual password string. "
                            "Pass the password directly when running this check "
                            "standalone; the OSINT orchestrator should not call "
                            "this scanner with the scan target domain."))

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    r = safe_get(f"https://api.pwnedpasswords.com/range/{prefix}",
                  req=req, timeout=8)
    if r is None or r.status_code != 200:
        return standard_response(
            tool="hibp_passwords", target="(redacted)", findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"HIBP unreachable (status={r.status_code if r else 'no-conn'})")

    count = 0
    for line in r.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            try:
                count = int(parts[1])
            except ValueError:
                count = 0
            break

    if count == 0:
        return standard_response(
            tool="hibp_passwords", target="(redacted)",
            findings=[wrap_finding(
                "Password NOT found in HIBP breach corpus",
                severity="POSITIVE", cwe="CWE-521", owasp="A07:2021",
                remediation="No action — this password has not appeared in any "
                            "of HIBP's 800M+ breached credentials. Continue rotating regularly.",
                evidence_marker=f"SHA-1 prefix {prefix}…: 0 appearances")],
            tests_performed=1, vulnerable=False,
            tests_summary="HIBP Pwned Passwords k-anonymity check (CONFIRMED clean)")

    severity = "CRITICAL" if count > 100000 else "HIGH" if count > 1000 else "MEDIUM"
    return standard_response(
        tool="hibp_passwords", target="(redacted)",
        findings=[wrap_finding(
            f"Password found in HIBP breach corpus — appears {count:,} times",
            severity=severity, cwe="CWE-521", cvss="7.5",
            owasp="A07:2021",
            remediation="ROTATE THIS PASSWORD IMMEDIATELY. It has been exposed "
                        "in known breaches and is on every credential-stuffing wordlist. "
                        "Choose a unique passphrase or use a password manager.",
            evidence_marker=f"SHA-1 prefix {prefix}…: {count} appearances (CONFIRMED via HIBP)")],
        tests_performed=1, vulnerable=True,
        tests_summary=f"HIBP Pwned Passwords — {count:,} appearances",
        raw_data={"appearance_count": count, "sha1_prefix": prefix})


@router.post("/api/osint/hibp_passwords")
@vl_verify()
async def scan_hibp_passwords(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="hibp_passwords", target="(redacted)", findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
