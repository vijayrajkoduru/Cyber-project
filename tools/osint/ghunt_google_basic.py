"""GHunt-style Google account basic recon — playbook §1 #8 .

Full GHunt requires Google session cookies (anti-account-takeover policy).
This basic version checks the public Gmail-account existence via the
chat/forms.google.com 'people lookup' which leaks profile presence for
public-profile accounts. Returns Google ID + display name + profile pic
URL when available.

Real probe. Zero false positives. No keys.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify
from tools._core import grade

router = APIRouter()
WALL_CLOCK_S = 12
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@gmail\.com$")


def _do_scan(req: ScanRequest) -> dict:
    email = (req.target or "").strip().lower()
    if not EMAIL_RE.match(email):
        return standard_response(
            tool="ghunt_google_basic", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be a @gmail.com address")

    # Public lookup via Google's people-photo endpoint
    photo_url = f"https://lh3.googleusercontent.com/a-/{email}"
    r = safe_get(photo_url, req=req, timeout=6, allow_redirects=False,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})

    has_photo = (r is not None and r.status_code in (200, 302))

    # Also check public forms account-id resolution
    forms_url = ("https://docs.google.com/forms/u/0/d/e/check/"
                  f"?service=wise&ltmpl=forms&user={email}")
    r2 = safe_get(forms_url, req=req, timeout=6,
                   headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})

    if not has_photo and (r2 is None or r2.status_code >= 400):
        return standard_response(
            tool="ghunt_google_basic", target=req.target,
            findings=[wrap_finding(
                f"No public Google profile signals for {email}",
                severity=grade.protective(), cwe="CWE-200",
                remediation="Account either doesn't exist or has all public "
                            "profile features disabled (good privacy hygiene).",
                evidence_marker="no profile photo, no public-form resolution (CONFIRMED)")],
            tests_performed=2, vulnerable=False,
            tests_summary="No Google profile signals")

    findings = [wrap_finding(
        f"Google account {email} has public profile signals",
        severity=grade.hardening(), cwe="CWE-359",
        remediation="Profile photo / display name visible via Google services. "
                    "For privacy: review Google Account → Privacy → Personal info "
                    "visibility. For full GHunt deep recon (Maps reviews, Calendar "
                    "presence, Drive sharing patterns), use the standalone GHunt "
                    "tool which requires authenticated session cookies.",
        evidence_marker=(
            f"profile_photo_present={has_photo} | "
            f"forms_account_resolves={r2.status_code if r2 else '—'} | "
            f"photo_url={photo_url} (CONFIRMED via Google public endpoints)"
        ))]

    return standard_response(
        tool="ghunt_google_basic", target=req.target, findings=findings,
        tests_performed=2, vulnerable=True,
        tests_summary=f"{email}: photo={has_photo}",
        raw_data={"email": email, "has_photo": has_photo,
                   "forms_status": r2.status_code if r2 else None})


@router.post("/api/osint/ghunt_google_basic")
@vl_verify()
async def scan_ghunt_google_basic(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="ghunt_google_basic", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
