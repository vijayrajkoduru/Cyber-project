"""Email pattern generation from name + domain — playbook §1 #15.

Target format: "Firstname Lastname@domain.com" or "firstname.lastname@domain.com"
Generates the 12 most common email patterns used by mid-market companies.
Pure-Python — no network call. Output is a candidate list for analysts to
verify (e.g. via SMTP probe or hunter.io if user has API key).

Zero false positives: all entries are clearly labeled as CANDIDATES, not
confirmed addresses.
"""
import asyncio
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 5


def _parse(target: str):
    """Parse 'First Last@domain.com' or 'first.last@domain.com'."""
    target = target.strip()
    if "@" not in target:
        return None, None, None
    name_part, domain = target.rsplit("@", 1)
    name_part = name_part.replace(".", " ").replace("_", " ").strip()
    bits = [b for b in re.split(r"\s+", name_part) if b]
    if len(bits) < 2:
        return None, None, None
    first = bits[0].lower()
    last = bits[-1].lower()
    return first, last, domain.lower()


def _do_scan(req: ScanRequest) -> dict:
    first, last, domain = _parse(req.target or "")
    if not first:
        return standard_response(
            tool="email_pattern_guess", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="target must be 'First Last@domain.com' or 'first.last@domain.com'")

    fi, li = first[0], last[0]
    patterns = [
        f"{first}.{last}@{domain}",
        f"{first}{last}@{domain}",
        f"{first}_{last}@{domain}",
        f"{first}-{last}@{domain}",
        f"{first}@{domain}",
        f"{last}@{domain}",
        f"{fi}{last}@{domain}",
        f"{fi}.{last}@{domain}",
        f"{first}{li}@{domain}",
        f"{first}.{li}@{domain}",
        f"{last}.{first}@{domain}",
        f"{last}{first}@{domain}",
    ]

    findings = [wrap_finding(
        f"Email pattern candidates for {first} {last} @ {domain}",
        severity="POSITIVE", cwe="CWE-200", owasp="A05:2021",
        remediation="Verify candidates via hunter.io domain-search or SMTP "
                    "validation. Most B2B orgs use {first}.{last} (~45% of "
                    "mid-market per Hunter data 2024).",
        evidence_marker=" | ".join(patterns))]

    return standard_response(
        tool="email_pattern_guess", target=req.target, findings=findings,
        tests_performed=len(patterns), vulnerable=False,
        tests_summary=f"{len(patterns)} email pattern candidates generated",
        raw_data={"candidates": patterns, "first": first, "last": last, "domain": domain})


@router.post("/api/osint/email_pattern_guess")
@vl_verify()
async def scan_email_pattern_guess(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="email_pattern_guess", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
