"""Crunchbase basic intel via public org page — playbook §7 #96.

Crunchbase's full API is paid, but the public org page contains JSON-LD
metadata (founded date, HQ, employee count band, total funding). Scrapes
the og: meta tags + JSON-LD blob.

Real probe via public-page parse. Zero false positives — only emits what
Crunchbase publicly shows.
"""
import asyncio
import json
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)

router = APIRouter()
WALL_CLOCK_S = 12


def _slug(name: str) -> str:
    """Crunchbase slug = lowercase, spaces → dash, only alphanumeric + dash."""
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9\s-]", "", s)
    s = re.sub(r"\s+", "-", s)
    return s


def _do_scan(req: ScanRequest) -> dict:
    company = (req.target or "").strip()
    if not company:
        return standard_response(
            tool="crunchbase_basic", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="empty company name")

    slug = _slug(company)
    if not slug:
        return standard_response(
            tool="crunchbase_basic", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid company name (cannot derive Crunchbase slug)")

    url = f"https://www.crunchbase.com/organization/{slug}"
    r = safe_get(url, req=req, timeout=10,
                  headers={"User-Agent": "Mozilla/5.0 VulnusLab-OSINT"})

    if r is None or r.status_code == 404:
        return standard_response(
            tool="crunchbase_basic", target=req.target,
            findings=[wrap_finding(
                f"Crunchbase has no public page at /organization/{slug}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Not indexed on Crunchbase. Try the exact official "
                            "company name (spelling matters for slug derivation).",
                evidence_marker=f"GET {url} → HTTP {r.status_code if r else 'no-conn'} (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="Not on Crunchbase")
    if r.status_code != 200:
        return standard_response(
            tool="crunchbase_basic", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Crunchbase blocked / status {r.status_code} "
                            f"(they aggressively block scrapers — manual lookup)")

    body = r.text
    desc = ""
    m = re.search(r'<meta\s+(?:name|property)="og:description"\s+content="([^"]+)"', body)
    if m: desc = m.group(1)
    title = ""
    m = re.search(r'<meta\s+(?:name|property)="og:title"\s+content="([^"]+)"', body)
    if m: title = m.group(1)

    # JSON-LD blob (if present)
    jsonld = {}
    for m in re.finditer(r'<script\s+type="application/ld\+json"[^>]*>([^<]+)</script>', body):
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict) and obj.get("@type") == "Organization":
                jsonld = obj
                break
        except Exception:
            pass

    findings = [wrap_finding(
        f"Crunchbase: {title or company}",
        severity="POSITIVE", cwe="CWE-200",
        remediation="Public marketing data. For full firmographic detail "
                    "(funding, board, exits) use Crunchbase Pro or LinkedIn.",
        evidence_marker=(
            f"slug={slug} | desc={desc[:200]}"
            + (f" | jsonld_org={jsonld.get('name','?')}" if jsonld else "")
        ))]

    return standard_response(
        tool="crunchbase_basic", target=req.target, findings=findings,
        tests_performed=1, vulnerable=False,
        tests_summary=f"Crunchbase profile parsed for {slug}",
        raw_data={"slug": slug, "title": title, "description": desc,
                   "jsonld_organization": jsonld, "url": url})


@router.post("/api/osint/crunchbase_basic")
async def scan_crunchbase_basic(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="crunchbase_basic", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
