"""Email-focused OSINT — pattern generation + target page scraping."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url, safe_get

router = APIRouter()


COMMON_PREFIXES = ["info","contact","admin","support","sales","security","webmaster",
                   "noreply","no-reply","hello","mail","abuse","postmaster","team",
                   "office","press","hr","careers","jobs","help","feedback",
                   "marketing","privacy","legal","dpo","compliance"]
CONTACT_PAGES = ["","/contact","/contact-us","/about","/about-us","/team",
                 "/staff","/people","/imprint","/legal","/privacy","/terms","/support"]


@router.post("/api/osint/email_osint")
async def osint_email(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target).lower()
    emails = set()
    for p in COMMON_PREFIXES:
        emails.add(f"{p}@{host}")
    generated = len(emails)
    scraped = []
    base = web_url(req.target).rstrip("/")
    pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    for p in CONTACT_PAGES:
        r = safe_get(base + p, req=req, allow_redirects=True, timeout=8)
        if r is None or r.status_code != 200:
            continue
        for m in pattern.findall(r.text or ""):
            ml = m.lower()
            if host in ml or ml.endswith("." + host):
                if ml not in emails:
                    scraped.append(ml)
                emails.add(ml)
    return {"ok": True, "target": host,
            "emails": sorted(emails), "total_emails": len(emails),
            "pattern_generated": generated, "scraped_real": len(scraped),
            "scraped_emails": scraped}


def register(app):
    app.include_router(router)
