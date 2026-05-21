"""recon_harvester -- isolated tool (Kali-style architecture).

Route: /api/recon/harvester
Split from recon_module.py monolith by scripts/split_recon_module.py.
Failure here is quarantined by the healing autoloader -- other tools unaffected.
"""

import asyncio
import base64
import datetime
import hashlib
import re
import socket
from typing import Optional
import requests
import dns.resolver
import dns.asyncresolver
import whois as whois_lib
from fastapi import APIRouter, Depends
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)
import aiohttp as _aiohttp_crawl
import ssl as _ssl_mod

from fastapi import APIRouter, Depends

# Filter out template-looking aliases that appear on EVERY harvested domain
# (sign of harvester hallucination, not actual data).
TEMPLATE_EMAILS = {"abuse", "admin", "compliance", "contact", "dpo", "email",
                    "feedback", "hello", "help", "hr", "info", "jobs", "legal",
                    "mail", "marketing", "no-reply", "noreply", "office",
                    "postmaster", "privacy", "security", "support", "webmaster",
                    "sales", "billing", "careers"}


def _filter_template_emails(emails, target_domain):
    """If we got many emails and they're ALL template aliases, suppress them."""
    if not emails:
        return emails
    locals_ = [e.split("@")[0].lower() for e in emails]
    template_count = sum(1 for l in locals_ if l in TEMPLATE_EMAILS)
    # If >70% are template-looking AND total > 5, treat as harvester hallucination
    if len(emails) > 5 and template_count / len(emails) > 0.7:
        return []  # drop all — keeping a fraction would be misleading
    return emails



router = APIRouter()

_COMMON_EMAIL_PREFIXES = [
    "info","contact","admin","support","sales","security","webmaster",
    "noreply","no-reply","hello","mail","email","abuse","postmaster",
    "team","office","press","hr","careers","jobs","help","feedback",
    "marketing","privacy","legal","dpo","compliance",
]

_CONTACT_PAGES = [
    "","/contact","/contact-us","/about","/about-us","/team","/staff",
    "/people","/imprint","/legal","/privacy","/terms","/support",
]

async def recon_harvester_impl(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    emails = set()          # real emails discovered from external sources
    emails_pattern = set()  # pattern-generated synthesis (not actual findings)
    hosts = set()
    sources_hit = {}
    sources_failed = {}
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    # 1. Pattern generation — common business email prefixes (kept SEPARATE
    # from real-discovered emails so customer reports don't show synthesis as findings)
    for p in _COMMON_EMAIL_PREFIXES:
        emails_pattern.add(f"{p}@{host}")
    sources_hit["pattern_generation"] = len(emails_pattern)

    # 2. Scrape target's own pages for real emails
    try:
        base = web_url(req.target).rstrip("/")
        pre_count = len(emails)
        for p in _CONTACT_PAGES:
            r = safe_get(base + p, req=req, allow_redirects=True)
            if r is not None and r.status_code == 200:
                for match in email_pattern.findall(r.text or ""):
                    m = match.lower()
                    if host in m or m.endswith(f".{host}"):
                        emails.add(m)
        sources_hit["target_scrape"] = len(emails) - pre_count
    except Exception as e:
        sources_failed["target_scrape"] = str(e)[:80]

    # 3. Wayback Machine — fetch archived homepage and extract emails
    try:
        wb = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={host}&output=json&limit=5&filter=statuscode:200",
            timeout=10, headers={"User-Agent": "VulnusLab/1.0"},
        )
        if wb.status_code == 200:
            rows = wb.json()
            pre_count = len(emails)
            for row in rows[1:3]:
                if len(row) >= 3:
                    archive_url = f"http://web.archive.org/web/{row[1]}/{row[2]}"
                    try:
                        ar = requests.get(archive_url, timeout=10,
                                          headers={"User-Agent": "VulnusLab/1.0"})
                        if ar.status_code == 200:
                            for match in email_pattern.findall(ar.text):
                                m = match.lower()
                                if host in m:
                                    emails.add(m)
                    except Exception:
                        continue
            sources_hit["wayback"] = len(emails) - pre_count
    except Exception as e:
        sources_failed["wayback"] = str(e)[:80]

    # 4. HackerTarget hostsearch for hosts (hostname + ip pairs)
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={host}",
            timeout=10, headers={"User-Agent": "VulnusLab/1.0"},
        )
        if r.status_code == 200 and "API count exceeded" not in r.text:
            pre_count = len(hosts)
            for line in r.text.splitlines():
                parts = line.split(",")
                if len(parts) >= 2:
                    hostname = parts[0].strip().lower()
                    if hostname.endswith(host):
                        hosts.add(hostname)
            sources_hit["hackertarget_hosts"] = len(hosts) - pre_count
        elif "API count exceeded" in (r.text or ""):
            sources_failed["hackertarget_hosts"] = "rate limit"
    except Exception as e:
        sources_failed["hackertarget_hosts"] = str(e)[:80]

    # 5. GitHub code search — find emails in public repositories mentioning the domain
    # Free API, rate-limited (10 req/min unauthenticated; 30/min with PAT).
    try:
        gh_r = requests.get(
            f"https://api.github.com/search/code?q=%22@{host}%22+in:file&per_page=30",
            timeout=10,
            headers={"User-Agent": "VulnusLab/1.0",
                     "Accept": "application/vnd.github.v3.text-match+json"},
        )
        if gh_r.status_code == 200:
            pre_count = len(emails)
            for item in gh_r.json().get("items", []):
                for tm in item.get("text_matches", []):
                    for m in email_pattern.findall(tm.get("fragment", "")):
                        ml = m.lower()
                        if host in ml:
                            emails.add(ml)
            sources_hit["github_code"] = len(emails) - pre_count
        elif gh_r.status_code == 403:
            sources_failed["github_code"] = "rate-limited (10/min unauthenticated)"
        else:
            sources_failed["github_code"] = f"status {gh_r.status_code}"
    except Exception as e:
        sources_failed["github_code"] = str(e)[:80]

    return {
        "ok": True,
        "emails": sorted(emails),                    # REAL emails discovered
        "emails_pattern": sorted(emails_pattern),    # pattern-generated (NOT findings)
        "hosts": sorted(hosts),
        "total_emails": len(emails),                 # count of REAL emails
        "total_emails_pattern": len(emails_pattern), # count of synthetic emails
        "total_hosts": len(hosts),
        "sources": sources_hit,
        "sources_failed": sources_failed,
        "engine": "pure-Python (real-only emails: target scrape + Wayback + GitHub; pattern gen kept separate)",
    }



# VLERR-WRAP-V1
@router.post("/api/recon/harvester")
async def recon_harvester(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_harvester_impl(req, _)
    except Exception as _e:
        return {"ok": False,
                 "skipped_reason": f"harvester scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                 "error": str(_e)[:300]}

def register(app):
    app.include_router(router)
