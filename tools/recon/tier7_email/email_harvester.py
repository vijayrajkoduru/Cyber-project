"""email_harvester — VL-FORGE OSINT. Own-code discovery, NO API key.
Sources: HTML crawl + JS bundle scan (SPA emails) + DNS SOA admin email."""
import asyncio, re
import requests
try:
    import dns.asyncresolver
    _HAS_DNS = True
except Exception:
    _HAS_DNS = False
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
router = APIRouter()
_PAGES = ["", "/contact", "/contact-us", "/about", "/about-us", "/team", "/careers",
          "/support", "/privacy", "/legal", "/security.txt", "/.well-known/security.txt"]
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_JS_RE = re.compile(r"(/[A-Za-z0-9_./-]+\.js)")
_HDRS = {"User-Agent": "Mozilla/5.0 (VulnusLab Recon)"}
_JUNK = ("example.com","sentry.io","wixpress.com","schema.org","w3.org","googleapis.com",
         "cloudflare.com","jquery","gravatar","fontawesome","googletagmanager","react","webpack","babel")
def _get(url):
    try:
        return requests.get(url, timeout=7, verify=False, allow_redirects=True, headers=_HDRS)
    except Exception:
        return None
def _clean(text):
    out = set()
    for m in _EMAIL_RE.findall(text or ""):
        e = m.strip().strip(".").lower()
        if any(j in e for j in _JUNK): continue
        if e.endswith((".png",".jpg",".jpeg",".gif",".svg",".webp",".css",".js",".woff",".ttf")): continue
        if len(e) > 80 or e.count("@") != 1: continue
        out.add(e)
    return out
async def gather(ctx):
    host = str(ctx.host); base = web_url(host).rstrip("/"); apex = base.split("//")[-1].split("/")[0]
    on, off, hit, home_html = set(), set(), 0, ""
    results = await asyncio.gather(*[asyncio.to_thread(_get, base + p) for p in _PAGES])
    for p, r in zip(_PAGES, results):
        if not r or r.status_code >= 400: continue
        hit += 1
        if p == "" and not home_html: home_html = r.text or ""
        for e in _clean(r.text):
            (on if e.split("@")[-1].endswith(apex) else off).add(e)
    if hit: ctx.source("site-crawl-%dp" % hit)
    js_urls = [base + p for p in dict.fromkeys(_JS_RE.findall(home_html))][:8]
    js_hit = 0
    if js_urls:
        for r in await asyncio.gather(*[asyncio.to_thread(_get, u) for u in js_urls]):
            if not r or r.status_code >= 400: continue
            js_hit += 1
            for e in _clean((r.text or "")[:600000]):
                (on if e.split("@")[-1].endswith(apex) else off).add(e)
        if js_hit: ctx.source("js-bundles-%d" % js_hit)
    if _HAS_DNS:
        try:
            res = dns.asyncresolver.Resolver(); res.timeout = 4; res.lifetime = 6
            for rd in await res.resolve(apex, "SOA"):
                rn = rd.rname.to_text().rstrip(".").replace("\\.", ".")
                local, _, dom = rn.partition(".")
                if dom.endswith(apex):
                    on.add("%s@%s" % (local, dom)); ctx.source("dns-soa")
        except Exception:
            pass
    emails = sorted(on)
    ctx.state.update({"emails": emails, "email_count": len(emails),
        "usernames": sorted({e.split("@")[0] for e in emails}),
        "offdomain_emails": sorted(off)[:10], "pages_crawled": hit, "js_scanned": js_hit})
def _r_found(s):
    em = s.get("emails") or []
    if not em: return None
    return {"name": "%d public email address(es) discovered" % len(em), "severity": "INFO", "cwe": "CWE-200",
            "evidence": ", ".join(em[:8]) + ((" (+%d more)" % (len(em)-8)) if len(em) > 8 else ""),
            "remediation": "Confirm these are intended public contacts; prefer role aliases over personal addresses."}
def _r_clean(s):
    if s.get("emails") or not s.get("pages_crawled"): return None
    return {"name": "No public email addresses exposed", "severity": "POSITIVE",
            "evidence": "Crawled %d pages + %d JS bundles + DNS SOA - none found" % (s.get("pages_crawled",0), s.get("js_scanned",0))}
FINDING_RULES = [_r_found, _r_clean]
INTEL_FIELDS = [("Emails discovered","emails"),("Email count","email_count"),("Usernames","usernames"),
                ("Off-domain contacts","offdomain_emails"),("Pages crawled","pages_crawled"),("JS bundles scanned","js_scanned")]
@router.post("/api/recon/email_harvester")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="email_harvester",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["emails","usernames","offdomain_emails"])
def register(app): app.include_router(router)
