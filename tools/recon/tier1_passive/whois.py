"""WHOIS Intelligence v2 — VL-FORGE multi-source async engine.
Route: /api/recon/whois

8 parallel sources via asyncio.gather:
  1. whois CLI (domain)        5. DNS A/AAAA/NS resolution
  2. whois CLI (per IP)        6. crt.sh CT log subdomains
  3. RDAP HTTP (domain)        7. Team Cymru ASN WHOIS
  4. RDAP HTTP (per IP)        8. python-whois library fallback

Then runs 30-rule findings engine in whois_findings.py against merged state.
"""
import asyncio, re, shutil
from datetime import datetime
import requests
import dns.asyncresolver
try:
    import whois as pywhois
except ImportError:
    pywhois = None
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner

router = APIRouter()
_WHOIS_BIN = shutil.which("whois")

# ─────── Async source helpers ───────

async def _whois_cli(target, server=None, timeout=12):
    if not _WHOIS_BIN: return ""
    args = [_WHOIS_BIN]
    if server: args += ["-h", server]
    args.append(target)
    try:
        proc = await asyncio.create_subprocess_exec(*args,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return out.decode("utf-8", errors="ignore")
    except Exception:
        return ""

async def _http_json(url, timeout=10):
    try:
        r = await asyncio.to_thread(requests.get, url, timeout=timeout,
            headers={"User-Agent":"VulnusLab/1.0"})
        if r and r.status_code == 200: return r.json()
    except Exception: pass
    return None

async def _http_text(url, timeout=15):
    try:
        r = await asyncio.to_thread(requests.get, url, timeout=timeout,
            headers={"User-Agent":"VulnusLab/1.0"})
        if r and r.status_code == 200: return r.text
    except Exception: pass
    return None

async def _dns_records(host):
    res = {"A": [], "AAAA": [], "NS": []}
    r = dns.asyncresolver.Resolver(); r.timeout=5; r.lifetime=8
    for rt in res:
        try:
            ans = await r.resolve(host, rt)
            res[rt] = [str(x).rstrip(".") for x in ans]
        except Exception: pass
    return res

async def _crt_sh(domain):
    txt = await _http_text(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not txt: return set()
    import json
    try: data = json.loads(txt)
    except Exception: return set()
    subs = set()
    for entry in (data or [])[:500]:
        for n in (entry.get("name_value","") or "").split("\n"):
            n = n.strip().lower()
            if n.endswith(domain) and n != domain and "*" not in n:
                subs.add(n)
    return subs

async def _team_cymru_asn(ip):
    raw = await _whois_cli(f" -v {ip}", server="whois.cymru.com", timeout=10)
    if not raw: return None
    for line in raw.splitlines():
        if "|" not in line: continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 7 and parts[0].isdigit():
            return {"asn": "AS"+parts[0], "country": parts[2],
                    "registry": parts[3], "org": parts[6]}
    return None

def _pywhois_sync(host):
    if not pywhois: return None
    try: return pywhois.whois(host)
    except Exception: return None

# ─────── Parsers ───────

def _parse_date(val):
    if not val: return None
    if isinstance(val, datetime): return val
    if isinstance(val, list) and val: val = val[0]
    if isinstance(val, str):
        for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%d %H:%M:%S","%Y-%m-%dT%H:%M:%SZ",
                    "%d-%b-%Y","%Y.%m.%d","%Y-%m-%d"):
            try: return datetime.strptime(val[:19], fmt)
            except Exception: continue
    return None

def _grab(raw, key):
    if not raw: return None
    m = re.search(rf"^\s*{key}\s*:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip()[:120] if m else None

def _grab_email(raw):
    if not raw: return None
    m = re.search(r"abuse[^:]*:\s*([\w._%+-]+@[\w.-]+\.[a-z]{2,})", raw, re.IGNORECASE)
    return m.group(1).lower() if m else None

def _is_privacy(raw, pyw):
    ind = ["whoisguard","domains by proxy","privacy protect","redacted for privacy",
           "private whois","contact privacy","perfect privacy","privacy service"]
    blob = ((raw or "") + " " + str(pyw or "")).lower()
    return any(i in blob for i in ind)

_CDN_NS = [
    ("Cloudflare",   ["cloudflare"]),
    ("Akamai",       ["akamai","akadns"]),
    ("Fastly",       ["fastly"]),
    ("AWS Route53",  ["awsdns"]),
    ("Google Cloud DNS", ["googledomains","ns-cloud","google-public"]),
    ("Azure DNS",    ["azure-dns"]),
    ("CloudFront",   ["cloudfront"]),
    ("NS1",          ["nsone.net"]),
    ("DNSimple",     ["dnsimple"]),
]

def _cdn_from_ns(ns_list):
    if not ns_list: return None
    blob = " ".join(ns_list).lower()
    for name, pats in _CDN_NS:
        if any(p in blob for p in pats): return name
    return None

_FREE_DNS_PATTERNS = ["freenom","cloudns.","afraid.org","duckdns","sitelutions"]
def _is_free_dns(ns_list):
    if not ns_list: return False
    blob = " ".join(ns_list).lower()
    return any(p in blob for p in _FREE_DNS_PATTERNS)

# ─────── Main gather ───────

async def gather(ctx: ScanContext):
    host = ctx.host

    # Phase 1: 5 sources fire in parallel
    cli_d, rdap_d, dns_data, ct_subs, pyw = await asyncio.gather(
        _whois_cli(host),
        _http_json(f"https://rdap.org/domain/{host}"),
        _dns_records(host),
        _crt_sh(host),
        asyncio.to_thread(_pywhois_sync, host),
        return_exceptions=False)

    if cli_d:       ctx.source("whois-cli-domain")
    if rdap_d:      ctx.source("rdap-domain")
    if any(dns_data.values()): ctx.source("dns-resolve")
    if ct_subs:     ctx.source(f"crt.sh ({len(ct_subs)} subs)")
    if pyw:         ctx.source("python-whois lib")

    ips = (dns_data.get("A") or []) + (dns_data.get("AAAA") or [])
    ns_list = dns_data.get("NS") or []

    # Phase 2: Per-IP enrichment (parallel)
    ip_clis, ip_rdaps, asn_lookups = [], [], []
    if ips:
        ip_clis = await asyncio.gather(
            *[_whois_cli(ip, timeout=8) for ip in ips[:5]],
            return_exceptions=True)
        ip_rdaps = await asyncio.gather(
            *[_http_json(f"https://rdap.org/ip/{ip}") for ip in ips[:5]],
            return_exceptions=True)
        asn_lookups = await asyncio.gather(
            *[_team_cymru_asn(ip) for ip in ips[:3]],
            return_exceptions=True)

    if any(isinstance(r,str) and r for r in ip_clis):  ctx.source("whois-cli-per-ip")
    if any(isinstance(r,dict) and r for r in ip_rdaps): ctx.source("rdap-per-ip")

    asn_data = next((a for a in asn_lookups
                     if isinstance(a, dict) and a.get("asn")), None)
    if asn_data: ctx.source("team-cymru-asn")

    # Phase 3: Parse + merge
    registrar = _grab(cli_d, "Registrar") or _grab(cli_d, "Sponsoring Registrar")
    if not registrar and pyw:
        r = getattr(pyw, "registrar", None)
        registrar = (r[0] if isinstance(r,list) and r else r) if r else None

    abuse_email = _grab_email(cli_d)
    if not abuse_email:
        for ipc in ip_clis:
            if isinstance(ipc, str):
                e = _grab_email(ipc)
                if e: abuse_email = e; break

    created = expires = None
    if pyw:
        created = _parse_date(getattr(pyw, "creation_date", None))
        expires = _parse_date(getattr(pyw, "expiration_date", None))
    if rdap_d and isinstance(rdap_d, dict):
        for ev in rdap_d.get("events", []) or []:
            act = (ev.get("eventAction") or "").lower()
            dt = _parse_date(ev.get("eventDate"))
            if not created and act == "registration": created = dt
            if not expires and act == "expiration":   expires = dt

    now = datetime.utcnow()
    age_days = (now - created).days if created else None
    days_to_expiry = (expires - now).days if expires else None

    cli_ok, rdap_ok, lib_ok = bool(cli_d), bool(rdap_d), bool(pyw)
    sources_count = sum([cli_ok, rdap_ok, lib_ok])

    ctx.state.update({
        "registrar":           registrar,
        "abuse_email":         abuse_email,
        "creation_date":       created.isoformat() if created else None,
        "expires":             expires.isoformat() if expires else None,
        "age_days":            age_days,
        "days_to_expiry":      days_to_expiry,
        "privacy_enabled":     _is_privacy(cli_d, pyw),
        "resolved_ips":        ips,
        "nameservers":         ns_list,
        "ns_records":          ns_list,  # alias for old rules
        "cdn_vendor":          _cdn_from_ns(ns_list),
        "free_dns_provider":   _is_free_dns(ns_list),
        "asn":                 asn_data.get("asn") if asn_data else None,
        "asn_org":             asn_data.get("org") if asn_data else None,
        "country":             asn_data.get("country") if asn_data else None,
        "ct_subdomain_count":  len(ct_subs),
        "ct_subdomains_sample": sorted(ct_subs)[:10],
        "sources_count":       sources_count,
        "sources_consistent":  sources_count >= 2,
        "rdap_data":           rdap_d if isinstance(rdap_d, dict) else None,
        "raw_whois_excerpt":   (cli_d or "")[:1500],
    })


INTEL_FIELDS = [
    ("Registrar",          "registrar"),
    ("Domain age",         "age_days_display"),
    ("Expires",            "expires"),
    ("Days to expiry",     "days_to_expiry"),
    ("Privacy proxy",      "privacy_enabled"),
    ("Abuse contact",      "abuse_email"),
    ("Nameservers",        "ns_display"),
    ("CDN detected",       "cdn_vendor"),
    ("Resolved IPs",       "ips_display"),
    ("ASN",                "asn"),
    ("ASN org",            "asn_org"),
    ("Country",            "country"),
    ("CT-log subdomains",  "ct_subdomain_count"),
    ("Sources consulted",  "sources_count"),
]


async def gather_with_display(ctx):
    await gather(ctx)
    s = ctx.state
    if s.get("age_days") is not None:
        s["age_days_display"] = f"{s['age_days']} days"
    if s.get("nameservers"):
        s["ns_display"] = ", ".join(s["nameservers"][:3])
    if s.get("resolved_ips"):
        s["ips_display"] = ", ".join(s["resolved_ips"][:3])


# Inline finding rules — work even if whois_findings.py rules don't match
def _r_expired(s):
    d = s.get("days_to_expiry")
    if d is None or d > 0: return None
    return {"name": f"Domain expired ({abs(d)} days ago)",
            "severity": "CRITICAL", "cvss": 9.5, "cwe": "CWE-298",
            "evidence": f"WHOIS expires: {s.get('expires')}",
            "remediation": "Renew domain immediately — site can be hijacked by anyone willing to register."}

def _r_expires_30(s):
    d = s.get("days_to_expiry")
    if d is None or d <= 0 or d > 30: return None
    return {"name": f"Domain expires in {d} days",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-298",
            "evidence": f"WHOIS expires: {s.get('expires')}",
            "remediation": "Renew domain within 2 weeks. Set auto-renew."}

def _r_expires_90(s):
    d = s.get("days_to_expiry")
    if d is None or d <= 30 or d > 90: return None
    return {"name": f"Domain expires in {d} days",
            "severity": "MEDIUM",
            "evidence": f"WHOIS expires: {s.get('expires')}",
            "remediation": "Schedule renewal."}

def _r_newly_registered(s):
    age = s.get("age_days")
    if age is None or age > 30: return None
    return {"name": f"Newly registered domain ({age} days old)",
            "severity": "MEDIUM", "cwe": "CWE-1325",
            "evidence": f"Created: {s.get('creation_date')}",
            "remediation": "New domains are phishing-prone. Verify legitimacy before trusting."}

def _r_free_dns(s):
    if not s.get("free_dns_provider"): return None
    return {"name": "Free/risky DNS provider in use",
            "severity": "HIGH", "cwe": "CWE-1188",
            "evidence": f"NS: {', '.join(s.get('nameservers') or [])}",
            "remediation": "Migrate to reputable DNS (Cloudflare/Route53/Google Cloud DNS)."}

def _r_no_abuse(s):
    if s.get("abuse_email"): return None
    if not s.get("registrar"): return None
    return {"name": "No abuse contact published in WHOIS",
            "severity": "MEDIUM", "cwe": "CWE-829",
            "evidence": "RFC 3912 requires abuse-c contact",
            "remediation": "Publish abuse@yourdomain.com or use registrar's privacy proxy that forwards abuse complaints."}

def _r_privacy_only(s):
    if not s.get("privacy_enabled"): return None
    return {"name": "WHOIS privacy proxy active",
            "severity": "INFO",
            "evidence": "Registrant identity masked behind proxy service"}

def _r_long_runway(s):
    d = s.get("days_to_expiry")
    if d is None or d < 365: return None
    return {"name": f"Domain has long expiry runway ({d} days)",
            "severity": "POSITIVE",
            "evidence": f"Expires: {s.get('expires')}"}

def _r_abuse_present(s):
    if not s.get("abuse_email"): return None
    return {"name": "Abuse contact published",
            "severity": "POSITIVE", "evidence": f"abuse: {s.get('abuse_email')}"}

def _r_registrar(s):
    if not s.get("registrar"): return None
    return {"name": f"Registrar: {s['registrar']}",
            "severity": "INFO", "evidence": "From WHOIS record"}

def _r_cdn(s):
    if not s.get("cdn_vendor"): return None
    return {"name": f"CDN detected: {s['cdn_vendor']}",
            "severity": "INFO", "evidence": f"NS pattern match against {s['cdn_vendor']} infrastructure"}

def _r_asn(s):
    if not s.get("asn"): return None
    return {"name": f"Hosted on {s['asn']} ({s.get('asn_org') or 'unknown'})",
            "severity": "INFO", "evidence": f"ASN via Team Cymru, country={s.get('country','?')}"}

def _r_ct_subs(s):
    n = s.get("ct_subdomain_count") or 0
    if n == 0: return None
    return {"name": f"{n} subdomains in CT logs",
            "severity": "INFO",
            "evidence": f"Sample: {', '.join((s.get('ct_subdomains_sample') or [])[:5])}"}

def _r_age(s):
    age = s.get("age_days")
    if age is None or age <= 30: return None
    years = age // 365
    return {"name": f"Domain age: {years}y {age%365}d",
            "severity": "INFO", "evidence": f"Created: {s.get('creation_date')}"}

def _r_sources_consistent(s):
    if not s.get("sources_consistent"): return None
    return {"name": f"Multi-source WHOIS data consistent ({s.get('sources_count')} sources)",
            "severity": "POSITIVE",
            "evidence": "whois CLI + RDAP + python-whois lib agreed"}

def _r_sources_thin(s):
    if (s.get("sources_count") or 0) >= 2: return None
    return {"name": "WHOIS data sourced from only 1 channel",
            "severity": "LOW",
            "evidence": "Cross-validation limited — registry may be rate-limiting"}

_INLINE_RULES = [_r_expired, _r_expires_30, _r_expires_90, _r_newly_registered,
                 _r_free_dns, _r_no_abuse, _r_privacy_only, _r_long_runway,
                 _r_abuse_present, _r_registrar, _r_cdn, _r_asn, _r_ct_subs,
                 _r_age, _r_sources_consistent, _r_sources_thin]

try:
    from tools._payloads.whois_findings import WHOIS_FINDING_RULES as _EXTERNAL_RULES
except ImportError:
    _EXTERNAL_RULES = []

FINDING_RULES = _INLINE_RULES + (_EXTERNAL_RULES or [])


@router.post("/api/recon/whois")
async def recon_whois(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=recon_host(req.target), tool="whois",
        gather_func=gather_with_display,
        finding_rules=FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["registrar","expires","creation_date","nameservers",
                         "resolved_ips","asn","cdn_vendor","ct_subdomain_count",
                         "abuse_email","privacy_enabled","ct_subdomains_sample"])


def register(app):
    app.include_router(router)
