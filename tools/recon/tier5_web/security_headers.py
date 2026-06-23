"""Security Headers v2 — VL-FORGE. securityheaders.com-grade scoring.
Route: /api/recon/security_headers
"""
import asyncio
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()

# ZERO-FP-V1 (2026-06-06): HSTS was emitted both here AND by the dedicated
# hsts_audit scanner, producing a duplicate HIGH finding ("No HSTS header" +
# "Missing critical security headers: Strict-Transport-Security"). HSTS is
# now owned exclusively by hsts_audit; this scanner only handles the other
# response headers.
# ZERO-FP-V2 (2026-06-23): PASSIVE recon header checks are informational —
# a missing header is not exploitation proof. Capped at LOW (MEDIUM max,
# LOW preferred). CSP/XFO were MEDIUM; downgraded to LOW so passive recon
# does not inflate the customer's risk score with un-proven HIGH/MEDIUM
# findings. Active webapp module reserves higher severities for real proof.
_HEADERS_AUDIT = {
    "Content-Security-Policy":  {"sev":"LOW","cwe":"CWE-693","weight":15,
        "fix":"Add 'default-src \\'self\\'; script-src \\'self\\'' to ALL responses."},
    "X-Frame-Options":          {"sev":"LOW","cwe":"CWE-1021","weight":10,
        "fix":"Add 'X-Frame-Options: DENY' (or CSP frame-ancestors)."},
    "X-Content-Type-Options":   {"sev":"LOW","cwe":"CWE-79","weight":5,
        "fix":"Add 'X-Content-Type-Options: nosniff'."},
    "Referrer-Policy":          {"sev":"LOW","cwe":"CWE-200","weight":5,
        "fix":"Add 'Referrer-Policy: strict-origin-when-cross-origin'."},
    "Permissions-Policy":       {"sev":"LOW","cwe":"CWE-200","weight":5,
        "fix":"Add 'Permissions-Policy: geolocation=(), camera=(), microphone=()'."},
    "X-XSS-Protection":         {"sev":"INFO","cwe":"CWE-79","weight":0,
        "fix":"Modern browsers ignore this — CSP is the replacement."},
}

def _get(url):
    try:
        return requests.get(url, timeout=8, verify=False, allow_redirects=True,
                            headers={"User-Agent":"VulnusLab/1.0"})
    except Exception:
        return None

async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    r = await asyncio.to_thread(_get, base + "/")
    if not r:
        ctx.state["target_reachable"] = False; return
    ctx.state["target_reachable"] = True
    ctx.source("homepage")
    hdrs = {k.lower(): v for k,v in r.headers.items()}
    present, missing = [], []
    for h in _HEADERS_AUDIT:
        if h.lower() in hdrs:
            present.append({"name":h, "value":hdrs[h.lower()][:200]})
        else:
            missing.append(h)
    ctx.state["present_headers"] = present
    ctx.state["missing_headers"] = missing
    # securityheaders.com-style grade
    total_weight = sum(v["weight"] for v in _HEADERS_AUDIT.values())
    earned = sum(_HEADERS_AUDIT[p["name"]]["weight"] for p in present)
    pct = (earned * 100) // total_weight if total_weight else 0
    ctx.state["grade_pct"] = pct
    ctx.state["grade_letter"] = "A" if pct>=90 else ("B" if pct>=75 else ("C" if pct>=60 else ("D" if pct>=40 else "F")))
    ctx.state["server_header"] = hdrs.get("server","")[:80]
    ctx.state["powered_by"] = hdrs.get("x-powered-by","")[:80]
    ctx.state["set_cookie_raw"] = hdrs.get("set-cookie","")[:400]
    ctx.source(f"audit-{len(present)}of{len(_HEADERS_AUDIT)}")

def r_missing(s):
    miss = s.get("missing_headers") or []
    high = [h for h in miss if _HEADERS_AUDIT[h]["sev"] == "HIGH"]
    if not high: return None
    return {"name":f"Missing critical security headers: {', '.join(high)}",
            "severity":"HIGH","cvss":7.0,"cwe":_HEADERS_AUDIT[high[0]]["cwe"],
            "owasp":"A05:2021 — Security Misconfiguration",
            "evidence":f"Missing: {', '.join(high)}",
            "remediation":" | ".join(_HEADERS_AUDIT[h]["fix"] for h in high)}

def r_missing_med(s):
    miss = s.get("missing_headers") or []
    med = [h for h in miss if _HEADERS_AUDIT[h]["sev"] == "MEDIUM"]
    if not med: return None
    return {"name":f"Missing medium-severity headers: {', '.join(med)}",
            "severity":"MEDIUM","cwe":_HEADERS_AUDIT[med[0]]["cwe"],
            "owasp":"A05:2021","evidence":f"Missing: {', '.join(med)}",
            "remediation":" | ".join(_HEADERS_AUDIT[h]["fix"] for h in med[:3])}

def r_missing_low(s):
    miss = s.get("missing_headers") or []
    low = [h for h in miss if _HEADERS_AUDIT[h]["sev"] == "LOW"]
    if not low: return None
    return {"name":f"Missing hardening headers: {', '.join(low)}","severity":"LOW",
            "evidence":f"Missing: {', '.join(low)}",
            "remediation":" | ".join(_HEADERS_AUDIT[h]["fix"] for h in low[:3])}

def r_grade(s):
    g = s.get("grade_letter")
    if not g: return None
    sev = "INFO"  # summary metric; real severity carried by the r_missing_* rules
    return {"name":f"Security headers grade: {g} ({s.get('grade_pct')}%)",
            "severity": sev, "evidence":f"{len(s.get('present_headers') or [])} of {len(_HEADERS_AUDIT)} hardening headers present"}

def r_server_leak(s):
    sv = s.get("server_header") or ""
    if not sv: return None
    # Detect version leaks (e.g., "nginx/1.18.0", "Apache/2.4.41")
    if "/" in sv and any(c.isdigit() for c in sv):
        return {"name":f"Server version leaked: {sv}","severity":"LOW","cwe":"CWE-200",
                "evidence":f"Server header: {sv}",
                "remediation":"nginx: server_tokens off; | Apache: ServerTokens Prod / ServerSignature Off"}
    return {"name":f"Server header: {sv}","severity":"INFO","evidence":"From Server response header"}

def r_powered_by(s):
    pb = s.get("powered_by") or ""
    if not pb: return None
    return {"name":f"X-Powered-By header leaks tech: {pb}","severity":"LOW","cwe":"CWE-200",
            "evidence":f"X-Powered-By: {pb}",
            "remediation":"Remove X-Powered-By header in your stack config."}

def r_clean(s):
    if not s.get("target_reachable"): return None
    if (s.get("missing_headers") or []): return None
    return {"name":"All security headers present","severity":"POSITIVE",
            "evidence":f"All {len(_HEADERS_AUDIT)} hardening headers detected"}

def r_unreach(s):
    if s.get("target_reachable"): return None
    return {"name":"Target unreachable","severity":"INFO","evidence":"HTTP fetch failed"}

FINDING_RULES = [r_missing, r_missing_med, r_missing_low, r_grade, r_server_leak,
                 r_powered_by, r_clean, r_unreach]

INTEL_FIELDS = [("Target reachable","target_reachable"),("Grade","grade_letter"),
                ("Grade %","grade_pct"),("Server","server_header"),
                ("Headers present","present_headers_count"),("Headers missing","missing_headers_count")]

async def gather_with_display(ctx):
    await gather(ctx)
    ctx.state["present_headers_count"] = len(ctx.state.get("present_headers") or [])
    ctx.state["missing_headers_count"] = len(ctx.state.get("missing_headers") or [])

@router.post("/api/recon/security_headers")
async def recon_security_headers(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="security_headers",
        gather_func=gather_with_display, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["present_headers","missing_headers","grade_letter","grade_pct","server_header"])

def register(app): app.include_router(router)
