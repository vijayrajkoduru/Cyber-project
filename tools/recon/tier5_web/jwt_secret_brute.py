"""JWT Secret Brute-Force — Route: /api/recon/jwt_secret_brute
Probes target for JWTs in HTML/cookies/headers, brute-forces HS256 against jwt_secrets.txt."""
import asyncio, re, base64
from pathlib import Path
import requests
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import ScanContext, run_scanner

router = APIRouter()
_PAYLOAD = Path(__file__).resolve().parent.parent.parent / "_payloads" / "recon" / "jwt_secrets.txt"
_MAX, _TO = 500, 5

def _load():
    try:
        if _PAYLOAD.exists():
            return [s.strip() for s in _PAYLOAD.read_text(encoding="utf-8").splitlines()
                    if s.strip() and not s.startswith("#")][:_MAX]
    except Exception: pass
    return ["secret","password","key","jwt","your-256-bit-secret","changeme"]

def _find(text):
    return re.findall(r'eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+', text or '')

def _decode(jwt, secret):
    try:
        from jose import jwt as jj
        jj.decode(jwt, secret, algorithms=["HS256","HS384","HS512"])
        return True
    except Exception:
        return False

def _get(url):
    try:
        return requests.get(url, timeout=_TO, verify=False,
                            headers={"User-Agent":"VulnusLab/1.0"}, allow_redirects=True)
    except Exception:
        return None

async def gather(ctx: ScanContext):
    r = await asyncio.to_thread(_get, web_url(ctx.host).rstrip("/") + "/")
    if not r:
        ctx.state["target_reachable"] = False; return
    ctx.state["target_reachable"] = True
    ctx.source("homepage")
    jwts = set(_find(r.text))
    for h,v in r.headers.items():
        if h.lower() in ("set-cookie","authorization"):
            jwts.update(_find(v))
    for c in r.cookies:
        jwts.update(_find(str(c.value)))
    jwts = list(jwts)[:5]
    ctx.state["jwts_found"] = jwts
    ctx.state["jwts_count"] = len(jwts)
    if not jwts: return
    ctx.source(f"jwts ({len(jwts)})")
    secrets = _load()
    ctx.state["secrets_tested"] = len(secrets)
    cracked = []
    for j in jwts:
        try:
            hb = j.split('.')[0]; hb += '=' * (-len(hb) % 4)
            hdr = base64.urlsafe_b64decode(hb).decode('utf-8', errors='ignore')
            if not any(a in hdr for a in ("HS256","HS384","HS512")):
                continue
        except Exception:
            continue
        for s in secrets:
            if await asyncio.to_thread(_decode, j, s):
                cracked.append({"jwt": j[:40]+"...", "secret": s}); break
    ctx.state["cracked"] = cracked
    ctx.state["cracked_count"] = len(cracked)
    if cracked: ctx.source(f"cracked ({len(cracked)})")

def r_cracked(s):
    c = s.get("cracked") or []
    if not c: return None
    return {"name": f"JWT secret cracked — full session takeover ({len(c)})",
            "severity": "CRITICAL", "cvss": 9.8, "cwe": "CWE-798",
            "cwe_name": "Use of Hard-coded Credentials",
            "owasp": "A07:2021 — Identification and Authentication Failures",
            "evidence": "; ".join(f"{x['jwt']} secret={x['secret']!r}" for x in c[:3]),
            "remediation": "Rotate JWT signing secret IMMEDIATELY. Use 256+ bit random secret. Migrate to RS256 (asymmetric)."}

def r_jwts(s):
    if not s.get("jwts_count"): return None
    if s.get("cracked"): return None
    return {"name": f"JWT(s) exposed in client response ({s['jwts_count']})",
            "severity": "INFO",
            "evidence": f"Found on homepage. None cracked vs {s.get('secrets_tested',0)} common secrets."}

def r_clean(s):
    if not s.get("target_reachable"): return None
    if s.get("jwts_found"): return None
    return {"name": "No JWTs exposed in client response",
            "severity": "POSITIVE",
            "evidence": "Homepage HTML + cookies + headers scanned — no JWT-like strings."}

def r_unreach(s):
    if s.get("target_reachable"): return None
    return {"name": "Target unreachable — JWT brute skipped",
            "severity": "INFO", "evidence": "HTTP fetch failed"}

FINDING_RULES = [r_cracked, r_jwts, r_clean, r_unreach]
INTEL_FIELDS = [("Target reachable","target_reachable"),("JWTs found","jwts_count"),
                ("Secrets tested","secrets_tested"),("Secrets cracked","cracked_count")]

@router.post("/api/recon/jwt_secret_brute")
async def recon_jwt_secret_brute(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="jwt_secret_brute",
        gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS,
        flat_field_keys=["jwts_found","cracked"])

def register(app): app.include_router(router)
