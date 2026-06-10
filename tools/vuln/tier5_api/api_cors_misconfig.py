"""API CORS misconfiguration (origin reflection / null / wildcard+creds). VL-FORGE Vuln tier5 - §5 #68.

VL-VERIFY: scanner audits CORS headers on the homepage. SPA homepages are
real - their CORS config is the real config under test. We stamp
spa_catchall on state for report transparency, but no behavior change.
"""
import asyncio
import ssl
import urllib.request
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import detect_spa_catchall

router = APIRouter()
_EVIL = "https://evil.example.com"
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


def _cors(url, origin, timeout=8):
    req = urllib.request.Request(url, headers={"Origin": origin, "User-Agent": "Mozilla/5.0 (VulnusLab Vuln)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            h = {k.lower(): v for k, v in r.headers.items()}
    except Exception as e:
        h = {k.lower(): v for k, v in e.headers.items()} if getattr(e, "headers", None) else {}
    return h.get("access-control-allow-origin"), h.get("access-control-allow-credentials")


async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    spa = await detect_spa_catchall(base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    acao, acac = await asyncio.to_thread(_cors, base + "/", _EVIL)
    acao_null, _ = await asyncio.to_thread(_cors, base + "/", "null")
    ctx.source("http")
    ctx.state["tested"] = 2
    ctx.state["acao"] = acao
    ctx.state["acac"] = acac
    ctx.state["acao_null"] = acao_null


def _r_reflect(s):
    acao = s.get("acao") or ""
    if _EVIL not in acao:
        return None
    creds = str(s.get("acac")).lower() == "true"
    return {"name": "CORS reflects arbitrary Origin", "severity": "HIGH" if creds else "MEDIUM",
            "cvss": 7.5 if creds else 5.3, "cwe": "CWE-942",
            "evidence": f"ACAO reflected attacker origin ({acao}); Allow-Credentials={s.get('acac')}",
            "remediation": "Use an explicit origin allow-list; never reflect Origin with Allow-Credentials:true."}


def _r_null(s):
    if (s.get("acao_null") or "") != "null":
        return None
    return {"name": "CORS allows 'null' origin", "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-942",
            "evidence": "ACAO: null - exploitable from sandboxed iframes/data URIs",
            "remediation": "Do not allow the 'null' origin."}


def _r_wild(s):
    if (s.get("acao") or "") != "*" or str(s.get("acac")).lower() != "true":
        return None
    return {"name": "CORS wildcard with credentials", "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-942",
            "evidence": "ACAO:* with Allow-Credentials:true", "remediation": "Never combine '*' with credentials."}


def _r_clean(s):
    if (s.get("tested") or 0) < 1:
        return None
    if (_EVIL in (s.get("acao") or "")) or (s.get("acao_null") == "null"):
        return None
    return {"name": "No CORS misconfiguration detected", "severity": "POSITIVE",
            "evidence": f"ACAO did not reflect attacker/null origin (ACAO={s.get('acao') or 'absent'})."}


FINDING_RULES = [_r_reflect, _r_null, _r_wild, _r_clean]
INTEL_FIELDS = [("ACAO", "acao")]


@router.post("/api/vuln/api_cors_misconfig")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="api_cors_misconfig",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
