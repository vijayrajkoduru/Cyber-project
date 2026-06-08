"""CORS misconfig (web) - passive ACAO/ACAC header analysis. Self-contained.
Strategy: send GET with attacker Origin header, check Access-Control-Allow-Origin
+ Access-Control-Allow-Credentials response combinations for dangerous patterns."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner
from tools.vuln._vuln_common import probe_url, http_get_h

router = APIRouter()

ATTACKER_ORIGIN = "https://evil.vlattacker.com"


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = probe_url(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    r = http_get_h(base_url, headers={"Origin": ATTACKER_ORIGIN}, timeout=8)
    if not r:
        ctx.state["cors_response"] = None
        return
    hdrs = r.get("headers", {}) or {}
    acao = hdrs.get("access-control-allow-origin", "") or ""
    acac = (hdrs.get("access-control-allow-credentials", "") or "").lower()
    issues = []
    # Wildcard + credentials = forbidden by spec but some apps misconfigure
    if acao.strip() == "*" and acac == "true":
        issues.append({"severity": "HIGH", "issue": "ACAO:* with ACAC:true (browsers reject but indicates misconfig)"})
    # Reflected attacker origin
    if ATTACKER_ORIGIN.lower() in acao.lower():
        if acac == "true":
            issues.append({"severity": "CRITICAL", "issue": "Reflects arbitrary Origin AND allows credentials (full CORS bypass)"})
        else:
            issues.append({"severity": "MEDIUM", "issue": "Reflects arbitrary Origin (data leak possible if any auth via API key in URL)"})
    # null origin allowed
    r2 = http_get_h(base_url, headers={"Origin": "null"}, timeout=6)
    if r2:
        acao2 = (r2.get("headers", {}) or {}).get("access-control-allow-origin", "") or ""
        if acao2.strip().lower() == "null":
            issues.append({"severity": "HIGH", "issue": "Allows Origin: null (sandboxed iframes / file:// can bypass)"})
    ctx.state["acao"] = acao[:120]
    ctx.state["acac"] = acac
    ctx.state["cors_issues"] = issues


def _r_crit(s):
    crit = [i for i in (s.get("cors_issues") or []) if i["severity"] == "CRITICAL"]
    if not crit:
        return None
    return {"name": "CORS allows arbitrary origin with credentials (CRITICAL)",
            "severity": "CRITICAL", "cvss": 9.1, "cwe": "CWE-942",
            "evidence": crit[0]["issue"],
            "remediation": "Replace ACAO reflection with strict allow-list. Never combine ACAO:* with ACAC:true."}


def _r_high(s):
    high = [i for i in (s.get("cors_issues") or []) if i["severity"] == "HIGH"]
    if not high:
        return None
    return {"name": "CORS misconfig - high severity",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-942",
            "evidence": "; ".join(i["issue"] for i in high),
            "remediation": "Whitelist exact origins. Reject 'null' and wildcards."}


def _r_med(s):
    med = [i for i in (s.get("cors_issues") or []) if i["severity"] == "MEDIUM"]
    if not med:
        return None
    return {"name": "CORS reflects arbitrary origin",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-942",
            "evidence": "; ".join(i["issue"] for i in med),
            "remediation": "Use a static allow-list of trusted origins instead of reflecting Origin header."}


FINDING_RULES = [_r_crit, _r_high, _r_med]
INTEL_FIELDS = [("ACAO", "acao"), ("ACAC", "acac"), ("CORS issues", "cors_issues")]


@router.post("/api/vuln/web_cors_misconfig")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="web_cors_misconfig",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
