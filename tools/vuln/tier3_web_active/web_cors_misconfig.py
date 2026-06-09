"""Web CORS misconfig - ACAO/ACAC header analysis. VL-METHOD Wave 3.

Refactored 2026-06-09 to MethodologyScanner. Verify uses a SECOND attacker
origin. Real Origin-reflection bug echoes any origin value; a static
ACAO:* config wouldn't change behaviour either way (so the alt-origin
result discriminates reflection vs wildcard).
"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._methodology import MethodologyScanner
from tools.vuln._vuln_common import (probe_url_async, http_get_h_async,
                                      http_get_async)

router = APIRouter()

ATTACKER_ORIGIN_QUICK  = "https://evil.vlattacker.com"
ATTACKER_ORIGIN_VERIFY = "https://vlcorscheck.attacker.test"


def _classify(acao, acac, attacker_origin):
    issues = []
    if acao.strip() == "*" and acac == "true":
        issues.append({"severity": "HIGH",
                       "issue": "ACAO:* with ACAC:true (browsers reject but indicates misconfig)"})
    if attacker_origin.lower() in acao.lower():
        if acac == "true":
            issues.append({"severity": "CRITICAL",
                           "issue": "Reflects arbitrary Origin AND allows credentials"})
        else:
            issues.append({"severity": "MEDIUM",
                           "issue": "Reflects arbitrary Origin (data leak possible)"})
    return issues


async def _probe_origin(base_url, origin):
    r = await http_get_h_async(base_url, headers={"Origin": origin}, timeout=8)
    if not r:
        return "", "", []
    hdrs = r.get("headers", {}) or {}
    acao = hdrs.get("access-control-allow-origin", "") or ""
    acac = (hdrs.get("access-control-allow-credentials", "") or "").lower()
    return acao, acac, _classify(acao, acac, origin)


class WebCorsMisconfig(MethodologyScanner):
    name = "web_cors_misconfig"

    async def pre_flight(self, ctx):
        base_url, base = await probe_url_async(str(ctx.host), "/")
        if not base:
            ctx.state["tested"] = 0
            ctx.state["skipped_reason"] = "Target unreachable"
            return False
        ctx.source("http")
        ctx.state["tested"] = 1
        ctx.state["base_url"] = base_url
        return True

    async def fingerprint(self, ctx):
        r = await http_get_async(ctx.state["base_url"], timeout=6)
        if r:
            hdrs = r.get("headers") or {}
            ctx.state["fingerprint"] = {
                "server": (hdrs.get("server") or "")[:80],
            }

    async def quick_probe(self, ctx):
        acao, acac, issues = await _probe_origin(ctx.state["base_url"],
                                                   ATTACKER_ORIGIN_QUICK)
        ctx.state["acao"] = acao[:120]
        ctx.state["acac"] = acac
        ctx.state["quick_hits"] = issues
        return [dict(i) for i in issues]

    async def deep_scan(self, ctx):
        # Deep: null Origin
        r = await http_get_h_async(ctx.state["base_url"],
                                     headers={"Origin": "null"}, timeout=6)
        deep_issues = []
        if r:
            acao2 = ((r.get("headers") or {}).get("access-control-allow-origin") or "").strip().lower()
            if acao2 == "null":
                deep_issues.append({"severity": "HIGH",
                                     "issue": "Allows Origin: null (sandboxed iframes / file:// can bypass)"})
        ctx.state["deep_hits"] = deep_issues
        return [dict(i) for i in deep_issues]

    async def verify(self, ctx, finding):
        # Only the reflection-based findings need verification with alt origin.
        # ACAO:* / null findings are static configs - re-probe with same input.
        if "Reflects arbitrary Origin" in finding["issue"]:
            acao, acac, issues2 = await _probe_origin(ctx.state["base_url"],
                                                        ATTACKER_ORIGIN_VERIFY)
            if any("Reflects arbitrary Origin" in i["issue"] for i in issues2):
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = f"alt-origin-{ATTACKER_ORIGIN_VERIFY}-also-reflected"
            else:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "alt-origin-not-reflected"
        else:
            # Static config findings (ACAO:*, null) - re-probe with same Origin
            acao, acac, issues2 = await _probe_origin(ctx.state["base_url"],
                                                        ATTACKER_ORIGIN_QUICK)
            if any(i["issue"] == finding["issue"] for i in issues2):
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "refetch-config-stable"
            else:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "refetch-config-changed"
        return finding


def _r_crit(s):
    verified = s.get("methodology_findings") or []
    crit = [f for f in verified
             if f.get("severity") == "CRITICAL" and f.get("confidence") == "CONFIRMED"]
    if not crit:
        return None
    return {"name": "CORS allows arbitrary origin with credentials (CRITICAL, CONFIRMED)",
            "severity": "CRITICAL", "cvss": 9.1, "cwe": "CWE-942",
            "evidence": crit[0]["issue"] + " - reproduced with two distinct origins",
            "remediation": "Replace ACAO reflection with strict allow-list. "
                            "Never combine ACAO:* with ACAC:true."}


def _r_high(s):
    verified = s.get("methodology_findings") or []
    high = [f for f in verified
             if f.get("severity") == "HIGH" and f.get("confidence") == "CONFIRMED"]
    if not high:
        return None
    return {"name": "CORS misconfig - high severity (CONFIRMED)",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-942",
            "evidence": "; ".join(i["issue"] for i in high),
            "remediation": "Whitelist exact origins. Reject 'null' and wildcards."}


def _r_med(s):
    verified = s.get("methodology_findings") or []
    med = [f for f in verified
            if f.get("severity") == "MEDIUM" and f.get("confidence") == "CONFIRMED"]
    if not med:
        return None
    return {"name": "CORS reflects arbitrary origin (CONFIRMED)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-942",
            "evidence": "; ".join(i["issue"] for i in med),
            "remediation": "Use a static allow-list of trusted origins instead of "
                            "reflecting Origin header."}


def _r_susp(s):
    verified = s.get("methodology_findings") or []
    susp = [f for f in verified if f.get("confidence") == "SUSPECTED"]
    if not susp:
        return None
    return {"name": f"{len(susp)} CORS finding(s) did not reproduce (SUSPECTED)",
            "severity": "LOW", "cvss": 2.0, "cwe": "CWE-942",
            "evidence": "; ".join(i["issue"] for i in susp),
            "remediation": "Manually re-test each finding with custom Origin headers."}


FINDING_RULES = [_r_crit, _r_high, _r_med, _r_susp]
INTEL_FIELDS = [
    ("ACAO", "acao"),
    ("ACAC", "acac"),
    ("Quick-probe hits", "quick_hits"),
    ("Deep-scan hits", "deep_hits"),
    ("Verified findings", "methodology_findings"),
    ("Stage timings (ms)", "stage_timings"),
]


@router.post("/api/vuln/web_cors_misconfig")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    scanner = WebCorsMisconfig()
    return await scanner.run_as_endpoint(req,
        finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
