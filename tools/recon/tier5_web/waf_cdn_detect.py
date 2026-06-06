"""waf_cdn_detect — VL-FORGE Recon §5 Web App Recon (real, zero-FP)."""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import ScanContext, run_scanner
from tools.recon._web_helpers import fetch, base_url


router = APIRouter()

async def gather(ctx: ScanContext):
    url = base_url(ctx.host)
    code, hdrs, body = await fetch(url)
    lh = {k.lower(): v for k,v in hdrs.items()}
    fingerprints = []
    sigs = {
        "Cloudflare":["cf-ray","cf-cache-status","__cf_bm"],
        "AWS CloudFront":["x-amz-cf-id","x-amz-cf-pop"],
        "Akamai":["x-akamai","akamai-request-id","x-akamai-staging"],
        "Fastly":["x-fastly","fastly-debug"],
        "Sucuri":["x-sucuri-id","x-sucuri-cache"],
        "Imperva/Incapsula":["x-iinfo","x-cdn"],
        "Azure CDN":["x-azure-ref","x-msedge-ref"],
        "AWS WAF":["x-amzn-requestid"],
        "F5 BIG-IP":["x-waf","bigipserver"],
    }
    text = " ".join(f"{k}:{v}" for k,v in lh.items()).lower()
    for name, marks in sigs.items():
        if any(m in text for m in marks): fingerprints.append(name)
    ctx.state["fingerprints"] = sorted(set(fingerprints))
    ctx.state["detected"] = bool(fingerprints)
    ctx.source("Header fingerprint — 9 WAF/CDN providers")

def _r_chain_handoff(s):
    fps = s.get("fingerprints") or []
    detected = s.get("detected")
    chain_next = []
    reasons = []
    fps_lower = " ".join(f.lower() for f in fps)
    if "cloudflare" in fps_lower:
        for n in ("origin_ip_bypass","cloudfront_disco"):
            if n not in chain_next: chain_next.append(n)
        reasons.append("Cloudflare->origin_ip_bypass,cloudfront_disco")
    if any(k in fps_lower for k in ("akamai","fastly","aws waf")):
        if "origin_ip_bypass" not in chain_next: chain_next.append("origin_ip_bypass")
        reasons.append("Akamai/Fastly/AWS-WAF->origin_ip_bypass")
    if detected:
        if "http_server_cve" not in chain_next: chain_next.append("http_server_cve")
        reasons.append("WAF->http_server_cve")
    else:
        for n in ("http_method_enum","api_endpoint_brute"):
            if n not in chain_next: chain_next.append(n)
        reasons.append("no-WAF->http_method_enum,api_endpoint_brute")
    if any(k in fps_lower for k in ("cloudfront","fastly","akamai","azure cdn","cloudflare")):
        if "passive_dns" not in chain_next: chain_next.append("passive_dns")
        reasons.append("CDN-edge->passive_dns")
    if s.get("waf_bypassed"):
        if "tech_stack_detect" not in chain_next: chain_next.append("tech_stack_detect")
        reasons.append("WAF-bypassed->tech_stack_detect")
    if not chain_next: return None
    return {
        "name": "Cross-module chain handoff - WAF/CDN posture identifies follow-up scanners",
        "severity": "INFO",
        "evidence": f"Detected: {', '.join(fps) if fps else 'none'}; suggests {len(chain_next)} follow-up scanner(s) ("+ "; ".join(reasons) +")",
        "remediation": "WAF/CDN typically hide origin IP. Run origin-discovery + passive-DNS to find real backend.",
        "cwe": "CWE-1006",
        "chain_next": chain_next,
        "discovery_method": "waf_cdn_to_origin_chain",
        "source_stage": "chain_handoff",
        "confidence": "INFO",
    }

RULES = [
    _r_chain_handoff,
]

@router.post("/api/recon/waf_cdn_detect")
async def recon_waf_cdn_detect(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    return await run_scanner(host=host, tool="waf_cdn_detect",
                              gather_func=gather, finding_rules=RULES,
                              intel_fields=[("Fingerprints","fingerprints"),("Detected","detected")])

def register(app):
    app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - upstream scanners trigger us via
#  _chain_callable. Full chain execution goes through the orchestrator.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target, options, jwt=None) -> dict:
    return {"tool": "waf_cdn_detect", "target": target, "_skipped": True,
            "skipped_reason": "Use orchestrator for full chain execution", "findings": []}

from tools._methodology import chain_registry
chain_registry.register("waf_cdn_detect", _chain_callable)
