"""OSINT module orchestrator — VL-FORGE v2 streaming.

Same engine as recon/vuln/webapp orchestrators. As new OSINT scanners drop
into tools/osint/, add them to OSINT_TOOLS_BY_TIER below and they slot in.

POST /api/osint/run_all          — NDJSON stream
POST /api/osint/run_all_buffered — single big JSON
GET  /api/osint/run_all/tiers    — tier discovery
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import (
    run_module_parallel, run_module_streaming,
)

router = APIRouter()


# VL-FOUNDRY OSINT Layer 2 — 12 scanners across 4 tiers.
# Order = customer-facing run order (passive surface first, leak/code last).
OSINT_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_passive_domain": [
        ("geoip",            "/api/osint/geoip"),
        ("dnstwist",         "/api/osint/dnstwist"),
        ("wayback_history",  "/api/osint/wayback_history"),
    ],
    "tier2_people_identity": [
        ("harvester_emails", "/api/osint/harvester_emails"),
        ("crtsh_emails",     "/api/osint/crtsh_emails"),
        ("social_handles",   "/api/osint/social_handles"),
    ],
    "tier3_leaks_code": [
        ("github_recon",     "/api/osint/github_recon"),
        ("pastebin_search",  "/api/osint/pastebin_search"),
        ("breach_check",     "/api/osint/breach_check"),
    ],
    "tier4_metadata_dorking": [
        ("document_metadata","/api/osint/document_metadata"),
        ("search_dorks",     "/api/osint/search_dorks"),
        ("gravatar_check",   "/api/osint/gravatar_check"),
    ],
    # ── VL-FORGE 2026-05-30: +30 new real probes across 6 new tiers ──────
    "tier5_people_identity_deep": [
        ("hibp_passwords",       "/api/osint/hibp_passwords"),
        ("email_pattern_guess",  "/api/osint/email_pattern_guess"),
        ("email_validate_mx",    "/api/osint/email_validate_mx"),
        ("github_user_intel",    "/api/osint/github_user_intel"),
        ("github_org_intel",     "/api/osint/github_org_intel"),
        ("sherlock_username",    "/api/osint/sherlock_username"),
    ],
    "tier6_domain_infra_deep": [
        ("rdap_domain",            "/api/osint/rdap_domain"),
        ("crtsh_full_certs",       "/api/osint/crtsh_full_certs"),
        ("shodan_internetdb",      "/api/osint/shodan_internetdb"),
        ("bgp_he_asn",             "/api/osint/bgp_he_asn"),
        ("hackertarget_reverseip", "/api/osint/hackertarget_reverseip"),
        ("wayback_cdx_search",     "/api/osint/wayback_cdx_search"),
        ("favicon_hash_mmh3",      "/api/osint/favicon_hash_mmh3"),
        ("dns_propagation_check",  "/api/osint/dns_propagation_check"),
    ],
    "tier7_threat_intel": [
        ("urlhaus_lookup",       "/api/osint/urlhaus_lookup"),
        ("threatfox_iocs",       "/api/osint/threatfox_iocs"),
        ("malwarebazaar_hash",   "/api/osint/malwarebazaar_hash"),
        ("otx_indicators",       "/api/osint/otx_indicators"),
        ("feodotracker_ip",      "/api/osint/feodotracker_ip"),
    ],
    "tier8_breach_darkweb": [
        ("hibp_breaches_domain", "/api/osint/hibp_breaches_domain"),
        ("hudson_rock_cavalier", "/api/osint/hudson_rock_cavalier"),
        ("leakix_search",        "/api/osint/leakix_search"),
    ],
    "tier9_corporate_financial": [
        ("sec_edgar_company",    "/api/osint/sec_edgar_company"),
        ("uspto_patent_search",  "/api/osint/uspto_patent_search"),
        ("opencorporates_search","/api/osint/opencorporates_search"),
        ("crunchbase_basic",     "/api/osint/crunchbase_basic"),
    ],
    "tier10_ai_llm_osint": [
        ("llm_entity_extraction","/api/osint/llm_entity_extraction"),
        ("llm_pretext_draft",    "/api/osint/llm_pretext_draft"),
        ("llm_disinfo_detect",   "/api/osint/llm_disinfo_detect"),
        ("llm_image_to_text",    "/api/osint/llm_image_to_text"),
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in OSINT_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class OsintRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 6
    options: Optional[dict] = None


def _resolve(req: "OsintRunAllRequest", request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in OSINT_TOOLS_BY_TIER:
                tools.extend(OSINT_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/osint/run_all")
async def osint_run_all(req: "OsintRunAllRequest", request: Request,
                        _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 6, 12))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="osint",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/osint/run_all_buffered")
async def osint_run_all_buffered(req: "OsintRunAllRequest", request: Request,
                                 _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 6, 12))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="osint",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/osint/run_all/tiers")
async def osint_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in OSINT_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in OSINT_TOOLS_BY_TIER.values()),
    }


def register(app): app.include_router(router)
