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
    # ── VL-FORGE 2026-05-30 round 2: +15 real probes across 4 new tiers ──
    "tier11_social_media": [
        ("nitter_twitter_recent",  "/api/osint/nitter_twitter_recent"),
        ("reddit_user_history",    "/api/osint/reddit_user_history"),
        ("mastodon_user_lookup",   "/api/osint/mastodon_user_lookup"),
        ("youtube_channel_rss",    "/api/osint/youtube_channel_rss"),
        ("github_activity_recent", "/api/osint/github_activity_recent"),
    ],
    "tier12_image_geo": [
        ("exif_metadata_url",      "/api/osint/exif_metadata_url"),
        ("reverse_image_search",   "/api/osint/reverse_image_search"),
        ("osm_location_lookup",    "/api/osint/osm_location_lookup"),
    ],
    "tier13_corporate_extra": [
        ("uk_companies_house",     "/api/osint/uk_companies_house"),
        ("mca_indian_company",     "/api/osint/mca_indian_company"),
        ("censys_certs_free",      "/api/osint/censys_certs_free"),
    ],
    "tier14_developer_intel": [
        ("github_secrets_scan",    "/api/osint/github_secrets_scan"),
        ("commoncrawl_cdx",        "/api/osint/commoncrawl_cdx"),
        ("certspotter_history",    "/api/osint/certspotter_history"),
        ("wayback_robots_history", "/api/osint/wayback_robots_history"),
    ],
    # ── VL-FORGE 2026-05-30 round 3: +15 real probes across 4 new tiers ──
    "tier15_identity_deep": [
        ("holehe_email_check",     "/api/osint/holehe_email_check"),
        ("ghunt_google_basic",     "/api/osint/ghunt_google_basic"),
        ("greynoise_community",    "/api/osint/greynoise_community"),
    ],
    "tier16_platform_user_lookups": [
        ("twitch_user_lookup",     "/api/osint/twitch_user_lookup"),
        ("bluesky_user_lookup",    "/api/osint/bluesky_user_lookup"),
        ("stackoverflow_user",     "/api/osint/stackoverflow_user"),
        ("devto_user_lookup",      "/api/osint/devto_user_lookup"),
        ("hashnode_user_lookup",   "/api/osint/hashnode_user_lookup"),
        ("medium_user_intel",      "/api/osint/medium_user_intel"),
    ],
    "tier17_messaging_intel": [
        ("discord_invite_intel",   "/api/osint/discord_invite_intel"),
        ("telegram_public_channel","/api/osint/telegram_public_channel"),
    ],
    "tier18_dns_archive_geo": [
        ("dns_zone_walk_nsec",     "/api/osint/dns_zone_walk_nsec"),
        ("wayback_emails_grep",    "/api/osint/wayback_emails_grep"),
        ("mapillary_location",     "/api/osint/mapillary_location"),
        ("urlscan_io_search",      "/api/osint/urlscan_io_search"),
    ],
    # ── VL-FORGE round 4: +8 paid-API integrations (advisory + real-probe) ──
    "tier19_paid_api_breach_intel": [
        ("dehashed_search",            "/api/osint/dehashed_search"),
        ("intelx_search",              "/api/osint/intelx_search"),
        ("snusbase_search",            "/api/osint/snusbase_search"),
    ],
    "tier20_paid_api_intel_discovery": [
        ("hunter_io_domain",           "/api/osint/hunter_io_domain"),
        ("phoneinfoga_lookup",         "/api/osint/phoneinfoga_lookup"),
        ("securitytrails_passive_dns", "/api/osint/securitytrails_passive_dns"),
        ("fofa_search",                "/api/osint/fofa_search"),
        ("zoomeye_search",             "/api/osint/zoomeye_search"),
        ("domaintools_historical",     "/api/osint/domaintools_historical"),
    ],
    # ── VL-FORGE round 5: +9 enterprise threat-intel + people-search (advisory) ──
    "tier21_enterprise_intel_people": [
        ("censys_hosts_search",         "/api/osint/censys_hosts_search"),
        ("greynoise_paid_advisory",     "/api/osint/greynoise_paid_advisory"),
        ("misp_threat_feed_advisory",   "/api/osint/misp_threat_feed_advisory"),
        ("mandiant_advantage_advisory", "/api/osint/mandiant_advantage_advisory"),
        ("crowdstrike_falcon_advisory", "/api/osint/crowdstrike_falcon_advisory"),
        ("recorded_future_advisory",    "/api/osint/recorded_future_advisory"),
        ("spokeo_whitepages_advisory",  "/api/osint/spokeo_whitepages_advisory"),
        ("pimeyes_face_advisory",       "/api/osint/pimeyes_face_advisory"),
        ("osint_industries_aggregator", "/api/osint/osint_industries_aggregator"),
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
    # VL-TURBO 2.0 for OSINT: default 12 (cap 20). Higher than the legacy
    # 6 default but still respects API rate limits — OSINT calls 30+
    # third-party APIs and the per-source VL-PRIME rate buckets prevent
    # any single provider being hammered. The orchestrator parallelism
    # is module-level, not per-source.
    concurrency: Optional[int] = 12
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
    concurrency = max(1, min(req.concurrency or 12, 20))  # VL-TURBO 2.0
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
    concurrency = max(1, min(req.concurrency or 12, 20))  # VL-TURBO 2.0
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
