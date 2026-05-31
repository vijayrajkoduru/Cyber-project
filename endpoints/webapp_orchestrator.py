"""Webapp module orchestrator endpoint — VL-FORGE v2 streaming.

Same pattern as endpoints/recon_orchestrator.py but for the 34 web-application
pentest scanners. Single POST /api/scan/run_all replaces 34 sequential frontend
calls. Backend fans out to every /api/scan/<tool> endpoint in parallel via the
shared orchestrator engine in tools/_framework/orchestrator.py.

Expected speedup on a real target: ~10 min sequential -> ~60-90 sec parallel.

Tier organization mirrors the existing PHASES list in App.js so the frontend
can render tier-filter checkboxes ("Quick scan: Recon + Injection only").
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


WEBAPP_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    # Discovery — runs FIRST so other scanners can use scan_state.json
    "tier1_discovery": [
        ("spa_crawler", "/api/webapp/scan/spa_crawler"),
    ],
    # Recon & Fingerprinting
    # (dns / techstack / ssl_cert removed — they live in tools/recon/, not
    #  tools/webapp/ — the Recon module already handles them. Keeping the
    #  webapp module focused on app-layer tests only.)
    "tier2_recon": [
        ("cms",      "/api/webapp/scan/cms"),
        ("ssl",      "/api/webapp/scan/ssl"),
        ("portscan", "/api/webapp/scan/portscan"),
    ],
    # Injection Attacks (highest customer impact)
    "tier3_injection": [
        ("xss",            "/api/webapp/scan/xss"),
        ("sqli",           "/api/webapp/scan/sqli"),
        ("cmd_injection",  "/api/webapp/scan/cmd_injection"),
        ("xxe",            "/api/webapp/scan/xxe"),
    ],
    # Authentication & Session
    "tier4_auth": [
        ("headers", "/api/webapp/scan/headers"),     # security_headers route alias
        ("cookies", "/api/webapp/scan/cookies"),
        ("csrf",    "/api/webapp/scan/csrf"),
        ("jwt",     "/api/webapp/scan/jwt"),
    ],
    # File & Path
    "tier5_file_path": [
        ("lfi",           "/api/webapp/scan/lfi"),
        ("exposed_files", "/api/webapp/scan/exposed_files"),
    ],
    # Network & Protocol
    "tier6_network": [
        ("cors",          "/api/webapp/scan/cors"),
        ("ssrf",          "/api/webapp/scan/ssrf"),
        ("http_methods",  "/api/webapp/scan/http_methods"),
        ("open_redirect", "/api/webapp/scan/open_redirect"),
        ("clickjacking",  "/api/webapp/scan/clickjacking"),
    ],
    # Access Control & Modern API
    "tier7_access": [
        ("idor",            "/api/webapp/scan/idor"),
        ("mass_assignment", "/api/webapp/scan/mass_assignment"),
        ("nosql",           "/api/webapp/scan/nosql"),
        ("access_control",  "/api/webapp/scan/access_control"),
    ],
    # Framework-specific + Heavy
    "tier8_framework": [
        ("nikto",          "/api/webapp/scan/nikto"),
        ("nuclei",         "/api/webapp/scan/nuclei"),
        ("force_browse",   "/api/webapp/scan/force_browse"),
        ("file_upload",    "/api/webapp/scan/file_upload"),
        ("ssti",           "/api/webapp/scan/ssti"),
        ("graphql",        "/api/webapp/scan/graphql"),
        ("sensitive_data", "/api/webapp/scan/sensitive_data"),
        ("stored_xss",     "/api/webapp/scan/stored_xss"),
        ("wpscan",         "/api/webapp/scan/wpscan"),
    ],
    # Tier 9 — AI-curated discovery (newly forged, big wordlists, async-parallel)
    "tier9_ai_curated_discovery": [
        ("directory_brute",  "/api/webapp/directory_brute"),    # 940 paths
        ("param_discovery",  "/api/webapp/param_discovery"),    # 577 names
        ("crawler",          "/api/webapp/crawler"),            # 203 seeds
        ("secrets",          "/api/webapp/secrets"),            # 97 regex patterns
    ],
    # Tier 10 — Modern attack-surface coverage (AI-curated payload lists)
    "tier10_modern_attacks": [
        ("nosqli",                "/api/webapp/nosqli"),                # 20 MongoDB operators
        ("ldap_injection",        "/api/webapp/ldap_injection"),        # 20 LDAP filter probes
        ("crlf_injection",        "/api/webapp/crlf_injection"),        # 18 CRLF variants
        ("prototype_pollution",   "/api/webapp/prototype_pollution"),   # 19 gadgets
        ("host_header_injection", "/api/webapp/host_header_injection"), # 25 header variants
        ("cache_poisoning",       "/api/webapp/cache_poisoning"),       # 25 unkeyed headers
        ("deserialization_probe", "/api/webapp/deserialization_probe"), # 53 markers
        ("http_smuggling",        "/api/webapp/http_smuggling"),        # CL.TE timing probe
    ],
    # Tier 11 — Discovery-deep (pre-existing real implementations now wired in)
    "tier11_discovery_deep": [
        ("backup_files",          "/api/webapp/backup_files"),
        ("directory_listing",     "/api/webapp/directory_listing"),
        ("swagger_discovery",     "/api/webapp/swagger_discovery"),
        ("graphql_introspection", "/api/webapp/graphql_introspection"),
        ("retire_js",             "/api/webapp/retire_js"),
        ("api_endpoint_fuzz",     "/api/webapp/api_endpoint_fuzz"),
        ("param_reflection",      "/api/webapp/param_reflection"),
    ],
    # Tier 12 — Auth & session (pre-existing real implementations now wired in)
    "tier12_auth_session": [
        ("broken_auth",           "/api/webapp/broken_auth"),
        ("session_fixation",      "/api/webapp/session_fixation"),
        ("oauth_redirect_bypass", "/api/webapp/oauth_redirect_bypass"),
        ("password_reset_flaws",  "/api/webapp/password_reset_flaws"),
        ("privilege_escalation",  "/api/webapp/privilege_escalation"),
    ],
    # Tier 13 — Modern + framework-specific (pre-existing real implementations)
    "tier13_modern_framework": [
        ("csp_bypass",            "/api/webapp/csp_bypass"),
        ("weak_crypto",           "/api/webapp/weak_crypto"),
        ("race_condition",        "/api/webapp/race_condition"),
        ("drupal_scan",           "/api/webapp/drupal_scan"),
        ("joomla_scan",           "/api/webapp/joomla_scan"),
        ("file_upload_bypass",    "/api/webapp/file_upload_bypass"),
    ],
    # ── VL-FORGE 2026-05-30: +8 modern attack-surface scanners ──
    "tier14_modern_attack_surface": [
        ("graphql_batching_abuse",         "/api/webapp/scan/graphql_batching_abuse"),
        ("websocket_auth_audit",           "/api/webapp/scan/websocket_auth_audit"),
        ("jwt_algorithm_confusion",        "/api/webapp/scan/jwt_algorithm_confusion"),
        ("oauth_state_validation",         "/api/webapp/scan/oauth_state_validation"),
        ("postmessage_origin_audit",       "/api/webapp/scan/postmessage_origin_audit"),
        ("dom_clobbering_probe",           "/api/webapp/scan/dom_clobbering_probe"),
        ("cookie_security_advanced_audit", "/api/webapp/scan/cookie_security_advanced_audit"),
        ("csp3_audit",                      "/api/webapp/scan/csp3_audit"),
    ],
    # ── VL-FORGE round 2: +8 edge / proxy / signature-attack scanners ──
    "tier15_edge_proxy_signature": [
        ("saml_xml_signature_wrap",  "/api/webapp/scan/saml_xml_signature_wrap"),
        ("http2_request_smuggling",  "/api/webapp/scan/http2_request_smuggling"),
        ("web_cache_deception",      "/api/webapp/scan/web_cache_deception"),
        ("service_worker_audit",     "/api/webapp/scan/service_worker_audit"),
        ("esi_injection_probe",      "/api/webapp/scan/esi_injection_probe"),
        ("request_forgery_origin",   "/api/webapp/scan/request_forgery_origin"),
        ("content_type_confusion",   "/api/webapp/scan/content_type_confusion"),
        ("xs_leaks_probe",           "/api/webapp/scan/xs_leaks_probe"),
    ],
    # ── VL-FORGE round 3: +8 protocol / TLS / identity scanners ──
    "tier16_protocol_tls_identity": [
        ("webrtc_stun_audit",              "/api/webapp/scan/webrtc_stun_audit"),
        ("regex_dos_probe",                "/api/webapp/scan/regex_dos_probe"),
        ("hsts_audit_deep",                "/api/webapp/scan/hsts_audit_deep"),
        ("mtls_audit",                     "/api/webapp/scan/mtls_audit"),
        ("oidc_discovery_audit",           "/api/webapp/scan/oidc_discovery_audit"),
        ("graphql_introspection_authz",    "/api/webapp/scan/graphql_introspection_authz"),
        ("path_normalization_bypass",      "/api/webapp/scan/path_normalization_bypass"),
        ("open_redirect_oauth_extension",  "/api/webapp/scan/open_redirect_oauth_extension"),
    ],
    # ── VL-FORGE round 4: +8 OWASP-API + supply-chain + header hygiene ──
    "tier17_owasp_api_supply_chain": [
        ("graphql_alias_injection",     "/api/webapp/scan/graphql_alias_injection"),
        ("ai_api_key_leak_in_html",     "/api/webapp/scan/ai_api_key_leak_in_html"),
        ("csrf_token_quality",          "/api/webapp/scan/csrf_token_quality"),
        ("broken_function_level_auth",  "/api/webapp/scan/broken_function_level_auth"),
        ("sri_audit",                   "/api/webapp/scan/sri_audit"),
        ("server_timing_leak",          "/api/webapp/scan/server_timing_leak"),
        ("permissions_policy_audit",    "/api/webapp/scan/permissions_policy_audit"),
        ("robots_disallow_disclosure",  "/api/webapp/scan/robots_disallow_disclosure"),
    ],
    # ── VL-FORGE round 5: +8 deep-protocol + identity + telemetry ──
    "tier18_deep_protocol_identity": [
        ("crlf_header_injection_deep",      "/api/webapp/scan/crlf_header_injection_deep"),
        ("http3_quic_negotiation",          "/api/webapp/scan/http3_quic_negotiation"),
        ("jsonp_callback_abuse",            "/api/webapp/scan/jsonp_callback_abuse"),
        ("oauth_scope_creep",               "/api/webapp/scan/oauth_scope_creep"),
        ("forwarded_header_trust",          "/api/webapp/scan/forwarded_header_trust"),
        ("graphql_persisted_query_bypass",  "/api/webapp/scan/graphql_persisted_query_bypass"),
        ("webmail_imap_smtp_ssrf",          "/api/webapp/scan/webmail_imap_smtp_ssrf"),
        ("csp_report_uri_audit",            "/api/webapp/scan/csp_report_uri_audit"),
    ],
    # ── VL-FORGE round 6: +8 SAML/OAuth/HTTP-method/DoS scanners ──
    "tier19_method_saml_oauth_dos": [
        ("saml_response_time_bomb",    "/api/webapp/scan/saml_response_time_bomb"),
        ("oauth_client_id_confusion",  "/api/webapp/scan/oauth_client_id_confusion"),
        ("options_method_tampering",   "/api/webapp/scan/options_method_tampering"),
        ("head_method_side_channel",   "/api/webapp/scan/head_method_side_channel"),
        ("gzip_bomb_upload",           "/api/webapp/scan/gzip_bomb_upload"),
        ("trace_method_enabled",       "/api/webapp/scan/trace_method_enabled"),
        ("cors_preflight_cache_abuse", "/api/webapp/scan/cors_preflight_cache_abuse"),
        ("x_original_url_bypass",      "/api/webapp/scan/x_original_url_bypass"),
    ],
    # ── VL-FORGE round 7: +8 upload/export/file/framework scanners ──
    "tier20_upload_export_framework": [
        ("xss_via_filename_upload",      "/api/webapp/scan/xss_via_filename_upload"),
        ("csv_injection_export",         "/api/webapp/scan/csv_injection_export"),
        ("lfi_log_injection",            "/api/webapp/scan/lfi_log_injection"),
        ("nextjs_rsc_audit",             "/api/webapp/scan/nextjs_rsc_audit"),
        ("websocket_message_size_dos",   "/api/webapp/scan/websocket_message_size_dos"),
        ("odata_query_bypass",           "/api/webapp/scan/odata_query_bypass"),
        ("graphql_subscription_auth",    "/api/webapp/scan/graphql_subscription_auth"),
        ("proto_pollution_chain",        "/api/webapp/scan/proto_pollution_chain"),
    ],
    # ── VL-FORGE round 8: +8 enterprise + supply-chain + URL-scheme ──
    "tier21_enterprise_url_scheme": [
        ("client_side_template_injection","/api/webapp/scan/client_side_template_injection"),
        ("fetch_metadata_audit",          "/api/webapp/scan/fetch_metadata_audit"),
        ("scim_endpoint_enumeration",     "/api/webapp/scan/scim_endpoint_enumeration"),
        ("ms_graph_api_leak",             "/api/webapp/scan/ms_graph_api_leak"),
        ("grpc_reflection_audit",         "/api/webapp/scan/grpc_reflection_audit"),
        ("webhook_secret_validation",     "/api/webapp/scan/webhook_secret_validation"),
        ("svg_xss_upload",                "/api/webapp/scan/svg_xss_upload"),
        ("ssrf_url_schema_smuggle",       "/api/webapp/scan/ssrf_url_schema_smuggle"),
    ],
    # ── VL-FORGE round 9: +8 server/framework/auth scanners ──
    "tier22_server_framework_auth": [
        ("apache_ssi_includes",            "/api/webapp/scan/apache_ssi_includes"),
        ("tomcat_ajp_exposure",            "/api/webapp/scan/tomcat_ajp_exposure"),
        ("spring_spel_injection",          "/api/webapp/scan/spring_spel_injection"),
        ("graphql_field_suggestions_leak", "/api/webapp/scan/graphql_field_suggestions_leak"),
        ("sql_truncation_attack",          "/api/webapp/scan/sql_truncation_attack"),
        ("mass_assignment_patch",          "/api/webapp/scan/mass_assignment_patch"),
        ("oauth_front_channel_logout",     "/api/webapp/scan/oauth_front_channel_logout"),
        ("apache_modrewrite_confusion",    "/api/webapp/scan/apache_modrewrite_confusion"),
    ],
    # ── VL-FORGE round 10: +8 protocol/CMS/CI scanners (closing to 95%) ──
    "tier23_protocol_cms_ci": [
        ("xxe_json_xml_conversion",   "/api/webapp/scan/xxe_json_xml_conversion"),
        ("h2c_smuggling",             "/api/webapp/scan/h2c_smuggling"),
        ("webdav_exposure",           "/api/webapp/scan/webdav_exposure"),
        ("nestjs_pipe_injection",     "/api/webapp/scan/nestjs_pipe_injection"),
        ("strapi_admin_default",      "/api/webapp/scan/strapi_admin_default"),
        ("postman_api_discovery",     "/api/webapp/scan/postman_api_discovery"),
        ("cache_stampede_detect",     "/api/webapp/scan/cache_stampede_detect"),
        ("github_actions_oidc_leak",  "/api/webapp/scan/github_actions_oidc_leak"),
    ],
    # ── VL-FORGE round 11: +8 cloud/data/identity scanners — 100% playbook ──
    "tier24_cloud_data_identity": [
        ("mtls_server_cert_pin_audit",     "/api/webapp/scan/mtls_server_cert_pin_audit"),
        ("opa_policy_bypass",              "/api/webapp/scan/opa_policy_bypass"),
        ("k8s_serviceaccount_token_leak",  "/api/webapp/scan/k8s_serviceaccount_token_leak"),
        ("trino_presto_sql_injection",     "/api/webapp/scan/trino_presto_sql_injection"),
        ("opensearch_query_injection",     "/api/webapp/scan/opensearch_query_injection"),
        ("trino_metadata_leak",            "/api/webapp/scan/trino_metadata_leak"),
        ("kafka_rest_proxy_exposure",      "/api/webapp/scan/kafka_rest_proxy_exposure"),
        ("aws_cognito_unauth_admin",       "/api/webapp/scan/aws_cognito_unauth_admin"),
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in WEBAPP_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class WebAppRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None       # subset, e.g. ["tier3_injection"]
    concurrency: Optional[int] = 8          # max in-flight tool calls
    auth_cookie: Optional[str] = None       # SPA session cookie (forwarded)
    auth_bearer: Optional[str] = None       # JWT bearer (forwarded)
    options: Optional[dict] = None          # per-scanner options (rare)


def _resolve_tools_and_jwt(req: "WebAppRunAllRequest", request: Request):
    """Common request unpacking."""
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in WEBAPP_TOOLS_BY_TIER:
                tools.extend(WEBAPP_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()

    extra = {}
    if req.options:
        extra.update(req.options)

    auth_header = request.headers.get("authorization") or ""
    jwt_token = None
    if auth_header.lower().startswith("bearer "):
        jwt_token = auth_header.split(" ", 1)[1].strip()

    return tools, extra, jwt_token


@router.post("/api/webapp/scan/run_all")
async def webapp_run_all(req: "WebAppRunAllRequest",
                          request: Request,
                          _=Depends(verify_scan_quota)):
    """Stream per-scanner results as NDJSON. See run_module_streaming for shape.

    Each event line:
      {"event":"scan_started", "module":"webapp", "target":"...", "total_tools":...}
      {"event":"tool_complete", "tool":..., "duration_sec":..., "result":{...}}
      ... N tool_complete events ...
      {"event":"heartbeat", "elapsed_sec":..., "completed":N, "total":M, "in_flight":...}
      {"event":"scan_complete", "duration_sec":..., "summary":{...}, "timing":{...}}
    """
    tools, extra, jwt_token = _resolve_tools_and_jwt(req, request)
    # VL-TURBO 2.0 — default concurrency 12→24 (cap 16→32). Webapp grew from
    # 34 tools to ~160+ across 20+ tiers; at 12 in-flight a full scan needed
    # ~13 waves. At 24 in-flight that drops to ~7 waves, roughly halving
    # wall-clock time. httpx pool bumped to keepalive=2*concurrency anyway.
    concurrency = max(1, min(req.concurrency or 24, 32))

    generator = run_module_streaming(
        target=req.target,
        tools=tools,
        module_name="webapp",
        concurrency=concurrency,
        auth_cookie=req.auth_cookie,
        auth_bearer=req.auth_bearer,
        extra_body=extra or None,
        jwt_token=jwt_token,
    )
    return StreamingResponse(
        generator,
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control":     "no-store, no-transform",
            "Connection":        "keep-alive",
        },
    )


@router.post("/api/webapp/scan/run_all_buffered")
async def webapp_run_all_buffered(req: "WebAppRunAllRequest",
                                    request: Request,
                                    _=Depends(verify_scan_quota)):
    """Non-streaming version — buffers all 34 results then returns one big JSON.
    Use only when streaming isn't suitable (CLI tools, server-to-server)."""
    tools, extra, jwt_token = _resolve_tools_and_jwt(req, request)
    # VL-TURBO 2.0 — default concurrency 12→24 (cap 16→32). Webapp grew from
    # 34 tools to ~160+ across 20+ tiers; at 12 in-flight a full scan needed
    # ~13 waves. At 24 in-flight that drops to ~7 waves, roughly halving
    # wall-clock time. httpx pool bumped to keepalive=2*concurrency anyway.
    concurrency = max(1, min(req.concurrency or 24, 32))
    return await run_module_parallel(
        target=req.target,
        tools=tools,
        module_name="webapp",
        concurrency=concurrency,
        auth_cookie=req.auth_cookie,
        auth_bearer=req.auth_bearer,
        extra_body=extra or None,
        jwt_token=jwt_token,
    )


@router.get("/api/webapp/scan/run_all/tiers")
async def webapp_run_all_tiers():
    """Discovery endpoint — list tier IDs the frontend can filter by."""
    return {
        "tiers": [
            {"id": tier_id, "tools": [name for name, _ in tools],
              "count": len(tools)}
            for tier_id, tools in WEBAPP_TOOLS_BY_TIER.items()
        ],
        "total_tools": sum(len(t) for t in WEBAPP_TOOLS_BY_TIER.values()),
    }


# ─── ModuleAutoPanel-compatible aliases (no /scan/ middle path) ────────
# The dashboard's generic ModuleAutoPanel fetches /api/<mod>/run_all/tiers
# and POSTs to /api/<mod>/run_all. Webapp's original endpoints use
# /api/webapp/scan/run_all (legacy from the pre-orchestrator era). These
# two aliases let the standard tier UI work without rewriting the legacy
# routes that the custom WebappModule still calls.

@router.get("/api/webapp/run_all/tiers")
async def webapp_run_all_tiers_alias():
    return await webapp_run_all_tiers()


@router.post("/api/webapp/run_all")
async def webapp_run_all_alias(req: "WebAppRunAllRequest",
                                 request: Request,
                                 _=Depends(verify_scan_quota)):
    return await webapp_run_all(req, request, _)


def register(app):
    app.include_router(router)
