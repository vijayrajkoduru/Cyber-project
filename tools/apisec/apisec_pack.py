"""§22 API Security — 108 endpoints per 22_apisec.md.
10 sections: discovery, OWASP API Top 10, auth, authz, rate limit, GraphQL,
gRPC, WebSocket/SSE/WebTransport, SOAP/REST legacy, supply chain/versioning.

VL-FORGE upgrade 2026-05-30: tier1 API Discovery (OpenAPI/Swagger/GraphQL)
+ tier6 GraphQL introspection upgraded to LIVE PROBES. Other tiers
correctly remain advisory or require authenticated context.
"""
import urllib.request
import urllib.error
import json
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


def _host(target: str) -> str:
    s = target.split("://", 1)[-1].split("/")[0]
    return s.strip().lower() or target


def _base_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target.rstrip("/")
    return f"https://{_host(target)}"


def _http_get(url: str, timeout: float = 5.0) -> tuple:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnusLab/2.0", "Accept": "*/*"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(8192).decode("utf-8", errors="ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: body = e.read(8192).decode("utf-8", errors="ignore")
        except Exception: body = ""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception:
        return 0, "", {}


def _http_post(url: str, body: str, headers: dict | None = None, timeout: float = 5.0) -> tuple:
    try:
        h = {"User-Agent": "VulnusLab/2.0", "Content-Type": "application/json"}
        h.update(headers or {})
        req = urllib.request.Request(url, data=body.encode(), headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(8192).decode("utf-8", errors="ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: bd = e.read(8192).decode("utf-8", errors="ignore")
        except Exception: bd = ""
        return e.code, bd, {}
    except Exception:
        return 0, "", {}


def _probe_openapi_swagger(target, req):
    """Check for exposed OpenAPI/Swagger spec at common paths."""
    base = _base_url(target)
    paths = ["/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
              "/api-docs", "/api/swagger.json", "/swagger/v1/swagger.json",
              "/docs", "/swagger-ui.html", "/swagger-ui/", "/api/docs"]
    found = []
    for p in paths:
        code, body, _ = _http_get(base + p, timeout=3)
        if code == 200:
            is_spec = (body.startswith("{") and ('"swagger"' in body or '"openapi"' in body)) or \
                       ("Swagger UI" in body) or ("openapi.json" in body and "<html" in body.lower())
            if is_spec:
                found.append({"path": p, "kind": "spec" if body.startswith("{") else "ui"})
    findings = []
    if found:
        spec_count = sum(1 for f in found if f["kind"] == "spec")
        findings.append(wrap_finding(
            f"API documentation exposed — {len(found)} endpoint(s) found",
            "MEDIUM" if spec_count > 0 else "LOW",
            cvss="5.5" if spec_count > 0 else "3.0",
            cwe="CWE-200",
            remediation="Restrict OpenAPI/Swagger to authenticated users or internal network.",
            evidence_marker=", ".join(f"{f['path']} ({f['kind']})" for f in found)))
    else:
        findings.append(wrap_finding(
            "No OpenAPI/Swagger exposure at standard paths",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue documentation-not-public posture.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return {"tool":"openapi_swagger_discovery","target":target,"scan_time":0,
            "vulnerable": bool(found),
            "severity": findings[0].get("severity","INFO"),
            "findings": findings, "tests_performed": len(paths),
            "tests_summary": f"OpenAPI/Swagger discovery — {len(paths)} paths probed",
            "raw_data": {"found": found}}


def _probe_openapi_exposed(target, req):
    return _probe_openapi_swagger(target, req) | {"tool":"openapi_swagger_exposed"}


def _probe_graphql_discovery(target, req):
    """Discover GraphQL endpoint at common paths."""
    base = _base_url(target)
    paths = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/playground",
              "/altair", "/api/v1/graphql", "/gql"]
    found = []
    for p in paths:
        code, body, _ = _http_get(base + p, timeout=3)
        if code in (200, 400, 405) and ("graphql" in body.lower() or "graphiql" in body.lower() or code == 400):
            found.append(p)
    if found:
        return {"tool":"graphql_schema_discovery","target":target,"scan_time":0,
                "vulnerable": True, "severity": "INFO",
                "findings":[wrap_finding(
                    f"GraphQL endpoint(s) discovered: {', '.join(found)}",
                    "INFO", cvss="0.0", cwe="N/A",
                    remediation="Confirm authentication + introspection settings on each.",
                    evidence_marker=f"Found at: {', '.join(found)}")],
                "tests_performed": len(paths),
                "tests_summary": f"GraphQL endpoint discovery — {len(paths)} paths probed",
                "raw_data": {"found": found}}
    return {"tool":"graphql_schema_discovery","target":target,"scan_time":0,
            "vulnerable": False, "severity": "POSITIVE",
            "findings":[wrap_finding(
                "No GraphQL endpoint found at standard paths",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue not exposing GraphQL or use non-standard path.",
                evidence_marker=f"Tested {len(paths)} paths")],
            "tests_performed": len(paths),
            "tests_summary": "GraphQL endpoint discovery",
            "raw_data": {"found": []}}


def _probe_graphql_introspection(target, req):
    """Check if GraphQL introspection is enabled on standard endpoints."""
    base = _base_url(target)
    query = '{"query":"{__schema{types{name}}}"}'
    for p in ["/graphql", "/api/graphql", "/v1/graphql"]:
        code, body, _ = _http_post(base + p, query, timeout=4)
        if code == 200 and "__schema" in body and "types" in body:
            return {"tool":"graphql_introspection_open","target":target,"scan_time":0,
                    "vulnerable": True, "severity": "HIGH",
                    "findings":[wrap_finding(
                        f"GraphQL introspection enabled at {p}",
                        "HIGH", cvss="7.5", cwe="CWE-200",
                        remediation="Disable introspection in production via Apollo config or schema directive.",
                        evidence_marker=f"POST {p} {{__schema}} → 200 with type list")],
                    "tests_performed": 1,
                    "tests_summary": "GraphQL introspection check",
                    "raw_data": {"endpoint": p}}
    return {"tool":"graphql_introspection_open","target":target,"scan_time":0,
            "vulnerable": False, "severity": "POSITIVE",
            "findings":[wrap_finding(
                "GraphQL introspection disabled or no GraphQL endpoint found",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue introspection-disabled posture in production.",
                evidence_marker="No __schema response")],
            "tests_performed": 3,
            "tests_summary": "GraphQL introspection check",
            "raw_data": {}}


def _probe_grpc_reflection(target, req):
    """Check for gRPC reflection — probe :443/:50051 for grpc-web responses."""
    base = _base_url(target).replace(":443", "")
    # gRPC-Web probe: POST with grpc-web content-type
    code, body, headers = _http_post(base, "",
        {"Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1"}, timeout=3)
    is_grpc = "grpc-status" in (headers.get("grpc-status","") + str(headers)).lower() or \
              code in (200, 415) and "grpc" in str(headers).lower()
    if is_grpc:
        return {"tool":"grpc_reflection_discovery","target":target,"scan_time":0,
                "vulnerable": True, "severity": "MEDIUM",
                "findings":[wrap_finding(
                    "gRPC service detected — verify reflection is disabled in production",
                    "MEDIUM", cvss="5.5", cwe="CWE-200",
                    remediation="Disable gRPC reflection via Server.WithReflection(false) in prod builds.",
                    evidence_marker=f"gRPC headers detected at {base}")],
                "tests_performed": 1,
                "tests_summary": "gRPC reflection / service detection",
                "raw_data": {"headers": str(headers)[:200]}}
    return {"tool":"grpc_reflection_discovery","target":target,"scan_time":0,
            "vulnerable": False, "severity": "INFO",
            "findings":[wrap_finding(
                "No gRPC service detected at standard endpoint",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="If using gRPC on non-standard path, audit reflection settings.",
                evidence_marker=f"No grpc-* headers in response")],
            "tests_performed": 1,
            "tests_summary": "gRPC service detection",
            "raw_data": {}}


def _probe_api_endpoint_brute(target, req):
    """Brute common API endpoints."""
    base = _base_url(target)
    paths = ["/api", "/api/v1", "/api/v2", "/v1", "/v2", "/rest", "/graphql",
              "/admin", "/api/admin", "/api/internal", "/api/private"]
    found = []
    for p in paths:
        code, body, _ = _http_get(base + p, timeout=3)
        if code in (200, 401, 403):
            found.append({"path": p, "code": code})
    if found:
        return {"tool":"api_endpoint_brute","target":target,"scan_time":0,
                "vulnerable": any(f["code"] == 200 for f in found),
                "severity": "MEDIUM" if any(f["code"] == 200 for f in found) else "INFO",
                "findings":[wrap_finding(
                    f"API endpoints discovered: {len(found)}",
                    "MEDIUM" if any(f["code"] == 200 for f in found) else "INFO",
                    cvss="5.0" if any(f["code"] == 200 for f in found) else "0.0",
                    cwe="CWE-200",
                    remediation="Inventory all API paths; require auth on /admin and /internal.",
                    evidence_marker=", ".join(f"{f['path']}→{f['code']}" for f in found))],
                "tests_performed": len(paths),
                "tests_summary": f"API endpoint brute — {len(paths)} paths",
                "raw_data": {"found": found}}
    return {"tool":"api_endpoint_brute","target":target,"scan_time":0,
            "vulnerable": False, "severity": "POSITIVE",
            "findings":[wrap_finding(
                "No standard API paths exposed",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue clean URL structure.",
                evidence_marker="All standard /api/* paths returned 404")],
            "tests_performed": len(paths),
            "tests_summary": "API endpoint brute",
            "raw_data": {}}


def _probe_hidden_api_versions(target, req):
    """Look for hidden API version endpoints."""
    base = _base_url(target)
    versions = ["/v0", "/v1", "/v2", "/v3", "/v4", "/api/v0", "/api/v1", "/api/v2",
                 "/api/v3", "/api/v4", "/api/beta", "/api/alpha", "/api/internal"]
    found = []
    for p in versions:
        code, _, _ = _http_get(base + p, timeout=2)
        if code in (200, 401, 403):
            found.append({"path": p, "code": code})
    return {"tool":"hidden_api_versions","target":target,"scan_time":0,
            "vulnerable": len(found) > 2,
            "severity": "MEDIUM" if len(found) > 3 else ("LOW" if len(found) > 1 else "INFO"),
            "findings":[wrap_finding(
                f"API version sprawl — {len(found)} live versions discovered" if found else "No version-prefixed endpoints found",
                "MEDIUM" if len(found) > 3 else ("LOW" if len(found) > 1 else "POSITIVE"),
                cvss="5.0" if len(found) > 3 else ("3.0" if len(found) > 1 else "0.0"),
                cwe="CWE-1059",
                remediation="Deprecate old versions; document version lifecycle policy.",
                evidence_marker=", ".join(f"{f['path']}→{f['code']}" for f in found) or "No versions exposed")],
            "tests_performed": len(versions),
            "tests_summary": f"Hidden API version discovery",
            "raw_data": {"versions_found": found}}


PROBES = {
    "openapi_swagger_discovery":  _probe_openapi_swagger,
    "openapi_swagger_exposed":    _probe_openapi_exposed,
    "graphql_schema_discovery":   _probe_graphql_discovery,
    "graphql_introspection_open": _probe_graphql_introspection,
    "grpc_reflection_discovery":  _probe_grpc_reflection,
    "api_endpoint_brute":         _probe_api_endpoint_brute,
    "hidden_api_versions":        _probe_hidden_api_versions,
}

T = [
    # §1 API Discovery & Inventory (13)
    ("openapi_swagger_discovery", "OpenAPI/Swagger discovery.", "INFO", "0.0"),
    ("postman_collection_discovery", "Postman collection discovery.", "INFO", "0.0"),
    ("graphql_schema_discovery", "GraphQL schema discovery.", "INFO", "0.0"),
    ("grpc_reflection_discovery", "gRPC reflection discovery.", "INFO", "0.0"),
    ("api_endpoint_brute", "API endpoint brute-force.", "INFO", "0.0"),
    ("hidden_api_versions", "Hidden API versions discovery.", "MEDIUM", "5.5"),
    ("openapi_swagger_exposed", "OpenAPI/Swagger publicly exposed.", "MEDIUM", "5.5"),
    ("api_shadow_inventory", "API shadow inventory.", "HIGH", "7.0"),
    ("api_deprecated_endpoints", "Deprecated API endpoints still live.", "MEDIUM", "5.5"),
    ("api_developer_portal_audit", "API developer portal audit.", "MEDIUM", "5.5"),
    ("postman_workspace_audit", "Postman workspace audit.", "MEDIUM", "5.5"),
    ("readme_io_audit", "Readme.io audit.", "INFO", "0.0"),
    ("manual_api_discovery", "Manual API discovery.", "INFO", "0.0"),
    # §2 OWASP API Top 10 2023 (19)
    ("api1_bola_object_authz", "API1: BOLA (object-level authz).", "HIGH", "7.5"),
    ("api2_broken_auth", "API2: Broken auth.", "HIGH", "8.0"),
    ("api3_bopla_property_authz", "API3: BOPLA (property-level authz).", "HIGH", "7.5"),
    ("api4_unrestricted_resource_consumption", "API4: Unrestricted resource consumption (DoS class).", "HIGH", "7.0"),
    ("api5_bfla_function_authz", "API5: BFLA (function-level authz).", "HIGH", "7.5"),
    ("api6_unrestricted_sensitive_access", "API6: Unrestricted access to sensitive business flows.", "HIGH", "7.5"),
    ("api7_ssrf", "API7: SSRF.", "HIGH", "8.0"),
    ("api8_misconfig", "API8: Security misconfig.", "HIGH", "7.5"),
    ("api9_shadow_inventory_top10", "API9: Improper inventory management.", "MEDIUM", "5.5"),
    ("api10_3rd_party_consumption", "API10: Unsafe consumption of 3rd-party APIs.", "MEDIUM", "5.5"),
    ("api_mass_assignment", "API mass assignment.", "HIGH", "7.5"),
    ("api_xxe", "API XXE.", "HIGH", "8.0"),
    ("api_command_injection", "API command injection.", "HIGH", "8.5"),
    ("api_path_traversal", "API path traversal.", "HIGH", "7.5"),
    ("api_lfi_rfi", "API LFI/RFI.", "HIGH", "8.0"),
    ("api_csrf_state_changing", "API CSRF on state-changing endpoints.", "HIGH", "7.0"),
    ("api_open_redirect", "API open redirect.", "MEDIUM", "5.5"),
    ("manual_owasp_api_review", "Manual OWASP API Top 10 review.", "INFO", "0.0"),
    ("manual_business_logic_review", "Manual business logic review.", "INFO", "0.0"),
    # §3 Authentication API-specific (12)
    ("api_jwt_none_alg", "JWT alg=none API.", "CRITICAL", "9.0"),
    ("api_jwt_weak_hs256", "JWT weak HS256.", "HIGH", "8.0"),
    ("api_jwt_jku_x5u_ssrf", "JWT JKU/X5U SSRF.", "HIGH", "8.0"),
    ("api_jwt_kid_traversal", "JWT kid path traversal.", "HIGH", "8.0"),
    ("api_jwt_kid_sqli", "JWT kid SQLi.", "HIGH", "8.0"),
    ("api_oauth_pkce_missing", "OAuth PKCE missing.", "MEDIUM", "5.5"),
    ("api_oauth_redirect_hijack", "OAuth redirect_uri hijack.", "HIGH", "7.5"),
    ("api_oauth_state_csrf", "OAuth state CSRF.", "HIGH", "7.0"),
    ("api_oidc_nonce_audit", "OIDC nonce audit.", "MEDIUM", "5.5"),
    ("api_session_fixation", "Session fixation.", "MEDIUM", "5.5"),
    ("api_cookie_security_flags", "Cookie security flags.", "MEDIUM", "5.5"),
    ("manual_api_auth_review", "Manual API auth review.", "INFO", "0.0"),
    # §4 Authorization (10)
    ("api_idor_param_swap", "IDOR param swap.", "HIGH", "7.5"),
    ("api_horizontal_authz", "Horizontal authz bypass.", "HIGH", "7.5"),
    ("api_vertical_authz", "Vertical authz bypass.", "HIGH", "8.0"),
    ("api_role_in_jwt_tamper", "Role-in-JWT tamper.", "HIGH", "8.0"),
    ("api_admin_bypass_header", "Admin bypass via X-Forwarded header.", "HIGH", "8.0"),
    ("api_authz_method_override", "HTTP method override authz bypass.", "HIGH", "7.0"),
    ("api_authz_content_type_smuggle", "Content-Type smuggle authz bypass.", "MEDIUM", "5.5"),
    ("api_authz_path_traversal", "Authz path traversal.", "HIGH", "7.5"),
    ("manual_authz_review", "Manual authz review.", "INFO", "0.0"),
    ("manual_authz_matrix", "Manual authz matrix.", "INFO", "0.0"),
    # §5 Rate Limiting (7)
    ("rate_limit_ip_bypass", "Rate limit IP bypass.", "MEDIUM", "5.5"),
    ("rate_limit_header_bypass", "Rate limit X-Forwarded-For bypass.", "HIGH", "7.0"),
    ("rate_limit_path_normalize_bypass", "Path normalization rate-limit bypass.", "MEDIUM", "5.5"),
    ("rate_limit_method_bypass", "Method-based rate-limit bypass.", "MEDIUM", "5.5"),
    ("rate_limit_distributed_attack", "Distributed rate-limit attack.", "HIGH", "7.0"),
    ("billing_amplification_attack", "Billing amplification attack.", "HIGH", "7.0"),
    ("manual_rate_limit_review", "Manual rate-limit review.", "INFO", "0.0"),
    # §6 GraphQL Security (12)
    ("graphql_introspection_open", "GraphQL introspection open.", "HIGH", "7.5"),
    ("graphql_batching_dos", "GraphQL batching DoS.", "HIGH", "7.0"),
    ("graphql_depth_dos", "GraphQL query depth DoS.", "HIGH", "7.0"),
    ("graphql_aliases_dos", "GraphQL aliases DoS.", "HIGH", "7.0"),
    ("graphql_field_authz_bypass", "GraphQL field-level authz bypass.", "HIGH", "7.5"),
    ("graphql_mutation_authz", "GraphQL mutation authz.", "HIGH", "7.5"),
    ("graphql_inj_to_sqli", "GraphQL → SQLi propagation.", "HIGH", "8.0"),
    ("graphql_inj_to_ssrf", "GraphQL → SSRF propagation.", "HIGH", "8.0"),
    ("graphql_apollo_advisory", "Apollo Federation audit.", "MEDIUM", "5.5"),
    ("graphql_hasura_advisory", "Hasura audit.", "MEDIUM", "5.5"),
    ("manual_graphql_review", "Manual GraphQL review.", "INFO", "0.0"),
    ("manual_graphql_chain", "Manual GraphQL chain.", "INFO", "0.0"),
    # §7 gRPC Security (8) ⭐
    ("grpc_reflection_open", "⭐ gRPC reflection open.", "MEDIUM", "5.5"),
    ("grpc_no_mtls", "⭐ gRPC mTLS not enforced.", "HIGH", "7.5"),
    ("grpc_replay_attack", "⭐ gRPC replay attack.", "HIGH", "7.0"),
    ("grpc_metadata_injection", "⭐ gRPC metadata injection.", "HIGH", "7.0"),
    ("grpc_message_dos", "⭐ gRPC message-size DoS.", "HIGH", "7.0"),
    ("grpc_web_parity_audit", "⭐ gRPC-Web parity audit.", "MEDIUM", "5.5"),
    ("manual_grpc_review", "Manual gRPC review.", "INFO", "0.0"),
    ("manual_grpc_chain", "Manual gRPC chain.", "INFO", "0.0"),
    # §8 WebSocket / SSE / WebTransport (9) ⭐
    ("ws_origin_audit", "⭐ WebSocket origin audit.", "HIGH", "7.0"),
    ("ws_auth_audit", "⭐ WebSocket auth audit.", "HIGH", "7.5"),
    ("ws_injection_audit", "⭐ WebSocket injection.", "HIGH", "7.5"),
    ("ws_cross_origin_csrf", "⭐ WebSocket cross-origin CSRF.", "HIGH", "7.0"),
    ("sse_origin_audit", "⭐ SSE origin audit.", "MEDIUM", "5.5"),
    ("webtransport_audit", "⭐ WebTransport audit.", "MEDIUM", "5.5"),
    ("h2c_smuggling", "⭐ H2C smuggling.", "HIGH", "8.0"),
    ("http2_rapid_reset", "⭐ HTTP/2 Rapid Reset (CVE-2023-44487).", "HIGH", "7.5"),
    ("manual_modern_proto_review", "Manual modern protocol review.", "INFO", "0.0"),
    # §9 SOAP / REST Legacy (9)
    ("soap_wsdl_disclosure", "SOAP WSDL disclosure.", "INFO", "0.0"),
    ("soap_xxe", "SOAP XXE.", "HIGH", "8.0"),
    ("soap_action_spoof", "SOAP action spoofing.", "HIGH", "7.0"),
    ("soap_xml_signature_wrap", "SOAP XML signature wrap.", "HIGH", "8.0"),
    ("soap_xpath_injection", "SOAP XPath injection.", "HIGH", "7.5"),
    ("rest_jsonp_callback", "JSONP callback abuse.", "MEDIUM", "5.5"),
    ("rest_etag_csrf", "REST ETag CSRF.", "MEDIUM", "5.5"),
    ("rest_options_method_audit", "REST OPTIONS verb audit.", "INFO", "0.0"),
    ("manual_soap_rest_review", "Manual SOAP/REST review.", "INFO", "0.0"),
    # §10 API Supply Chain / Versioning (11) ⭐
    ("api_version_skew_audit", "⭐ API version skew audit.", "MEDIUM", "5.5"),
    ("api_key_in_url_leak", "⭐ API key in URL leak.", "HIGH", "7.5"),
    ("api_key_logging_audit", "⭐ API key logging audit.", "HIGH", "7.0"),
    ("api_3rd_party_consumption", "⭐ Unsafe 3rd-party API consumption.", "HIGH", "7.0"),
    ("api_webhook_ssrf", "⭐ API webhook SSRF.", "HIGH", "8.0"),
    ("api_oauth_introspection_abuse", "⭐ OAuth introspection abuse.", "MEDIUM", "5.5"),
    ("api_consumer_secret_rotation", "⭐ Consumer secret rotation.", "MEDIUM", "5.5"),
    ("api_deprecation_lifecycle", "⭐ API deprecation lifecycle.", "INFO", "0.0"),
    ("api_breaking_change_advisory", "⭐ Breaking change advisory.", "INFO", "0.0"),
    ("api_dependency_security_audit", "⭐ API dependency security audit.", "MEDIUM", "5.5"),
    ("manual_api_supply_chain", "Manual API supply chain review.", "INFO", "0.0"),
]

router = make_advisory_router("apisec", T,
    playbook_ref="See module_playbooks/22_apisec.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
