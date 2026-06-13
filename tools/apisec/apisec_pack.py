"""§22 API Security — 108 endpoints per 22_apisec.md.
10 sections: discovery, OWASP API Top 10, auth, authz, rate limit, GraphQL,
gRPC, WebSocket/SSE/WebTransport, SOAP/REST legacy, supply chain/versioning.

VulnusLab is a Vulnerability Assessment platform — every probe is SAFE,
read-only DETECTION. We never inject exploitation payloads, never flood for
DoS, never tamper authz/tokens against the server. Techniques that can only
be confirmed by exploiting (injection, mass-assign, JWT tampering), by
authenticating (BOLA/BFLA/two-account authz), by DoS load, or by a
specialized protocol client (gRPC/HTTP2/WebSocket/mTLS) are returned as
honest [ADVISORY-BY-DESIGN] rather than fake findings or bare scaffolds.

Probe coverage 2026-06-12:
  Live safe probes   : 24
  Advisory-by-design : 84 (auth-required / exploitation / DoS / protocol / OSINT / manual)
  Scaffold (fake)    : 0
"""
import base64
import os
import re
import time
import shutil
import subprocess
import urllib.request
import urllib.error
import json
from tools._pack_common import (
    make_advisory_router, _adv_response, _advisory_by_design_response,
)
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


def _resp(tool, target, findings, tested, summary):
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "POSITIVE": 0}
    top = "INFO"
    for f in findings:
        if sev_order.get(f.get("severity", "INFO"), 0) > sev_order.get(top, 0):
            top = f.get("severity", "INFO")
    return {"tool": tool, "target": target, "scan_time": 0,
            "vulnerable": top in ("CRITICAL", "HIGH", "MEDIUM"),
            "severity": top, "findings": findings,
            "tests_performed": tested, "tests_summary": summary, "raw_data": {}}


def _abd(slug, title, reason, cwe="CWE-1395"):
    """Factory: advisory-by-design probe (cannot be SaaS-probed safely)."""
    def _p(target, req):
        return _advisory_by_design_response(slug, target, title, reason=reason, cwe=cwe)
    return _p


# Reusable advisory reasons
_CREDS = ("Requires authenticated context — a valid session/token, and often two "
          "accounts of different privilege to compare responses. Supply auth_cookie/"
          "auth_bearer or run under engagement scope; it cannot be confirmed anonymously.")
_EXPLOIT = ("Confirming this requires sending an active injection/exploitation payload, "
            "which is out of Vulnerability-Assessment scope and never chained. The Webapp "
            "module performs safe detection of this class; confirm impact manually.")
_DOS = ("Confirming this needs flooding / large-payload / DoS-style load that is unsafe "
        "to run against a production target from a SaaS scanner.")
_OSINT = ("Requires external OSINT sources (GitHub, Postman, Wayback, API marketplaces) "
          "rather than probing the target directly; gather those inputs and re-run.")
_PROTO = ("Requires a specialized protocol client (HTTP/2, gRPC, WebSocket, mTLS) and "
          "usually a known service definition; it cannot be done from the anonymous HTTP "
          "probe path.")
_TOKEN = ("Requires a sample token/spec as input (auth_bearer / api_spec_url), and for "
          "secret-strength tests an offline brute that is not part of the live-probe path.")
_MANUAL = "Analyst task — manual review under engagement scope."


# ───────────────────── existing live probes (kept) ─────────────────────
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
    return {"tool": "openapi_swagger_discovery", "target": target, "scan_time": 0,
            "vulnerable": bool(found),
            "severity": findings[0].get("severity", "INFO"),
            "findings": findings, "tests_performed": len(paths),
            "tests_summary": f"OpenAPI/Swagger discovery — {len(paths)} paths probed",
            "raw_data": {"found": found}}


def _probe_openapi_exposed(target, req):
    return _probe_openapi_swagger(target, req) | {"tool": "openapi_swagger_exposed"}


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
        return {"tool": "graphql_schema_discovery", "target": target, "scan_time": 0,
                "vulnerable": True, "severity": "INFO",
                "findings": [wrap_finding(
                    f"GraphQL endpoint(s) discovered: {', '.join(found)}",
                    "INFO", cvss="0.0", cwe="N/A",
                    remediation="Confirm authentication + introspection settings on each.",
                    evidence_marker=f"Found at: {', '.join(found)}")],
                "tests_performed": len(paths),
                "tests_summary": f"GraphQL endpoint discovery — {len(paths)} paths probed",
                "raw_data": {"found": found}}
    return {"tool": "graphql_schema_discovery", "target": target, "scan_time": 0,
            "vulnerable": False, "severity": "POSITIVE",
            "findings": [wrap_finding(
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
            return {"tool": "graphql_introspection_open", "target": target, "scan_time": 0,
                    "vulnerable": True, "severity": "HIGH",
                    "findings": [wrap_finding(
                        f"GraphQL introspection enabled at {p}",
                        "HIGH", cvss="7.5", cwe="CWE-200",
                        remediation="Disable introspection in production via Apollo config or schema directive.",
                        evidence_marker=f"POST {p} {{__schema}} -> 200 with type list")],
                    "tests_performed": 1,
                    "tests_summary": "GraphQL introspection check",
                    "raw_data": {"endpoint": p}}
    return {"tool": "graphql_introspection_open", "target": target, "scan_time": 0,
            "vulnerable": False, "severity": "POSITIVE",
            "findings": [wrap_finding(
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
    code, body, headers = _http_post(base, "",
        {"Content-Type": "application/grpc-web+proto", "X-Grpc-Web": "1"}, timeout=3)
    is_grpc = "grpc-status" in (headers.get("grpc-status", "") + str(headers)).lower() or \
              code in (200, 415) and "grpc" in str(headers).lower()
    if is_grpc:
        return {"tool": "grpc_reflection_discovery", "target": target, "scan_time": 0,
                "vulnerable": True, "severity": "MEDIUM",
                "findings": [wrap_finding(
                    "gRPC service detected — verify reflection is disabled in production",
                    "MEDIUM", cvss="5.5", cwe="CWE-200",
                    remediation="Disable gRPC reflection via Server.WithReflection(false) in prod builds.",
                    evidence_marker=f"gRPC headers detected at {base}")],
                "tests_performed": 1,
                "tests_summary": "gRPC reflection / service detection",
                "raw_data": {"headers": str(headers)[:200]}}
    return {"tool": "grpc_reflection_discovery", "target": target, "scan_time": 0,
            "vulnerable": False, "severity": "INFO",
            "findings": [wrap_finding(
                "No gRPC service detected at standard endpoint",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="If using gRPC on non-standard path, audit reflection settings.",
                evidence_marker="No grpc-* headers in response")],
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
        return {"tool": "api_endpoint_brute", "target": target, "scan_time": 0,
                "vulnerable": any(f["code"] == 200 for f in found),
                "severity": "MEDIUM" if any(f["code"] == 200 for f in found) else "INFO",
                "findings": [wrap_finding(
                    f"API endpoints discovered: {len(found)}",
                    "MEDIUM" if any(f["code"] == 200 for f in found) else "INFO",
                    cvss="5.0" if any(f["code"] == 200 for f in found) else "0.0",
                    cwe="CWE-200",
                    remediation="Inventory all API paths; require auth on /admin and /internal.",
                    evidence_marker=", ".join(f"{f['path']}->{f['code']}" for f in found))],
                "tests_performed": len(paths),
                "tests_summary": f"API endpoint brute — {len(paths)} paths",
                "raw_data": {"found": found}}
    return {"tool": "api_endpoint_brute", "target": target, "scan_time": 0,
            "vulnerable": False, "severity": "POSITIVE",
            "findings": [wrap_finding(
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
    return {"tool": "hidden_api_versions", "target": target, "scan_time": 0,
            "vulnerable": len(found) > 2,
            "severity": "MEDIUM" if len(found) > 3 else ("LOW" if len(found) > 1 else "INFO"),
            "findings": [wrap_finding(
                f"API version sprawl — {len(found)} live versions discovered" if found else "No version-prefixed endpoints found",
                "MEDIUM" if len(found) > 3 else ("LOW" if len(found) > 1 else "POSITIVE"),
                cvss="5.0" if len(found) > 3 else ("3.0" if len(found) > 1 else "0.0"),
                cwe="CWE-1059",
                remediation="Deprecate old versions; document version lifecycle policy.",
                evidence_marker=", ".join(f"{f['path']}->{f['code']}" for f in found) or "No versions exposed")],
            "tests_performed": len(versions),
            "tests_summary": "Hidden API version discovery",
            "raw_data": {"versions_found": found}}


def _probe_rate_limit(target, req):
    """Probe API rate-limit posture by rapid-fire (10 reqs) to /api/health or /."""
    base = _base_url(target)
    paths = ["/api/health", "/health", "/api", "/"]
    findings = []
    for p in paths:
        url = base + p
        codes = []
        start = time.time()
        for _ in range(10):
            code, _, h = _http_get(url, timeout=2)
            codes.append(code)
            if code == 429: break
        elapsed = time.time() - start
        if 429 in codes:
            findings.append(wrap_finding(
                f"Rate limit ENFORCED at {p} — 429 after {codes.index(429)+1} requests",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue rate-limiting; consider per-endpoint limits.",
                evidence_marker=f"Codes: {codes[:5]}..."))
        elif all(c == codes[0] and c < 400 for c in codes if c):
            findings.append(wrap_finding(
                f"Rate limit NOT enforced at {p} — 10 rapid requests all succeeded",
                "HIGH", cvss="7.0", cwe="CWE-770",
                remediation="Implement token-bucket or sliding-window rate limit per IP/user.",
                evidence_marker=f"10 requests in {elapsed:.1f}s, all {codes[0]}"))
        if findings: break
    if not findings:
        findings.append(wrap_finding(
            "Rate-limit probe inconclusive — endpoint unreachable or non-200",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Test against an actual reachable endpoint.",
            evidence_marker=f"Paths probed: {paths}"))
    return {"tool": "rate_limit_ip_bypass", "target": target, "scan_time": 0,
            "vulnerable": any(f.get("severity") == "HIGH" for f in findings),
            "severity": findings[0].get("severity", "INFO"),
            "findings": findings, "tests_performed": 10,
            "tests_summary": "Rate-limit rapid-fire probe (10 req burst)",
            "raw_data": {}}


def _probe_ws_origin(target, req):
    """Detect WebSocket endpoint + check origin enforcement via HTTP Upgrade probe."""
    base = _base_url(target)
    paths = ["/ws", "/websocket", "/socket", "/socket.io/", "/api/ws", "/realtime"]
    found = []
    for p in paths:
        url = base + p
        try:
            r = urllib.request.Request(url, headers={
                "User-Agent": "VulnusLab/2.0",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Origin": "https://evil.example.com",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                "Sec-WebSocket-Version": "13",
            })
            with urllib.request.urlopen(r, timeout=3) as resp:
                if resp.status in (101, 200):
                    found.append({"path": p, "code": resp.status, "accepted_evil_origin": True})
        except urllib.error.HTTPError as e:
            if e.code in (101, 426):
                found.append({"path": p, "code": e.code, "accepted_evil_origin": False})
        except Exception:
            pass
    findings = []
    if any(f["accepted_evil_origin"] for f in found):
        findings.append(wrap_finding(
            "WebSocket accepted cross-origin handshake from evil.example.com",
            "HIGH", cvss="7.5", cwe="CWE-346",
            remediation="Validate Origin header server-side; reject non-allow-listed origins.",
            evidence_marker=", ".join(f["path"] for f in found if f["accepted_evil_origin"])))
    elif found:
        findings.append(wrap_finding(
            f"WebSocket endpoint(s) found at {len(found)} path(s), origin enforcement looks ok",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Continue origin validation.",
            evidence_marker=", ".join(f"{f['path']}->{f['code']}" for f in found)))
    else:
        findings.append(wrap_finding(
            "No WebSocket endpoint at standard paths",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="If using WS, ensure origin validation in place.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return {"tool": "ws_origin_audit", "target": target, "scan_time": 0,
            "vulnerable": any(f["accepted_evil_origin"] for f in found),
            "severity": findings[0].get("severity", "INFO"),
            "findings": findings, "tests_performed": len(paths),
            "tests_summary": "WebSocket cross-origin handshake probe",
            "raw_data": {"found": found}}


def _probe_sse_origin(target, req):
    """Probe Server-Sent Events endpoint discovery + origin check."""
    base = _base_url(target)
    paths = ["/events", "/stream", "/api/events", "/api/stream", "/sse"]
    found = []
    for p in paths:
        url = base + p
        code, body, headers = _http_get(url, timeout=3)
        ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
        if "text/event-stream" in ct:
            found.append({"path": p, "code": code, "content_type": ct})
    findings = []
    if found:
        findings.append(wrap_finding(
            f"SSE endpoint discovered: {', '.join(f['path'] for f in found)}",
            "INFO", cvss="0.0", cwe="CWE-346",
            remediation="Ensure SSE endpoints validate Origin + require auth.",
            evidence_marker=", ".join(f"{f['path']} ({f['content_type']})" for f in found)))
    else:
        findings.append(wrap_finding(
            "No SSE endpoint at standard paths",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue.",
            evidence_marker=f"Tested {len(paths)} paths"))
    return {"tool": "sse_origin_audit", "target": target, "scan_time": 0,
            "vulnerable": False, "severity": findings[0].get("severity", "INFO"),
            "findings": findings, "tests_performed": len(paths),
            "tests_summary": "SSE endpoint discovery",
            "raw_data": {"found": found}}


def _probe_api_key_in_url(target, req):
    """Check if a target's response references credentials in URL parameters."""
    base = _base_url(target)
    code, body, _ = _http_get(base, timeout=4)
    if not body:
        return _adv_response("api_key_in_url_leak", target,
            "Target unreachable — skipping URL-credential probe",
            "INFO", "0.0", evidence=f"GET {base} -> {code}")
    patterns = [
        (r'[?&](api[_-]?key|token|secret|access[_-]?token)=([A-Za-z0-9_\-]{16,})', "credential in URL param"),
        (r'(AKIA|ASIA)[A-Z0-9]{16}', "AWS access key in body"),
        (r'sk_live_[A-Za-z0-9]{20,}', "Stripe live key in body"),
        (r'AIza[A-Za-z0-9_-]{35}', "Google API key in body"),
    ]
    leaks = []
    for pat, label in patterns:
        m = re.search(pat, body[:8192])
        if m: leaks.append({"label": label, "match": m.group(0)[:60]})
    return {"tool": "api_key_in_url_leak", "target": target, "scan_time": 0,
            "vulnerable": bool(leaks),
            "severity": "CRITICAL" if leaks else "POSITIVE",
            "findings": [wrap_finding(
                f"Credential exposure: {len(leaks)} match(es)" if leaks else "No credential patterns in response body",
                "CRITICAL" if leaks else "POSITIVE",
                cvss="9.0" if leaks else "0.0", cwe="CWE-798",
                remediation="Never embed API keys in URLs; use headers/cookies with HttpOnly+Secure.",
                evidence_marker=", ".join(f"{l['label']}: {l['match']}" for l in leaks) or "Clean")],
            "tests_performed": len(patterns),
            "tests_summary": "API key/secret leak pattern scan",
            "raw_data": {"leaks": leaks}}


# ───────────────────── NEW live probes ─────────────────────
def _probe_api8_misconfig(target, req):
    """API8: security misconfig — CORS reflection, verbose errors, missing headers."""
    base = _base_url(target)
    findings = []; tested = 0
    code, body, headers = _http_get(base, timeout=4); tested += 1
    hk = {k.lower() for k in headers.keys()}
    # CORS reflection
    evil = "https://evil.vulnuslab-canary.com"
    h = {}
    try:
        r = urllib.request.Request(base, headers={"User-Agent": "VulnusLab/2.0", "Origin": evil})
        with urllib.request.urlopen(r, timeout=4) as resp:
            h = {k.lower(): v for k, v in dict(resp.headers).items()}
    except urllib.error.HTTPError as e:
        h = {k.lower(): v for k, v in (dict(e.headers) if e.headers else {}).items()}
    except Exception:
        h = {}
    tested += 1
    acao = h.get("access-control-allow-origin", "")
    acac = (h.get("access-control-allow-credentials", "") or "").lower()
    if evil in acao:
        sev = "HIGH" if acac == "true" else "MEDIUM"
        findings.append(wrap_finding(
            f"CORS reflects an arbitrary Origin ({evil}){' WITH credentials' if acac == 'true' else ''}",
            sev, cvss="7.5" if sev == "HIGH" else "5.5", cwe="CWE-942", owasp="API8:2023",
            remediation="Never reflect the Origin header; use a strict allow-list; never combine Origin reflection with Access-Control-Allow-Credentials.",
            evidence_marker=f"ACAO reflects {evil}; ACAC={acac or 'absent'}"))
    elif acao == "*":
        findings.append(wrap_finding(
            "CORS Access-Control-Allow-Origin: * (wildcard)",
            "LOW", cvss="3.7", cwe="CWE-942", owasp="API8:2023",
            remediation="Restrict ACAO to an allow-list of trusted origins for any authenticated API.",
            evidence_marker="ACAO=*"))
    # verbose error / stack trace
    code2, body2, _ = _http_get(base + "/vl-canary-error-%27%22%3C", timeout=4); tested += 1
    bl = body2[:8192].lower()
    if any(s in bl for s in ["stack trace", "traceback (most recent", "exception in thread",
                              "sqlstate", "at org.springframework", "system.web.httpexception",
                              "org.apache.catalina", "<b>fatal error</b>", "nonetype"]):
        findings.append(wrap_finding(
            "Verbose error / stack trace leaked from the API",
            "MEDIUM", cvss="5.3", cwe="CWE-209", owasp="API8:2023",
            remediation="Return generic error bodies; log stack traces server-side only.",
            evidence_marker="Stack-trace/exception markers present in error response"))
    # missing security headers (only if the base request actually connected)
    miss = [hdr for hdr in ["x-content-type-options", "strict-transport-security"] if hdr not in hk] if code else []
    if miss:
        findings.append(wrap_finding(
            f"Missing security headers: {', '.join(miss)}",
            "LOW", cvss="3.1", cwe="CWE-693", owasp="API8:2023",
            remediation="Add X-Content-Type-Options: nosniff and HSTS (Strict-Transport-Security).",
            evidence_marker=", ".join(miss)))
    if not findings:
        findings.append(wrap_finding(
            "No API misconfig detected (CORS reflection / verbose errors / core headers clean)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"{tested} misconfig checks run"))
    return _resp("api8_misconfig", target, findings, tested,
                 "API8 misconfig: CORS reflection + verbose errors + security headers")


def _probe_api2_broken_auth(target, req):
    """API2: detect sensitive endpoints returning data WITHOUT authentication.
    SPA-canary guarded: only structured (JSON) bodies that are not HTML."""
    base = _base_url(target)
    sensitive = ["/api/users", "/api/v1/users", "/api/admin", "/api/accounts",
                 "/api/orders", "/api/customers", "/api/v1/admin", "/api/internal",
                 "/api/config", "/api/me", "/api/user", "/actuator/env",
                 "/api/v1/users/1", "/api/secrets"]
    exposed = []
    for p in sensitive:
        code, body, headers = _http_get(base + p, timeout=3)
        ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
        bs = body.strip()
        if code == 200 and ("json" in ct or bs.startswith(("[", "{"))) and len(bs) > 2 \
           and "<html" not in body[:200].lower():
            exposed.append({"path": p, "bytes": len(body)})
    findings = []
    if exposed:
        findings.append(wrap_finding(
            f"Sensitive API endpoint(s) return JSON data WITHOUT authentication ({len(exposed)})",
            "HIGH", cvss="8.0", cwe="CWE-306", owasp="API2:2023",
            remediation="Require authentication and authorization on every data endpoint; deny by default.",
            evidence_marker=", ".join(f"{e['path']} ({e['bytes']}b JSON)" for e in exposed[:6])))
    else:
        findings.append(wrap_finding(
            "No unauthenticated sensitive API endpoint detected",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"Probed {len(sensitive)} sensitive paths (SPA-HTML responses ignored)"))
    return _resp("api2_broken_auth", target, findings, len(sensitive),
                 "API2 unauthenticated sensitive-endpoint probe")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _probe_api_open_redirect(target, req):
    """API8/open redirect — inject a canary external URL into common redirect
    params and inspect the Location header WITHOUT following it."""
    base = _base_url(target)
    canary_host = "vl-redirect-canary.example.com"
    canary = f"https://{canary_host}/x"
    params = ["next", "url", "redirect", "redirect_uri", "return", "returnUrl", "dest", "continue"]
    hits = []
    opener = urllib.request.build_opener(_NoRedirect)
    for prm in params:
        u = f"{base}/?{prm}={canary}"
        loc = ""
        try:
            r = urllib.request.Request(u, headers={"User-Agent": "VulnusLab/2.0"})
            with opener.open(r, timeout=3) as resp:
                loc = resp.headers.get("Location", "") or ""
        except urllib.error.HTTPError as e:
            loc = (e.headers.get("Location", "") if e.headers else "") or ""
        except Exception:
            loc = ""
        if canary_host in loc:
            hits.append(prm)
    findings = []
    if hits:
        findings.append(wrap_finding(
            f"Open redirect — Location header reflects an attacker-controlled URL via param(s): {', '.join(hits)}",
            "MEDIUM", cvss="6.1", cwe="CWE-601", owasp="API8:2023",
            remediation="Allow-list redirect targets; never reflect a user-supplied absolute URL into Location.",
            evidence_marker=f"?{hits[0]}=<canary> -> Location to {canary_host}"))
    else:
        findings.append(wrap_finding(
            "No open redirect via common redirect params",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"Tested {len(params)} redirect params; no canary in Location"))
    return _resp("api_open_redirect", target, findings, len(params),
                 "Open-redirect Location-header probe (no-follow, safe)")


def _get_set_cookies(url, timeout=4):
    try:
        r = urllib.request.Request(url, headers={"User-Agent": "VulnusLab/2.0"})
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        return (e.headers.get_all("Set-Cookie") or []) if e.headers else []
    except Exception:
        return []


def _probe_api_cookie_flags(target, req):
    """Audit Set-Cookie security flags (Secure / HttpOnly / SameSite)."""
    base = _base_url(target)
    cookies = _get_set_cookies(base, timeout=4)
    findings = []
    weak = []
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        flags_missing = []
        if "secure" not in low: flags_missing.append("Secure")
        if "httponly" not in low: flags_missing.append("HttpOnly")
        if "samesite" not in low: flags_missing.append("SameSite")
        if flags_missing:
            weak.append(f"{name} (missing {', '.join(flags_missing)})")
    if weak:
        sev = "MEDIUM" if any("Secure" in w or "HttpOnly" in w for w in weak) else "LOW"
        findings.append(wrap_finding(
            f"Cookie(s) missing security flags: {len(weak)}",
            sev, cvss="5.0" if sev == "MEDIUM" else "3.1", cwe="CWE-1004", owasp="API8:2023",
            remediation="Set Secure + HttpOnly + SameSite on session/auth cookies.",
            evidence_marker="; ".join(weak[:6])))
    elif cookies:
        findings.append(wrap_finding(
            f"All {len(cookies)} cookie(s) carry Secure/HttpOnly/SameSite flags",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"{len(cookies)} cookie(s) audited"))
    else:
        findings.append(wrap_finding(
            "No cookies set on the base response",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="If auth uses cookies, ensure flags are set on the login response.",
            evidence_marker="No Set-Cookie headers"))
    return _resp("api_cookie_security_flags", target, findings, max(1, len(cookies)),
                 "Set-Cookie security-flag audit")


def _probe_api_pkce_missing(target, req):
    """OAuth/OIDC PKCE advertisement check via discovery document."""
    host = _host(target); base = _base_url(target)
    urls = [f"https://{host}/.well-known/openid-configuration",
            f"https://login.{host}/.well-known/openid-configuration",
            base + "/.well-known/openid-configuration"]
    for u in urls:
        code, body, _ = _http_get(u, timeout=4)
        if code == 200 and body.strip().startswith("{"):
            try:
                cfg = json.loads(body)
            except Exception:
                continue
            pkce = cfg.get("code_challenge_methods_supported")
            if not pkce:
                return _resp("api_oauth_pkce_missing", target, [wrap_finding(
                    "OAuth/OIDC server does NOT advertise PKCE (code_challenge_methods_supported absent)",
                    "MEDIUM", cvss="5.5", cwe="CWE-1390",
                    remediation="Enable and require PKCE (S256) per RFC 7636 / OAuth 2.1.",
                    evidence_marker=f"{u}: code_challenge_methods_supported absent")], 1,
                    "OIDC PKCE advertisement check")
            if "S256" not in pkce:
                return _resp("api_oauth_pkce_missing", target, [wrap_finding(
                    f"OIDC advertises PKCE but not S256 (only {pkce})",
                    "LOW", cvss="3.7", cwe="CWE-1390",
                    remediation="Require the S256 code-challenge method; reject 'plain'.",
                    evidence_marker=f"code_challenge_methods_supported={pkce}")], 1,
                    "OIDC PKCE advertisement check")
            return _resp("api_oauth_pkce_missing", target, [wrap_finding(
                "OIDC advertises PKCE with S256 (good)",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="No action for this check.",
                evidence_marker="code_challenge_methods_supported includes S256")], 1,
                "OIDC PKCE advertisement check")
    return _resp("api_oauth_pkce_missing", target, [wrap_finding(
        "No OIDC discovery document found — PKCE advertisement not determinable",
        "INFO", cvss="0.0", cwe="N/A",
        remediation="If OAuth/OIDC is in use, expose the discovery doc and require PKCE.",
        evidence_marker=f"Tried {len(urls)} discovery URLs")], len(urls),
        "OIDC PKCE advertisement check")


def _probe_api_jwt_none(target, req):
    """Static, read-only analysis of a supplied JWT header (auth_bearer).
    Never sends a tampered token to the server (that would be exploitation)."""
    token = getattr(req, "auth_bearer", None) if req is not None else None
    if not token:
        return _advisory_by_design_response(
            "api_jwt_none_alg", target, "JWT alg=none / signature-bypass test",
            reason="Supply a sample JWT via auth_bearer to statically analyse its header. "
                   "Actively replaying an alg=none/confusion token against the server is "
                   "exploitation and out of scope.")
    parts = token.strip().split(".")
    if len(parts) < 2:
        return _resp("api_jwt_none_alg", target, [wrap_finding(
            "Provided bearer token is not a JWT (no header.payload structure)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Provide a JWT to analyse its algorithm.",
            evidence_marker="auth_bearer is not dot-delimited")], 1, "JWT header static analysis")
    try:
        seg = parts[0]
        seg += "=" * (-len(seg) % 4)
        hdr = json.loads(base64.urlsafe_b64decode(seg.encode()))
    except Exception:
        return _resp("api_jwt_none_alg", target, [wrap_finding(
            "Could not decode JWT header",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Ensure a valid JWT is provided.",
            evidence_marker="base64 decode of JWT header failed")], 1, "JWT header static analysis")
    alg = str(hdr.get("alg", "")).lower()
    findings = []
    if alg in ("none", ""):
        findings.append(wrap_finding(
            "Provided JWT declares alg=none — unsigned token in use",
            "CRITICAL", cvss="9.1", cwe="CWE-347", owasp="API2:2023",
            remediation="Reject alg=none; pin the expected algorithm server-side and verify signatures.",
            evidence_marker=f"JWT header alg={hdr.get('alg')}"))
    elif alg.startswith("hs"):
        findings.append(wrap_finding(
            f"Provided JWT uses symmetric {alg.upper()} — verify the signing secret is high-entropy and rotated",
            "LOW", cvss="3.7", cwe="CWE-326",
            remediation="HS256 with a weak/guessable secret is offline-brute-forceable; prefer RS256/ES256 or a strong rotated secret.",
            evidence_marker=f"JWT header alg={hdr.get('alg')}"))
    else:
        findings.append(wrap_finding(
            f"Provided JWT uses asymmetric {alg.upper()} (good)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"JWT header alg={hdr.get('alg')}"))
    if "jku" in hdr or "x5u" in hdr:
        findings.append(wrap_finding(
            "JWT header contains a jku/x5u URL — verify the key-source host is allow-listed (SSRF/key-injection risk)",
            "MEDIUM", cvss="5.5", cwe="CWE-918",
            remediation="Pin trusted JWKS URLs; never fetch keys from an attacker-controllable jku/x5u.",
            evidence_marker=f"header keys: {list(hdr.keys())}"))
    return _resp("api_jwt_none_alg", target, findings, 1, "JWT header static analysis (read-only)")


def _probe_soap_wsdl(target, req):
    """SOAP WSDL discovery — discloses every operation + parameter type."""
    base = _base_url(target)
    paths = ["/?wsdl", "/service?wsdl", "/services?wsdl", "/soap?wsdl", "/ws?wsdl",
             "/api?wsdl", "/Service.asmx?WSDL", "/service.svc?wsdl"]
    found = []
    for p in paths:
        code, body, _ = _http_get(base + p, timeout=3)
        bl = body[:4096].lower()
        if code == 200 and ("<wsdl:" in bl or "<definitions" in bl or "soap:address" in bl
                            or ("targetnamespace" in bl and "<?xml" in bl)):
            found.append(p)
    findings = []
    if found:
        findings.append(wrap_finding(
            f"SOAP WSDL exposed at {', '.join(found)} — discloses all operations and parameter types",
            "MEDIUM", cvss="5.3", cwe="CWE-200", owasp="API9:2023",
            remediation="Restrict WSDL to internal consumers; require auth on the SOAP service.",
            evidence_marker=", ".join(found)))
    else:
        findings.append(wrap_finding(
            "No SOAP WSDL exposed at standard paths",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"Tested {len(paths)} WSDL paths"))
    return _resp("soap_wsdl_disclosure", target, findings, len(paths), "SOAP WSDL discovery")


def _probe_options_audit(target, req):
    """OPTIONS method audit — Allow header + TRACE (XST) + risky verbs."""
    base = _base_url(target)
    allow = ""; code = 0
    try:
        r = urllib.request.Request(base, method="OPTIONS", headers={"User-Agent": "VulnusLab/2.0"})
        with urllib.request.urlopen(r, timeout=4) as resp:
            allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
            code = resp.status
    except urllib.error.HTTPError as e:
        if e.headers:
            allow = e.headers.get("Allow", "") or e.headers.get("Access-Control-Allow-Methods", "")
        code = e.code
    except Exception:
        allow = ""; code = 0
    au = allow.upper()
    findings = []
    if "TRACE" in au:
        findings.append(wrap_finding(
            "HTTP TRACE method enabled — Cross-Site Tracing (XST) risk",
            "MEDIUM", cvss="5.3", cwe="CWE-693",
            remediation="Disable TRACE on the web server / API gateway.",
            evidence_marker=f"Allow: {allow}"))
    risky = [m for m in ["PUT", "DELETE", "PATCH", "CONNECT"] if m in au]
    if risky:
        findings.append(wrap_finding(
            f"State-changing methods advertised via OPTIONS: {', '.join(risky)} — verify authorization",
            "LOW", cvss="3.1", cwe="CWE-650",
            remediation="Ensure PUT/DELETE/PATCH require authn+authz; remove if unused.",
            evidence_marker=f"Allow: {allow}"))
    if not findings:
        if allow:
            findings.append(wrap_finding(
                f"OPTIONS Allow header present, no risky verbs ({allow})",
                "INFO", cvss="0.0", cwe="N/A",
                remediation="No action for this check.",
                evidence_marker=f"Allow: {allow}"))
        else:
            findings.append(wrap_finding(
                "No Allow header returned to OPTIONS (method introspection disabled)",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="No action for this check.",
                evidence_marker=f"OPTIONS -> {code}, no Allow header"))
    return _resp("rest_options_method_audit", target, findings, 1, "OPTIONS / Allow / TRACE audit")


def _probe_jsonp(target, req):
    """JSONP callback reflection — data exfil via <script> across origins."""
    base = _base_url(target)
    cb = "vlCanaryCb1337"
    paths = ["/", "/api", "/api/v1", "/api/data"]
    hits = []
    for p in paths:
        code, body, headers = _http_get(f"{base}{p}?callback={cb}", timeout=3)
        ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
        if body.strip().startswith(cb + "(") and ("javascript" in ct or "json" in ct or ct == ""):
            hits.append(p)
    findings = []
    if hits:
        findings.append(wrap_finding(
            f"JSONP callback reflected at {', '.join(hits)} — responses readable cross-origin via <script>",
            "MEDIUM", cvss="5.5", cwe="CWE-1021", owasp="API8:2023",
            remediation="Avoid JSONP; use CORS with a strict allow-list; never wrap sensitive data in a caller-named callback.",
            evidence_marker=f"?callback={cb} -> body starts with {cb}("))
    else:
        findings.append(wrap_finding(
            "No JSONP callback reflection at common endpoints",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"Tested {len(paths)} endpoints with ?callback="))
    return _resp("rest_jsonp_callback", target, findings, len(paths), "JSONP callback reflection probe")


def _probe_dev_portal(target, req):
    """Public developer-portal / API-docs surface discovery."""
    base = _base_url(target)
    paths = ["/developer", "/developers", "/portal", "/api-portal", "/devportal",
             "/apidocs", "/api/docs", "/docs", "/redoc", "/swagger-ui.html",
             "/graphiql", "/playground"]
    found = []
    for p in paths:
        code, body, _ = _http_get(base + p, timeout=3)
        bl = body[:4096].lower()
        if code == 200 and any(s in bl for s in ["swagger", "redoc", "graphiql",
                                                  "api documentation", "developer portal",
                                                  "apigee", "readme", "try it out", "openapi"]):
            found.append(p)
    findings = []
    if found:
        findings.append(wrap_finding(
            f"Public developer portal / API docs exposed at {', '.join(found[:5])} — widens attack surface",
            "LOW", cvss="3.7", cwe="CWE-200", owasp="API9:2023",
            remediation="Gate developer portals/interactive docs behind auth or an internal network.",
            evidence_marker=", ".join(found[:5])))
    else:
        findings.append(wrap_finding(
            "No public developer portal / interactive API docs detected",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"Tested {len(paths)} portal paths"))
    return _resp("api_developer_portal_audit", target, findings, len(paths), "Developer-portal discovery")


def _probe_deprecated(target, req):
    """Deprecated/legacy endpoint detection via Deprecation/Sunset headers and
    legacy version endpoints still serving."""
    base = _base_url(target)
    flagged = []; tested = 0
    for p in ["/", "/api/v1", "/api/v0", "/v1", "/v0"]:
        code, body, headers = _http_get(base + p, timeout=3); tested += 1
        hl = {k.lower(): v for k, v in headers.items()}
        if "deprecation" in hl or "sunset" in hl:
            flagged.append(f"{p} (Deprecation/Sunset header)")
        elif p in ("/api/v0", "/v0") and code in (200, 401, 403):
            flagged.append(f"{p} (legacy v0 still live -> {code})")
    findings = []
    if flagged:
        findings.append(wrap_finding(
            f"Deprecated/legacy API surface still live ({len(flagged)})",
            "MEDIUM", cvss="5.3", cwe="CWE-1059", owasp="API9:2023",
            remediation="Retire deprecated/legacy versions; if kept, document Sunset and patch them like prod.",
            evidence_marker="; ".join(flagged)))
    else:
        findings.append(wrap_finding(
            "No deprecated/legacy API surface detected",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"Checked {tested} endpoints for Deprecation/Sunset + legacy v0"))
    return _resp("api_deprecated_endpoints", target, findings, tested, "Deprecated/legacy endpoint probe")


def _probe_hasura(target, req):
    """Hasura GraphQL engine detection + admin-secret-less introspection check."""
    base = _base_url(target)
    hit = False; ev = []
    code, body, _ = _http_get(base + "/v1/version", timeout=3)
    if code == 200 and "version" in body.lower() and len(body) < 400:
        hit = True; ev.append("/v1/version responds")
    code2, body2, _ = _http_get(base + "/console", timeout=3)
    if "hasura" in body2[:4096].lower():
        hit = True; ev.append("/console is Hasura")
    findings = []
    if hit:
        c3, b3, _ = _http_post(base + "/v1/graphql", '{"query":"{__schema{queryType{name}}}"}', timeout=4)
        if c3 == 200 and "__schema" in b3:
            findings.append(wrap_finding(
                "Hasura GraphQL engine exposed and answers introspection WITHOUT an admin secret",
                "HIGH", cvss="8.0", cwe="CWE-306", owasp="API2:2023",
                remediation="Set HASURA_GRAPHQL_ADMIN_SECRET; disable the console + introspection in production; configure role permissions.",
                evidence_marker="; ".join(ev) + "; POST /v1/graphql introspection -> 200"))
        else:
            findings.append(wrap_finding(
                "Hasura detected — verify admin secret is set and role permissions are configured",
                "MEDIUM", cvss="5.5", cwe="CWE-200",
                remediation="Ensure HASURA_GRAPHQL_ADMIN_SECRET is set and introspection/console are disabled in prod.",
                evidence_marker="; ".join(ev)))
    else:
        findings.append(wrap_finding(
            "No Hasura GraphQL engine detected",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker="No /v1/version or /console Hasura signature"))
    return _resp("graphql_hasura_advisory", target, findings, 3, "Hasura GraphQL engine probe")


def _probe_api_shadow_inventory(target, req):
    """Shadow/zombie API inventory — alias of the version-sprawl probe."""
    r = _probe_hidden_api_versions(target, req)
    r["tool"] = "api_shadow_inventory"
    return r


def _schemathesis_cli():
    """Return the installed Schemathesis CLI name ('schemathesis' or the
    short 'st'), or None if neither binary is on PATH."""
    for name in ("schemathesis", "st"):
        if shutil.which(name):
            return name
    return None


def _discover_spec_url(target, req):
    """Resolve the OpenAPI/Swagger spec URL.

    Precedence: explicit api_spec_url on the request -> common spec paths
    probed on the live target. Returns the spec URL string or None.
    Only returns a path if it actually serves a JSON OpenAPI/Swagger doc
    (read-only GET), so we never feed Schemathesis an HTML/SPA page."""
    # 1) caller-supplied spec URL (request field or generic options dict)
    supplied = getattr(req, "api_spec_url", None) if req is not None else None
    if not supplied and req is not None:
        opts = getattr(req, "options", None)
        if isinstance(opts, dict):
            supplied = opts.get("api_spec_url")
    if supplied and isinstance(supplied, str) and supplied.strip():
        return supplied.strip()
    # 2) discover at the well-known spec endpoints (JSON specs only)
    base = _base_url(target)
    for p in ("/openapi.json", "/swagger.json", "/v3/api-docs", "/v2/api-docs",
              "/api-docs", "/api/swagger.json", "/swagger/v1/swagger.json"):
        code, body, _ = _http_get(base + p, timeout=4)
        bs = (body or "").lstrip()
        if code == 200 and bs.startswith("{") and ('"openapi"' in body or '"swagger"' in body):
            return base + p
    return None


# Lines Schemathesis prints when a check (an actual confirmed defect) fails.
_ST_FAIL_MARKERS = (
    "server_error",            # 5xx from the API under valid input
    "status_code_conformance", # response status not in the documented set
    "response_schema_conformance",  # response body violates the declared schema
    "content_type_conformance",
    "response_headers_conformance",
    "schema_conformance",
    "negative_data_rejection",
    "use_after_free",
    "ensure_resource_availability",
    "ignored_auth",
    "unsupported_method",
)


def _parse_schemathesis(stdout, stderr):
    """Parse Schemathesis CLI output into confirmed failures only.

    Schemathesis prints a 'FAILURES' / 'SUMMARY' block; the per-check
    summary line reads e.g. 'server_error: 3 / 12 passed'. We extract only
    checks that actually recorded one or more failures, plus the failing
    operations listed in the FAILURES section. ZERO assumptions: if the
    output reports no failures, we emit nothing graded."""
    text = (stdout or "") + "\n" + (stderr or "")
    failed_checks = {}
    # Per-check summary lines: "<check_name>: <passed> / <total> passed"
    for m in re.finditer(r"(?im)^\s*([a-z_]+)\s*:\s*(\d+)\s*/\s*(\d+)\s+passed\b", text):
        name, passed, total = m.group(1), int(m.group(2)), int(m.group(3))
        if name in _ST_FAIL_MARKERS and total > passed:
            failed_checks[name] = total - passed
    # Failing operations explicitly listed under the FAILURES section.
    failing_ops = []
    for m in re.finditer(r"(?im)^\s*(?:[-_]+\s*)?((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/\S+)", text):
        op = m.group(1).strip()
        if op not in failing_ops:
            failing_ops.append(op)
    # Overall failed count from the final summary, if present.
    total_failed = 0
    mt = re.search(r"(?i)(\d+)\s+(?:failed|failures?)\b", text)
    if mt:
        total_failed = int(mt.group(1))
    return failed_checks, failing_ops, total_failed


# Map a Schemathesis check name to severity + CWE for a CONFIRMED failure.
_ST_CHECK_META = {
    "server_error":               ("HIGH",   "7.5", "CWE-248", "API8:2023"),
    "use_after_free":             ("HIGH",   "7.5", "CWE-416", "API8:2023"),
    "ignored_auth":               ("HIGH",   "7.5", "CWE-306", "API2:2023"),
    "ensure_resource_availability": ("HIGH", "7.0", "CWE-664", "API1:2023"),
    "status_code_conformance":    ("MEDIUM", "5.3", "CWE-1287", "API8:2023"),
    "response_schema_conformance": ("MEDIUM","5.3", "CWE-1287", "API8:2023"),
    "schema_conformance":         ("MEDIUM", "5.3", "CWE-1287", "API8:2023"),
    "content_type_conformance":   ("LOW",    "3.7", "CWE-1287", "API8:2023"),
    "response_headers_conformance": ("LOW",  "3.7", "CWE-1287", "API8:2023"),
    "negative_data_rejection":    ("MEDIUM", "5.3", "CWE-20",  "API8:2023"),
    "unsupported_method":         ("LOW",    "3.7", "CWE-650", "API8:2023"),
}


def _probe_schemathesis_fuzz(target, req):
    """Property-based API conformance fuzzing with Schemathesis.

    Drives the installed Schemathesis CLI against an OpenAPI/Swagger spec
    (supplied via api_spec_url, or auto-discovered at /openapi.json etc.)
    and emits findings ONLY for failures the tool actually confirmed
    (5xx server errors, schema/status conformance violations, ignored
    auth). If the spec is absent or the CLI is missing, returns an honest
    [ADVISORY-BY-DESIGN] INFO explaining how to supply api_spec_url —
    never a crash and never a fake HIGH."""
    cli = _schemathesis_cli()
    if not cli:
        return _advisory_by_design_response(
            "schemathesis_fuzz", target,
            "Schemathesis property-based API conformance fuzzing",
            reason="The Schemathesis CLI is not installed in this scan "
                   "environment, so the fuzz run could not be executed. "
                   "Install it (pip install schemathesis) and supply an "
                   "OpenAPI/Swagger spec via api_spec_url to enable this check.",
            cwe="CWE-1287")

    spec_url = _discover_spec_url(target, req)
    if not spec_url:
        return _advisory_by_design_response(
            "schemathesis_fuzz", target,
            "Schemathesis property-based API conformance fuzzing",
            reason="No OpenAPI/Swagger specification was provided or "
                   "discovered. Supply api_spec_url (the URL of your "
                   "openapi.json / swagger.json) in the scan request, or "
                   "expose the spec at /openapi.json, /swagger.json or "
                   "/v3/api-docs so it can be discovered automatically.",
            cwe="CWE-1287")

    # Build the command for whichever CLI is installed. Both 'schemathesis'
    # and the short 'st' alias accept the same 'run' sub-command and flags.
    cmd = [cli, "run", spec_url, "--checks", "all", "--max-examples", "20"]
    # Forward a bearer token for authenticated coverage if the caller gave one.
    bearer = getattr(req, "auth_bearer", None) if req is not None else None
    if bearer:
        cmd += ["-H", f"Authorization: Bearer {bearer}"]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
            env={"PATH": os.environ.get("PATH", ""),
                 "NO_COLOR": "1", "PYTHONUNBUFFERED": "1"})
        stdout, stderr = proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return _adv_response(
            "schemathesis_fuzz", target,
            "Schemathesis fuzz run exceeded the 120s wall-clock limit",
            "INFO", "0.0", cwe="N/A",
            remediation="Re-run against a smaller spec subset or lower "
                        "--max-examples; large APIs can exceed the timeout.",
            evidence=f"Timed out fuzzing spec {spec_url}")
    except Exception as e:
        return _adv_response(
            "schemathesis_fuzz", target,
            f"[PROBE ERROR] could not run Schemathesis: {str(e)[:120]}",
            "INFO", "0.0", cwe="N/A",
            remediation="Verify the Schemathesis CLI and the spec URL are reachable.",
            evidence=f"spec={spec_url}; error={str(e)[:160]}")

    failed_checks, failing_ops, total_failed = _parse_schemathesis(stdout, stderr)
    findings = []
    if failed_checks:
        for name, n in sorted(failed_checks.items(), key=lambda kv: kv[0]):
            sev, cvss, cwe, owasp = _ST_CHECK_META.get(
                name, ("MEDIUM", "5.3", "CWE-1287", "API8:2023"))
            label = name.replace("_", " ")
            findings.append(wrap_finding(
                f"Schemathesis confirmed {n} '{label}' failure(s) against the API spec",
                sev, cvss=cvss, cwe=cwe, owasp=owasp,
                remediation=(
                    "Fix the operations so responses conform to the declared "
                    "schema/status set and never return unhandled 5xx; "
                    "enforce input validation and authentication consistently."),
                evidence_marker=(
                    f"schemathesis run {spec_url}: check '{name}' had {n} failing case(s)"
                    + (f"; failing ops: {', '.join(failing_ops[:5])}" if failing_ops else ""))))
    elif total_failed > 0:
        # The summary reported failures but the per-check lines weren't parsed;
        # still report honestly as a generic conformance failure (no severity inflation).
        findings.append(wrap_finding(
            f"Schemathesis reported {total_failed} failing test case(s) against the API spec",
            "MEDIUM", cvss="5.3", cwe="CWE-1287", owasp="API8:2023",
            remediation="Review the failing operations; align responses with the "
                        "declared OpenAPI schema and handle errors gracefully.",
            evidence_marker=(
                f"schemathesis run {spec_url}: {total_failed} failed"
                + (f"; ops: {', '.join(failing_ops[:5])}" if failing_ops else ""))))
    else:
        findings.append(wrap_finding(
            "Schemathesis fuzzing found no spec conformance / server-error failures",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="No action for this check.",
            evidence_marker=f"schemathesis run {spec_url} --checks all --max-examples 20: all checks passed"))

    return {
        "tool": "schemathesis_fuzz", "target": target, "scan_time": 0,
        "vulnerable": any(f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM") for f in findings),
        "severity": _resp("", "", findings, 0, "")["severity"],
        "findings": findings,
        "tests_performed": 20,
        "tests_summary": "Schemathesis property-based API conformance fuzz (--checks all)",
        "raw_data": {"spec_url": spec_url, "cli": cli,
                     "failed_checks": failed_checks, "failing_ops": failing_ops[:10]},
    }


# ───────────────────────── PROBES registry ─────────────────────────
PROBES = {
    # §1 Discovery
    "openapi_swagger_discovery":  _probe_openapi_swagger,
    "openapi_swagger_exposed":    _probe_openapi_exposed,
    "graphql_schema_discovery":   _probe_graphql_discovery,
    "grpc_reflection_discovery":  _probe_grpc_reflection,
    "api_endpoint_brute":         _probe_api_endpoint_brute,
    "hidden_api_versions":        _probe_hidden_api_versions,
    "api_shadow_inventory":       _probe_api_shadow_inventory,
    "api_deprecated_endpoints":   _probe_deprecated,
    "api_developer_portal_audit": _probe_dev_portal,
    "schemathesis_fuzz":          _probe_schemathesis_fuzz,
    "postman_collection_discovery": _abd("postman_collection_discovery", "Postman collection harvesting", _OSINT),
    "postman_workspace_audit":    _abd("postman_workspace_audit", "Public Postman workspace audit", _OSINT),
    "readme_io_audit":            _abd("readme_io_audit", "Readme.io hosted-docs audit", _OSINT),
    "manual_api_discovery":       _abd("manual_api_discovery", "Manual API workflow mapping", _MANUAL),

    # §2 OWASP API Top 10 2023
    "api2_broken_auth":           _probe_api2_broken_auth,
    "api8_misconfig":             _probe_api8_misconfig,
    "api_open_redirect":          _probe_api_open_redirect,
    "api1_bola_object_authz":     _abd("api1_bola_object_authz", "API1 BOLA / object-level authz", _CREDS),
    "api3_bopla_property_authz":  _abd("api3_bopla_property_authz", "API3 BOPLA / property-level authz", _CREDS),
    "api4_unrestricted_resource_consumption": _abd("api4_unrestricted_resource_consumption", "API4 unrestricted resource consumption", _DOS),
    "api5_bfla_function_authz":   _abd("api5_bfla_function_authz", "API5 BFLA / function-level authz", _CREDS),
    "api6_unrestricted_sensitive_access": _abd("api6_unrestricted_sensitive_access", "API6 unrestricted sensitive business flow", _CREDS),
    "api7_ssrf":                  _abd("api7_ssrf", "API7 SSRF", _EXPLOIT),
    "api9_shadow_inventory_top10": _abd("api9_shadow_inventory_top10", "API9 improper inventory management", "Covered live by api_shadow_inventory / hidden_api_versions; full shadow/zombie diff needs an authoritative API inventory baseline as input."),
    "api10_3rd_party_consumption": _abd("api10_3rd_party_consumption", "API10 unsafe 3rd-party consumption", _MANUAL),
    "api_mass_assignment":        _abd("api_mass_assignment", "Mass assignment", _CREDS),
    "api_xxe":                    _abd("api_xxe", "API XXE", _EXPLOIT),
    "api_command_injection":      _abd("api_command_injection", "API command injection", _EXPLOIT),
    "api_path_traversal":         _abd("api_path_traversal", "API path traversal", _EXPLOIT),
    "api_lfi_rfi":                _abd("api_lfi_rfi", "API LFI/RFI", _EXPLOIT),
    "api_csrf_state_changing":    _abd("api_csrf_state_changing", "API CSRF on state-changing endpoints", _CREDS),
    "manual_owasp_api_review":    _abd("manual_owasp_api_review", "Manual OWASP API Top 10 review", _MANUAL),
    "manual_business_logic_review": _abd("manual_business_logic_review", "Manual business-logic review", _MANUAL),

    # §3 Authentication
    "api_jwt_none_alg":           _probe_api_jwt_none,
    "api_oauth_pkce_missing":     _probe_api_pkce_missing,
    "api_cookie_security_flags":  _probe_api_cookie_flags,
    "api_jwt_weak_hs256":         _abd("api_jwt_weak_hs256", "JWT weak HS256 secret", _TOKEN),
    "api_jwt_jku_x5u_ssrf":       _abd("api_jwt_jku_x5u_ssrf", "JWT JKU/X5U SSRF", _EXPLOIT),
    "api_jwt_kid_traversal":      _abd("api_jwt_kid_traversal", "JWT kid path traversal", _EXPLOIT),
    "api_jwt_kid_sqli":           _abd("api_jwt_kid_sqli", "JWT kid SQL injection", _EXPLOIT),
    "api_oauth_redirect_hijack":  _abd("api_oauth_redirect_hijack", "OAuth redirect_uri hijack", _EXPLOIT),
    "api_oauth_state_csrf":       _abd("api_oauth_state_csrf", "OAuth state CSRF", _CREDS),
    "api_oidc_nonce_audit":       _abd("api_oidc_nonce_audit", "OIDC nonce validation audit", _CREDS),
    "api_session_fixation":       _abd("api_session_fixation", "Session fixation", _CREDS),
    "manual_api_auth_review":     _abd("manual_api_auth_review", "Manual API auth review", _MANUAL),

    # §4 Authorization
    "api_idor_param_swap":        _abd("api_idor_param_swap", "IDOR param swap", _CREDS),
    "api_horizontal_authz":       _abd("api_horizontal_authz", "Horizontal authz bypass", _CREDS),
    "api_vertical_authz":         _abd("api_vertical_authz", "Vertical authz bypass", _CREDS),
    "api_role_in_jwt_tamper":     _abd("api_role_in_jwt_tamper", "Role-in-JWT tampering", _EXPLOIT),
    "api_admin_bypass_header":    _abd("api_admin_bypass_header", "Admin bypass via X-Forwarded header", _EXPLOIT),
    "api_authz_method_override":  _abd("api_authz_method_override", "HTTP method-override authz bypass", _CREDS),
    "api_authz_content_type_smuggle": _abd("api_authz_content_type_smuggle", "Content-Type smuggle authz bypass", _CREDS),
    "api_authz_path_traversal":   _abd("api_authz_path_traversal", "Authz path traversal", _EXPLOIT),
    "manual_authz_review":        _abd("manual_authz_review", "Manual authz review", _MANUAL),
    "manual_authz_matrix":        _abd("manual_authz_matrix", "Manual authz matrix", _MANUAL),

    # §5 Rate Limiting
    "rate_limit_ip_bypass":       _probe_rate_limit,
    "rate_limit_header_bypass":   _abd("rate_limit_header_bypass", "Rate-limit X-Forwarded-For bypass", _DOS),
    "rate_limit_path_normalize_bypass": _abd("rate_limit_path_normalize_bypass", "Path-normalization rate-limit bypass", _DOS),
    "rate_limit_method_bypass":   _abd("rate_limit_method_bypass", "Method-based rate-limit bypass", _DOS),
    "rate_limit_distributed_attack": _abd("rate_limit_distributed_attack", "Distributed rate-limit attack", _DOS),
    "billing_amplification_attack": _abd("billing_amplification_attack", "Billing amplification (cost-DoS)", _DOS),
    "manual_rate_limit_review":   _abd("manual_rate_limit_review", "Manual rate-limit review", _MANUAL),

    # §6 GraphQL
    "graphql_introspection_open": _probe_graphql_introspection,
    "graphql_hasura_advisory":    _probe_hasura,
    "graphql_batching_dos":       _abd("graphql_batching_dos", "GraphQL batching DoS", _DOS),
    "graphql_depth_dos":          _abd("graphql_depth_dos", "GraphQL query-depth DoS", _DOS),
    "graphql_aliases_dos":        _abd("graphql_aliases_dos", "GraphQL alias-overload DoS", _DOS),
    "graphql_field_authz_bypass": _abd("graphql_field_authz_bypass", "GraphQL field-level authz bypass", _CREDS),
    "graphql_mutation_authz":     _abd("graphql_mutation_authz", "GraphQL mutation authz", _CREDS),
    "graphql_inj_to_sqli":        _abd("graphql_inj_to_sqli", "GraphQL -> SQLi propagation", _EXPLOIT),
    "graphql_inj_to_ssrf":        _abd("graphql_inj_to_ssrf", "GraphQL -> SSRF propagation", _EXPLOIT),
    "graphql_apollo_advisory":    _abd("graphql_apollo_advisory", "Apollo Federation gateway audit", _PROTO),
    "manual_graphql_review":      _abd("manual_graphql_review", "Manual GraphQL review", _MANUAL),
    "manual_graphql_chain":       _abd("manual_graphql_chain", "Manual GraphQL chain", _MANUAL),

    # §7 gRPC
    "grpc_reflection_open":       _abd("grpc_reflection_open", "gRPC reflection enabled", _PROTO),
    "grpc_no_mtls":               _abd("grpc_no_mtls", "gRPC mTLS not enforced", _PROTO),
    "grpc_replay_attack":         _abd("grpc_replay_attack", "gRPC replay attack", _PROTO),
    "grpc_metadata_injection":    _abd("grpc_metadata_injection", "gRPC metadata injection", _EXPLOIT),
    "grpc_message_dos":           _abd("grpc_message_dos", "gRPC message-size DoS", _DOS),
    "grpc_web_parity_audit":      _abd("grpc_web_parity_audit", "gRPC-Web parity audit", _PROTO),
    "manual_grpc_review":         _abd("manual_grpc_review", "Manual gRPC review", _MANUAL),
    "manual_grpc_chain":          _abd("manual_grpc_chain", "Manual gRPC chain", _MANUAL),

    # §8 WebSocket / SSE / WebTransport
    "ws_origin_audit":            _probe_ws_origin,
    "sse_origin_audit":           _probe_sse_origin,
    "ws_auth_audit":              _abd("ws_auth_audit", "WebSocket post-upgrade auth audit", _PROTO),
    "ws_injection_audit":         _abd("ws_injection_audit", "WebSocket message injection", _EXPLOIT),
    "ws_cross_origin_csrf":       _abd("ws_cross_origin_csrf", "WebSocket cross-origin CSRF", _PROTO),
    "webtransport_audit":         _abd("webtransport_audit", "WebTransport stream auth audit", _PROTO),
    "h2c_smuggling":              _abd("h2c_smuggling", "H2C smuggling", _EXPLOIT),
    "http2_rapid_reset":          _abd("http2_rapid_reset", "HTTP/2 Rapid Reset (CVE-2023-44487)", _DOS),
    "manual_modern_proto_review": _abd("manual_modern_proto_review", "Manual modern-protocol review", _MANUAL),

    # §9 SOAP / REST Legacy
    "soap_wsdl_disclosure":       _probe_soap_wsdl,
    "rest_options_method_audit":  _probe_options_audit,
    "rest_jsonp_callback":        _probe_jsonp,
    "soap_xxe":                   _abd("soap_xxe", "SOAP XXE", _EXPLOIT),
    "soap_action_spoof":          _abd("soap_action_spoof", "SOAP action spoofing", _EXPLOIT),
    "soap_xml_signature_wrap":    _abd("soap_xml_signature_wrap", "SOAP XML signature wrapping", _EXPLOIT),
    "soap_xpath_injection":       _abd("soap_xpath_injection", "SOAP XPath injection", _EXPLOIT),
    "rest_etag_csrf":             _abd("rest_etag_csrf", "REST ETag CSRF", _CREDS),
    "manual_soap_rest_review":    _abd("manual_soap_rest_review", "Manual SOAP/REST review", _MANUAL),

    # §10 API Supply Chain / Versioning
    "api_key_in_url_leak":        _probe_api_key_in_url,
    "api_version_skew_audit":     _abd("api_version_skew_audit", "API version-skew audit", "Covered live by api_shadow_inventory / hidden_api_versions; confirming an old version is more vulnerable needs per-version behavioural diffing under engagement scope."),
    "api_deprecation_lifecycle":  _abd("api_deprecation_lifecycle", "API deprecation lifecycle compliance", "Covered live by api_deprecated_endpoints; full lifecycle/sunset compliance needs the documented version policy as input."),
    "api_key_logging_audit":      _abd("api_key_logging_audit", "API key logging audit", _CREDS),
    "api_3rd_party_consumption":  _abd("api_3rd_party_consumption", "Unsafe 3rd-party API consumption", _MANUAL),
    "api_webhook_ssrf":           _abd("api_webhook_ssrf", "API webhook SSRF", _EXPLOIT),
    "api_oauth_introspection_abuse": _abd("api_oauth_introspection_abuse", "OAuth introspection abuse", _CREDS),
    "api_consumer_secret_rotation": _abd("api_consumer_secret_rotation", "Consumer secret rotation audit", _CREDS),
    "api_breaking_change_advisory": _abd("api_breaking_change_advisory", "Breaking-change advisory", _MANUAL),
    "api_dependency_security_audit": _abd("api_dependency_security_audit", "API SDK/dependency vuln audit", "Requires the SDK/dependency manifest (SBOM/lockfile); use the Supply-Chain module with the dependency list."),
    "manual_api_supply_chain":    _abd("manual_api_supply_chain", "Manual API supply-chain review", _MANUAL),
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
    ("schemathesis_fuzz", "Schemathesis OpenAPI conformance fuzzing.", "HIGH", "7.5"),
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
    ("graphql_inj_to_sqli", "GraphQL -> SQLi propagation.", "HIGH", "8.0"),
    ("graphql_inj_to_ssrf", "GraphQL -> SSRF propagation.", "HIGH", "8.0"),
    ("graphql_apollo_advisory", "Apollo Federation audit.", "MEDIUM", "5.5"),
    ("graphql_hasura_advisory", "Hasura audit.", "MEDIUM", "5.5"),
    ("manual_graphql_review", "Manual GraphQL review.", "INFO", "0.0"),
    ("manual_graphql_chain", "Manual GraphQL chain.", "INFO", "0.0"),
    # §7 gRPC Security (8)
    ("grpc_reflection_open", "gRPC reflection open.", "MEDIUM", "5.5"),
    ("grpc_no_mtls", "gRPC mTLS not enforced.", "HIGH", "7.5"),
    ("grpc_replay_attack", "gRPC replay attack.", "HIGH", "7.0"),
    ("grpc_metadata_injection", "gRPC metadata injection.", "HIGH", "7.0"),
    ("grpc_message_dos", "gRPC message-size DoS.", "HIGH", "7.0"),
    ("grpc_web_parity_audit", "gRPC-Web parity audit.", "MEDIUM", "5.5"),
    ("manual_grpc_review", "Manual gRPC review.", "INFO", "0.0"),
    ("manual_grpc_chain", "Manual gRPC chain.", "INFO", "0.0"),
    # §8 WebSocket / SSE / WebTransport (9)
    ("ws_origin_audit", "WebSocket origin audit.", "HIGH", "7.0"),
    ("ws_auth_audit", "WebSocket auth audit.", "HIGH", "7.5"),
    ("ws_injection_audit", "WebSocket injection.", "HIGH", "7.5"),
    ("ws_cross_origin_csrf", "WebSocket cross-origin CSRF.", "HIGH", "7.0"),
    ("sse_origin_audit", "SSE origin audit.", "MEDIUM", "5.5"),
    ("webtransport_audit", "WebTransport audit.", "MEDIUM", "5.5"),
    ("h2c_smuggling", "H2C smuggling.", "HIGH", "8.0"),
    ("http2_rapid_reset", "HTTP/2 Rapid Reset (CVE-2023-44487).", "HIGH", "7.5"),
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
    # §10 API Supply Chain / Versioning (11)
    ("api_version_skew_audit", "API version skew audit.", "MEDIUM", "5.5"),
    ("api_key_in_url_leak", "API key in URL leak.", "HIGH", "7.5"),
    ("api_key_logging_audit", "API key logging audit.", "HIGH", "7.0"),
    ("api_3rd_party_consumption", "Unsafe 3rd-party API consumption.", "HIGH", "7.0"),
    ("api_webhook_ssrf", "API webhook SSRF.", "HIGH", "8.0"),
    ("api_oauth_introspection_abuse", "OAuth introspection abuse.", "MEDIUM", "5.5"),
    ("api_consumer_secret_rotation", "Consumer secret rotation.", "MEDIUM", "5.5"),
    ("api_deprecation_lifecycle", "API deprecation lifecycle.", "INFO", "0.0"),
    ("api_breaking_change_advisory", "Breaking change advisory.", "INFO", "0.0"),
    ("api_dependency_security_audit", "API dependency security audit.", "MEDIUM", "5.5"),
    ("manual_api_supply_chain", "Manual API supply chain review.", "INFO", "0.0"),
]

router = make_advisory_router("apisec", T,
    playbook_ref="See module_playbooks/22_apisec.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
