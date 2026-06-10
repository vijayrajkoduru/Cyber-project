"""forwarded_header_trust — X-Forwarded-* / Forwarded header trust audit.

Backend trusts client-supplied X-Forwarded-For / X-Real-IP / Forwarded
without validating the request originated from a trusted reverse proxy.
Attacker spoofs source IP to:
  - Bypass IP allow-list (admin-by-IP, GeoIP block)
  - Pollute rate-limit (per-IP throttle)
  - Inject into audit logs

Tests: send X-Forwarded-For with spoofed IPs, look for response that
reflects them (in body, in Set-Cookie, in error message).
"""
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo
from tools._vl_core.verify import vl_verify

router = APIRouter()

SPOOF_IPS = [
    "127.0.0.1",
    "169.254.169.254",        # cloud metadata
    "10.0.0.1",                # private
    "::1",
    "203.0.113.42",            # documentation IP
]
FORWARDED_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",         # cloudflare
    "X-Cluster-Client-IP",
    "Forwarded",                # RFC 7239
]


def _probe(url, headers, req):
    return safe_request("GET", url,
        headers={**headers, "User-Agent": "VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)


@router.post("/api/webapp/scan/forwarded_header_trust")
@vl_turbo()
@vl_verify()
def scan_forwarded_header_trust(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    # Baseline
    r0 = _probe(base + "/", {}, req)
    if r0 is None:
        return standard_response(
            tool="forwarded_header_trust", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No baseline response")

    baseline_status = r0.status_code
    baseline_body = (r0.text or "")[:5000]

    reflected_ips = []
    status_changes = []

    for hdr in FORWARDED_HEADERS:
        for ip in SPOOF_IPS:
            r = _probe(base + "/", {hdr: ip}, req)
            if r is None: continue
            body = (r.text or "")[:5000]
            # Reflection check: spoofed IP in body or in Set-Cookie value
            if ip in body and ip not in baseline_body:
                reflected_ips.append({"header": hdr, "ip": ip,
                                        "where": "body"})
            sc = r.headers.get("set-cookie", "") or ""
            if ip in sc:
                reflected_ips.append({"header": hdr, "ip": ip,
                                        "where": "Set-Cookie"})
            # Status change for localhost spoof (admin-by-IP bypass)
            if ip in ("127.0.0.1", "10.0.0.1"):
                if r.status_code != baseline_status and r.status_code == 200 and baseline_status in (401, 403):
                    status_changes.append({"header": hdr, "ip": ip,
                                            "baseline": baseline_status,
                                            "spoofed": r.status_code})

    findings = []
    if status_changes:
        findings.append(wrap_finding(
            f"IP-based access control bypassed via spoofed forwarded header ({len(status_changes)})",
            "HIGH", cvss="8.1", cwe="CWE-302", owasp="A01:2021",
            remediation="Backend trusts client-supplied forwarded-IP headers — "
                        "bypassing IP-based admin gates. (1) Configure web server "
                        "to ONLY trust forwarded headers when request comes from "
                        "known proxy IPs (nginx: 'set_real_ip_from <proxy-cidr>'; "
                        "Apache: 'RemoteIPInternalProxy'). (2) For app logic, use "
                        "request.remote_addr (true source) not header value, UNLESS "
                        "you've validated the trust chain.",
            evidence_marker=" | ".join(
                f"{c['header']}: {c['ip']} → HTTP {c['spoofed']} (baseline {c['baseline']})"
                for c in status_changes[:3]
            )))

    if reflected_ips:
        sev = "MEDIUM" if status_changes else "LOW"
        cvss = "5.3" if status_changes else "3.5"
        findings.append(wrap_finding(
            f"Forwarded IP reflected in response ({len(reflected_ips)} reflections)",
            sev, cvss=cvss, cwe="CWE-200", owasp="A05:2021",
            remediation="App reflects user-controlled forwarded-IP in response — "
                        "could enable log injection or XSS if rendered in HTML. "
                        "Sanitize before display.",
            evidence_marker=" | ".join(
                f"{r['header']}: {r['ip']} → {r['where']}" for r in reflected_ips[:5]
            )))

    if not findings:
        findings.append(wrap_finding(
            f"No forwarded-header trust issues detected",
            "POSITIVE", cwe="CWE-302",
            remediation="Maintain. Continue using request.remote_addr / properly "
                        "configured proxy_pass real-ip resolution.",
            evidence_marker=f"tested {len(FORWARDED_HEADERS)} headers × {len(SPOOF_IPS)} IPs"))

    return standard_response(
        tool="forwarded_header_trust", target=req.target, findings=findings,
        tests_performed=1 + len(FORWARDED_HEADERS) * len(SPOOF_IPS),
        vulnerable=bool(status_changes or reflected_ips),
        tests_summary=f"reflections: {len(reflected_ips)}, status_changes: {len(status_changes)}",
        raw_data={"reflected_ips": reflected_ips, "status_changes": status_changes,
                   "baseline_status": baseline_status})


def register(app):
    app.include_router(router)
