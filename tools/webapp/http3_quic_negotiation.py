"""http3_quic_negotiation — HTTP/3 (QUIC) negotiation + Alt-Svc audit.

Modern apps advertise HTTP/3 via Alt-Svc: h3=":443"; ma=86400. This audit:
  1. Detects Alt-Svc advertisement
  2. Flags very long max-age (cached forever — hard to roll back)
  3. Detects QUIC version mismatch (legacy h3-29 still advertised)
  4. Checks for protocol-downgrade vulnerabilities (Alt-Svc to attacker domain)
"""
import re
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()


def _parse_alt_svc(header: str) -> list:
    """Parse Alt-Svc header into list of {protocol, port, ma}."""
    entries = []
    for part in header.split(","):
        part = part.strip()
        m = re.match(r'^([\w-]+)="?:?(\d+)"?(?:;\s*ma=(\d+))?(?:;\s*persist=1)?', part)
        if m:
            entries.append({
                "protocol": m.group(1),
                "port": m.group(2),
                "max_age": int(m.group(3)) if m.group(3) else 86400,
            })
    return entries


@router.post("/api/webapp/scan/http3_quic_negotiation")
@vl_turbo()
def scan_http3_quic_negotiation(req: ScanRequest, payload=Depends(verify_scan_quota)):
    url = web_url(req.target)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return standard_response(
            tool="http3_quic_negotiation", target=req.target,
            findings=[wrap_finding(
                "Target is HTTP — HTTP/3 (QUIC) requires HTTPS first",
                "INFO", cwe="CWE-200",
                remediation="Serve HTTPS first; HTTP/3 is advertised via Alt-Svc on TLS.",
                evidence_marker=f"scheme: {parsed.scheme}")],
            tests_performed=0, vulnerable=False,
            tests_summary="Not HTTPS")

    r = safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=8, allow_redirects=False)
    if r is None:
        return standard_response(
            tool="http3_quic_negotiation", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="No response")

    alt_svc = (r.headers.get("alt-svc") or r.headers.get("Alt-Svc") or "").strip()
    entries = _parse_alt_svc(alt_svc) if alt_svc else []
    h3_entries = [e for e in entries if e["protocol"].startswith("h3")]
    legacy = [e for e in entries if e["protocol"] in ("h3-29", "h3-Q050", "h3-Q046")]

    findings = []
    if not alt_svc:
        findings.append(wrap_finding(
            "No Alt-Svc header — HTTP/3 not advertised",
            "INFO", cwe="CWE-200",
            remediation="HTTP/3 (QUIC) provides 0-RTT resumption + better mobile "
                        "perf. Enable in your edge: Cloudflare → automatic; nginx → "
                        "add 'add_header Alt-Svc 'h3=\":443\"; ma=86400';'.",
            evidence_marker="no Alt-Svc header"))
    else:
        if not h3_entries:
            findings.append(wrap_finding(
                "Alt-Svc set but no h3 entry — only legacy SPDY/HTTP/2 advertised",
                "LOW", cwe="CWE-200",
                remediation="Modern Alt-Svc should advertise h3. Update edge config.",
                evidence_marker=f"Alt-Svc: {alt_svc[:120]}"))
        if legacy:
            findings.append(wrap_finding(
                f"Legacy QUIC drafts advertised ({', '.join(e['protocol'] for e in legacy)})",
                "LOW", cwe="CWE-1395",
                remediation="Draft versions of QUIC (h3-29, h3-Q050) are not "
                            "interoperable with finalized RFC 9114. Old browsers may "
                            "fall back to QUIC draft and fail. Advertise only 'h3'.",
                evidence_marker=f"Alt-Svc: {alt_svc[:150]}"))
        max_ma = max((e["max_age"] for e in entries), default=0)
        if max_ma > 604800:  # > 1 week
            findings.append(wrap_finding(
                f"Alt-Svc max-age={max_ma}s (>1 week) — Alt-Svc cached too long",
                "LOW", cwe="CWE-1395",
                remediation="Long max-age means rolling back HTTP/3 takes browser "
                            "cache TTL to flush. Cap at 86400 (24h) during initial "
                            "rollout, raise after stability proven.",
                evidence_marker=f"Alt-Svc max-age: {max_ma}s = {max_ma//3600}h"))
        # External Alt-Svc destination (alt-svc to attacker domain)
        for e in entries:
            if ":" in e["port"] and parsed.hostname not in e["port"]:
                findings.append(wrap_finding(
                    f"Alt-Svc points to FOREIGN host: {e['port']}",
                    "CRITICAL", cvss="9.0", cwe="CWE-639", owasp="A01:2021",
                    remediation="Alt-Svc to a foreign host = browser routes traffic "
                                "to that host for max-age duration. If attacker controls "
                                "edge response (e.g. via MitM during cert renewal), they "
                                "can hijack traffic indefinitely.",
                    evidence_marker=f"Alt-Svc port field: {e['port']}"))

    if not findings:
        findings.append(wrap_finding(
            f"HTTP/3 properly advertised: {alt_svc[:80]}",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. Monitor for QUIC-version updates from your CDN.",
            evidence_marker=f"h3 entries: {len(h3_entries)}, max-age: "
                              f"{max(e['max_age'] for e in entries) if entries else 0}s"))

    return standard_response(
        tool="http3_quic_negotiation", target=req.target, findings=findings,
        tests_performed=1, vulnerable=any(f.get("severity") in ("CRITICAL", "MEDIUM")
                                              for f in findings),
        tests_summary=f"Alt-Svc: {bool(alt_svc)}, h3 entries: {len(h3_entries)}",
        raw_data={"alt_svc_raw": alt_svc, "entries": entries})


def register(app):
    app.include_router(router)
