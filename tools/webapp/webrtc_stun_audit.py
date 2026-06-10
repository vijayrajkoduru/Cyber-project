"""webrtc_stun_audit — WebRTC RTCPeerConnection config audit.

Static-source scan: find RTCPeerConnection() constructor calls + the
iceServers config. Risky patterns:
  - Default browser STUN (no iceServers config) → reveals real IP
  - Public STUN list (stun:stun.l.google.com) — fine for general but
    reveals client IP to Google
  - Missing TURN server (peers can't traverse symmetric NAT)
  - stun:// to non-https origin reveals IP cleartext

MASVS-NETWORK / WebRTC privacy.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

RTC_RE = re.compile(r"new\s+RTCPeerConnection\s*\(([^)]{0,800})\)", re.IGNORECASE)
STUN_URL_RE = re.compile(r'(?:stun|turn|stuns|turns):[A-Za-z0-9.\-]+(:\d+)?', re.IGNORECASE)
SCRIPT_SRC_RE = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+\.js)["\']', re.IGNORECASE)


@router.post("/api/webapp/scan/webrtc_stun_audit")
@vl_turbo()
def scan_webrtc_stun_audit(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    root = safe_request("GET", base + "/",
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=True)
    if root is None or root.status_code >= 400:
        return standard_response(
            tool="webrtc_stun_audit", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"Could not fetch homepage (HTTP {root.status_code if root else 'no-resp'})")

    sources = {"inline": root.text}
    fetched = 0
    for m in SCRIPT_SRC_RE.finditer(root.text):
        if fetched >= 8: break
        src = m.group(1)
        if src.startswith("//"): src = "https:" + src
        if src.startswith("/"):  src = base + src
        elif not src.startswith("http"): src = base + "/" + src
        if not src.startswith(base): continue
        r = safe_request("GET", src,
            headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
            req=req, timeout=8, allow_redirects=True)
        if r is None or r.status_code != 200: continue
        sources[src] = r.text[:200000]
        fetched += 1

    rtc_calls = []
    stun_urls = set()
    for src_name, text in sources.items():
        for m in RTC_RE.finditer(text):
            cfg = m.group(1)[:500]
            rtc_calls.append({"source": src_name[:80], "config": cfg.replace("\n", " ")})
        for m in STUN_URL_RE.finditer(text):
            stun_urls.add(m.group(0))

    findings = []
    if not rtc_calls:
        return standard_response(
            tool="webrtc_stun_audit", target=req.target,
            findings=[wrap_finding(
                "No RTCPeerConnection usage in homepage + linked scripts",
                "POSITIVE", cwe="CWE-200",
                remediation="No WebRTC = no IP leakage via STUN. Maintain.",
                evidence_marker=f"scanned {1+fetched} JS sources")],
            tests_performed=1+fetched, vulnerable=False,
            tests_summary="No WebRTC")

    issues = []
    # Issue 1: empty config (no iceServers) — default browser STUN reveals IP
    no_config = [c for c in rtc_calls if "iceservers" not in c["config"].lower()
                  and "{" not in c["config"]]
    if no_config:
        issues.append(("RTCPeerConnection() called with no iceServers config "
                       "(default browser STUN reveals client IP)", "MEDIUM"))

    # Issue 2: Google STUN (privacy leak)
    if any("stun.l.google.com" in u for u in stun_urls):
        issues.append(("Google STUN server used (stun.l.google.com) — "
                       "Google sees every client's real IP", "LOW"))

    # Issue 3: Cleartext stun:// (vs stuns://)
    cleartext_stun = [u for u in stun_urls if u.lower().startswith("stun:")]
    if cleartext_stun:
        issues.append((f"Cleartext STUN URLs ({len(cleartext_stun)}) — IP leaks via UDP", "LOW"))

    # Issue 4: No TURN configured (peers behind symmetric NAT can't connect)
    has_turn = any("turn" in u.lower() for u in stun_urls)
    if rtc_calls and not has_turn:
        issues.append(("No TURN server configured — connections fail behind "
                        "symmetric NAT (~10% of users)", "INFO"))

    if issues:
        sev = "MEDIUM" if any(s == "MEDIUM" for _, s in issues) else "LOW"
        findings.append(wrap_finding(
            f"WebRTC config issues ({len(issues)})",
            sev, cwe="CWE-200", owasp="A05:2021",
            remediation="(1) Always set iceServers to your own STUN/TURN servers. "
                        "(2) Use stuns:// + turns:// (TLS-encrypted) for sensitive flows. "
                        "(3) Provide a TURN fallback for connectivity. "
                        "(4) For privacy-critical apps (signal/chat), require TURN-only "
                        "mode to never reveal client IP.",
            evidence_marker=" | ".join(f"{m} [{s}]" for m, s in issues[:4])))
    else:
        findings.append(wrap_finding(
            f"WebRTC properly configured ({len(rtc_calls)} call(s), {len(stun_urls)} STUN/TURN URLs)",
            "POSITIVE", cwe="CWE-200",
            remediation="Maintain. Periodically re-audit STUN/TURN provider list.",
            evidence_marker=f"STUN/TURN urls: {', '.join(list(stun_urls)[:5])}"))

    return standard_response(
        tool="webrtc_stun_audit", target=req.target, findings=findings,
        tests_performed=1+fetched, vulnerable=bool(issues),
        tests_summary=f"{len(rtc_calls)} RTC calls / {len(stun_urls)} STUN-TURN urls / "
                       f"{len(issues)} issues",
        raw_data={"rtc_calls": rtc_calls[:10], "stun_urls": list(stun_urls)})


def register(app):
    app.include_router(router)
