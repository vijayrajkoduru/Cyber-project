"""ms_graph_api_leak — MS Graph / Azure AD config & token leak detection.

MS Graph is the Microsoft 365 / Azure AD API. App-bundled JS commonly
exposes:
  - MSAL config (tenant_id, client_id, authority URL — usually safe to bundle)
  - Access tokens (NEVER bundle, often accidentally cached)
  - Refresh tokens (NEVER bundle)
  - Azure storage SAS tokens (bundled in static assets — risky)

Scans homepage + linked JS for MSAL config, Bearer tokens with
Microsoft issuer claim, SAS tokens.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota, web_url,
                            safe_request, wrap_finding, standard_response)
from tools._vl_core.turbo import vl_turbo

router = APIRouter()

PATTERNS = [
    ("MSAL client_id (GUID)",  re.compile(rb"clientId[\"']?\s*[:=]\s*[\"']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", re.IGNORECASE)),
    ("MSAL tenant_id",         re.compile(rb"tenantId[\"']?\s*[:=]\s*[\"']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|common|organizations)", re.IGNORECASE)),
    ("Azure SAS token",        re.compile(rb"sig=[A-Za-z0-9%]{40,}&sv=\d{4}-\d{2}-\d{2}")),
    ("Azure Storage account",  re.compile(rb"https?://[a-z0-9]{3,24}\.blob\.core\.windows\.net")),
    ("OAuth Bearer (MS JWT)",  re.compile(rb"eyJ0eXAiOiJKV1QiLCJhbGc[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")),
    ("AAD app secret-ish",     re.compile(rb"[A-Za-z0-9~._-]{34,40}~[A-Za-z0-9]{10,}")),
]
SCRIPT_SRC_RE = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+\.js)["\']', re.IGNORECASE)


def _fetch(url, req):
    return safe_request("GET", url,
        headers={"User-Agent": "Mozilla/5.0 VulnusLab/1.0"},
        req=req, timeout=10, allow_redirects=True)


@router.post("/api/webapp/scan/ms_graph_api_leak")
@vl_turbo()
def scan_ms_graph_api_leak(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    root = _fetch(base + "/", req)
    if root is None or root.status_code >= 400:
        return standard_response(
            tool="ms_graph_api_leak", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="Could not fetch homepage")

    sources = {"inline": root.content}
    fetched = 0
    for m in SCRIPT_SRC_RE.finditer(root.text):
        if fetched >= 10: break
        src = m.group(1)
        if src.startswith("//"): src = "https:" + src
        if src.startswith("/"):  src = base + src
        elif not src.startswith("http"): src = base + "/" + src
        if not src.startswith(base): continue
        r = _fetch(src, req)
        if r is None or r.status_code != 200: continue
        sources[src] = r.content[:500_000]
        fetched += 1

    hits = []
    for src_name, content in sources.items():
        for name, pat in PATTERNS:
            for m in pat.finditer(content):
                val = m.group(0).decode(errors="ignore")
                # Filter dummies
                if "your-tenant-id" in val.lower() or "00000000" in val:
                    continue
                hits.append({
                    "type": name, "source": src_name[:80],
                    "preview": val[:50] + ("…" if len(val) > 50 else ""),
                })
                if len(hits) >= 20: break
            if len(hits) >= 20: break

    findings = []
    critical = [h for h in hits if h["type"] in
                 ("OAuth Bearer (MS JWT)", "AAD app secret-ish", "Azure SAS token")]
    info = [h for h in hits if h not in critical]

    if critical:
        findings.append(wrap_finding(
            f"CRITICAL: Microsoft tokens / secrets leaked in client bundle ({len(critical)})",
            "CRITICAL", cvss="9.8", cwe="CWE-798", owasp="A07:2021",
            remediation="Tokens / SAS / app secrets in client bundle = anyone with "
                        "DevTools can extract. (1) ROTATE the leaked credential at "
                        "Azure portal. (2) Move sensitive Graph calls server-side "
                        "(backend uses managed identity / client credentials, frontend "
                        "calls your API). (3) For SAS tokens: never bundle long-lived "
                        "SAS in static assets; generate user-delegation SAS server-side "
                        "per request with minimum-needed scope + short TTL.",
            evidence_marker=" | ".join(
                f"{h['type']}: {h['preview']} in {h['source']}" for h in critical[:5]
            )))

    if info and not critical:
        findings.append(wrap_finding(
            f"MS Graph / Azure AD config bundled ({len(info)} hits — non-secret)",
            "INFO", cwe="CWE-200",
            remediation="MSAL client_id + tenant_id ARE meant to be in client bundle "
                        "(they identify your app to Azure AD). Just verify token-"
                        "acquisition flows are PKCE (no client secret used client-side).",
            evidence_marker=" | ".join(
                f"{h['type']}: {h['preview']}" for h in info[:5]
            )))

    if not hits:
        findings.append(wrap_finding(
            f"No MS Graph / Azure AD bundling detected",
            "POSITIVE", cwe="CWE-200",
            remediation="No MS-specific surface from this scan.",
            evidence_marker=f"scanned {1+fetched} JS sources × {len(PATTERNS)} patterns"))

    return standard_response(
        tool="ms_graph_api_leak", target=req.target, findings=findings,
        tests_performed=1+fetched, vulnerable=bool(critical),
        tests_summary=f"{len(hits)} hits ({len(critical)} critical)",
        raw_data={"hits": hits[:15]})


def register(app):
    app.include_router(router)
