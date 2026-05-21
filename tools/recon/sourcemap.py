"""recon_sourcemap — detect .js.map exposure + extract leaked secrets."""
import re, json
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, safe_get, web_url

router = APIRouter()

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Live Secret"),
    (r"sk-ant-api03-[a-zA-Z0-9_\-]{30,}", "Anthropic API Key"),
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,}", "Slack Token"),
]


@router.post("/api/recon/sourcemap")
async def recon_sourcemap(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, maps_found, secrets_found = [], [], []
    r = safe_get(base, req=req)
    if r is None:
        return {"ok": True, "vulnerable": False, "skipped_reason": "Could not reach target"}
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js)["\']', r.text or "", re.I):
        h = m.group(1)
        if h.startswith("http"): js_urls.add(h)
        elif h.startswith("/"): js_urls.add(base + h)
    js_urls = list(js_urls)[:25]
    for p in ["/main.js", "/app.js", "/bundle.js", "/static/js/main.js"]:
        js_urls.append(base + p)
    for js_url in js_urls:
        map_url = js_url + ".map"
        rm = safe_get(map_url, req=req)
        if rm is None or rm.status_code != 200 or len(rm.content) < 100:
            continue
        try:
            data = json.loads(rm.text)
            sources = data.get("sources", [])
            sources_content = data.get("sourcesContent", [])
        except Exception:
            continue
        if not sources:
            continue
        maps_found.append({"url": map_url, "size": len(rm.content),
                           "sources_count": len(sources),
                           "sample_sources": sources[:5]})
        for i, sc in enumerate(sources_content[:50]):
            if not sc: continue
            for pat, label in SECRET_PATTERNS:
                for sm in re.finditer(pat, str(sc)[:50000]):
                    secrets_found.append({"type": label,
                        "value_preview": sm.group(0)[:30] + "...",
                        "source_file": sources[i] if i < len(sources) else "?",
                        "map_url": map_url})
        findings.append({"title": f"JavaScript source map exposed: {map_url}",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-540", "owasp": "A05:2021",
            "evidence": f"Source map at {map_url} contains {len(sources)} original sources",
            "remediation": "Strip .map files from production. Set webpack devtool: false."})
    seen = set()
    for s in secrets_found:
        k = (s["type"], s["value_preview"])
        if k in seen: continue
        seen.add(k)
        findings.append({"title": f"Hardcoded {s['type']} leaked via source map",
            "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"Found {s['type']} in {s['source_file']}",
            "remediation": f"Rotate the leaked {s['type']} IMMEDIATELY. Use env vars."})
    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "maps_found": maps_found, "secrets_found": secrets_found[:30],
            "total_maps": len(maps_found), "total_secrets": len(seen),
            "engine": f"source map probe + {len(SECRET_PATTERNS)}-pattern secret scanner"}


def register(app):
    app.include_router(router)
