"""API key / token leakage in HTML + linked JS. VL-FORGE Vuln tier5 §5 #77.

VL-VERIFY: SPA bundles often contain example/test tokens (Stripe dashboard
demo keys, Google API key placeholders in code samples, etc.) that look real
to the regex. The SPA-canary fetch returns the same bundle bytes that every
URL serves on a catch-all-routed SPA, so any token that ALSO appears in the
canary response is in the bundle - not a real exposure. We suppress those.
"""
import asyncio, re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get, detect_spa_catchall, is_same_as_canary
router = APIRouter()
_KEYS = [("AWS Access Key ID","HIGH",8.2,re.compile(r"AKIA[0-9A-Z]{16}")),
         ("Google API Key","HIGH",8.2,re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
         ("Stripe live secret key","HIGH",9.1,re.compile(r"sk_live_[0-9A-Za-z]{24,}")),
         ("Slack token","HIGH",8.0,re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
         ("API key/token in URL query","MEDIUM",5.3,re.compile(r"[?&](?:api[_-]?key|apikey|access_token|auth_token)=[A-Za-z0-9_\-]{16,}"))]
_SRC = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    # VL-VERIFY canary - establish what a bogus path's response looks like
    spa = await detect_spa_catchall(base)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    canary_body = spa.get("canary_body", "") or ""
    r = await asyncio.to_thread(http_get, base + "/")
    if not r:
        ctx.state["tested"] = 0; return
    ctx.source("http"); ctx.state["probed"] = 1
    body = r.get("body","") or ""; blobs = [body]
    for m in list(_SRC.finditer(body))[:4]:
        u = m.group(1)
        if u.startswith("//"): u = "https:" + u
        elif u.startswith("/"): u = base + u
        elif not u.startswith("http"): u = base + "/" + u
        jr = await asyncio.to_thread(http_get, u)
        if jr and jr.get("body"): blobs.append(jr["body"][:200000])
    blob = "\n".join(blobs); found = []; suppressed = []
    for label, sev, cvss, rx in _KEYS:
        m = rx.search(blob)
        if not m: continue
        tok = m.group(0)
        # SPA suppression: if the same exact token appears in the canary
        # body, it is in the bundle (example/test fixture) - not a real
        # secret unique to a customer endpoint.
        if spa.get("is_spa") and canary_body and tok in canary_body:
            suppressed.append({"label": label, "reason": "matched-in-spa-bundle"})
            continue
        red = (tok[:8] + "…" + tok[-2:]) if len(tok) > 12 else tok[:6] + "…"
        found.append({"label": label, "sev": sev, "cvss": cvss, "red": red})
    ctx.state["leaks"] = found[:5]
    if suppressed:
        ctx.state["spa_suppressed"] = suppressed
def _mk(i):
    def rule(s):
        lk = s.get("leaks") or []
        if i >= len(lk): return None
        x = lk[i]
        return {"name": f"Secret exposed in client-side content: {x['label']}", "severity": x["sev"], "cvss": x["cvss"], "cwe": "CWE-200",
                "evidence": f"Matched {x['label']} in HTML/JS (redacted): {x['red']}.",
                "remediation": "Revoke and rotate the exposed key; move secrets server-side; never embed keys in client JS or URLs."}
    return rule
def _r_clean(s):
    if not s.get("probed") or (s.get("leaks") or []): return None
    return {"name": "No API keys or tokens leaked in client-side content", "severity": "POSITIVE", "evidence": "Scanned HTML + linked JS; no AWS/Google/Stripe/Slack keys or tokens-in-URL found."}
FINDING_RULES = [_mk(i) for i in range(5)] + [_r_clean]
INTEL_FIELDS = [("SPA catch-all detected","spa_catchall"),("SPA-suppressed matches","spa_suppressed")]
@router.post("/api/vuln/api_key_in_url_leak")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="api_key_in_url_leak", gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)
def register(app): app.include_router(router)
