"""proxy_bypass_audit — detect code that intentionally disables / detects
proxies, blocking Burp / mitmproxy. Common patterns: querying
System.getProperty("https.proxyHost"), explicit Proxy.NO_PROXY, OkHttp
.proxy(Proxy.NO_PROXY). These break the customer's MITM workflow."""
from __future__ import annotations
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.proxy_bypass_audit_findings import PROXY_BYPASS_AUDIT_FINDING_RULES

router = APIRouter()

PROXY_MARKERS = {
    "System.getProperty proxy query":  ['"https.proxyHost"', '"http.proxyHost"', '"socksProxyHost"'],
    "Proxy.NO_PROXY OkHttp config":    ["Proxy$Type;->DIRECT", "Proxy.NO_PROXY", "->NO_PROXY"],
    "ProxySelector setDefault":        ["ProxySelector.setDefault", "java/net/ProxySelector"],
    "NetworkInfo proxy detection":     ["ConnectivityManager", "getProxyHost"],
    "OkHttp .proxy() explicit":        [".proxy(", "OkHttpClient$Builder;->proxy"],
}
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["proxy_bypass_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["proxy_bypass_audit_error"] = str(e)
        return

    proxy_defenses = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for label, markers in PROXY_MARKERS.items():
            for m in markers:
                if m in txt:
                    proxy_defenses.setdefault(label, [])
                    if p.name not in proxy_defenses[label] and len(proxy_defenses[label]) < 5:
                        proxy_defenses[label].append(p.name)
                    break

    ctx.state["proxy_defenses"] = proxy_defenses
    ctx.state["files_scanned"] = files_scanned
    ctx.state["proxy_bypass_audit_total"] = len(proxy_defenses)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("Proxy-detection / bypass code patterns", "proxy_defenses"),
]


@router.post("/api/mobile_network/proxy_bypass_audit")
async def mobile_network_proxy_bypass_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="proxy_bypass_audit",
        gather_func=gather,
        finding_rules=PROXY_BYPASS_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
