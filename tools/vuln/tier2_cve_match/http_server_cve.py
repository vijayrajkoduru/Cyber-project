"""HTTP server / X-Powered-By version disclosure -> NVD CVE association.
VL-FORGE Vuln tier2 - playbook §2 #15/#16/#18."""
import asyncio
import re
import urllib.parse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import http_get, http_json
from tools.vuln._cve_intel import cwe_meta, remediation_for
from tools._vl_core.verify import vl_verify

router = APIRouter()
_VER = re.compile(r"([A-Za-z][A-Za-z0-9_+.-]*?)[/ ]v?(\d+\.\d+(?:\.\d+)?)")


def _enrich(finding):
    """Advisory enrichment of an EXISTING finding: append the human-readable
    CWE name to evidence, and append curated remediation guidance for the
    finding's CWE when available. No new finding, no severity change - text
    only."""
    cwe = finding.get("cwe")
    meta = cwe_meta(cwe)
    if meta.get("name"):
        finding["evidence"] = f"{finding.get('evidence', '')} [{cwe}: {meta['name']}]".strip()
    extra = remediation_for(cwe)
    if extra and extra not in (finding.get("remediation") or ""):
        finding["remediation"] = f"{finding.get('remediation', '')} {extra}".strip()
    return finding


def _nvd_cves(product, version):
    q = urllib.parse.quote(f"{product} {version}")
    data = http_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={q}&resultsPerPage=20")
    if not data:
        return []
    out = []
    for v in (data.get("vulnerabilities") or []):
        c = v.get("cve", {})
        score = 0.0
        for metric in (c.get("metrics", {}) or {}).values():
            for item in (metric or []):
                score = max(score, float((item.get("cvssData", {}) or {}).get("baseScore", 0) or 0))
        out.append((c.get("id", ""), score))
    return out


async def gather(ctx):
    base = web_url(str(ctx.host)).rstrip("/")
    r = await asyncio.to_thread(http_get, base + "/")
    if not r:
        ctx.state["tested"] = 0
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    hdrs = r.get("headers", {})
    banners = [hdrs[h] for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator") if hdrs.get(h)]
    ctx.state["banners"] = banners
    products = []
    for b in banners:
        for m in _VER.finditer(b):
            products.append((m.group(1), m.group(2)))
    ctx.state["products"] = products[:4]
    hits = []
    for prod, ver in products[:3]:
        cves = await asyncio.to_thread(_nvd_cves, prod, ver)
        high = [(cid, sc) for cid, sc in cves if sc >= 7.0]
        if high:
            hits.append({"product": f"{prod} {ver}", "count": len(high),
                         "top": sorted(high, key=lambda x: -x[1])[:3]})
    ctx.state["cve_hits"] = hits


def _r_cve(s):
    hits = s.get("cve_hits") or []
    if not hits:
        return None
    h = hits[0]
    top = ", ".join(f"{c} ({sc})" for c, sc in h["top"])
    return _enrich({"name": f"Server '{h['product']}' maps to {h['count']} high-severity CVE(s) (version-based)",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-1395",
            "evidence": f"NVD: {top}. Version-inferred - confirm patch level (backports may apply).",
            "remediation": "Upgrade to the latest patched release; suppress version banners (server_tokens off)."})


def _r_disclosure(s):
    b = s.get("banners") or []
    if not b or (s.get("cve_hits") or []) or not (s.get("products") or []):
        return None
    return _enrich({"name": f"Server version disclosed: {b[0][:80]}", "severity": "LOW", "cwe": "CWE-200",
            "evidence": f"Headers: {', '.join(b)[:160]}",
            "remediation": "Suppress version banners (nginx: server_tokens off; remove X-Powered-By)."})


def _r_clean(s):
    if (s.get("tested") or 0) < 1 or (s.get("products") or []):
        return None
    return {"name": "No server version disclosed", "severity": "POSITIVE",
            "evidence": f"Banners: {', '.join(s.get('banners') or []) or 'none'} - no version string exposed."}


FINDING_RULES = [_r_cve, _r_disclosure, _r_clean]
INTEL_FIELDS = [("Server banners", "banners")]


@router.post("/api/vuln/http_server_cve")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="http_server_cve",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
