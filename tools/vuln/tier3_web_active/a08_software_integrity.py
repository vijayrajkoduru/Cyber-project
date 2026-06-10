"""A08 Software & Data Integrity - passive SRI absence check. Self-contained.
Strategy: parse <script src=...> / <link href=...> with external origins, check for
integrity= attribute (SRI). Missing SRI on 3rd-party assets = supply chain risk.

VL-VERIFY: this scanner inspects tag attributes on the homepage, so it isn't
directly SPA-FP prone. We stamp spa_catchall onto state so the report shows
the SPA context, useful for downstream interpretation.
"""
import re
from urllib.parse import urlparse
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools.vuln._vuln_common import probe_url_async, detect_spa_catchall

router = APIRouter()


async def gather(ctx):
    host = str(ctx.host)
    base_url, base = await probe_url_async(host, "/")
    if not base:
        ctx.state["tested"] = 0
        ctx.state["skipped_reason"] = "Target unreachable"
        return
    ctx.source("http")
    ctx.state["tested"] = 1
    spa = await detect_spa_catchall(base_url)
    ctx.state["spa_catchall"] = spa.get("is_spa", False)
    body = base.get("body") or ""
    base_host = urlparse(base_url).netloc.lower()
    # Find all <script src="..."> and <link rel="stylesheet" href="..."> tags
    tag_re = re.compile(r"""<(?:script|link)\s+[^>]*?(?:src|href)\s*=\s*["']([^"']+)["'][^>]*>""", re.IGNORECASE)
    sri_re = re.compile(r"""integrity\s*=\s*["'][^"']+["']""", re.IGNORECASE)
    third_party = []
    missing_sri = []
    for m in tag_re.finditer(body):
        url = m.group(1)
        full_tag = m.group(0)
        parsed = urlparse(url)
        # Only check absolute URLs with external host
        if not parsed.netloc:
            continue
        if parsed.netloc.lower() == base_host:
            continue
        third_party.append(parsed.netloc)
        if not sri_re.search(full_tag):
            missing_sri.append(url)
    ctx.state["third_party_assets"] = list(set(third_party))[:20]
    ctx.state["missing_sri"] = missing_sri[:20]


def _r_sri(s):
    missing = s.get("missing_sri") or []
    if not missing:
        return None
    sev = "HIGH" if len(missing) >= 3 else "MEDIUM"
    return {"name": f"{len(missing)} third-party asset(s) loaded without Subresource Integrity",
            "severity": sev, "cvss": 6.5 if sev == "HIGH" else 4.3, "cwe": "CWE-353",
            "evidence": "; ".join(missing[:5]) + (f" (+{len(missing)-5} more)" if len(missing) > 5 else ""),
            "remediation": "Add integrity=\"sha384-...\" + crossorigin=\"anonymous\" to all external <script>/<link> tags."}


FINDING_RULES = [_r_sri]
INTEL_FIELDS = [("3rd-party origins", "third_party_assets"), ("Missing SRI", "missing_sri")]


@router.post("/api/vuln/a08_software_integrity")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="a08_software_integrity",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
