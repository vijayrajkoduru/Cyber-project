"""LLM02 Sensitive Information Disclosure - advisory. VL-FORGE Vuln tier14_llm (OWASP LLM Top 10 2025).
Requires an exposed/authorized LLM endpoint to probe (interactive); on an external URL scan it cleanly SKIPS (no false positive).
Canonical: garak --probes leakreplay"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("llm02_sensitive_info_disclosure: requires an exposed/authorized LLM endpoint to probe (interactive) - not applicable to a passive URL scan. "
                                   "Canonical check: garak --probes leakreplay")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/llm02_sensitive_info_disclosure")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="llm02_sensitive_info_disclosure",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
