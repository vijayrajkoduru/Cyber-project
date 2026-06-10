"""npm/yarn/pnpm dependency CVE audit - advisory (access-gated). VL-FORGE Vuln tier7_sca.
Requires project source tree / dependency manifests; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: npm audit --json"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner
from tools._vl_core.verify import vl_verify

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("npm_yarn_audit: requires project source tree / dependency manifests - not applicable to an "
                                   "external URL scan. Canonical check: npm audit --json")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/npm_yarn_audit")
@vl_verify()
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="npm_yarn_audit",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
