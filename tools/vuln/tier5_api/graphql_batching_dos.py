"""GraphQL batching attack (DoS) - advisory. VL-FORGE Vuln tier5_api (playbook technique).
Cleanly SKIPS on a passive URL scan (no false positive). Method: InQL batch (authorized only)"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._vl_core import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = "graphql_batching_dos: InQL batch (authorized only)"


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/graphql_batching_dos")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="graphql_batching_dos",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
