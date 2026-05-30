"""DB server CIS hardening - advisory (access-gated). VL-FORGE Vuln tier11_cis.
Requires host OS / platform admin access; for an external URL scan it cleanly SKIPS (no false positive).
Canonical: sqlcheck"""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host
from tools._framework import run_scanner

router = APIRouter()


async def gather(ctx):
    ctx.state["skipped_reason"] = ("mysql_postgres_cis: requires host OS / platform admin access - not applicable to an "
                                   "external URL scan. Canonical check: sqlcheck")


FINDING_RULES = []
INTEL_FIELDS = []


@router.post("/api/vuln/mysql_postgres_cis")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="mysql_postgres_cis",
                             gather_func=gather, finding_rules=FINDING_RULES, intel_fields=INTEL_FIELDS)


def register(app):
    app.include_router(router)
