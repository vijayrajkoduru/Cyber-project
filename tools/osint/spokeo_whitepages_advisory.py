"""spokeo_whitepages_advisory — Spokeo / WhitePages / BeenVerified people-search advisory."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()


def _do_scan(req):
    target = (req.target or "").strip()
    return standard_response(
        tool="spokeo_whitepages_advisory", target=req.target,
        findings=[wrap_finding(
            f"Spokeo / WhitePages / BeenVerified people-search advisory for '{target}'",
            severity="POSITIVE", cwe="CWE-1395",
            remediation="People-search APIs are paid ($20-$80/mo per user). "
                        "Manual search URLs: "
                        f"spokeo.com/{target.replace(' ', '-')} | "
                        f"whitepages.com/name/{target.replace(' ', '-')} | "
                        f"beenverified.com/people/{target.replace(' ', '-')}. "
                        "Returns PII (address, phone, age, family) — USE ONLY "
                        "for authorized engagements.",
            evidence_marker=f"target: {target} | advisory + manual URLs")],
        tests_performed=0, vulnerable=False, tests_summary="advisory")


@router.post("/api/osint/spokeo_whitepages_advisory")
@vl_verify()
async def scan_spokeo_whitepages_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=5)


def register(app): app.include_router(router)
