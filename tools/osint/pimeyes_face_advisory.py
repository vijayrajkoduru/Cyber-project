"""pimeyes_face_advisory — PimEyes reverse-face-search advisory."""
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()


def _do_scan(req):
    target = (req.target or "").strip()
    return standard_response(
        tool="pimeyes_face_advisory", target=req.target,
        findings=[wrap_finding(
            "PimEyes face-search advisory",
            severity="POSITIVE", cwe="CWE-1395",
            remediation="PimEyes ($14.99/mo) reverse-image-searches faces across "
                        "billions of public images. For ethical use only: track "
                        "victims' exposure to stalkers, journalism, missing-persons. "
                        "Free alternatives: Yandex reverse image search (in our "
                        "reverse_image_search scanner). Submit face image at "
                        "pimeyes.com — they show first 3 matches free.",
            evidence_marker=f"target: {target} | manual upload required")],
        tests_performed=0, vulnerable=False, tests_summary="advisory")


@router.post("/api/osint/pimeyes_face_advisory")
@vl_verify()
async def scan_pimeyes_face_advisory(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await asyncio.wait_for(asyncio.to_thread(_do_scan, req), timeout=5)


def register(app): app.include_router(router)
