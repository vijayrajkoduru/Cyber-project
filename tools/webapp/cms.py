"""CMS detection at /api/scan/cms — wraps techstack with CMS focus."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, standard_response

router = APIRouter()

_KNOWN_CMS = ["WordPress", "Drupal", "Joomla", "Magento", "Shopify",
              "Ghost", "TYPO3", "Wix", "Squarespace", "Webflow", "Hugo",
              "Jekyll", "Gatsby", "Tilda", "Strikingly"]


@router.post("/api/scan/cms")
async def scan_cms(req: ScanRequest, payload=Depends(verify_scan_quota)):
    from tools.recon.techstack import scan_techstack
    ts = await scan_techstack(req, payload)
    detected_techs = ts.get("raw_data", {}).get("techstack", {}).get("detected", [])
    cms_techs = [t for t in detected_techs if t.get("name") in _KNOWN_CMS]
    if not cms_techs:
        return standard_response(
            tool="cms", target=req.target, findings=[],
            tests_performed=ts.get("tests_performed", 1),
            vulnerable=False,
            skipped_reason="No CMS detected on target",
            raw_data={"cms": {"detected": [], "all_techs": detected_techs}},
        )
    cms_findings = [f for f in ts.get("findings", [])
                    if any(cms in f.get("detail", "") for cms in _KNOWN_CMS)]
    return standard_response(
        tool="cms", target=req.target, findings=cms_findings,
        tests_performed=ts.get("tests_performed", 1),
        tests_summary=f"CMS detection via tech-stack: {', '.join(t['name'] for t in cms_techs)}",
        raw_data={"cms": {"detected": cms_techs, "all_techs": detected_techs}},
    )


def register(app):
    app.include_router(router)
