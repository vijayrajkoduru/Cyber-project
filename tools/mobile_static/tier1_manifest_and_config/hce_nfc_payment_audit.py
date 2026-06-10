"""hce_nfc_payment_audit — Host Card Emulation / NFC payment config audit.

Apps with NFC HCE (Host Card Emulation) effectively become payment cards.
Risky manifest combinations:
  - HOST_APDU_SERVICE without proper aid-group filter (any card AID accepted)
  - NFC permission + READ_PHONE_STATE (de-anonymization)
  - NFC + READ_EXTERNAL_STORAGE on Android < 10 (eavesdrop on tap)

MASVS-PAYMENT-3.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.hce_nfc_payment_audit_findings import \
    HCE_NFC_PAYMENT_AUDIT_FINDING_RULES

router = APIRouter()
NS_A = "{http://schemas.android.com/apk/res/android}"


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["hce_nfc_payment_audit_total"] = 0
        ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["hce_nfc_payment_audit_error"] = str(e); return

    manifest = unpacked / "AndroidManifest.xml"
    if not manifest.is_file():
        ctx.state["hce_nfc_payment_audit_total"] = 0
        ctx.source("not-android"); return
    try: root = ET.parse(str(manifest)).getroot()
    except ET.ParseError:
        ctx.state["hce_nfc_payment_audit_error"] = "manifest-not-parseable"; return

    perms = [p.get(f"{NS_A}name") or "" for p in root.findall("uses-permission")]
    has_nfc = "android.permission.NFC" in perms

    hce_services = []
    app = root.find("application")
    if app is not None:
        for svc in app.findall("service"):
            perm = svc.get(f"{NS_A}permission") or ""
            if perm == "android.permission.BIND_NFC_SERVICE":
                hce_services.append({
                    "name": svc.get(f"{NS_A}name") or "?",
                    "exported": svc.get(f"{NS_A}exported"),
                })

    ctx.state["has_nfc_perm"] = has_nfc
    ctx.state["hce_services"] = hce_services
    ctx.state["hce_nfc_payment_audit_total"] = len(hce_services) + (1 if has_nfc else 0)
    ctx.source(f"NFC={has_nfc}, HCE services={len(hce_services)}")


INTEL_FIELDS = [
    ("HCE services",     "hce_services"),
    ("NFC permission",   "has_nfc_perm"),
]


@router.post("/api/mobile_static/hce_nfc_payment_audit")
async def mobile_static_hce_nfc_payment_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="hce_nfc_payment_audit", gather_func=gather,
        finding_rules=HCE_NFC_PAYMENT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
