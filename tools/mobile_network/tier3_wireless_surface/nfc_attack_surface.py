"""nfc_attack_surface — detect NFC usage. NFC = card-emulation (HCE),
tag-reading, P2P. NFC payment apps, transit cards, access-control fobs
all use NFC. Auditing the surface tells the customer whether to bring
Proxmark / Flipper Zero / Android-NFC reader to the pentest."""
from __future__ import annotations
from pathlib import Path
from xml.etree import ElementTree as ET

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.nfc_attack_surface_findings import NFC_ATTACK_SURFACE_FINDING_RULES

router = APIRouter()

NS = {"a": "http://schemas.android.com/apk/res/android"}
NFC_PERMS = (
    "android.permission.NFC",
    "android.permission.NFC_TRANSACTION_EVENT",
    "android.permission.NFC_PREFERRED_PAYMENT_INFO",
    "android.permission.BIND_NFC_SERVICE",
)
NFC_API_MARKERS = (
    "NfcAdapter", "NdefMessage", "NdefRecord",
    "IsoDep", "MifareClassic", "MifareUltralight",
    "Ndef", "NfcA", "NfcB", "NfcF", "NfcV",
    "HostApduService", "OffHostApduService",
    "ApduServiceInfo", "CardEmulation",
)
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["nfc_attack_surface_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["nfc_attack_surface_error"] = str(e)
        return

    perms_found = []
    has_hce_service = False
    manifest = unpacked / "AndroidManifest.xml"
    if manifest.is_file():
        try:
            root = ET.parse(str(manifest)).getroot()
            for p in root.findall("uses-permission"):
                name = p.get(f"{{{NS['a']}}}name", "")
                if name in NFC_PERMS:
                    perms_found.append(name)
            # Check for HostApduService declarations
            app = root.find("application")
            if app is not None:
                for svc in app.findall("service"):
                    perm = svc.get(f"{{{NS['a']}}}permission", "")
                    if "BIND_NFC_SERVICE" in perm:
                        has_hce_service = True
        except ET.ParseError:
            pass

    api_hits = {}
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        for marker in NFC_API_MARKERS:
            if marker in txt:
                api_hits.setdefault(marker, [])
                if p.name not in api_hits[marker] and len(api_hits[marker]) < 5:
                    api_hits[marker].append(p.name)
                break

    ctx.state["nfc_permissions"] = perms_found
    ctx.state["nfc_api_hits"] = api_hits
    ctx.state["nfc_hce_service_declared"] = has_hce_service
    ctx.state["files_scanned"] = files_scanned
    ctx.state["nfc_attack_surface_total"] = (
        (1 if perms_found else 0) + (1 if api_hits else 0) + (1 if has_hce_service else 0))
    ctx.source(f"manifest + {files_scanned} smali files")


INTEL_FIELDS = [
    ("NFC permissions", "nfc_permissions"),
    ("NFC API usage", "nfc_api_hits"),
    ("HostApduService (card emulation) declared", "nfc_hce_service_declared"),
]


@router.post("/api/mobile_network/nfc_attack_surface")
async def mobile_network_nfc_attack_surface(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="nfc_attack_surface",
        gather_func=gather,
        finding_rules=NFC_ATTACK_SURFACE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
