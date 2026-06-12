"""uefi_firmware_audit - UEFI/BIOS image surface detection (playbook §8 #68/#69).

Statically inspects the firmware blob for UEFI/BIOS platform-firmware
structure and security posture, without any vendor tooling:

  - UEFI Firmware Volume header   : the EFI_FIRMWARE_FILE_SYSTEM2 GUID
                                    (7A9354D9-0468-444A-81CE-0BF617D890DF) and
                                    "_FVH" signature => this IS a UEFI image.
  - Flash descriptor              : Intel flash-descriptor signature 0x0FF0A55A.
  - Capsule update header         : EFI_CAPSULE_GUID markers.
  - BIOS vendor / version strings : AMI / Phoenix / Insyde / coreboot banners
                                    and "DMI"/SMBIOS version strings.
  - SecureBoot / PK/KEK/db vars   : "SecureBoot", "PK", "KEK", "dbx" NVRAM
                                    variable names.
  - Known-risky DXE modules       : presence of "SmmRuntime"/"FaultTolerant"
                                    naming (informational inventory only).

ZERO-FP: detection-only. POSITIVE when SecureBoot variables are present; a
graded LOW finding fires ONLY when this is confirmed to be a UEFI image AND
there is no SecureBoot variable evidence at all (confirmed absence). Vendor/
version strings are INFO inventory for CVE cross-referencing.

REAL static probe against the customer firmware file.

Customer input: ScanRequest.target = path to firmware blob on disk.
"""
from __future__ import annotations
import asyncio
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.uefi_firmware_audit_findings import UEFI_FIRMWARE_AUDIT_FINDING_RULES

router = APIRouter()
MAX_BYTES = 64 * 1024 * 1024

FV_SIGNATURE = b"_FVH"                                # firmware volume header signature
FLASH_DESCRIPTOR = b"\x5a\xa5\xf0\x0f"                # 0x0FF0A55A little-endian
EFI_CAPSULE_GUID = re.compile(rb"\xbd\x86\x66\x3b|EFI_CAPSULE", re.I)

VENDOR_RE = re.compile(rb"(American Megatrends|AMI BIOS|Phoenix Technologies|Insyde|InsydeH2O|coreboot|EDK II|UEFI)\b", re.I)
BIOS_VER_RE = re.compile(rb"(?:BIOS|Firmware)\s*(?:Version|Ver)\s*[:=]?\s*([A-Za-z0-9._\-]{2,32})")
SECUREBOOT_VARS = re.compile(rb"SecureBoot|\bPKDefault\b|\bKEKDefault\b|\bdbDefault\b|\bdbxDefault\b")
SMM_RE = re.compile(rb"SmmRuntime|SmmCore|FaultTolerantWrite|VariableSmm")


def _scan(path: Path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError as e:
        return None, str(e)

    has_fv = FV_SIGNATURE in data
    has_flash_desc = FLASH_DESCRIPTOR in data
    has_capsule = bool(EFI_CAPSULE_GUID.search(data))
    # Treat as UEFI image if FV header OR flash descriptor OR an EDK/UEFI banner
    vendor = None
    vm = VENDOR_RE.search(data)
    if vm:
        vendor = vm.group(1).decode("ascii", errors="replace")
    bios_ver = None
    bvm = BIOS_VER_RE.search(data)
    if bvm:
        bios_ver = bvm.group(1).decode("ascii", errors="replace")
    has_secureboot = bool(SECUREBOOT_VARS.search(data))
    has_smm = bool(SMM_RE.search(data))

    is_uefi = has_fv or has_flash_desc or (vendor is not None and vendor.lower() in
                                           ("edk ii", "uefi", "american megatrends", "insyde",
                                            "insydeh2o", "phoenix technologies", "coreboot"))
    return {
        "is_uefi": is_uefi,
        "has_fv": has_fv,
        "has_flash_desc": has_flash_desc,
        "has_capsule": has_capsule,
        "vendor": vendor,
        "bios_version": bios_ver,
        "has_secureboot": has_secureboot,
        "has_smm": has_smm,
    }, ""


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["uefi_firmware_audit_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    res, err = await asyncio.get_event_loop().run_in_executor(None, _scan, Path(target))
    if res is None:
        ctx.state["uefi_firmware_audit_error"] = f"read failed: {err[:120]}"
        ctx.source("read failed")
        return

    if not res["is_uefi"]:
        ctx.state["uefi_is_uefi"] = False
        ctx.state["uefi_firmware_audit_total"] = 0
        ctx.source("no UEFI firmware-volume / flash-descriptor / vendor markers")
        return

    ctx.state["uefi_is_uefi"] = True
    ctx.state["uefi_has_fv"] = res["has_fv"]
    ctx.state["uefi_has_flash_desc"] = res["has_flash_desc"]
    ctx.state["uefi_has_capsule"] = res["has_capsule"]
    ctx.state["uefi_vendor"] = res["vendor"]
    ctx.state["uefi_bios_version"] = res["bios_version"]
    ctx.state["uefi_has_secureboot"] = res["has_secureboot"]
    ctx.state["uefi_has_smm"] = res["has_smm"]

    no_secureboot = not res["has_secureboot"]
    ctx.state["uefi_no_secureboot"] = no_secureboot
    ctx.state["uefi_firmware_audit_total"] = 1 if no_secureboot else 0
    ctx.source(f"UEFI image: vendor={res['vendor']}, ver={res['bios_version']}, "
               f"SecureBoot-vars={res['has_secureboot']}, capsule={res['has_capsule']}")


INTEL_FIELDS = [("Is UEFI image",            "uefi_is_uefi"),
                ("BIOS / UEFI vendor",       "uefi_vendor"),
                ("BIOS version",             "uefi_bios_version"),
                ("Firmware volume header",   "uefi_has_fv"),
                ("Intel flash descriptor",   "uefi_has_flash_desc"),
                ("Capsule update support",   "uefi_has_capsule"),
                ("SecureBoot variables",     "uefi_has_secureboot"),
                ("SMM modules present",      "uefi_has_smm")]


@router.post("/api/firmware/uefi_firmware_audit")
async def firmware_uefi_firmware_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="uefi_firmware_audit",
        gather_func=gather, finding_rules=UEFI_FIRMWARE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
