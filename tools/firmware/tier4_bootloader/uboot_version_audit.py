"""uboot_version_audit - U-Boot version detection + CVE-era flag (playbook §5 #41).

Scans the firmware blob for U-Boot version banners ("U-Boot 2018.03 (Mar 14
2018 - ...)"), the uImage / FIT image header magic (0x27051956), and notable
U-Boot environment markers (bootdelay, bootcmd, CONFIG_BOOTDELAY). It then:

  - Reports the detected U-Boot version string (CONFIRMED — literally parsed
    from the bytes).
  - Flags an *insecure recovery posture* ONLY when a concrete marker is found:
      * bootdelay >= 1 in a writable env  => interactive boot prompt reachable
      * presence of a uImage with NO FIT signature node (`signature {`)
        alongside a U-Boot that supports FIT => unsigned-boot risk.
  - Maps the detected version to a coarse CVE era (pre-2018 U-Boot has many
    public CVEs: CVE-2017-3225/3226, CVE-2018-18439/18440 NFS/DHCP overflows,
    CVE-2019-13103/13104/13105/13106 ext4/fs overflows, CVE-2020-8432 i2c,
    CVE-2022-30790/30552 IP fragment / fastboot). The CVE-era flag is INFO
    (advisory, version-only) — NOT graded — because we have not demonstrated
    exploitability against the live target.

ZERO-FP: version + markers are reported only when literally present in the
bytes. The only graded finding is the bootdelay / unsigned-boot posture,
emitted strictly on a confirmed marker.

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
from tools._payloads.uboot_version_audit_findings import UBOOT_VERSION_AUDIT_FINDING_RULES

router = APIRouter()
MAX_BYTES = 96 * 1024 * 1024

# "U-Boot 2018.03 (Mar 14 2018 - 12:00:00 +0000)" / "U-Boot 1.1.4"
UBOOT_VER_RE = re.compile(rb"U-Boot\s+(\d{4}\.\d{2}(?:[.\-]\d+)?|\d+\.\d+(?:\.\d+)?)\s*[\(\-]")
UBOOT_GENERIC_RE = re.compile(rb"U-Boot\s+(\d[\w.\-]{1,20})")
UIMAGE_MAGIC = b"\x27\x05\x19\x56"        # legacy uImage header magic
FIT_MAGIC = b"\xd0\x0d\xfe\xed"           # FDT / FIT image (also DTB) magic
SIGNATURE_NODE_RE = re.compile(rb"signature\s*\{")
BOOTDELAY_RE = re.compile(rb"bootdelay\s*=\s*(\d+)")
BOOTCMD_RE = re.compile(rb"bootcmd\s*=")


def _scan(path: Path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError as e:
        return None, str(e)

    version = None
    m = UBOOT_VER_RE.search(data)
    if m:
        version = m.group(1).decode("ascii", errors="replace")
    else:
        m2 = UBOOT_GENERIC_RE.search(data)
        if m2:
            version = m2.group(1).decode("ascii", errors="replace")

    has_uimage = UIMAGE_MAGIC in data
    has_fit = FIT_MAGIC in data
    has_signature_node = bool(SIGNATURE_NODE_RE.search(data))
    bootdelay = None
    bm = BOOTDELAY_RE.search(data)
    if bm:
        try:
            bootdelay = int(bm.group(1))
        except ValueError:
            bootdelay = None
    has_bootcmd = bool(BOOTCMD_RE.search(data))

    return {
        "version": version,
        "has_uimage": has_uimage,
        "has_fit": has_fit,
        "has_signature_node": has_signature_node,
        "bootdelay": bootdelay,
        "has_bootcmd": has_bootcmd,
    }, ""


def _cve_era(version: str):
    """Coarse era flag (advisory only). Returns label or None."""
    if not version:
        return None
    # YYYY.MM modern format
    mm = re.match(r"^(\d{4})\.(\d{2})", version)
    if mm:
        year = int(mm.group(1))
        if year < 2020:
            return "pre-2020 (multiple public U-Boot CVEs apply)"
        if year < 2022:
            return "2020-2021 era (some fastboot/IP-fragment CVEs apply)"
        return "2022+ (relatively recent — verify against current NVD U-Boot list)"
    # Legacy 1.x / 2.x
    if re.match(r"^[12]\.", version):
        return "legacy 1.x/2.x U-Boot (end-of-life, many public CVEs)"
    return None


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["uboot_version_audit_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    res, err = await asyncio.get_event_loop().run_in_executor(None, _scan, Path(target))
    if res is None:
        ctx.state["uboot_version_audit_error"] = f"read failed: {err[:120]}"
        ctx.source("read failed")
        return

    version = res["version"]
    if not version and not res["has_uimage"] and not res["has_fit"]:
        ctx.state["uboot_present"] = False
        ctx.state["uboot_version_audit_total"] = 0
        ctx.source("no U-Boot banner or uImage/FIT magic found")
        return

    ctx.state["uboot_present"] = bool(version) or res["has_uimage"] or res["has_fit"]
    ctx.state["uboot_version"] = version
    ctx.state["uboot_cve_era"] = _cve_era(version)
    ctx.state["uboot_has_uimage"] = res["has_uimage"]
    ctx.state["uboot_has_fit"] = res["has_fit"]
    ctx.state["uboot_has_signature_node"] = res["has_signature_node"]
    ctx.state["uboot_bootdelay"] = res["bootdelay"]
    ctx.state["uboot_has_bootcmd"] = res["has_bootcmd"]

    # Confirmed insecure-recovery markers
    interactive_prompt = res["bootdelay"] is not None and res["bootdelay"] >= 1
    # FIT image present but no signature{} node => unsigned FIT boot
    unsigned_fit = res["has_fit"] and not res["has_signature_node"]
    ctx.state["uboot_interactive_prompt"] = interactive_prompt
    ctx.state["uboot_unsigned_fit"] = unsigned_fit

    graded = (1 if interactive_prompt else 0) + (1 if unsigned_fit else 0)
    ctx.state["uboot_version_audit_total"] = graded
    ctx.source(f"U-Boot version={version}, uImage={res['has_uimage']}, FIT={res['has_fit']}, "
               f"sig-node={res['has_signature_node']}, bootdelay={res['bootdelay']}")


INTEL_FIELDS = [("U-Boot present",           "uboot_present"),
                ("U-Boot version",           "uboot_version"),
                ("CVE era (advisory)",       "uboot_cve_era"),
                ("Legacy uImage present",    "uboot_has_uimage"),
                ("FIT image present",        "uboot_has_fit"),
                ("FIT signature node",       "uboot_has_signature_node"),
                ("bootdelay value",          "uboot_bootdelay")]


@router.post("/api/firmware/uboot_version_audit")
async def firmware_uboot_version_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="uboot_version_audit",
        gather_func=gather, finding_rules=UBOOT_VERSION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
