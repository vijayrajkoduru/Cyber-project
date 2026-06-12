"""bmc_component_audit - BMC / iLO / iDRAC component fingerprint (playbook §8 #70).

Statically inspects the firmware blob for Baseboard Management Controller
(BMC) software components and their versions, since BMC firmware (HPE iLO,
Dell iDRAC, OpenBMC, AMI MegaRAC, Lenovo XCC) is a frequent source of
critical remote vulnerabilities (e.g. the MegaRAC "BMC&C" / CVE-2023-34329
auth bypass family, iLO CVE-2017-12542, IPMI cipher-0).

Detects:
  - BMC platform banners      : iLO / iDRAC / OpenBMC / MegaRAC / IPMI / XCC /
                                "Aspeed AST2400/2500/2600" SoC strings.
  - Component versions         : u-boot / linux kernel / lighttpd / busybox /
                                dropbear / openssl version strings (for CVE
                                cross-referencing).
  - IPMI / Redfish surface     : "ipmi", "/redfish/v1", "RAKP" markers.
  - Default-cred markers       : the classic "ADMIN/ADMIN", "root/calvin"
                                (iDRAC), "Administrator" default account hints
                                in plaintext config.

ZERO-FP: all output is detection-only. Versions/markers are reported as INFO
inventory for CVE matching. A graded LOW finding fires ONLY when a literal
known default-credential marker string (e.g. "root:calvin", "ADMIN:ADMIN")
is found in the bytes — a confirmed presence, not an inference.

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
from tools._payloads.bmc_component_audit_findings import BMC_COMPONENT_AUDIT_FINDING_RULES

router = APIRouter()
MAX_BYTES = 96 * 1024 * 1024

PLATFORM_RE = re.compile(
    rb"(Integrated Lights-Out|iLO[\s\-]?[2-6]?|iDRAC[\s\-]?[6-9]?|OpenBMC|MegaRAC|AMI[\s\-]?BMC|"
    rb"XClarity|Aspeed|AST2[456]00|IPMI|Redfish|Supermicro BMC)", re.I)

# Component version strings (component -> regex capturing version)
COMPONENTS = [
    ("linux_kernel", re.compile(rb"Linux version (\d+\.\d+[\w.\-]*)")),
    ("busybox",      re.compile(rb"BusyBox v(\d+\.\d+\.\d+)")),
    ("dropbear",     re.compile(rb"[Dd]ropbear[ _v]*(\d{4}\.\d+|\d+\.\d+)")),
    ("openssl",      re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)")),
    ("lighttpd",     re.compile(rb"lighttpd[/ ](\d+\.\d+\.\d+)")),
    ("u_boot",       re.compile(rb"U-Boot (\d{4}\.\d{2}|\d+\.\d+\.\d+)")),
]

SURFACE_RE = re.compile(rb"/redfish/v1|\bRAKP\b|ipmitool|\bipmi\b", re.I)

# Literal default-cred markers (confirmed presence => graded LOW)
DEFAULT_CRED_MARKERS = [
    (rb"root\s*[:=]\s*calvin", "iDRAC default root:calvin"),
    (rb"ADMIN\s*[:=]\s*ADMIN", "Supermicro/AMI default ADMIN:ADMIN"),
    (rb"admin\s*[:=]\s*admin\b", "default admin:admin"),
    (rb"Administrator\s*[:=]\s*password", "default Administrator:password"),
    (rb"sysadmin\s*[:=]\s*superuser", "default sysadmin:superuser"),
]


def _scan(path: Path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError as e:
        return None, str(e)

    platforms = []
    seen_p = set()
    for m in PLATFORM_RE.finditer(data):
        v = m.group(1).decode("ascii", errors="replace").strip()
        kl = v.lower()
        if kl in seen_p:
            continue
        seen_p.add(kl)
        platforms.append(v)
        if len(platforms) >= 12:
            break

    components = {}
    for name, pat in COMPONENTS:
        m = pat.search(data)
        if m:
            components[name] = m.group(1).decode("ascii", errors="replace")

    has_mgmt_surface = bool(SURFACE_RE.search(data))

    default_creds = []
    for pat, label in DEFAULT_CRED_MARKERS:
        if re.search(pat, data):
            default_creds.append(label)

    is_bmc = bool(platforms) or has_mgmt_surface
    return {
        "is_bmc": is_bmc,
        "platforms": platforms,
        "components": components,
        "has_mgmt_surface": has_mgmt_surface,
        "default_creds": default_creds,
    }, ""


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["bmc_component_audit_total"] = 0
        ctx.source("firmware file not found at target path")
        return

    res, err = await asyncio.get_event_loop().run_in_executor(None, _scan, Path(target))
    if res is None:
        ctx.state["bmc_component_audit_error"] = f"read failed: {err[:120]}"
        ctx.source("read failed")
        return

    if not res["is_bmc"]:
        ctx.state["bmc_is_bmc"] = False
        ctx.state["bmc_component_audit_total"] = 0
        ctx.source("no BMC/IPMI/Redfish platform markers found")
        return

    ctx.state["bmc_is_bmc"] = True
    ctx.state["bmc_platforms"] = res["platforms"]
    ctx.state["bmc_components"] = res["components"]
    ctx.state["bmc_has_mgmt_surface"] = res["has_mgmt_surface"]
    ctx.state["bmc_default_creds"] = res["default_creds"]
    ctx.state["bmc_component_audit_total"] = len(res["default_creds"])
    ctx.source(f"BMC platforms={res['platforms'][:3]}, components={list(res['components'])}, "
               f"default-creds={len(res['default_creds'])}")


INTEL_FIELDS = [("Is BMC firmware",        "bmc_is_bmc"),
                ("BMC platform banners",   "bmc_platforms"),
                ("Component versions",     "bmc_components"),
                ("IPMI/Redfish surface",   "bmc_has_mgmt_surface"),
                ("Default-cred markers",   "bmc_default_creds")]


@router.post("/api/firmware/bmc_component_audit")
async def firmware_bmc_component_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="bmc_component_audit",
        gather_func=gather, finding_rules=BMC_COMPONENT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
