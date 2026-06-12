"""firmware module orchestrator - Embedded / IoT firmware static audit.

Per module_playbooks/31_firmware.md - 8 sections, 76 techniques.
Tiered scanner set (real static probes + honest advisory-by-design):
  - tier1_extract    : binwalk_signature_scan, jefferson_jffs2_extract,
                       firmware_filetype_audit, cpio_archive_extract,
                       squashfs_filesystem_audit               (playbook §2/§3)
  - tier2_analysis   : radare2_strings_audit, binary_entropy_audit,
                       firmware_emulation_audit, elf_section_security_audit,
                       firmware_url_endpoint_audit             (playbook §2/§4)
  - tier3_secrets    : hardcoded_credentials_search            (playbook §2 #20)
  - tier4_bootloader : uboot_version_audit, secure_boot_chain_audit (playbook §5)
  - tier5_modern     : uefi_firmware_audit, bmc_component_audit (playbook §8)
  - tier6_hardware   : hardware_interface_advisory, sidechannel_fault_advisory,
                       physical_acquisition_advisory  (advisory-by-design §1/§6/§7)

Concurrency default = 2 (binwalk/unsquashfs extraction is I/O + memory heavy).
ScanRequest.target = path to firmware blob on disk (customer uploads to /tmp).
The tier6 advisory scanners emit honest [ADVISORY-BY-DESIGN] INFO for the
physical-access / lab-hardware techniques that an external SaaS cannot perform.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


FIRMWARE_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_extract": [
        ("binwalk_signature_scan",       "/api/firmware/binwalk_signature_scan"),
        ("jefferson_jffs2_extract",      "/api/firmware/jefferson_jffs2_extract"),
        ("firmware_filetype_audit",      "/api/firmware/firmware_filetype_audit"),
        ("cpio_archive_extract",         "/api/firmware/cpio_archive_extract"),
        ("squashfs_filesystem_audit",    "/api/firmware/squashfs_filesystem_audit"),
    ],
    "tier2_analysis": [
        ("radare2_strings_audit",        "/api/firmware/radare2_strings_audit"),
        ("binary_entropy_audit",         "/api/firmware/binary_entropy_audit"),
        ("firmware_emulation_audit",     "/api/firmware/firmware_emulation_audit"),
        ("elf_section_security_audit",   "/api/firmware/elf_section_security_audit"),
        ("firmware_url_endpoint_audit",  "/api/firmware/firmware_url_endpoint_audit"),
    ],
    "tier3_secrets": [
        ("hardcoded_credentials_search", "/api/firmware/hardcoded_credentials_search"),
    ],
    "tier4_bootloader": [
        ("uboot_version_audit",          "/api/firmware/uboot_version_audit"),
        ("secure_boot_chain_audit",      "/api/firmware/secure_boot_chain_audit"),
    ],
    "tier5_modern": [
        ("uefi_firmware_audit",          "/api/firmware/uefi_firmware_audit"),
        ("bmc_component_audit",          "/api/firmware/bmc_component_audit"),
    ],
    "tier6_hardware": [
        ("hardware_interface_advisory",   "/api/firmware/hardware_interface_advisory"),
        ("sidechannel_fault_advisory",    "/api/firmware/sidechannel_fault_advisory"),
        ("physical_acquisition_advisory", "/api/firmware/physical_acquisition_advisory"),
    ],
}


def _all_tools():
    out = []
    for tier in FIRMWARE_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class FirmwareRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 2
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in FIRMWARE_TOOLS_BY_TIER:
                tools.extend(FIRMWARE_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/firmware/run_all")
async def firmware_run_all(req: FirmwareRunAllRequest, request: Request,
                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 4))
    gen = run_module_streaming(target=req.target, tools=tools, module_name="firmware",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/firmware/run_all_buffered")
async def firmware_run_all_buffered(req: FirmwareRunAllRequest, request: Request,
                                      _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 2, 4))
    return await run_module_parallel(target=req.target, tools=tools, module_name="firmware",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/firmware/run_all/tiers")
async def firmware_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in FIRMWARE_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in FIRMWARE_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
