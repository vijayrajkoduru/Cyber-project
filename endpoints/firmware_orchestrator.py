"""firmware module orchestrator - Embedded / IoT firmware static audit.

Per module_playbooks/31_firmware.md - 8 sections, 76 techniques.
Starter set (5 scanners) covers:
  - tier1_extract  : binwalk_signature_scan + jefferson_jffs2_extract  (playbook §2 #11/12, §3 #24)
  - tier2_analysis : radare2_strings_audit + binary_entropy_audit       (playbook §2 #20, §2 #19)
  - tier3_secrets  : hardcoded_credentials_search                       (playbook §2 #20 byte-level)

Concurrency default = 2 (binwalk extraction is I/O heavy + memory-intensive).
ScanRequest.target = path to firmware blob on disk (customer uploads to /tmp).
More scanners (unblob, FACT, EMBA, firmwalker, CHIPSEC, UEFITool, BMC) will be
added per playbook section in subsequent commits.
"""
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Request, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota, writable_base
from tools._shared import verify_scan_authorization
from tools._framework.orchestrator import run_module_parallel, run_module_streaming

router = APIRouter()


# ─── FIRMWARE-UPLOAD-V1: customer uploads the firmware blob ──────
# Firmware scanners take req.target = a file path, and the artifact guard in
# main.py only accepts paths inside the upload roots (tools._shared.
# artifact_roots). Before this there was no way to get a firmware image into
# those roots, so every firmware scan was refused. Firmware formats vary too
# much for a magic-byte allowlist (raw flash dumps, uImage, TRX, squashfs,
# vendor containers), so we only enforce size + a non-empty file; the
# scanners read it with binwalk/radare2 in a non-root container.
FW_UPLOAD_DIR = writable_base("VL_UPLOAD_DIR", "/uploads") / "firmware"
try:
    FW_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass
FW_MAX_UPLOAD_BYTES = 256 * 1024 * 1024  # 256 MB


@router.post("/api/firmware/upload")
async def firmware_upload(file: UploadFile = File(...),
                          _=Depends(verify_scan_quota)):
    """Receive a firmware image, store it under the firmware upload root and
    return its server path for use as the scan target."""
    FW_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    scan_id = uuid.uuid4().hex[:12]
    safe_name = "".join(c for c in (file.filename or "firmware.bin")
                        if c.isalnum() or c in "._-")[:80].lstrip(".") or "firmware.bin"
    out_path = FW_UPLOAD_DIR / f"{scan_id}_{safe_name}"
    total = 0
    with out_path.open("wb") as f:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > FW_MAX_UPLOAD_BYTES:
                f.close()
                out_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413,
                                    detail=f"File exceeds {FW_MAX_UPLOAD_BYTES // (1024*1024)} MB")
            f.write(chunk)
    if total == 0:
        out_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Empty file")
    return {"scan_id": scan_id, "path": str(out_path),
            "filename": safe_name, "size": total}


FIRMWARE_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_extract": [
        ("binwalk_signature_scan",       "/api/firmware/binwalk_signature_scan"),
        ("jefferson_jffs2_extract",      "/api/firmware/jefferson_jffs2_extract"),
        ("firmware_filetype_audit",      "/api/firmware/firmware_filetype_audit"),
    ],
    "tier2_analysis": [
        ("radare2_strings_audit",        "/api/firmware/radare2_strings_audit"),
        ("binary_entropy_audit",         "/api/firmware/binary_entropy_audit"),
        ("firmware_emulation_audit",     "/api/firmware/firmware_emulation_audit"),
    ],
    "tier3_secrets": [
        ("hardcoded_credentials_search", "/api/firmware/hardcoded_credentials_search"),
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
                            _=Depends(verify_scan_quota), _vlauthz=Depends(verify_scan_authorization)):
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
                                      _=Depends(verify_scan_quota), _vlauthz=Depends(verify_scan_authorization)):
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
