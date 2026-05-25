"""mobile_static module orchestrator — APK/IPA/PE/ELF binary static analysis.

Workflow:
  1. POST /api/mobile_static/upload      — customer uploads binary file
                                            returns {scan_id, apk_path}
  2. POST /api/mobile_static/run_all     — runs all 12 scanners against apk_path
                                            returns NDJSON stream
  3. Or POST /api/mobile_static/<scanner> — run one scanner

NOTE: scanners take `req.target` = the apk_path (file path on backend disk),
NOT a domain. The upload endpoint sets this.
"""
import uuid
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Request, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import (
    run_module_parallel, run_module_streaming,
)

router = APIRouter()


# ─── Upload pipeline ─────────────────────────────────────────────
UPLOAD_DIR = Path("/uploads/mobile_static")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
VALID_MAGIC = (
    b"PK",          # APK / IPA / JAR (ZIP)
    b"\x7fELF",     # Linux ELF
    b"MZ\x90\x00",  # Windows PE
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary
    b"\xfe\xed\xfa",      # Mach-O thin binary (32-bit prefix)
    b"\xcf\xfa\xed",      # Mach-O thin binary (64-bit prefix)
)


@router.post("/api/mobile_static/upload")
async def mobile_static_upload(file: UploadFile = File(...),
                                _=Depends(verify_scan_quota)):
    """Receive an APK / IPA / PE / ELF binary. Validate + store."""
    head = await file.read(4)
    if not any(head.startswith(m[:len(head)]) for m in VALID_MAGIC):
        raise HTTPException(status_code=400,
                            detail="Invalid binary format (not APK/IPA/PE/ELF/Mach-O)")
    await file.seek(0)
    scan_id = uuid.uuid4().hex[:12]
    safe_name = "".join(c for c in (file.filename or "upload")
                         if c.isalnum() or c in "._-")[:80] or "upload.bin"
    out_path = UPLOAD_DIR / f"{scan_id}_{safe_name}"
    total = 0
    with out_path.open("wb") as f:
        while chunk := await file.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                f.close()
                out_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413,
                                    detail=f"File exceeds {MAX_UPLOAD_BYTES} bytes")
            f.write(chunk)
    return {
        "scan_id": scan_id,
        "apk_path": str(out_path),
        "filename": safe_name,
        "size": total,
    }


# ─── Scanner registry ────────────────────────────────────────────
MOBILE_STATIC_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_manifest_and_config": [
        ("android_manifest_audit",        "/api/mobile_static/android_manifest_audit"),
        ("ios_plist_audit",               "/api/mobile_static/ios_plist_audit"),
        ("network_security_config_audit", "/api/mobile_static/network_security_config_audit"),
    ],
    "tier2_secret_and_crypto": [
        ("secret_extraction_audit",       "/api/mobile_static/secret_extraction_audit"),
        ("weak_crypto_audit",             "/api/mobile_static/weak_crypto_audit"),
        ("hardcoded_url_and_ip_audit",    "/api/mobile_static/hardcoded_url_and_ip_audit"),
    ],
    "tier3_binary_hardening": [
        ("native_lib_hardening",          "/api/mobile_static/native_lib_hardening"),
        ("pe_hardening_audit",            "/api/mobile_static/pe_hardening_audit"),
        ("elf_symbol_audit",              "/api/mobile_static/elf_symbol_audit"),
    ],
    "tier4_behavioral_and_aggregate": [
        ("bytecode_malware_signatures",   "/api/mobile_static/bytecode_malware_signatures"),
        ("third_party_sdk_audit",         "/api/mobile_static/third_party_sdk_audit"),
        ("mobsf_aggregate_scan",          "/api/mobile_static/mobsf_aggregate_scan"),
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in MOBILE_STATIC_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class MobileStaticRunAllRequest(BaseModel):
    target: str  # the apk_path returned by /upload
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 4    # static analysis is heavy; default lower
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in MOBILE_STATIC_TOOLS_BY_TIER:
                tools.extend(MOBILE_STATIC_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/mobile_static/run_all")
async def mobile_static_run_all(req: MobileStaticRunAllRequest, request: Request,
                                _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="mobile_static",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/mobile_static/run_all_buffered")
async def mobile_static_run_all_buffered(req: MobileStaticRunAllRequest, request: Request,
                                          _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="mobile_static",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/mobile_static/run_all/tiers")
async def mobile_static_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in MOBILE_STATIC_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in MOBILE_STATIC_TOOLS_BY_TIER.values()),
    }


# ─── Pre-bundled sample binaries (for demo / first-time customer) ─
# Customers without their own APK can pick one of these from a dropdown
# and run a full scan without uploading anything. Paths come from the
# Dockerfile's /app/samples/mobile stage.
SAMPLE_BINARIES = [
    {
        "id": "insecurebankv2",
        "name": "InsecureBankv2 — banking-app vulnerabilities (broad)",
        "path": "/app/samples/mobile/insecurebankv2.apk",
        "description": "OWASP MASVS training APK. Triggers ~30 findings across mobile_static + mobile_storage — hardcoded credentials, weak crypto, exported components, cleartext traffic, plain SharedPreferences.",
    },
    {
        "id": "allsafe",
        "name": "Allsafe — anti-tamper / Frida training lab",
        "path": "/app/samples/mobile/allsafe.apk",
        "description": "Modern (2021+) APK with RootBeer + SafetyNet + Frida detection + SSL pinning wired in. Best target for mobile_runtime module — fires all 6 anti-tamper scanners.",
    },
    {
        "id": "ovaa",
        "name": "OVAA — Oversecured Vulnerable Android App",
        "path": "/app/samples/mobile/ovaa.apk",
        "description": "Comprehensive modern lab covering MASVS storage / IPC / WebView / deep links / native code. Best for breadth of findings across all 3 mobile modules.",
    },
    {
        "id": "injuredandroid",
        "name": "InjuredAndroid — CTF-style training (13+ flags)",
        "path": "/app/samples/mobile/injuredandroid.apk",
        "description": "Modern (2020+) Kotlin CTF app. 13+ deliberate vulnerabilities mapped to flags - hardcoded creds, exported activities, weak crypto, deep-link hijack, login bypass.",
    },
    {
        "id": "androgoat",
        "name": "AndroGoat — Kotlin MASVS lab (~20 categories)",
        "path": "/app/samples/mobile/androgoat.apk",
        "description": "Kotlin-based vulnerable app aligned to OWASP MASVS controls. Useful when demoing MASVS-mapped customer reports.",
    },
]


@router.get("/api/mobile_static/samples")
async def mobile_static_samples():
    """List demo binaries pre-bundled in the image. Only returns samples
    whose files actually exist (so a failed Docker download doesn't show
    a broken entry in the UI)."""
    out = []
    for s in SAMPLE_BINARIES:
        p = Path(s["path"])
        if p.exists() and p.is_file():
            out.append({
                **s,
                "size": p.stat().st_size,
                "size_mb": round(p.stat().st_size / 1024 / 1024, 2),
            })
    return {"samples": out, "count": len(out)}


def register(app):
    app.include_router(router)
