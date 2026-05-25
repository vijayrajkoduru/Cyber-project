"""mobile_storage module orchestrator — §3 STORAGE (Data-at-Rest).

Static analysis of APK / IPA binaries for storage-related vulnerabilities:
  - SharedPreferences (plain vs encrypted, sensitive keys)
  - SQLite + SQLCipher usage
  - iOS Plist sensitive keys
  - FLAG_SECURE on sensitive Activities
  - WebView cache config
  - Hardcoded external-storage paths
  - Logcat leaks
  - Clipboard API in sensitive flows
  - External-storage permissions
  - Backup extraction policy (allowBackup + rules)

Reuses the /api/mobile_static/upload endpoint to receive binaries
(customer uploads once, both modules scan the same cached binary via
binary_cache.py SHA-256-keyed cache).
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import (
    run_module_parallel, run_module_streaming,
)

router = APIRouter()


# ─── Scanner registry ────────────────────────────────────────────
MOBILE_STORAGE_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_db_and_prefs": [
        ("sharedprefs_audit",        "/api/mobile_storage/sharedprefs_audit"),
        ("sqlite_usage_audit",       "/api/mobile_storage/sqlite_usage_audit"),
        ("sqlcipher_presence_check", "/api/mobile_storage/sqlcipher_presence_check"),
        ("ios_plist_storage_audit",  "/api/mobile_storage/ios_plist_storage_audit"),
    ],
    "tier2_cache_and_logs": [
        ("flag_secure_audit",        "/api/mobile_storage/flag_secure_audit"),
        ("webview_cache_audit",      "/api/mobile_storage/webview_cache_audit"),
        ("image_cache_paths_audit",  "/api/mobile_storage/image_cache_paths_audit"),
        ("logcat_leak_audit",        "/api/mobile_storage/logcat_leak_audit"),
    ],
    "tier3_perms_and_backup": [
        ("clipboard_api_audit",      "/api/mobile_storage/clipboard_api_audit"),
        ("external_storage_audit",   "/api/mobile_storage/external_storage_audit"),
        ("backup_extraction_audit",  "/api/mobile_storage/backup_extraction_audit"),
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in MOBILE_STORAGE_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class MobileStorageRunAllRequest(BaseModel):
    target: str  # the apk_path returned by /api/mobile_static/upload
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 4
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in MOBILE_STORAGE_TOOLS_BY_TIER:
                tools.extend(MOBILE_STORAGE_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/mobile_storage/run_all")
async def mobile_storage_run_all(req: MobileStorageRunAllRequest, request: Request,
                                  _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="mobile_storage",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/mobile_storage/run_all_buffered")
async def mobile_storage_run_all_buffered(req: MobileStorageRunAllRequest, request: Request,
                                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="mobile_storage",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/mobile_storage/run_all/tiers")
async def mobile_storage_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in MOBILE_STORAGE_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in MOBILE_STORAGE_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
