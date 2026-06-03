"""websocket_origin_audit - WebSocket Origin header validation.
Same-origin policy doesn't auto-apply to WS. Code that opens
ws://... or wss://... should also pin server certificate and verify
Sec-WebSocket-Protocol echo. MSTG-NETWORK-5."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.websocket_origin_audit_findings import WEBSOCKET_ORIGIN_AUDIT_FINDING_RULES

router = APIRouter()
WS_USE_RE = re.compile(r'WebSocket\s*\(|URLSessionWebSocketTask|ws://|wss://|okhttp3\.WebSocket')
WS_ORIGIN_RE = re.compile(r'(?:Origin|Sec-WebSocket-Origin)\s*[:=]', re.IGNORECASE)
WS_TLS_VERIFY_RE = re.compile(r'sslSocketFactory|sslContext|requestSslContextFactory')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["websocket_origin_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["websocket_origin_audit_error"] = str(e); return
    ws_users = []
    ws_origin_users = 0
    ws_tls_verify_users = 0
    plain_ws_urls = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".h", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if WS_USE_RE.search(txt):
            if len(ws_users) < 25:
                ws_users.append(p.name)
            if "ws://" in txt and len(plain_ws_urls) < 25:
                plain_ws_urls.append(p.name)
        if WS_ORIGIN_RE.search(txt): ws_origin_users += 1
        if WS_TLS_VERIFY_RE.search(txt): ws_tls_verify_users += 1
    findings_total = 0
    if plain_ws_urls: findings_total += 1
    if ws_users and ws_origin_users == 0: findings_total += 1
    ctx.state["ws_users"] = ws_users
    ctx.state["plain_ws_urls"] = plain_ws_urls
    ctx.state["ws_origin_set_callers"] = ws_origin_users
    ctx.state["ws_tls_verify_callers"] = ws_tls_verify_users
    ctx.state["files_scanned"] = files_scanned
    ctx.state["websocket_origin_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("WebSocket users", "ws_users"),
                ("Plain ws:// (no TLS)", "plain_ws_urls"),
                ("Origin-set callers", "ws_origin_set_callers"),
                ("TLS-verify callers", "ws_tls_verify_callers")]


@router.post("/api/mobile_network/websocket_origin_audit")
async def mobile_network_websocket_origin_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="websocket_origin_audit",
        gather_func=gather, finding_rules=WEBSOCKET_ORIGIN_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
