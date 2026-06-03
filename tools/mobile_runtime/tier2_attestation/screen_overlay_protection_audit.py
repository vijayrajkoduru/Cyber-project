"""screen_overlay_protection_audit - runtime FLAG_WINDOW_IS_OBSCURED check.

Detects whether the app sets View.setFilterTouchesWhenObscured(true) on
sensitive activities OR registers a MotionEvent.FLAG_WINDOW_IS_OBSCURED
listener. Prevents tapjacking with malicious overlays. MASVS-PLATFORM-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.screen_overlay_protection_audit_findings import SCREEN_OVERLAY_PROTECTION_AUDIT_FINDING_RULES

router = APIRouter()
FILTER_TOUCHES_RE = re.compile(r"setFilterTouchesWhenObscured\s*\(\s*true\s*\)|filterTouchesWhenObscured=\"true\"")
OBSCURED_FLAG_RE = re.compile(r"FLAG_WINDOW_IS_OBSCURED|FLAG_WINDOW_IS_PARTIALLY_OBSCURED")
SENSITIVE_HINTS = ("login", "pin", "password", "auth", "payment", "card",
                    "transfer", "vault", "wallet", "otp", "biometric", "checkout")
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["screen_overlay_protection_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["screen_overlay_protection_audit_error"] = str(e); return
    filter_users, obscured_handlers = [], []
    sensitive_views, sensitive_unprotected = [], []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".xml"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        has_filter = bool(FILTER_TOUCHES_RE.search(txt))
        has_flag = bool(OBSCURED_FLAG_RE.search(txt))
        if has_filter and len(filter_users) < 20:
            filter_users.append(p.name)
        if has_flag and len(obscured_handlers) < 20:
            obscured_handlers.append(p.name)
        name_lc = p.name.lower()
        if any(h in name_lc for h in SENSITIVE_HINTS):
            sensitive_views.append(p.name)
            if not (has_filter or has_flag):
                sensitive_unprotected.append(p.name)
    findings_total = 0
    if sensitive_unprotected:
        findings_total += 1
    ctx.state["filter_touches_users"] = filter_users
    ctx.state["obscured_flag_handlers"] = obscured_handlers
    ctx.state["sensitive_views"] = sensitive_views[:25]
    ctx.state["unprotected_sensitive_views"] = sensitive_unprotected[:25]
    ctx.state["files_scanned"] = files_scanned
    ctx.state["screen_overlay_protection_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("filterTouchesWhenObscured users", "filter_touches_users"),
                ("OBSCURED flag handlers", "obscured_flag_handlers"),
                ("Sensitive views", "sensitive_views"),
                ("Unprotected sensitive views", "unprotected_sensitive_views")]


@router.post("/api/mobile_runtime/screen_overlay_protection_audit")
async def mobile_runtime_screen_overlay_protection_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="screen_overlay_protection_audit",
        gather_func=gather, finding_rules=SCREEN_OVERLAY_PROTECTION_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
