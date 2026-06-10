"""flag_secure_audit — check whether Activities set WindowManager.LayoutParams.FLAG_SECURE.
FLAG_SECURE prevents screenshots, screen-recording, and app-switcher
thumbnail leaks. Banks and password managers MUST set it on login/PIN/payment screens."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.flag_secure_audit_findings import FLAG_SECURE_AUDIT_FINDING_RULES

router = APIRouter()

FLAG_SECURE_PATTERN = re.compile(r"FLAG_SECURE|0x2000|setFlags\([^)]*0x2000")
SENSITIVE_ACTIVITY_HINTS = ("login", "pin", "password", "auth", "payment",
                             "card", "transfer", "vault", "wallet", "otp",
                             "biometric", "fingerprint", "checkout")
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["flag_secure_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["flag_secure_audit_error"] = str(e)
        return

    flag_secure_users = []
    sensitive_activities = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        name_lc = p.name.lower()
        is_sensitive = any(h in name_lc for h in SENSITIVE_ACTIVITY_HINTS)
        has_flag = bool(FLAG_SECURE_PATTERN.search(txt))

        if is_sensitive:
            sensitive_activities.append({"file": p.name, "has_flag_secure": has_flag})
        if has_flag and len(flag_secure_users) < 30:
            flag_secure_users.append(p.name)

    # Unsafe sensitive activities = sensitive AND missing flag
    unsafe = [a for a in sensitive_activities if not a["has_flag_secure"]]

    ctx.state["flag_secure_users"] = flag_secure_users
    ctx.state["sensitive_activities"] = sensitive_activities[:30]
    ctx.state["unsafe_activities"] = unsafe[:30]
    ctx.state["files_scanned"] = files_scanned
    ctx.state["flag_secure_audit_total"] = len(unsafe)
    ctx.source(f"{files_scanned} smali files")


INTEL_FIELDS = [
    ("FLAG_SECURE users", "flag_secure_users"),
    ("Sensitive activities", "sensitive_activities"),
    ("Unsafe (sensitive + no FLAG_SECURE)", "unsafe_activities"),
]


@router.post("/api/mobile_storage/flag_secure_audit")
async def mobile_storage_flag_secure_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="flag_secure_audit",
        gather_func=gather,
        finding_rules=FLAG_SECURE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
