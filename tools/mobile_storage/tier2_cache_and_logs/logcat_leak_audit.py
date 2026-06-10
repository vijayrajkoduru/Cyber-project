"""logcat_leak_audit — detect Log.d/i/w/e/v calls likely to leak sensitive data.
Heuristic: Log call with a variable name or string literal containing
'token', 'password', 'auth', 'jwt', 'pin', etc. Production builds
should strip Log calls via Proguard rules (-assumenosideeffects)."""
from __future__ import annotations
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.logcat_leak_audit_findings import LOGCAT_LEAK_AUDIT_FINDING_RULES

router = APIRouter()

LOG_CALL_RE = re.compile(
    r"Log->(?:d|i|w|e|v|wtf)\(.*?,(.*?)\)",
    re.DOTALL)
SENSITIVE_HINTS = ("token", "password", "passwd", "pwd", "jwt", "auth",
                    "session", "api_key", "apikey", "secret", "credential",
                    "pin", "otp", "private_key", "card", "cvv")
SCAN_MAX_FILES = 2500


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["logcat_leak_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["logcat_leak_audit_error"] = str(e)
        return

    log_call_total = 0
    suspicious_log_calls = []
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1

        for m in LOG_CALL_RE.finditer(txt):
            arg = m.group(1)[:200].lower()
            log_call_total += 1
            for h in SENSITIVE_HINTS:
                if h in arg:
                    if len(suspicious_log_calls) < 30:
                        suspicious_log_calls.append({"file": p.name,
                                                      "hint": h,
                                                      "snippet": m.group(1).strip()[:120]})
                    break
            if log_call_total > 5000:
                break

    ctx.state["log_call_total"] = log_call_total
    ctx.state["suspicious_log_calls"] = suspicious_log_calls
    ctx.state["files_scanned"] = files_scanned
    ctx.state["logcat_leak_audit_total"] = len(suspicious_log_calls)
    ctx.source(f"{files_scanned} smali files, {log_call_total} Log calls")


INTEL_FIELDS = [
    ("Total Log.* calls", "log_call_total"),
    ("Suspicious Log calls", "suspicious_log_calls"),
]


@router.post("/api/mobile_storage/logcat_leak_audit")
async def mobile_storage_logcat_leak_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="logcat_leak_audit",
        gather_func=gather,
        finding_rules=LOGCAT_LEAK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
