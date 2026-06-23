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
from tools._payloads.mobile._fp_gates import is_app_code_path, has_sensitive_value

router = APIRouter()

LOG_CALL_RE = re.compile(
    r"Log->(?:d|i|w|e|v|wtf)\(.*?,(.*?)\)",
    re.DOTALL)
# A literal string/const ref inside the Log argument — used to look for a real
# secret/PII VALUE in the logged data, not just a sensitively-named variable.
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
    confirmed_log_calls = []   # Log call argument carries a real secret/PII VALUE
    hint_log_calls = []        # only a sensitively-named variable, no value (INFO)
    files_scanned = 0
    for p in unpacked.rglob("*.smali"):
        if files_scanned >= SCAN_MAX_FILES:
            break
        try:
            txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned += 1
        try:
            rel = str(p.relative_to(unpacked))
        except ValueError:
            rel = p.name
        # "presence != usage": Log calls inside bundled SDKs / test code are not
        # the app's logging behaviour.
        if not is_app_code_path(rel):
            continue

        for m in LOG_CALL_RE.finditer(txt):
            raw_arg = m.group(1)[:300]
            arg_lc = raw_arg.lower()
            log_call_total += 1
            # CONFIRMED: a real secret/PII value sits inside THIS Log call's
            # argument (not just anywhere in the file).
            if has_sensitive_value(raw_arg):
                if len(confirmed_log_calls) < 30:
                    confirmed_log_calls.append({"file": p.name,
                                                 "hint": "secret/PII value",
                                                 "snippet": raw_arg.strip()[:120]})
            else:
                # NAME-ONLY: a sensitively-named field but no literal value
                # observed -> weak signal, reported at INFO.
                for h in SENSITIVE_HINTS:
                    if h in arg_lc:
                        if len(hint_log_calls) < 30:
                            hint_log_calls.append({"file": p.name,
                                                    "hint": h,
                                                    "snippet": raw_arg.strip()[:120]})
                        break
            if log_call_total > 5000:
                break

    ctx.state["log_call_total"] = log_call_total
    ctx.state["confirmed_log_calls"] = confirmed_log_calls
    ctx.state["hint_log_calls"] = hint_log_calls
    # Back-compat: keep the old key populated (confirmed first, then hints).
    ctx.state["suspicious_log_calls"] = (confirmed_log_calls + hint_log_calls)[:30]
    ctx.state["files_scanned"] = files_scanned
    ctx.state["logcat_leak_audit_total"] = len(confirmed_log_calls)
    ctx.source(f"{files_scanned} smali files, {log_call_total} Log calls")


INTEL_FIELDS = [
    ("Total Log.* calls (app code)", "log_call_total"),
    ("Confirmed secret/PII in Log call", "confirmed_log_calls"),
    ("Sensitively-named Log calls (no value)", "hint_log_calls"),
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
