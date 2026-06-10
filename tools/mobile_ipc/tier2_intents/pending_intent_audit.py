"""pending_intent_audit - PendingIntent mutability + StrandHogg-class hijack.

PendingIntent.getActivity(..., FLAG_MUTABLE) on Android 12+ lets the
receiving app rewrite Intent extras. Also catches launchMode=singleTask /
taskAffinity tricks that StrandHogg 2.0 abuses. MASVS-PLATFORM-1."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.pending_intent_audit_findings import PENDING_INTENT_AUDIT_FINDING_RULES

router = APIRouter()
PENDING_INTENT_RE = re.compile(r'PendingIntent\.(getActivity|getService|getBroadcast|getForegroundService)')
FLAG_MUTABLE_RE = re.compile(r'FLAG_MUTABLE|\b67108864\b')
FLAG_IMMUTABLE_RE = re.compile(r'FLAG_IMMUTABLE')
TASK_AFFINITY_RE = re.compile(r'android:taskAffinity="(?!""\b)[^"]+"|android:launchMode="singleTask"|android:launchMode="singleInstance"')
TASK_REPARENT_RE = re.compile(r'android:allowTaskReparenting="true"')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["pending_intent_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["pending_intent_audit_error"] = str(e); return
    mutable_pending = []
    immutable_count = 0
    task_hijack_susp = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".xml"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if p.suffix == ".smali":
            if PENDING_INTENT_RE.search(txt):
                if FLAG_MUTABLE_RE.search(txt) and len(mutable_pending) < 20:
                    mutable_pending.append(p.name)
                if FLAG_IMMUTABLE_RE.search(txt):
                    immutable_count += 1
        else:
            if TASK_AFFINITY_RE.search(txt) or TASK_REPARENT_RE.search(txt):
                if len(task_hijack_susp) < 10:
                    task_hijack_susp.append(p.name)
    findings_total = 0
    if mutable_pending: findings_total += 1
    if task_hijack_susp: findings_total += 1
    ctx.state["mutable_pending_callers"] = mutable_pending
    ctx.state["immutable_pending_callers"] = immutable_count
    ctx.state["task_hijack_suspects"] = task_hijack_susp
    ctx.state["files_scanned"] = files_scanned
    ctx.state["pending_intent_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("FLAG_MUTABLE callers", "mutable_pending_callers"),
                ("FLAG_IMMUTABLE callers", "immutable_pending_callers"),
                ("StrandHogg-class task tricks", "task_hijack_suspects")]


@router.post("/api/mobile_ipc/pending_intent_audit")
async def mobile_ipc_pending_intent_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="pending_intent_audit",
        gather_func=gather, finding_rules=PENDING_INTENT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
