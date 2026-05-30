"""tapjacking_audit — overlay attack protection check.

Tapjacking: malicious app overlays a transparent view on top of your app's
sensitive button. User thinks they're tapping benign content but is
actually clicking your 'Transfer $1000' button. Mitigation:
android:filterTouchesWhenObscured='true' on sensitive Views, or set
View.setFilterTouchesWhenObscured(true) programmatically.

MASVS-PLATFORM-1 / MSTG-PLATFORM-9.
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.tapjacking_audit_findings import \
    TAPJACKING_AUDIT_FINDING_RULES

router = APIRouter()

PROTECT_MARKERS = [
    b"filterTouchesWhenObscured",
    b"setFilterTouchesWhenObscured",
    b"FLAG_NOT_TOUCH_MODAL",  # ignored alternative for dialogs
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["tapjacking_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["tapjacking_audit_error"] = str(e); return

    matched = []
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".xml", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for m in PROTECT_MARKERS:
            cnt = data.count(m)
            if cnt:
                matched.append({"marker": m.decode(), "count": cnt,
                                  "file": f.relative_to(unpacked).as_posix()})
                break  # one match per file is enough signal

    total = sum(h["count"] for h in matched)
    ctx.state["tapjacking_protection_hits"] = matched
    ctx.state["tapjacking_audit_total"] = total
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned}, {total} protect markers")


INTEL_FIELDS = [
    ("Tapjacking protection hits", "tapjacking_audit_total"),
    ("Files scanned",              "files_scanned"),
]


@router.post("/api/mobile_static/tapjacking_audit")
async def mobile_static_tapjacking_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="tapjacking_audit",
        gather_func=gather,
        finding_rules=TAPJACKING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
