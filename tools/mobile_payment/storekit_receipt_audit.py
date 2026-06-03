"""storekit_receipt_audit - iOS StoreKit / StoreKit2 receipt validation.
Catches client-side-only receipt validation (replay vulnerable) +
absence of Apple server verification. PCI MASS, MASVS-PAYMENT."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.storekit_receipt_audit_findings import STOREKIT_RECEIPT_AUDIT_FINDING_RULES

router = APIRouter()
STOREKIT_RE = re.compile(r'StoreKit|SKPaymentTransaction|SKReceiptRefreshRequest|Transaction\.currentEntitlements')
LOCAL_VALIDATE_RE = re.compile(r'appStoreReceiptURL|receiptData\.base64|signature\(of:\)|jwsRepresentation')
APPLE_VERIFY_URL_RE = re.compile(r'buy\.itunes\.apple\.com/verifyReceipt|sandbox\.itunes\.apple\.com/verifyReceipt|api\.storekit\.itunes\.apple\.com')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["storekit_receipt_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["storekit_receipt_audit_error"] = str(e); return
    is_ios = False
    storekit_users = []
    local_validate = []
    server_validate_endpoints = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".swift", ".m", ".h"): continue
        is_ios = True
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if STOREKIT_RE.search(txt) and len(storekit_users) < 20: storekit_users.append(p.name)
        if LOCAL_VALIDATE_RE.search(txt) and len(local_validate) < 20: local_validate.append(p.name)
        if APPLE_VERIFY_URL_RE.search(txt) and len(server_validate_endpoints) < 10:
            server_validate_endpoints.append(p.name)
    findings_total = 0
    if storekit_users and not server_validate_endpoints: findings_total += 1
    ctx.state["is_ios"] = is_ios
    ctx.state["storekit_users"] = storekit_users
    ctx.state["local_validate_callers"] = local_validate
    ctx.state["server_validate_endpoints"] = server_validate_endpoints
    ctx.state["files_scanned"] = files_scanned
    ctx.state["storekit_receipt_audit_total"] = findings_total
    ctx.source(f"{files_scanned} iOS files")


INTEL_FIELDS = [("iOS detected", "is_ios"),
                ("StoreKit users", "storekit_users"),
                ("Local-validate callers", "local_validate_callers"),
                ("Apple server-verify endpoints", "server_validate_endpoints")]


@router.post("/api/mobile_payment/storekit_receipt_audit")
async def mobile_payment_storekit_receipt_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="storekit_receipt_audit",
        gather_func=gather, finding_rules=STOREKIT_RECEIPT_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
