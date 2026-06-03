"""play_billing_audit - Android Google Play Billing receipt validation.
Detect BillingClient usage + server-side signature verification via
Play Developer API. PCI MASS, MASVS-PAYMENT."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.play_billing_audit_findings import PLAY_BILLING_AUDIT_FINDING_RULES

router = APIRouter()
BILLING_RE = re.compile(r'BillingClient|com/android/billingclient|Purchase\.\$Builder')
LOCAL_VERIFY_RE = re.compile(r'verifyPurchase|Security\.verifyPurchase|signature\.verify')
SERVER_API_RE = re.compile(r'androidpublisher/v3|googleapis\.com/androidpublisher')
PURCHASE_TOKEN_FORWARD_RE = re.compile(r'purchaseToken|getPurchaseToken')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["play_billing_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["play_billing_audit_error"] = str(e); return
    billing_users = []
    local_verify = []
    server_api_refs = []
    token_forwarders = 0
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".java"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if BILLING_RE.search(txt) and len(billing_users) < 20: billing_users.append(p.name)
        if LOCAL_VERIFY_RE.search(txt) and len(local_verify) < 20: local_verify.append(p.name)
        if SERVER_API_RE.search(txt) and len(server_api_refs) < 10: server_api_refs.append(p.name)
        if PURCHASE_TOKEN_FORWARD_RE.search(txt): token_forwarders += 1
    findings_total = 0
    if billing_users and not server_api_refs and token_forwarders == 0:
        findings_total += 1
    ctx.state["billing_users"] = billing_users
    ctx.state["local_verify_callers"] = local_verify
    ctx.state["server_api_references"] = server_api_refs
    ctx.state["purchase_token_forwarders"] = token_forwarders
    ctx.state["files_scanned"] = files_scanned
    ctx.state["play_billing_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("BillingClient users", "billing_users"),
                ("Local-verify callers", "local_verify_callers"),
                ("Server-API references", "server_api_references"),
                ("purchaseToken forwarders", "purchase_token_forwarders")]


@router.post("/api/mobile_payment/play_billing_audit")
async def mobile_payment_play_billing_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="play_billing_audit",
        gather_func=gather, finding_rules=PLAY_BILLING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
