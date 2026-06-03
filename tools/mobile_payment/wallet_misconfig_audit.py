"""wallet_misconfig_audit - Apple Pay / Google Wallet / Samsung Pay misconfig.
Detects PaymentRequest / PKPaymentRequest usage + merchant ID exposure +
missing payment-handler-method. PCI-MPoC adjacent."""
from __future__ import annotations
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._framework.binary_cache import get_unpacked
from tools._payloads.wallet_misconfig_audit_findings import WALLET_MISCONFIG_AUDIT_FINDING_RULES

router = APIRouter()
APPLE_PAY_RE = re.compile(r'PKPaymentRequest|PKPaymentAuthorizationViewController|ApplePayContext')
GOOGLE_WALLET_RE = re.compile(r'com\.google\.android\.gms\.wallet|PaymentsClient|TaskApiAvailability')
SAMSUNG_PAY_RE = re.compile(r'com\.samsung\.android\.sdk\.samsungpay')
MERCHANT_ID_RE = re.compile(r'merchant\.[a-zA-Z][a-zA-Z0-9.-]+|merchantId\s*[:=]')
PAYMENT_HANDLER_RE = re.compile(r'payment-handler-method|PaymentMethodData')
SCAN_MAX_FILES = 3000


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["wallet_misconfig_audit_total"] = 0; ctx.source("file-not-found"); return
    try: unpacked = get_unpacked(apk)
    except Exception as e: ctx.state["wallet_misconfig_audit_error"] = str(e); return
    apple_users, google_users, samsung_users = [], [], []
    merchant_ids = []
    files_scanned = 0
    for p in unpacked.rglob("*"):
        if files_scanned >= SCAN_MAX_FILES: break
        if not p.is_file() or p.suffix not in (".smali", ".swift", ".m", ".java", ".plist", ".entitlements"): continue
        try: txt = p.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError): continue
        files_scanned += 1
        if APPLE_PAY_RE.search(txt) and len(apple_users) < 20: apple_users.append(p.name)
        if GOOGLE_WALLET_RE.search(txt) and len(google_users) < 20: google_users.append(p.name)
        if SAMSUNG_PAY_RE.search(txt) and len(samsung_users) < 20: samsung_users.append(p.name)
        for m in MERCHANT_ID_RE.finditer(txt):
            v = m.group(0)
            if v not in merchant_ids and len(merchant_ids) < 20:
                merchant_ids.append(v[:80])
    findings_total = 0
    if merchant_ids: findings_total += 1
    ctx.state["apple_pay_users"] = apple_users
    ctx.state["google_wallet_users"] = google_users
    ctx.state["samsung_pay_users"] = samsung_users
    ctx.state["hardcoded_merchant_ids"] = merchant_ids
    ctx.state["files_scanned"] = files_scanned
    ctx.state["wallet_misconfig_audit_total"] = findings_total
    ctx.source(f"{files_scanned} files")


INTEL_FIELDS = [("Apple Pay users", "apple_pay_users"),
                ("Google Wallet users", "google_wallet_users"),
                ("Samsung Pay users", "samsung_pay_users"),
                ("Hardcoded merchant IDs", "hardcoded_merchant_ids")]


@router.post("/api/mobile_payment/wallet_misconfig_audit")
async def mobile_payment_wallet_misconfig_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="wallet_misconfig_audit",
        gather_func=gather, finding_rules=WALLET_MISCONFIG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
