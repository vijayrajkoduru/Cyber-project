"""iap_billing_audit — detect in-app-purchase / billing integration.

Detects Google Play Billing Library + Apple StoreKit signatures. Useful
for: (a) confirming proper IAP integration vs custom-payment flows that
violate store policy, (b) flagging server-side receipt-verification
absence (custom payment flows bypassing 30% store fee).

MASVS-PRIVACY-2 / MASVS-CODE-2 (payment compliance).
"""
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.iap_billing_audit_findings import \
    IAP_BILLING_AUDIT_FINDING_RULES

router = APIRouter()

IAP_MARKERS = {
    "google_billing": [
        b"Lcom/android/billingclient/api/",
        b"BillingClient", b"PurchasesUpdatedListener",
        b"BillingFlowParams",
    ],
    "google_play_billing_old": [
        b"Lcom/android/vending/billing/",
        b"IInAppBillingService",
    ],
    "apple_storekit": [
        b"StoreKit", b"SKProduct", b"SKPaymentTransaction",
        b"SKPaymentQueue",
    ],
    "stripe": [
        b"Lcom/stripe/android/",  # Third-party payment SDK
        b"PaymentSheet",
    ],
    "razorpay": [
        b"Lcom/razorpay/",
    ],
    "paypal": [
        b"Lcom/paypal/", b"PayPalCheckoutSdk",
    ],
}

# Server-side receipt verification markers (Good Practice)
RECEIPT_VERIFY_MARKERS = [
    b"verifyPurchase", b"verifyReceipt",
    b"acknowledgePurchase", b"BillingClient.acknowledge",
    b"validateReceipt",
]


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["iap_billing_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["iap_billing_audit_error"] = str(e); return

    found = {}  # provider -> first_file
    has_verify = False
    files_scanned = 0
    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for provider, markers in IAP_MARKERS.items():
            if provider in found: continue
            for m in markers:
                if m in data:
                    found[provider] = f.relative_to(unpacked).as_posix()
                    break
        for m in RECEIPT_VERIFY_MARKERS:
            if m in data:
                has_verify = True
                break

    ctx.state["iap_providers_found"] = list(found.keys())
    ctx.state["iap_provider_locations"] = found
    ctx.state["receipt_verification_present"] = has_verify
    ctx.state["iap_billing_audit_total"] = len(found)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"scanned {files_scanned} files, {len(found)} payment SDK(s)")


INTEL_FIELDS = [
    ("Payment SDKs detected",       "iap_providers_found"),
    ("Receipt-verify code present", "receipt_verification_present"),
    ("Files scanned",               "files_scanned"),
]


@router.post("/api/mobile_static/iap_billing_audit")
async def mobile_static_iap_billing_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="iap_billing_audit",
        gather_func=gather,
        finding_rules=IAP_BILLING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
