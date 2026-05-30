"""iap_billing_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("iap_billing_audit_total", 0)
    if n > 0: return None
    return {"name": "No in-app-purchase / payment SDK detected",
            "severity": "POSITIVE",
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files, no IAP markers",
            "remediation": "Free / ad-supported app — no payment compliance burden. "
                           "If you intend to add IAP later, prefer native Google Play "
                           "Billing / Apple StoreKit (store policy) unless you qualify "
                           "for the EU DMA exception."}


def rule_third_party_payment_on_store(s):
    found = s.get("iap_providers_found") or []
    third_party = [p for p in found if p in ("stripe", "razorpay", "paypal")]
    has_store_billing = any(p in found for p in
                              ("google_billing", "google_play_billing_old", "apple_storekit"))
    if not third_party: return None
    sev = "MEDIUM" if has_store_billing else "HIGH"
    cvss = "5.3" if has_store_billing else "7.0"
    return {"name": f"Third-party payment SDK(s): {', '.join(third_party)}",
            "severity": sev, "cvss": cvss,
            "cwe": "CWE-693", "owasp": "M9:2023",
            "evidence": "third-party: " + ", ".join(third_party) +
                        (f"; native-also-present" if has_store_billing else ""),
            "remediation": (
                "Apple App Store and Google Play REQUIRE in-app purchases of "
                "DIGITAL goods to use their billing systems (30% cut). Third-party "
                "payment SDKs are OK for PHYSICAL goods / real-world services "
                "(Uber, Amazon Shopping). If your app sells digital items: app "
                "rejection risk. Exception: EU DMA gatekeepers allow third-party "
                "billing for EU users (Mar 2024+)."
            )}


def rule_no_receipt_verify(s):
    if s.get("iap_billing_audit_total", 0) == 0: return None
    if s.get("receipt_verification_present"): return None
    found = s.get("iap_providers_found") or []
    has_store = any(p in found for p in ("google_billing", "apple_storekit"))
    if not has_store: return None
    return {"name": "Native IAP detected but no acknowledgement / receipt-verify code",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-345", "owasp": "M9:2023",
            "evidence": "no acknowledgePurchase / verifyReceipt markers in DEX",
            "remediation": "(1) Google Play Billing REQUIRES acknowledging purchases "
                           "within 3 days — un-acknowledged purchases are auto-refunded. "
                           "(2) Server-side receipt verification is the only protection "
                           "against IAP-cracker apps (LuckyPatcher, etc). Verify "
                           "purchases server-side via Google Play Developer API / "
                           "Apple verifyReceipt endpoint BEFORE delivering content."}


def rule_iap_inventory(s):
    n = s.get("iap_billing_audit_total", 0)
    if n == 0: return None
    found = s.get("iap_providers_found") or []
    return {"name": f"Payment SDK inventory ({n} provider(s))",
            "severity": "INFO",
            "cwe": "CWE-200", "owasp": "M2:2023",
            "evidence": ", ".join(found),
            "remediation": "Document each in your Privacy Policy + Store listing. "
                           "Multiple payment providers can confuse users — consider "
                           "consolidating."}
