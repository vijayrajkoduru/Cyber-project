"""Shared zero-FP gates for the Mobile static-analysis suite.

CORE PRINCIPLE: "presence != usage". A string / API / permission appearing
in decompiled bytecode or a bundled 3rd-party SDK is NOT proof the APP uses
it in a risky way. These helpers let scanners distinguish:

  * APP code path     vs.  bundled library / SDK code path
  * test / mock path  vs.  production code
  * real PII/secret   vs.  a name substring that merely looks sensitive

Scanners use these to DOWNGRADE unconfirmed/library-only hits to INFO/LOW.
They never invent findings — only add context gates.

Lives in the isolated `mobile` payload pool so every mobile_* scanner can
import it without crossing module boundaries.
"""
from __future__ import annotations

import re

# ── Known 3rd-party SDK / library package roots ───────────────────────────
# A weak-crypto / TLS-bypass / dangerous-API hit inside one of these paths is
# the LIBRARY's code, not the app's. Matched as a substring against the
# forward-slashed relative path of the smali/source file (lowercased).
#
# These are *vendor* paths. Detecting MD5 inside okhttp/firebase/play-services
# tells you nothing about how the app uses crypto — it is the SDK's internals.
LIBRARY_PATH_MARKERS = (
    # Crypto libraries (legitimately reference every primitive)
    "/org/bouncycastle/", "/bouncycastle/",
    "/org/conscrypt/", "/conscrypt/",
    "/com/google/crypto/tink/", "/google/crypto/tink/",
    "/org/spongycastle/", "/spongycastle/",
    "/javax/crypto/", "/sun/security/",
    # Networking / HTTP stacks
    "/okhttp3/", "/okhttp/", "/com/squareup/okhttp",
    "/retrofit2/", "/com/squareup/retrofit",
    "/com/squareup/okio/", "/okio/",
    "/org/apache/http/", "/org/apache/commons/",
    "/io/netty/", "/com/android/volley/",
    # Google / Firebase / Play services
    "/com/google/firebase/", "/com/google/android/gms/",
    "/com/google/android/play/", "/com/google/api/",
    "/com/google/common/", "/com/google/gson/",
    "/com/google/protobuf/", "/com/google/android/material/",
    "/androidx/", "/android/support/", "/kotlin/", "/kotlinx/",
    # Common SDKs / ad / analytics / social
    "/com/facebook/", "/com/twitter/", "/com/amazon/", "/com/amazonaws/",
    "/com/microsoft/", "/com/appsflyer/", "/com/adjust/",
    "/com/flurry/", "/com/mixpanel/", "/com/segment/",
    "/com/onesignal/", "/com/braze/", "/com/urbanairship/",
    "/com/crashlytics/", "/io/sentry/", "/com/bugsnag/",
    "/com/stripe/", "/com/braintree", "/com/paypal/",
    "/com/unity3d/", "/com/applovin/", "/com/mopub/",
    "/com/ironsource/", "/com/vungle/", "/com/chartboost/",
    "/com/inmobi/", "/com/mbridge/", "/com/bytedance/",
    "/cordova/", "/org/apache/cordova/", "/com/getcapacitor/",
    "/com/reactnativecommunity/", "/io/flutter/",
    "/net/sqlcipher/", "/org/sqlite/",
    "/dagger/", "/javax/inject/", "/io/reactivex/", "/rx/",
    "/com/squareup/picasso/", "/com/bumptech/glide/",
    "/com/airbnb/lottie/", "/com/google/zxing/",
)

# ── Test / mock / debug path markers ──────────────────────────────────────
# A TLS bypass or weak primitive inside a test/mock/debug class is not part of
# the shipped attack surface (and is often build-stripped). Downgrade to INFO.
TEST_PATH_MARKERS = (
    "/test/", "/tests/", "/androidtest/", "/instrumentation/",
    "/mock/", "/mocks/", "/fake/", "/fakes/", "/stub/", "/stubs/",
    "/debug/", "/sample/", "/samples/", "/example/", "/examples/",
    "test.smali", "tests.smali", "mock.smali", "fake.smali", "stub.smali",
    "espresso", "junit", "mockito", "robolectric", "testutil",
)


def _norm(path: str) -> str:
    # Prefix a leading "/" so segment markers like "/com/google/firebase/" match
    # even when the relative path starts with the package directly (no leading
    # slash) or with an apktool prefix (smali/ , smali_classes2/).
    return "/" + str(path).replace("\\", "/").lower().lstrip("/")


def is_library_path(rel_path) -> bool:
    """True if the file lives inside a known 3rd-party SDK / library package."""
    p = _norm(rel_path)
    return any(m in p for m in LIBRARY_PATH_MARKERS)


def is_test_path(rel_path) -> bool:
    """True if the file is a test / mock / debug / sample artifact."""
    p = _norm(rel_path)
    return any(m in p for m in TEST_PATH_MARKERS)


def is_app_code_path(rel_path) -> bool:
    """True only if the file is APP code (not a bundled lib, test, or mock)."""
    return not is_library_path(rel_path) and not is_test_path(rel_path)


# ── Sensitive-value evidence (for logcat / clipboard leaks) ───────────────
# "presence of the word token in a file" is NOT a leak. We require a real
# secret/PII pattern INSIDE the actual sink call argument, or a literal secret.
_SECRET_VALUE_RE = re.compile(
    r"""(?xi)
    eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+    # JWT
    | \bAKIA[0-9A-Z]{16}\b                                      # AWS key id
    | \bAIza[0-9A-Za-z_\-]{35}\b                                # Google API key
    | \bsk_live_[0-9a-zA-Z]{16,}\b                              # Stripe live
    | \bghp_[A-Za-z0-9]{30,}\b                                  # GitHub PAT
    | -----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY    # private key
    | \b[A-Za-z0-9+/]{40,}={0,2}\b                              # long base64 blob
    | \b[0-9a-fA-F]{32,}\b                                      # long hex blob
    """
)
# PII-shaped values that should never reach logcat in the clear.
_PII_VALUE_RE = re.compile(
    r"""(?xi)
    \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b          # email
    | \b(?:\d[ -]?){13,19}\b                                    # PAN / card-ish
    | \b\d{3}-\d{2}-\d{4}\b                                     # SSN
    """
)


def has_secret_value(text: str) -> bool:
    """True if `text` (a sink argument) contains a real secret/credential value."""
    if not text:
        return False
    return bool(_SECRET_VALUE_RE.search(text))


def has_pii_value(text: str) -> bool:
    """True if `text` (a sink argument) contains a real PII value (email/card/SSN)."""
    if not text:
        return False
    return bool(_PII_VALUE_RE.search(text))


def has_sensitive_value(text: str) -> bool:
    """True if a sink argument carries a real secret OR PII value (not just a name)."""
    return has_secret_value(text) or has_pii_value(text)


# ── Manifest component package gating ─────────────────────────────────────
# Exported components whose class lives in a known SDK package are the SDK's
# components (FileProvider, Firebase init, Play billing, ad activities, etc.) —
# almost always intentionally exported and not the app's own attack surface.
SDK_COMPONENT_PREFIXES = (
    "com.google.", "com.google.android.gms.", "com.google.firebase.",
    "com.google.android.play.", "androidx.", "android.support.",
    "com.facebook.", "com.android.", "com.amazon.", "com.amazonaws.",
    "com.microsoft.", "com.adjust.", "com.appsflyer.", "com.flurry.",
    "com.onesignal.", "com.urbanairship.", "com.braze.", "io.branch.",
    "com.crashlytics.", "io.sentry.", "com.bugsnag.", "com.stripe.",
    "com.braintreepayments.", "com.paypal.", "com.unity3d.",
    "com.applovin.", "com.mopub.", "com.ironsource.", "com.vungle.",
    "com.chartboost.", "com.inmobi.", "com.mbridge.", "io.flutter.",
    "org.apache.cordova.", "com.getcapacitor.", "expo.", "com.reactnativecommunity.",
)
# Substring hints in an exported component's name that flag it as security-
# sensitive (matched case-insensitively, same semantics as the inline tuples).
SENSITIVE_COMPONENT_HINTS = (
    "login", "signin", "sign_in", "auth", "oauth", "sso",
    "pin", "password", "passcode", "credential", "biometric",
    "payment", "checkout", "card", "billing", "wallet",
    "transfer", "transaction", "vault", "admin",
    "secret", "token", "export", "import", "backup", "account",
)


def is_sdk_component(name: str) -> bool:
    """True if an exported component's class belongs to a known 3rd-party SDK."""
    n = (name or "").lower()
    return any(n.startswith(pfx.lower()) for pfx in SDK_COMPONENT_PREFIXES)


def is_sensitive_component(name: str) -> bool:
    """True if an exported component's name hints at a security-sensitive surface."""
    n = (name or "").lower()
    return any(h in n for h in SENSITIVE_COMPONENT_HINTS)
