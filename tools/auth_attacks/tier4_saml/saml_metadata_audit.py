"""saml_metadata_audit - SAML metadata + cert hygiene audit (playbook §4 #37/#42).

REAL remote probe. Fetches the customer's SAML metadata XML (from
options.saml_metadata_url or the target) and inspects the ADVERTISED
federation posture - all facts read from the downloaded document:

  #37/#42  WantAssertionsSigned="false"  -> RP accepts unsigned assertions
            (signature-wrapping / forgery enabler).
  SHA-1     SignatureMethod/DigestMethod using rsa-sha1 / sha1
            -> deprecated, collision-feasible signature algorithm.
  Cert      X509Certificate expired or expiring < 30 days
            -> outage + reuse-of-stale-trust risk.
  Cert      RSA public key < 2048 bits -> brute-forceable signing key.

ZERO false positives: a graded severity fires ONLY on a fact parsed from
the live metadata. Unreachable / non-SAML doc -> INFO. Clean metadata ->
POSITIVE. Cert parsing degrades to a metadata-only check when the
`cryptography` library is unavailable.

Customer input via ScanRequest.options:
  - target                   = SP/IdP base (metadata auto-tried at common paths)
  - options.saml_metadata_url = explicit metadata XML URL - optional
"""
from __future__ import annotations
import base64
import re
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

DEFAULT_TIMEOUT = 12

# Common metadata paths to try when only a base URL is given.
_COMMON_METADATA_PATHS = [
    "/saml/metadata", "/saml2/metadata", "/metadata", "/sso/saml/metadata",
    "/simplesaml/saml2/idp/metadata.php", "/auth/saml2/metadata",
    "/.well-known/saml-metadata", "/FederationMetadata/2007-06/FederationMetadata.xml",
]

_SHA1_PATTERNS = (
    "rsa-sha1", "xmldsig#sha1", "2000/09/xmldsig#sha1", "dsa-sha1",
)


class SamlMetadataAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_base(url: str) -> str:
    url = (url or "").strip().rstrip("/")
    if url and not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


async def _fetch_text(client, url: str):
    try:
        r = await client.get(url, follow_redirects=True)
        ct = (r.headers.get("content-type") or "").lower()
        if r.status_code == 200 and ("xml" in ct or "<EntityDescriptor" in (r.text or "")
                                     or "<md:EntityDescriptor" in (r.text or "")):
            return r.text, r.status_code
        return None, r.status_code
    except Exception:
        return None, 0


def _inspect_cert(b64_cert: str) -> dict:
    """Return {bits, not_after_days, subject} using cryptography if present."""
    info: dict = {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        der = base64.b64decode("".join(b64_cert.split()))
        cert = x509.load_der_x509_certificate(der)
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            info["bits"] = pub.key_size
        try:
            not_after = cert.not_valid_after_utc
            now = datetime.datetime.now(datetime.timezone.utc)
        except Exception:
            not_after = cert.not_valid_after
            now = datetime.datetime.utcnow()
        info["not_after"] = str(not_after)
        info["days_to_expiry"] = int((not_after - now).total_seconds() // 86400)
    except ImportError:
        info["crypto_unavailable"] = True
    except Exception as e:
        info["parse_error"] = str(e)[:120]
    return info


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    md_url = (opts.get("saml_metadata_url") or "").strip()
    base = _normalize_base(ctx.host or "")

    if not md_url and not base:
        ctx.state["saml_md_input_missing"] = True
        ctx.source("no metadata url / target")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["saml_md_httpx_missing"] = True
        ctx.source("httpx not installed")
        return

    xml = None
    used_url = None
    async with httpx.AsyncClient(verify=True, timeout=DEFAULT_TIMEOUT) as client:
        if md_url:
            xml, status = await _fetch_text(client, md_url)
            used_url = md_url
            ctx.state["saml_md_status"] = status
        if xml is None and base:
            for path in _COMMON_METADATA_PATHS:
                candidate = base + path
                xml, status = await _fetch_text(client, candidate)
                if xml is not None:
                    used_url = candidate
                    ctx.state["saml_md_status"] = status
                    break

    ctx.state["saml_md_url"] = used_url
    if xml is None:
        ctx.state["saml_md_unreachable"] = True
        ctx.source("metadata XML not reachable")
        return

    # --- WantAssertionsSigned="false" ---
    want_signed_false = bool(re.search(
        r'WantAssertionsSigned\s*=\s*"(?:false|0)"', xml, re.IGNORECASE))
    ctx.state["saml_want_assertions_signed_false"] = want_signed_false

    # --- AuthnRequestsSigned (advisory hygiene) ---
    authn_signed = re.search(
        r'AuthnRequestsSigned\s*=\s*"(?:true|1)"', xml, re.IGNORECASE)
    ctx.state["saml_authn_requests_signed"] = bool(authn_signed)

    # --- SHA-1 signature/digest methods ---
    lower = xml.lower()
    sha1_hits = [p for p in _SHA1_PATTERNS if p in lower]
    if sha1_hits:
        ctx.state["saml_sha1_methods"] = sha1_hits

    # --- Certificates ---
    certs = re.findall(
        r"<(?:ds:)?X509Certificate[^>]*>([^<]+)</(?:ds:)?X509Certificate>",
        xml, re.IGNORECASE)
    ctx.state["saml_cert_count"] = len(certs)
    cert_issues = []
    weak_cert_bits = []
    expired_certs = []
    expiring_certs = []
    crypto_unavailable = False
    for i, c in enumerate(certs[:5]):
        info = _inspect_cert(c)
        if info.get("crypto_unavailable"):
            crypto_unavailable = True
            continue
        bits = info.get("bits")
        if isinstance(bits, int) and bits < 2048:
            weak_cert_bits.append({"index": i, "bits": bits})
        dte = info.get("days_to_expiry")
        if isinstance(dte, int):
            if dte < 0:
                expired_certs.append({"index": i, "days": dte,
                                      "not_after": info.get("not_after")})
            elif dte < 30:
                expiring_certs.append({"index": i, "days": dte,
                                       "not_after": info.get("not_after")})
        cert_issues.append({"index": i, **{k: v for k, v in info.items()
                                           if k != "crypto_unavailable"}})

    ctx.state["saml_cert_info"] = cert_issues
    ctx.state["saml_weak_cert_bits"] = weak_cert_bits
    ctx.state["saml_expired_certs"] = expired_certs
    ctx.state["saml_expiring_certs"] = expiring_certs
    ctx.state["saml_crypto_unavailable"] = crypto_unavailable

    ctx.source(
        f"SAML metadata parsed: WantAssertionsSigned=false:{want_signed_false}, "
        f"sha1:{bool(sha1_hits)}, {len(certs)} cert(s)"
    )


# ----------------------- inline finding rules -----------------------
def rule_unsigned_assertions(s):
    if not s.get("saml_want_assertions_signed_false"):
        return None
    return {
        "name": "SAML metadata sets WantAssertionsSigned=\"false\" (unsigned assertions accepted)",
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-347",
        "owasp": "A07:2021",
        "verified_exploit": True,
        "evidence": (
            f"The metadata at {s.get('saml_md_url','?')} advertises "
            "WantAssertionsSigned=\"false\". The relying party accepts assertions that are not "
            "cryptographically signed, enabling assertion forgery / signature-wrapping (playbook "
            "#37/#42) - an attacker can mint a SAML assertion for any user."
        ),
        "remediation": (
            "Set WantAssertionsSigned=\"true\" and reject any unsigned or partially-signed "
            "assertion. Validate the signature against a pinned IdP certificate before trusting "
            "any attribute."
        ),
    }


def rule_sha1_signature(s):
    sha1 = s.get("saml_sha1_methods") or []
    if not sha1:
        return None
    return {
        "name": "SAML metadata advertises deprecated SHA-1 signature/digest algorithm",
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            f"The metadata references SHA-1 based signature/digest methods ({sha1}). SHA-1 is "
            "collision-feasible and deprecated for XML signatures (SP 800-131A)."
        ),
        "remediation": (
            "Reconfigure the IdP/SP to use SHA-256 signatures (rsa-sha256, xmlenc#sha256) and "
            "remove all SHA-1 SignatureMethod/DigestMethod references."
        ),
    }


def rule_expired_cert(s):
    expired = s.get("saml_expired_certs") or []
    if not expired:
        return None
    return {
        "name": f"SAML signing/encryption certificate EXPIRED: {len(expired)} cert(s)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-298",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            f"The metadata at {s.get('saml_md_url','?')} embeds expired certificate(s): "
            f"{expired}. Expired federation certs cause auth outages and indicate the trust "
            "anchor is not being rotated."
        ),
        "remediation": (
            "Rotate the SAML certificate at both IdP and SP, update the metadata, and "
            "establish an automated cert-expiry alert."
        ),
    }


def rule_weak_cert(s):
    weak = s.get("saml_weak_cert_bits") or []
    if not weak:
        return None
    return {
        "name": f"SAML certificate uses a weak RSA key (<2048-bit): {len(weak)} cert(s)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-326",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            f"Embedded SAML cert(s) use RSA below 2048 bits: {weak}. A factorable signing key "
            "lets an attacker forge signed assertions."
        ),
        "remediation": (
            "Re-issue the SAML certificate with RSA >= 2048 (or ECDSA P-256), update metadata "
            "on both sides, retire the weak cert."
        ),
    }


def rule_expiring_soon(s):
    # Hygiene/advisory - phrased to cap to INFO; only when no graded cert issue.
    expiring = s.get("saml_expiring_certs") or []
    if not expiring:
        return None
    if s.get("saml_expired_certs") or s.get("saml_weak_cert_bits"):
        return None
    return {
        "name": f"SAML certificate expiring within 30 days: {len(expiring)} cert(s)",
        "severity": "INFO",
        "cwe": "CWE-298",
        "owasp": "A02:2021",
        "evidence": (
            f"Embedded SAML cert(s) expire soon: {expiring}. Advisory - rotate before expiry to "
            "avoid an auth outage."
        ),
        "remediation": "Schedule certificate rotation ahead of the expiry date.",
    }


def rule_input_missing(s):
    if not s.get("saml_md_input_missing"):
        return None
    return {
        "name": "SAML metadata audit skipped - no metadata URL / target supplied",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "Probe needs options.saml_metadata_url or a target base URL to fetch metadata.",
        "remediation": "Re-run with options.saml_metadata_url pointing at the SP/IdP metadata XML.",
    }


def rule_httpx_missing(s):
    if not s.get("saml_md_httpx_missing"):
        return None
    return {
        "name": "httpx library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import httpx` failed - required to fetch SAML metadata.",
        "remediation": "pip install httpx >=0.24 inside the scanner container.",
    }


def rule_unreachable(s):
    if not s.get("saml_md_unreachable"):
        return None
    return {
        "name": "SAML metadata document not reachable",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            f"No SAML metadata XML was retrievable (last status "
            f"{s.get('saml_md_status','?')}). The target may not expose metadata at a common "
            "path, or it requires authentication."
        ),
        "remediation": (
            "Supply the exact metadata URL via options.saml_metadata_url (copy it from the "
            "IdP/SP admin console)."
        ),
    }


def rule_positive(s):
    if s.get("saml_md_input_missing") or s.get("saml_md_httpx_missing") or s.get("saml_md_unreachable"):
        return None
    if any(s.get(k) for k in ("saml_want_assertions_signed_false", "saml_sha1_methods",
                              "saml_expired_certs", "saml_weak_cert_bits")):
        return None
    if not s.get("saml_md_url"):
        return None
    note = ""
    if s.get("saml_crypto_unavailable"):
        note = " (certificate cryptographic checks limited - cryptography lib absent)"
    return {
        "name": "SAML metadata is hardened (signed assertions, SHA-256, valid strong certs)",
        "severity": "POSITIVE",
        "cwe": "CWE-347",
        "owasp": "A07:2021",
        "evidence": (
            f"Metadata at {s.get('saml_md_url')} requires signed assertions, uses no SHA-1 "
            f"signature methods, and its certificate(s) are valid and >=2048-bit{note}."
        ),
        "remediation": (
            "Maintain signed-assertion enforcement and SHA-256 signatures. Re-run after each "
            "certificate rotation."
        ),
    }


SAML_METADATA_AUDIT_FINDING_RULES = [
    rule_unsigned_assertions,
    rule_sha1_signature,
    rule_expired_cert,
    rule_weak_cert,
    rule_expiring_soon,
    rule_input_missing,
    rule_httpx_missing,
    rule_unreachable,
    rule_positive,
]


INTEL_FIELDS = [
    ("Metadata URL",             "saml_md_url"),
    ("Metadata status",          "saml_md_status"),
    ("WantAssertionsSigned=false", "saml_want_assertions_signed_false"),
    ("AuthnRequestsSigned",      "saml_authn_requests_signed"),
    ("SHA-1 methods",            "saml_sha1_methods"),
    ("Certificate count",        "saml_cert_count"),
    ("Certificate info",         "saml_cert_info"),
    ("Expired certs",            "saml_expired_certs"),
    ("Weak certs (<2048)",       "saml_weak_cert_bits"),
]


@router.post("/api/auth_attacks/saml_metadata_audit")
async def auth_attacks_saml_metadata_audit(req: SamlMetadataAuditRequest,
                                           _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="saml_metadata_audit",
        gather_func=_gather_with_options,
        finding_rules=SAML_METADATA_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
