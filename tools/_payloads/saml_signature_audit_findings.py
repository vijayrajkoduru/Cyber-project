"""saml_signature_audit - finding rules (VL-METHOD aware).

SAML XML Signature attack family (XSW1-XSW8, signature stripping,
comment injection, replay, audience confusion, expired-assertion
acceptance). Reads state populated by SamlSignatureAudit's 7-stage
flow:

  - methodology_findings   : list of probed SAML variants + acceptance
  - target_base            : SAML SP under audit
  - acs_url                : Assertion Consumer Service URL
  - fingerprint            : dict with sig_alg, has_assertion_signature,
                              has_response_signature, audience, x509,
                              saml_version, c14n_method, etc.
  - quick_probe_attempts   : 5 XSW serial variants attempted
  - quick_probe_hits       : accepted XSW count from quick_probe
  - deep_tests_run         : extended XSW + replay + audience + expiry
  - chain_next             : downstream chained scanners
  - skipped_reason         : pre_flight skip reason
  - lxml_missing           : lxml import failed
  - httpx_missing          : httpx import failed

Severity model:
  CONFIRMED signature_stripping          -> CRITICAL CVSS 9.8 CWE-347
  CONFIRMED XSW + admin_impersonation    -> CRITICAL CVSS 9.4 CWE-347
  CONFIRMED XSW + user_impersonation     -> HIGH     CVSS 8.1 CWE-347
  CONFIRMED comment_injection_nameid     -> HIGH     CVSS 7.5 CWE-347
  CONFIRMED expired_assertion accepted   -> HIGH     CVSS 7.5 CWE-613
  CONFIRMED replay (no protection)       -> MEDIUM   CVSS 6.5 CWE-294
  CONFIRMED audience_not_validated       -> MEDIUM   CVSS 6.5 CWE-345
  SHA1 signature in fingerprint          -> MEDIUM   CVSS 5.3 CWE-327
  Response-only signature (no assertion) -> MEDIUM   CVSS 5.3
  SUSPECTED any                          -> LOW      CVSS 3.7
  Clean posture (0 bypasses + sig OK)    -> POSITIVE
  Input missing / lxml missing           -> INFO
"""


INTEL_FIELDS = [
    ("SAML SP Target",            "target_base"),
    ("ACS URL",                   "acs_url"),
    ("SAML Fingerprint",          "fingerprint"),
    ("Quick-probe XSW tests",     "quick_probe_attempts"),
    ("Accepted bypasses",         "quick_probe_hits"),
    ("Stage timings (ms)",        "stage_timings"),
    ("Stage errors",              "stage_errors"),
    ("Chain ID",                  "chain_id"),
]


# ────────────────────────────────────────────────────────────────────
#  helper: group methodology_findings by attack class
# ────────────────────────────────────────────────────────────────────


def _findings_by_attack_class(s):
    """Group methodology_findings into buckets the rules consume.

    Buckets are keyed by the attack class / outcome we want a distinct
    rule to fire on:

      confirmed_sig_stripping  - signature_stripping CONFIRMED
      confirmed_xsw_admin      - XSW family CONFIRMED + admin_impersonation
      confirmed_xsw_user       - XSW family CONFIRMED + user_impersonation
      confirmed_comment_inj    - comment_injection_nameid CONFIRMED
      confirmed_replay         - replay_attack_3x CONFIRMED
      confirmed_audience       - audience_mismatch CONFIRMED
      confirmed_expired        - expired_assertion CONFIRMED
      suspected_any            - confidence=SUSPECTED (any kind)
    """
    buckets = {
        "confirmed_sig_stripping":  [],
        "confirmed_xsw_admin":      [],
        "confirmed_xsw_user":       [],
        "confirmed_comment_inj":    [],
        "confirmed_replay":         [],
        "confirmed_audience":       [],
        "confirmed_expired":        [],
        "suspected_any":            [],
    }
    xsw_kinds = ("xsw_clone_sibling", "xsw_wrap_extensions",
                 "xsw_clone_after", "xsw_wrap_object",
                 "xsw_multi_assertion")

    for f in (s.get("methodology_findings") or []):
        conf = f.get("confidence", "INFO")
        kind = f.get("kind", "")
        priv = f.get("privilege", "")
        if conf == "CONFIRMED":
            if kind == "signature_stripping":
                buckets["confirmed_sig_stripping"].append(f)
            elif kind in xsw_kinds:
                if priv == "admin_impersonation":
                    buckets["confirmed_xsw_admin"].append(f)
                else:
                    buckets["confirmed_xsw_user"].append(f)
            elif kind == "comment_injection_nameid":
                buckets["confirmed_comment_inj"].append(f)
            elif kind == "replay_attack_3x":
                buckets["confirmed_replay"].append(f)
            elif kind == "audience_mismatch":
                buckets["confirmed_audience"].append(f)
            elif kind == "expired_assertion":
                buckets["confirmed_expired"].append(f)
        elif conf == "SUSPECTED":
            buckets["suspected_any"].append(f)
    return buckets


# ────────────────────────────────────────────────────────────────────
#  INFO rules: scan didn't run for input/env reasons
# ────────────────────────────────────────────────────────────────────


def rule_input_missing(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "requires target + acs_url" not in reason:
        return None
    return {
        "name": "SAML signature audit skipped - required inputs missing",
        "severity": "INFO",
        "evidence": ("This audit needs three inputs: (1) target SAML SP "
                     "base URL, (2) options.acs_url (the Assertion "
                     "Consumer Service endpoint that processes SAML "
                     "responses), and (3) options.saml_response - a "
                     "base64-encoded SAML response captured from a real "
                     "successful login. Capture it via browser DevTools "
                     "Network tab during a working SSO sign-in."),
        "remediation": ("Re-run the scan with options.acs_url and "
                        "options.saml_response populated. The customer "
                        "must supply a valid SAML response baseline so "
                        "the auditor can construct signed-preserving "
                        "wrapped variants."),
        "cwe": "CWE-1006",
    }


def rule_invalid_saml(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "saml_response not valid base64 xml" not in reason:
        return None
    return {
        "name": "Provided saml_response is not valid base64 XML",
        "severity": "INFO",
        "evidence": ("The saml_response option failed base64-decode or "
                     "XML-parse. Skip reason: " +
                     (s.get("skipped_reason") or "unknown")),
        "remediation": ("Capture the SAMLResponse parameter exactly as it "
                        "appears in the browser's POST to /acs (URL-decode "
                        "but do NOT XML-parse it before passing). It is a "
                        "single base64 string."),
        "cwe": "CWE-1006",
    }


def rule_lxml_missing(s):
    if not s.get("lxml_missing"):
        return None
    return {
        "name": "lxml not installed - SAML signature audit cannot run",
        "severity": "INFO",
        "evidence": ("This scanner requires the lxml Python library to "
                     "parse + manipulate XML signatures. The current "
                     "container does not have lxml installed."),
        "remediation": ("Install lxml in the backend image (pip install "
                        "lxml). Most Kali-derived images ship it already, "
                        "but a stripped Alpine base may need it added to "
                        "the Dockerfile."),
        "cwe": "CWE-1006",
    }


def rule_httpx_missing(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "httpx python library not installed" not in reason:
        return None
    return {
        "name": "httpx not installed - cannot POST forged SAML responses",
        "severity": "INFO",
        "evidence": ("This scanner uses httpx to send crafted SAML "
                     "responses to the ACS endpoint. The current "
                     "container is missing httpx."),
        "remediation": "Add httpx to the backend image (pip install httpx).",
        "cwe": "CWE-1006",
    }


def rule_target_unreachable(s):
    reason = (s.get("skipped_reason") or "").lower()
    if "not reachable over http" not in reason:
        return None
    return {
        "name": "SAML SP target not reachable - audit could not run",
        "severity": "INFO",
        "evidence": s.get("skipped_reason") or "Target unreachable",
        "remediation": ("Verify the target URL is correct + reachable from "
                        "the scanner host. If the SP is behind VPN/IP "
                        "allowlist, scan from an internal vantage."),
        "cwe": "CWE-1006",
    }


# ────────────────────────────────────────────────────────────────────
#  Fingerprint-based posture rules (run regardless of acceptance)
# ────────────────────────────────────────────────────────────────────


def rule_sha1_signature(s):
    """SHA-1 in signature algorithm is deprecated since NIST SP 800-131A.
    SHA-1 collision attacks are practical since SHAttered (2017)."""
    fp = s.get("fingerprint") or {}
    sig_alg = (fp.get("sig_alg") or "").lower()
    if "sha1" not in sig_alg:
        return None
    return {
        "name": "SAML response signed with SHA-1 - deprecated digest",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "evidence": ("Signature algorithm in the captured SAML response "
                     "uses SHA-1, which is deprecated by NIST SP 800-131A "
                     "and considered cryptographically broken since "
                     "SHAttered (2017). Detected sig_alg: '" +
                     str(fp.get("sig_alg")) + "'."),
        "remediation": ("Reconfigure the Identity Provider to sign SAML "
                        "responses with RSA-SHA256 (or stronger). For "
                        "ADFS: Set-AdfsRelyingPartyTrust -SignatureAlgorithm "
                        "'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'. "
                        "For Okta/Azure AD: SHA-256 is default - verify "
                        "no legacy override is set on this SP."),
    }


def rule_no_assertion_signature(s):
    """Response-level signature only, no per-assertion signature. Some
    XSW variants exploit this gap by wrapping the unsigned assertion
    inside a signed response envelope."""
    fp = s.get("fingerprint") or {}
    if not (fp.get("has_assertion_signature") is False
            and fp.get("has_response_signature") is True):
        return None
    return {
        "name": "Only response-level SAML signature - assertion unsigned",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "evidence": ("Captured SAML response has a Signature on the "
                     "<samlp:Response> element but NOT on the inner "
                     "<saml:Assertion>. Several XSW variants (XSW3/XSW7) "
                     "specifically target this gap by injecting a forged "
                     "Assertion that the signed Response envelope still "
                     "validates."),
        "remediation": ("Reconfigure the IdP to sign the Assertion itself "
                        "(not just the Response wrapper). For Okta: enable "
                        "'Sign Assertion' under SAML settings. For ADFS: "
                        "Set-AdfsRelyingPartyTrust -SamlResponseSignature "
                        "'AssertionOnly' or 'MessageAndAssertion'."),
    }


# ────────────────────────────────────────────────────────────────────
#  CONFIRMED-bypass rules
# ────────────────────────────────────────────────────────────────────


def rule_confirmed_signature_stripping(s):
    g = _findings_by_attack_class(s)
    if not g["confirmed_sig_stripping"]:
        return None
    f = g["confirmed_sig_stripping"][0]
    return {
        "name": ("CRITICAL: SAML signature stripping accepted - "
                 "unsigned SAML responses authenticate any user"),
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "evidence": ("The ACS endpoint accepted a SAML response with the "
                     "<ds:Signature> element removed entirely - the SP "
                     "does not enforce signature presence. Verification "
                     "method: " + str(f.get("verification_method", "")) +
                     ". HTTP signal: " + str(f.get("signal", "")) +
                     ". Anyone can forge a SAML response that grants any "
                     "identity full access to this SP."),
        "remediation": ("CRITICAL - fix immediately. The SAML library / "
                        "ACS handler must REJECT any SAML response that "
                        "lacks a valid ds:Signature element. For "
                        "python-saml/python3-saml: set 'wantAssertionsSigned' "
                        "+ 'wantMessagesSigned' = True. For java-saml-toolkit: "
                        "WantAssertionsSigned=true. For Shibboleth SP: "
                        "signing='true' in attribute-policy.xml. Rotate IdP "
                        "signing key after fix in case existing tokens "
                        "are circulating."),
    }


def rule_confirmed_xsw_admin(s):
    g = _findings_by_attack_class(s)
    if not g["confirmed_xsw_admin"]:
        return None
    variants = sorted({f.get("variant", "?") for f in g["confirmed_xsw_admin"]})
    return {
        "name": ("CRITICAL: SAML XML Signature Wrapping (XSW) - "
                 f"admin impersonation via {', '.join(variants)}"),
        "severity": "CRITICAL",
        "cvss": "9.4",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "evidence": ("The ACS endpoint accepted XSW-wrapped SAML "
                     f"responses ({len(g['confirmed_xsw_admin'])} variant"
                     "(s)) that preserve the original signed Assertion "
                     "verbatim (signature still validates) but inject a "
                     "second, unsigned, copy with NameID rewritten to an "
                     "admin identity. Verified by re-sending with a "
                     "different NameID and confirming the SP also "
                     "accepted that. Affected XSW variants: " +
                     ", ".join(variants) + "."),
        "remediation": ("CRITICAL - the SAML processor must enforce that "
                        "the SIGNED element is the SAME element it then "
                        "reads identity from (no decoupling). Switch to a "
                        "SAML library that mandates id-Reference matching "
                        "(python3-saml >=1.16, OneLogin Ruby SAML >=1.18.0, "
                        "Shibboleth SP >=3.4). Audit attribute extraction "
                        "code: must use XPath that's anchored to the "
                        "signature's URI Reference, not document-order or "
                        "first-match. Rotate IdP signing key + invalidate "
                        "all active sessions after fix."),
    }


def rule_confirmed_xsw_user(s):
    g = _findings_by_attack_class(s)
    if not g["confirmed_xsw_user"]:
        return None
    variants = sorted({f.get("variant", "?") for f in g["confirmed_xsw_user"]})
    return {
        "name": ("HIGH: SAML XML Signature Wrapping (XSW) - "
                 f"user impersonation via {', '.join(variants)}"),
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "evidence": ("The ACS endpoint accepted XSW-wrapped SAML "
                     f"responses ({len(g['confirmed_xsw_user'])} variant"
                     "(s)) targeting a non-admin identity. Even without "
                     "admin escalation, this lets an attacker authenticate "
                     "as any tenant user. Verified by re-sending with "
                     "different NameID. Variants: " + ", ".join(variants) + "."),
        "remediation": ("Apply the same XSW fix as admin-class - the "
                        "underlying defect is identical, only the chosen "
                        "victim identity differs. See: enforce signed-"
                        "element / identity-element coupling; upgrade SAML "
                        "library; audit attribute extraction XPath."),
    }


def rule_confirmed_comment_injection(s):
    g = _findings_by_attack_class(s)
    if not g["confirmed_comment_inj"]:
        return None
    return {
        "name": ("HIGH: SAML NameID comment-injection accepted - "
                 "parser drops comments after signature validation"),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "evidence": ("The ACS endpoint accepted a SAML response with "
                     "<NameID>admin@victim.com<!--user@victim.com-->"
                     "</NameID>. The signature validates against the "
                     "canonical bytes (which include the comment) but "
                     "the application reads the text-content of NameID "
                     "(which the parser normalizes to drop comments), "
                     "yielding the admin identity. Class: "
                     "CVE-2018-0489 / Duo Bypass (2018)."),
        "remediation": ("Upgrade the SAML library to a version that "
                        "uses str() on the NameID node BEFORE signature "
                        "validation, not after - or that explicitly "
                        "rejects NameID elements containing comments. "
                        "python3-saml >=1.16.0 contains the fix; "
                        "ruby-saml >=1.7.2 (CVE-2017-11428). Rotate keys "
                        "+ invalidate sessions."),
    }


def rule_confirmed_replay_accepted(s):
    g = _findings_by_attack_class(s)
    if not g["confirmed_replay"]:
        return None
    return {
        "name": ("MEDIUM: SAML replay protection missing - same response "
                 "accepted 3 times within 30s"),
        "severity": "MEDIUM",
        "cvss": "6.5",
        "cwe": "CWE-294",
        "owasp": "A02:2021",
        "evidence": ("The ACS endpoint accepted the identical SAML "
                     "response (same AssertionID, same signature) on "
                     "every one of 3 sends within a ~2s window. SAML "
                     "AssertionID must be one-time-use per RFC 7522. "
                     "Without replay protection, a captured SAML "
                     "response stays valid for the entire NotOnOrAfter "
                     "window."),
        "remediation": ("Implement AssertionID replay cache in the SP. "
                        "Store each consumed AssertionID until "
                        "NotOnOrAfter expires, reject duplicates. For "
                        "python3-saml: use the OneLogin replay-detection "
                        "extension. For Shibboleth SP: enable "
                        "ReplayCache. For ADFS-protected apps: this is "
                        "enforced by ADFS itself; if the SP is custom, "
                        "build a Redis-backed nonce cache."),
    }


def rule_confirmed_audience_not_validated(s):
    g = _findings_by_attack_class(s)
    if not g["confirmed_audience"]:
        return None
    return {
        "name": ("MEDIUM: SAML AudienceRestriction not enforced - "
                 "SP accepted assertion bound to attacker.com"),
        "severity": "MEDIUM",
        "cvss": "6.5",
        "cwe": "CWE-345",
        "owasp": "A02:2021",
        "evidence": ("The ACS endpoint accepted a SAML response whose "
                     "<saml:Audience> was rewritten to 'https://attacker"
                     ".com/audience'. The SP did not verify that the "
                     "Audience matches its own EntityID. An attacker "
                     "who captures a SAML response intended for ANOTHER "
                     "SP can replay it here."),
        "remediation": ("The SAML library must verify "
                        "AudienceRestriction.Audience matches the SP's "
                        "configured EntityID, and REJECT otherwise. For "
                        "python3-saml: set 'strict' = True in settings + "
                        "configure 'sp.entityId' correctly. For "
                        "OneLogin/Auth0/Okta hosted SAML: typically "
                        "enforced; if you see this finding, an SP-side "
                        "override has disabled it."),
    }


def rule_confirmed_expired_assertion_accepted(s):
    g = _findings_by_attack_class(s)
    if not g["confirmed_expired"]:
        return None
    return {
        "name": ("HIGH: SAML expired-assertion accepted - SP ignores "
                 "Conditions/NotOnOrAfter"),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-613",
        "owasp": "A02:2021",
        "evidence": ("The ACS endpoint accepted a SAML response with "
                     "<Conditions NotOnOrAfter='2000-01-01T00:00:00Z'>. "
                     "A captured SAML response retains validity "
                     "indefinitely against this SP, eliminating the "
                     "time-bounded protection SAML assertions are "
                     "supposed to have."),
        "remediation": ("The SAML library must compare Conditions/"
                        "NotOnOrAfter against current time and REJECT "
                        "expired assertions. For python3-saml: set "
                        "'strict' = True. For java-saml-toolkit: "
                        "enforceTimestamp=true. Verify clock-skew "
                        "tolerance is small (<=2 minutes)."),
    }


def rule_suspected_saml_bypass(s):
    g = _findings_by_attack_class(s)
    if not g["suspected_any"]:
        return None
    suspected = g["suspected_any"]
    kinds = sorted({f.get("kind", "?") for f in suspected})
    return {
        "name": (f"SUSPECTED SAML signature bypass ({len(suspected)} "
                 "variant(s)) - manual confirmation needed"),
        "severity": "LOW",
        "cvss": "3.7",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "evidence": ("First send appeared to be accepted but the retest "
                     "with a different NameID was rejected. This can "
                     "indicate session-specific acceptance (the original "
                     "SAML response was reusable but the SP wouldn't "
                     "accept a wrapped clone with a different identity), "
                     "or a transient acceptance signal we mis-interpreted. "
                     "Affected variants: " + ", ".join(kinds) + "."),
        "remediation": ("Manually reproduce: capture a fresh SAML "
                        "response, craft the same XSW variant by hand "
                        "(see SAMLRaider in Burp), and verify against "
                        "the ACS. If a different NameID is also "
                        "accepted, treat as CONFIRMED + escalate to "
                        "CRITICAL/HIGH."),
    }


# ────────────────────────────────────────────────────────────────────
#  POSITIVE rule: clean posture
# ────────────────────────────────────────────────────────────────────


def rule_clean_saml_posture(s):
    """Fires when: 0 bypasses accepted + assertion signed + audience set +
    SHA-256 (or stronger). Confirms a clean SP posture."""
    hits = s.get("quick_probe_hits", 0)
    if hits > 0:
        return None
    # Don't fire if there are any CONFIRMED accepted methodology findings
    confirmed_any = [f for f in (s.get("methodology_findings") or [])
                     if f.get("confidence") == "CONFIRMED" and f.get("accepted")]
    if confirmed_any:
        return None
    fp = s.get("fingerprint") or {}
    sig_alg = (fp.get("sig_alg") or "").lower()
    if "sha1" in sig_alg or sig_alg in ("", "unknown"):
        return None
    if not fp.get("has_assertion_signature"):
        return None
    if not (fp.get("audience") or "").strip():
        return None
    # Need to have actually run probes (not skipped at pre_flight)
    if s.get("quick_probe_attempts", 0) == 0:
        return None
    return {
        "name": ("SAML SP implementation rejects all XSW variants + "
                 "signature stripping - signature validation appears "
                 "correct"),
        "severity": "POSITIVE",
        "evidence": (f"Tried {s.get('quick_probe_attempts', 0)} XSW "
                     "variants (clone-sibling, wrap-extensions, signature-"
                     "stripping, comment-injection, replay) - all "
                     "rejected. Assertion is signed with " +
                     str(fp.get("sig_alg")) + ", AudienceRestriction is "
                     "set to '" + str(fp.get("audience"))[:80] + "', and "
                     "SHA-1 is not in use."),
        "remediation": ("Maintain current posture. Monitor for SAML "
                        "library CVEs (python3-saml, ruby-saml, java-saml-"
                        "toolkit) and apply patches within 14 days. "
                        "Consider periodic rotation of the IdP signing "
                        "key (annual minimum)."),
        "cwe": "CWE-1006",
        "owasp": "A02:2021",
    }


# ────────────────────────────────────────────────────────────────────
#  Chain handoff rule
# ────────────────────────────────────────────────────────────────────


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed SAML bypass enables downstream scanners: " +
                     ", ".join(chain_next)),
        "remediation": ("The VL-METHOD chaining engine will automatically "
                        "spawn: " + ", ".join(chain_next) + ". These "
                        "inherit the bypass context (forged session "
                        "cookie / chain_id) and run post-exploit / "
                        "session-prediction probes."),
        "cwe": "CWE-1006",
    }


# ────────────────────────────────────────────────────────────────────
#  Export
# ────────────────────────────────────────────────────────────────────


SAML_SIGNATURE_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_invalid_saml,
    rule_lxml_missing,
    rule_httpx_missing,
    rule_target_unreachable,
    rule_sha1_signature,
    rule_no_assertion_signature,
    rule_confirmed_signature_stripping,
    rule_confirmed_xsw_admin,
    rule_confirmed_xsw_user,
    rule_confirmed_comment_injection,
    rule_confirmed_replay_accepted,
    rule_confirmed_audience_not_validated,
    rule_confirmed_expired_assertion_accepted,
    rule_suspected_saml_bypass,
    rule_clean_saml_posture,
    rule_chain_handoff,
]
