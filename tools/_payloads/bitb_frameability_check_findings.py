"""bitb_frameability_check - findings rules.

A login page that can be embedded in an <iframe> by an arbitrary origin
is the prerequisite for a Browser-in-the-Browser (BitB) attack and for
classic clickjacking. The defence is the page refusing to be framed.

ZERO-FALSE-POSITIVE rule: a graded (MEDIUM/LOW) severity is emitted ONLY
after a successful HTTP fetch whose framing-control headers were actually
parsed (bitb_fetched_ok is True). A failed/blocked fetch, a missing URL,
or a missing dependency is INFO — never graded.

A framable page is clickjacking/BitB *surface*, not a confirmed exploit. We
never frame the page, run JS, or demonstrate a working overlay — so a missing
XFO / frame-ancestors header is framable-advisory (LOW), not a graded MEDIUM
vulnerability.

Severity model:
  LOW      - page IS framable by any origin (no XFO deny + no/weak CSP
             frame-ancestors) -> BitB + clickjacking surface (advisory; no
             confirmed exploit)
  LOW      - only protection is the obsolete `X-Frame-Options: ALLOW-FROM`
             (ignored by modern browsers) and CSP doesn't cover it
  INFO     - no target_url / httpx missing / fetch failed / non-2xx page
  POSITIVE - framing denied by XFO DENY/SAMEORIGIN or CSP frame-ancestors
"""

_CWE_FRAMING = "CWE-1021"   # Improper Restriction of Rendered UI Layers (Clickjacking)
_NIST = "NIST 800-53 SC-18 (Mobile Code)"


def rule_input_missing(s):
    if not s.get("bitb_input_missing"):
        return None
    return {
        "name": "BitB frameability probe skipped - no options.target_url supplied",
        "severity": "INFO",
        "evidence": (
            "This probe needs the URL of the real login page via "
            "options.target_url (e.g. https://acme.com/login) so it can read "
            "the framing-control response headers."
        ),
        "remediation": (
            "Re-run with options.target_url set to your login page. The probe "
            "only performs a read-only GET and inspects response headers - it "
            "frames nothing and runs no JavaScript."
        ),
        "cwe": "CWE-1006",
    }


def rule_dep_missing(s):
    err = s.get("bitb_error") or ""
    if "not installed" not in err.lower():
        return None
    return {
        "name": "BitB frameability probe skipped - missing Python dependency",
        "severity": "INFO",
        "evidence": err,
        "remediation": "Install httpx on the scanner host: pip install httpx.",
        "cwe": "CWE-1006",
    }


def rule_fetch_failed(s):
    err = s.get("bitb_error") or ""
    if "fetch failed" not in err.lower():
        return None
    return {
        "name": "BitB frameability probe failed - couldn't fetch target_url",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "Confirm the URL is reachable from the scanner egress IP. If your "
            "login page is behind a WAF / geo-block, allowlist the scanner IP "
            "for this probe."
        ),
        "cwe": "CWE-1006",
    }


def rule_framable(s):
    # MEDIUM only on a real, parsed response.
    if not s.get("bitb_fetched_ok"):
        return None
    v = s.get("bitb_verdict") or {}
    if not v.get("framable_by_any"):
        return None
    fa = s.get("bitb_frame_ancestors")
    why = ("no X-Frame-Options deny and "
           + ("CSP frame-ancestors permits a wildcard origin"
              if v.get("fa_wildcard")
              else "no CSP frame-ancestors directive"))
    return {
        "name": (f"Login page {s.get('bitb_target_url', '?')} is framable by "
                 "any origin - Browser-in-the-Browser / clickjacking surface"),
        "severity": "LOW",
        "cvss": "4.3",
        "cwe": _CWE_FRAMING,
        "cwe_name": "Improper Restriction of Rendered UI Layers (Clickjacking)",
        "owasp": "A05:2021",
        "evidence": (
            f"GET {s.get('bitb_target_url')} returned HTTP "
            f"{s.get('bitb_http_status')} with {why}. "
            f"X-Frame-Options: {v.get('xfo_value') or 'absent'}. "
            f"CSP frame-ancestors: "
            f"{(' '.join(fa) if fa else 'absent')}. "
            "Because the page does not refuse framing, the page is potentially "
            "embeddable inside a Browser-in-the-Browser overlay or a "
            "clickjacking frame. This is framable SURFACE (advisory) — the "
            "probe did not frame the page, run JavaScript, or demonstrate a "
            "working overlay, so no exploit is confirmed."
        ),
        "remediation": (
            "Add a framing-deny response header to the login page (and ideally "
            "all authenticated pages): `Content-Security-Policy: "
            "frame-ancestors 'none'` (or `'self'` if you legitimately embed "
            "your own login). Optionally add `X-Frame-Options: DENY` for "
            "legacy clients. Note that BitB renders fake chrome rather than a "
            "real iframe, so ALSO enforce phishing-resistant MFA (FIDO2 / "
            "passkeys) and origin-bound sessions, which a framed/overlaid "
            f"clone cannot replay. Compliance: {_NIST}, OWASP Clickjacking "
            "Defense Cheat Sheet."
        ),
    }


def rule_allow_from_only(s):
    # LOW: the only framing control is the obsolete ALLOW-FROM directive.
    if not s.get("bitb_fetched_ok"):
        return None
    v = s.get("bitb_verdict") or {}
    if v.get("framable_by_any"):
        return None  # already MEDIUM via rule_framable
    if not v.get("xfo_allow_from"):
        return None
    if v.get("fa_denies"):
        return None  # CSP already covers it properly
    return {
        "name": (f"Login page relies on obsolete `X-Frame-Options: ALLOW-FROM`"
                 " - ignored by modern browsers"),
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": _CWE_FRAMING,
        "owasp": "A05:2021",
        "evidence": (
            f"GET {s.get('bitb_target_url')} set "
            f"`X-Frame-Options: {v.get('xfo_value')}` and no enforcing CSP "
            "frame-ancestors directive. The `ALLOW-FROM` form of "
            "X-Frame-Options was never implemented by Chrome and was removed "
            "from Firefox/Edge, so it provides no framing protection in "
            "current browsers."
        ),
        "remediation": (
            "Replace `X-Frame-Options: ALLOW-FROM <uri>` with "
            "`Content-Security-Policy: frame-ancestors <uri>` (the modern, "
            "browser-honored equivalent). RFC 7034 §2.3."
        ),
    }


def rule_positive(s):
    if not s.get("bitb_fetched_ok"):
        return None
    v = s.get("bitb_verdict") or {}
    if v.get("framable_by_any"):
        return None
    if not (v.get("xfo_denies") or v.get("fa_denies")):
        return None
    return {
        "name": ("Login page refuses cross-origin framing "
                 "(Browser-in-the-Browser / clickjacking defended)"),
        "severity": "POSITIVE",
        "evidence": (
            f"GET {s.get('bitb_target_url')} denies framing via "
            f"{v.get('deny_reason')}. An attacker cannot embed the genuine "
            "login UI in an iframe to back a BitB or clickjacking lure."
        ),
        "remediation": (
            "Maintain: keep `frame-ancestors` (and/or X-Frame-Options) on "
            "every authenticated route, and pair it with phishing-resistant "
            "MFA so even a pixel-perfect fake-chrome clone cannot replay a "
            "session."
        ),
        "cwe": _CWE_FRAMING,
        "owasp": "A05:2021",
    }


BITB_FRAMEABILITY_CHECK_FINDING_RULES = [
    rule_input_missing,
    rule_dep_missing,
    rule_fetch_failed,
    rule_framable,
    rule_allow_from_only,
    rule_positive,
]
