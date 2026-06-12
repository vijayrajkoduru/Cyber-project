"""open_redirect_probe - findings rules.

An open redirect on a trusted domain is a phishing-link-laundering
primitive: the lure URL stays on the brand the victim (and the mail
filter) trusts, while the server bounces the click to the attacker's
harvest page.

ZERO-FALSE-POSITIVE rule: HIGH fires ONLY when a real HTTP probe ran
(openredir_evaluated) AND the server returned a 3xx whose Location host
exactly equals the non-routable canary host we injected
(openredir_confirmed). Anything else - same-origin redirect, relative
Location, 2xx, fetch failure - is INFO/POSITIVE, never HIGH.

Severity model:
  HIGH     - confirmed off-site redirect to the injected canary host
  INFO     - no redirect_url / httpx missing / fetch failed
  INFO     - probe ran but endpoint did NOT redirect off-site (evidence
             of not-vulnerable behaviour, recorded for the report)
  POSITIVE - endpoint sanitized/refused the off-site target (2xx or
             same-origin Location)
"""

_CWE_OPENREDIR = "CWE-601"   # URL Redirection to Untrusted Site (Open Redirect)
_NIST = "NIST 800-53 SI-10 (Information Input Validation)"


def rule_input_missing(s):
    if not s.get("openredir_input_missing"):
        return None
    return {
        "name": "Open-redirect probe skipped - no options.redirect_url supplied",
        "severity": "INFO",
        "evidence": (
            "This probe needs a URL on your own domain that performs a "
            "redirect, via options.redirect_url. Put the literal token "
            "`VL_REDIR` where the redirect target value goes (e.g. "
            "https://acme.com/login?next=VL_REDIR), or supply a URL whose "
            "redirect parameter the probe can auto-detect."
        ),
        "remediation": (
            "Re-run with options.redirect_url set. The probe injects a "
            "non-routable .invalid canary as the redirect target and only "
            "READS the 3xx Location header - it never follows the redirect "
            "and performs no exploitation."
        ),
        "cwe": "CWE-1006",
    }


def rule_dep_or_fetch(s):
    err = s.get("openredir_error") or ""
    if not err:
        return None
    if "not installed" in err.lower():
        return {
            "name": "Open-redirect probe skipped - httpx not installed",
            "severity": "INFO",
            "evidence": err,
            "remediation": "Install httpx on the scanner host: pip install httpx.",
            "cwe": "CWE-1006",
        }
    return {
        "name": "Open-redirect probe could not run",
        "severity": "INFO",
        "evidence": err,
        "remediation": (
            "Confirm the redirect_url is reachable from the scanner egress IP "
            "and is well-formed. Re-run after fixing."
        ),
        "cwe": "CWE-1006",
    }


def rule_confirmed(s):
    # HIGH ONLY on a confirmed off-site redirect to our injected canary.
    if not s.get("openredir_evaluated"):
        return None
    if not s.get("openredir_confirmed"):
        return None
    return {
        "name": (f"Open redirect CONFIRMED on {s.get('openredir_probe_url', '?')}"
                 " - trusted domain can launder phishing links off-site"),
        "severity": "HIGH",
        "cvss": "6.1",
        "cwe": _CWE_OPENREDIR,
        "cwe_name": "URL Redirection to Untrusted Site (Open Redirect)",
        "owasp": "A01:2021",
        "verified_exploit": True,   # we observed the off-site 3xx, not inferred it
        "evidence": (
            f"GET {s.get('openredir_probe_url')} returned HTTP "
            f"{s.get('openredir_status')} with "
            f"`Location: {s.get('openredir_location')}` - the Location host "
            f"is `{s.get('openredir_location_host')}`, which is the external "
            f"canary `{s.get('openredir_canary_host')}` the probe injected. "
            "The endpoint therefore redirects to an arbitrary off-site host "
            "supplied in the request. A phisher can send "
            f"`{s.get('openredir_input_url')}` (which mail filters and users "
            "trust because it is on your domain) and silently bounce the "
            "victim to a credential-harvest page. NOTE: the canary uses the "
            "reserved .invalid TLD and never resolves - no redirect was "
            "followed; only the capability was confirmed."
        ),
        "remediation": (
            "Do not reflect a caller-supplied URL into a redirect. Instead: "
            "(1) redirect only to a server-side allowlist of known paths "
            "keyed by a short token, OR (2) reject any redirect target whose "
            "host is not exactly your own registrable domain (compare the "
            "parsed host, not a substring/prefix - `acme.com.evil.com` and "
            "`//evil.com` are classic bypasses), OR (3) show an interstitial "
            "'you are leaving acme.com' confirmation page for off-site "
            f"targets. Compliance: {_NIST}, OWASP Unvalidated Redirects and "
            "Forwards Cheat Sheet."
        ),
    }


def rule_not_vulnerable(s):
    # INFO evidence: a probe ran and the endpoint did NOT redirect off-site.
    if not s.get("openredir_evaluated"):
        return None
    if s.get("openredir_confirmed"):
        return None
    status = s.get("openredir_status")
    loc_host = s.get("openredir_location_host")
    # POSITIVE when there WAS a redirect but it stayed same-origin / sanitized.
    if s.get("openredir_is_3xx") and loc_host and loc_host != s.get("openredir_canary_host"):
        return {
            "name": (f"Redirect endpoint sanitized the off-site target "
                     f"({s.get('openredir_input_url', '?')})"),
            "severity": "POSITIVE",
            "evidence": (
                f"GET {s.get('openredir_probe_url')} returned HTTP {status} "
                f"with Location host `{loc_host}` - the server did NOT honor "
                "the injected external canary as the redirect target, so an "
                "attacker cannot redirect arbitrary off-site from this URL."
            ),
            "remediation": (
                "Maintain the allowlist / same-origin enforcement on this "
                "redirect endpoint. Re-test if the redirect logic changes."
            ),
            "cwe": _CWE_OPENREDIR,
            "owasp": "A01:2021",
        }
    # Otherwise (2xx, or 3xx with no/relative Location): not an open redirect.
    return {
        "name": (f"Redirect endpoint did not redirect off-site "
                 f"({s.get('openredir_input_url', '?')})"),
        "severity": "INFO",
        "evidence": (
            f"GET {s.get('openredir_probe_url')} returned HTTP {status} "
            f"with Location `{s.get('openredir_location') or '(none)'}`. The "
            "injected external canary host was not reflected into an off-site "
            "redirect, so no open-redirect capability was confirmed at this "
            "URL. (If you expected a redirect here, confirm you marked the "
            "correct parameter with VL_REDIR and re-run.)"
        ),
        "remediation": (
            "No action required for this URL. If your app has OTHER redirect "
            "parameters, re-run the probe against each."
        ),
        "cwe": _CWE_OPENREDIR,
    }


OPEN_REDIRECT_PROBE_FINDING_RULES = [
    rule_input_missing,
    rule_dep_or_fetch,
    rule_confirmed,
    rule_not_vulnerable,
]
