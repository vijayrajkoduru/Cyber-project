"""csp_bypass_audit - findings rules.

Severity model (CSP is a defense-in-depth layer — its absence/weakness
is a MISSING MITIGATION, not a demonstrated exploit; other controls
[output encoding, framework auto-escaping, WAF] may still block XSS):
  HIGH     - no CSP at all (no defense-in-depth XSS mitigation layer;
             downgraded from CRITICAL — a missing header is not a proven
             exploit and other controls may apply)
  HIGH     - each individual bypass class (unsafe-inline, JSONP host, etc.)
  INFO     - report-only mode (CSP gathers data but doesn't block)
  POSITIVE - strict-CSP best practice (nonces/hashes, object-src 'none',
             base-uri 'self', script-src no wildcards / unsafe-*)
"""


def rule_no_csp(s):
    if not s.get("csp_no_csp_at_all"):
        return None
    return {
        "name": "No Content-Security-Policy present on target URL",
        "severity": "HIGH",
        "cvss": "6.1",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
        "verified_exploit": False,
        "evidence": (f"GET {s.get('csp_target_url')} returned no "
                     "Content-Security-Policy response header and no "
                     "<meta http-equiv='Content-Security-Policy'> tag was "
                     "found in the rendered HTML. CSP is a defense-in-depth "
                     "layer, so its absence is a MISSING MITIGATION rather "
                     "than a demonstrated exploit — other controls (output "
                     "encoding, framework auto-escaping, a WAF) may still "
                     "block XSS. However, should a reflected or stored XSS "
                     "exist on this page it would execute with no CSP "
                     "mitigation layer to contain it."),
        "remediation": (
            "Deploy a strict CSP that pins script-src to a nonce or hash, "
            "locks object-src 'none', base-uri 'self', and frame-ancestors "
            "to a whitelist. Start in Report-Only via "
            "Content-Security-Policy-Report-Only + a report-uri / "
            "report-to endpoint, observe violations for 1-2 weeks, then "
            "flip to enforcement. Reference: "
            "https://csp.withgoogle.com/docs/strict-csp.html"
        ),
    }


def rule_unsafe_inline(s):
    summ = s.get("csp_summary") or {}
    if not summ.get("unsafe_inline_script"):
        return None
    return {
        "name": "CSP allows 'unsafe-inline' for script-src",
        "severity": "HIGH",
        "cvss": "7.2",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "evidence": ("script-src (or default-src) contains 'unsafe-inline'. "
                     "Any reflected/stored XSS that injects an inline "
                     "<script> tag or inline event handler executes "
                     "successfully — CSP is providing zero protection "
                     "against XSS on this page."),
        "remediation": (
            "Migrate to a nonce-based CSP: add a per-response random nonce "
            "to script-src 'nonce-{rand}', remove 'unsafe-inline', then "
            "add nonce attributes to every legitimate inline <script>. "
            "Browsers that support CSP Level 2 ignore 'unsafe-inline' "
            "when a nonce/hash is present, so back-compat is automatic."
        ),
    }


def rule_unsafe_eval(s):
    summ = s.get("csp_summary") or {}
    if not summ.get("unsafe_eval_script"):
        return None
    return {
        "name": "CSP allows 'unsafe-eval' for script-src",
        "severity": "HIGH",
        "cvss": "6.5",
        "cwe": "CWE-95",
        "owasp": "A03:2021",
        "evidence": ("script-src (or default-src) contains 'unsafe-eval'. "
                     "eval(), new Function(), setTimeout(string), and "
                     "setInterval(string) are unrestricted — an attacker "
                     "who can inject a string into one of these sinks "
                     "achieves arbitrary JS execution."),
        "remediation": (
            "Audit the codebase for eval/new Function/string-form "
            "setTimeout/setInterval and migrate to compiled / pre-parsed "
            "code. Modern bundlers (Webpack/Vite/esbuild) require zero "
            "'unsafe-eval' for production builds. After removal, drop "
            "'unsafe-eval' from CSP."
        ),
    }


def rule_jsonp_hosts(s):
    summ = s.get("csp_summary") or {}
    hosts = summ.get("jsonp_trusted_hosts") or []
    if not hosts:
        return None
    return {
        "name": (f"CSP whitelists {len(hosts)} JSONP / open-callback host(s) "
                  "— bypassable"),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-829",
        "owasp": "A05:2021",
        "evidence": ("script-src whitelists: " + ", ".join(sorted(hosts)) +
                     ". These hosts serve callback-style JSONP endpoints "
                     "(e.g. ajax.googleapis.com/ajax/libs/angularjs/1.2.x/) "
                     "that an attacker can leverage as `?callback=alert(1)` "
                     "to execute arbitrary JS within your CSP."),
        "remediation": (
            "Replace the whitelist entry with a SubResource Integrity "
            "(SRI) hash for the exact CDN file you load, or self-host "
            "the resource. Reference Google's CSP bypass cheat sheet "
            "for the full list of bypassable trusted hosts: "
            "https://github.com/google/csp-evaluator"
        ),
    }


def rule_wildcard_or_scheme(s):
    summ = s.get("csp_summary") or {}
    bits = []
    if summ.get("wildcard_script_src"):
        bits.append("'*' wildcard")
    if summ.get("https_scheme_script"):
        bits.append("scheme-only source ('https:' / 'http:')")
    if summ.get("data_scheme_script"):
        bits.append("'data:' scheme")
    if not bits:
        return None
    return {
        "name": f"CSP script-src too permissive ({', '.join(bits)})",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
        "evidence": (f"script-src contains {', '.join(bits)}. Any host "
                     "an attacker controls can serve a script that runs "
                     "in your origin (data: lets the attacker inline a "
                     "base64-encoded payload directly)."),
        "remediation": (
            "Replace wildcards/scheme sources with the explicit list of "
            "CDN hostnames you actually use, each pinned via SRI. Better: "
            "switch to a nonce-based strict CSP — script-src 'self' "
            "'nonce-{rand}' 'strict-dynamic' — which Chrome/Firefox treat "
            "as transitively trusting only scripts loaded by your nonced "
            "ones, eliminating the need for any host whitelist."
        ),
    }


def rule_missing_object_src(s):
    summ = s.get("csp_summary") or {}
    if not summ.get("missing_object_src"):
        return None
    return {
        "name": "CSP missing object-src 'none' (plugin XSS pivot open)",
        "severity": "HIGH",
        "cvss": "6.5",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
        "evidence": ("object-src is not set (or not 'none'). An attacker "
                     "with an HTML-injection primitive can drop <object>, "
                     "<embed>, or <applet> elements pointing at a flash "
                     ".swf / .jar / .xap that runs in your origin and "
                     "exfiltrates cookies / DOM."),
        "remediation": (
            "Add `object-src 'none'` to CSP. There is essentially no "
            "modern use case for browser plugins — Chrome and Firefox "
            "removed NPAPI/PPAPI entirely in 2020-2021. This is a free "
            "win that breaks no production traffic."
        ),
    }


def rule_missing_base_uri(s):
    summ = s.get("csp_summary") or {}
    if not summ.get("missing_base_uri"):
        return None
    return {
        "name": "CSP missing base-uri (dangling-markup / <base> hijack open)",
        "severity": "MEDIUM",
        "cvss": "5.4",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
        "evidence": ("base-uri directive is missing. An HTML-injection "
                     "attacker can insert <base href='https://evil/'> to "
                     "rewrite every relative URL in the document — "
                     "stealing form submissions, hijacking script loads, "
                     "and rerouting <a> clicks to the attacker's domain."),
        "remediation": (
            "Add `base-uri 'self'` (or 'none' if your app never uses "
            "<base>) to your CSP. This is a single-token addition that "
            "has zero impact on production."
        ),
    }


def rule_report_only_mode(s):
    summ = s.get("csp_summary") or {}
    if not summ.get("report_only_used"):
        return None
    # Only flag if there's NO enforcing CSP — otherwise report-only is fine
    # alongside an enforcing one.
    if (s.get("csp_policies_header") or s.get("csp_policies_meta")):
        return None
    return {
        "name": "Only Content-Security-Policy-Report-Only is present (no enforcement)",
        "severity": "HIGH",
        "cvss": "6.5",
        "cwe": "CWE-1021",
        "owasp": "A05:2021",
        "evidence": ("The target sets Content-Security-Policy-Report-Only "
                     "but no enforcing Content-Security-Policy header. "
                     "Browsers log violations to the report-uri but don't "
                     "block anything — i.e. CSP is providing zero runtime "
                     "mitigation."),
        "remediation": (
            "After a 1-2 week soak period reviewing violations, switch the "
            "header name from `Content-Security-Policy-Report-Only` to "
            "`Content-Security-Policy` to enforce the policy. Keep a "
            "separate Report-Only header during major refactors to "
            "test stricter policies."
        ),
    }


def rule_fetch_failed(s):
    err = s.get("csp_error")
    if not err:
        return None
    return {
        "name": "CSP audit could not fetch target URL",
        "severity": "INFO",
        "evidence": str(err)[:300],
        "remediation": ("Confirm the URL is reachable from the scanner host, "
                        "uses a valid scheme (http/https), and isn't blocked "
                        "by upstream WAF/firewall."),
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if s.get("csp_no_csp_at_all"):
        return None
    if s.get("csp_error"):
        return None
    summ = s.get("csp_summary") or {}
    weak = any(summ.get(k) for k in (
        "unsafe_inline_script", "unsafe_eval_script", "wildcard_script_src",
        "https_scheme_script", "data_scheme_script", "missing_object_src",
        "missing_base_uri",
    ))
    if weak or summ.get("jsonp_trusted_hosts"):
        return None
    if not summ.get("script_src_present"):
        return None
    return {
        "name": "Strict CSP detected (no obvious bypass class)",
        "severity": "POSITIVE",
        "evidence": (f"{summ.get('policy_count', 0)} CSP policy/policies "
                     "evaluated, none of the bypass classes "
                     "(unsafe-inline, unsafe-eval, '*', 'https:', "
                     "'data:', JSONP-trusted host, missing object-src, "
                     "missing base-uri) triggered. script-src is "
                     "explicitly defined."),
        "remediation": ("Maintain CSP nonces/hashes during refactors. "
                        "Re-run after every front-end deploy — adding a "
                        "third-party widget can silently weaken the "
                        "policy."),
        "cwe": "CWE-1021",
    }


CSP_BYPASS_AUDIT_FINDING_RULES = [
    rule_no_csp,
    rule_unsafe_inline,
    rule_unsafe_eval,
    rule_jsonp_hosts,
    rule_wildcard_or_scheme,
    rule_missing_object_src,
    rule_missing_base_uri,
    rule_report_only_mode,
    rule_fetch_failed,
    rule_positive,
]
