"""cors_preflight_audit - findings rules.

Severity model:
  CRITICAL - Reflected/wildcard Origin + Allow-Credentials: true
             (attacker page reads authenticated responses)
  CRITICAL - "null" Origin allowed with credentials
             (sandboxed iframe / data: URL primitives)
  HIGH     - Reflected Origin without credentials
             (still reads public + IP-bound internal APIs)
  HIGH     - Null Origin accepted without credentials
  HIGH     - Mistyped / suffix-bypass / subdomain wildcard accepted
  MEDIUM   - HTTP downgrade accepted (mixed-content read)
  INFO     - Probe failed / target unreachable / no ACAO at all
  POSITIVE - ACAO present, locks to explicit origin(s), no reflection
"""


def _ev_list(rs):
    parts = []
    for r in rs[:6]:
        parts.append(
            f"sent Origin: {r.get('origin_sent','?')} -> "
            f"ACAO: {r.get('acao','-') or '-'}, "
            f"ACAC: {r.get('acac','-') or '-'}"
        )
    return " | ".join(parts)


def rule_wildcard_with_creds(s):
    rs = s.get("cors_wildcard_with_creds") or []
    if not rs:
        return None
    return {
        "name": ("CORS misconfig — wildcard Allow-Origin '*' + "
                  "Allow-Credentials: true (browser spec violation, but "
                  "exploitable on older middleware)"),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "evidence": _ev_list(rs),
        "remediation": (
            "Per the Fetch spec a browser MUST refuse `*` + credentials, "
            "but some Node middleware (cors npm < 2.8.5), nginx configs, "
            "and AWS API Gateway have edge cases that still leak. "
            "Remove the wildcard and replace with an explicit allowlist "
            "of trusted origins, validated server-side per request. "
            "Reference: https://fetch.spec.whatwg.org/#cors-protocol-and-credentials"
        ),
    }


def rule_reflected_with_creds(s):
    rs = [r for r in (s.get("cors_critical_hits") or [])
          if r.get("classify", {}).get("reflected_origin")
          and (r.get("acac") or "").strip().lower() == "true"]
    if not rs:
        return None
    return {
        "name": ("CORS misconfig — Origin reflected back AND "
                  "Allow-Credentials: true (authenticated cross-origin read)"),
        "severity": "CRITICAL",
        "cvss": "9.1",
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "evidence": _ev_list(rs),
        "remediation": (
            "Disable origin reflection entirely. Replace your dynamic "
            "`res.setHeader('Access-Control-Allow-Origin', req.headers.origin)` "
            "with a strict allowlist check:\n\n"
            "  const allow = new Set([\n"
            "    'https://app.example.com',\n"
            "    'https://api.partner.com',\n"
            "  ]);\n"
            "  if (allow.has(req.headers.origin)) {\n"
            "    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n"
            "    res.setHeader('Vary', 'Origin');\n"
            "  }\n\n"
            "Always add `Vary: Origin` to keep CDN caches from poisoning "
            "the response with the wrong allow-origin."
        ),
    }


def rule_null_with_creds(s):
    rs = [r for r in (s.get("cors_null_allowed") or [])
          if (r.get("acac") or "").strip().lower() == "true"]
    if not rs:
        return None
    return {
        "name": "CORS misconfig — 'null' Origin allowed with credentials",
        "severity": "CRITICAL",
        "cvss": "8.6",
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "evidence": _ev_list(rs),
        "remediation": (
            "Remove 'null' from the allowlist. Browsers send `Origin: null` "
            "from sandboxed iframes (<iframe sandbox>), data: URLs, "
            "and file:// pages. An attacker who can land such a page in "
            "the victim's browser (via XSS on ANY site, or an opened "
            ".html email attachment) can issue credentialed reads "
            "against your API."
        ),
    }


def rule_reflected_no_creds(s):
    rs = [r for r in (s.get("cors_reflected") or [])
          if (r.get("acac") or "").strip().lower() != "true"]
    if not rs:
        return None
    return {
        "name": "CORS misconfig — Origin reflected (no credentials)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "evidence": _ev_list(rs),
        "remediation": (
            "Even without credentials, reflected Origin lets any attacker "
            "page READ this API's responses — exposing public data, "
            "internal IP-bound endpoints (LAN dashboards, cloud metadata "
            "services). Lock down to an explicit allowlist."
        ),
    }


def rule_null_no_creds(s):
    rs = [r for r in (s.get("cors_null_allowed") or [])
          if (r.get("acac") or "").strip().lower() != "true"]
    if not rs:
        return None
    return {
        "name": "CORS misconfig — 'null' Origin allowed (no credentials)",
        "severity": "HIGH",
        "cvss": "6.5",
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "evidence": _ev_list(rs),
        "remediation": ("Remove 'null' from the allowlist — see the "
                        "credentials variant of this finding for the "
                        "threat model."),
    }


def rule_mistype_or_bypass(s):
    rs = s.get("cors_mistype_or_bypass") or []
    if not rs:
        return None
    flavours: set = set()
    for r in rs:
        c = r.get("classify") or {}
        for k in ("mistyped_allowed", "suffix_bypass",
                  "prefix_bypass", "evil_subdomain"):
            if c.get(k):
                flavours.add(k)
    return {
        "name": ("CORS allowlist bypass via Origin mistype / suffix / "
                  "subdomain match"),
        "severity": "HIGH",
        "cvss": "7.4",
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "evidence": (f"Bypass patterns accepted: {', '.join(sorted(flavours))}. "
                     f"{_ev_list(rs)}"),
        "remediation": (
            "Replace substring / endsWith / startsWith origin checks with "
            "EXACT string match against an allowlist Set. Common buggy "
            "patterns:\n"
            "  origin.endsWith('target.com')   // matches evil-target.com\n"
            "  origin.includes('target.com')   // matches anywhere\n"
            "  /target\\.com/.test(origin)     // unescaped regex\n"
            "Fix: `allowSet.has(origin)`."
        ),
    }


def rule_http_downgrade(s):
    rs = s.get("cors_http_downgrade") or []
    if not rs:
        return None
    return {
        "name": "CORS allows plain-HTTP version of same host (mixed-content downgrade)",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-942",
        "owasp": "A05:2021",
        "evidence": _ev_list(rs),
        "remediation": (
            "Restrict ACAO to the HTTPS scheme only. An MITM on the user's "
            "network can hijack any plain-HTTP request from the user's "
            "browser and use this allowance to issue cross-origin reads "
            "against your HTTPS API."
        ),
    }


def rule_probe_failed(s):
    err = s.get("cors_error")
    if not err:
        return None
    return {
        "name": "CORS preflight audit could not complete",
        "severity": "INFO",
        "evidence": str(err)[:300],
        "remediation": ("Confirm httpx is installed and the target URL "
                        "supports OPTIONS preflight (return 200/204 with "
                        "ACA headers). If the URL only serves the front-end, "
                        "re-run against the actual /api/* endpoint."),
        "cwe": "CWE-1006",
    }


def rule_no_acao(s):
    if s.get("cors_error"):
        return None
    if s.get("cors_any_acao_present"):
        return None
    return {
        "name": "Target returns no Access-Control-Allow-Origin (CORS not enabled — safe)",
        "severity": "INFO",
        "evidence": (f"{s.get('cors_probes_sent', 0)} OPTIONS preflight(s) "
                     "delivered; no probe received an ACAO header. The "
                     "Same-Origin Policy default-deny is in effect."),
        "remediation": ("No action — this is the secure default. Re-run "
                        "on routes that DO need CORS (your /api/* hosts) "
                        "to audit those specifically."),
        "cwe": "N/A",
    }


def rule_positive(s):
    if s.get("cors_error"):
        return None
    if not s.get("cors_any_acao_present"):
        return None
    if (s.get("cors_critical_hits") or s.get("cors_high_hits")
            or s.get("cors_medium_hits")):
        return None
    return {
        "name": "CORS policy locks to explicit origin(s) — no reflection / null",
        "severity": "POSITIVE",
        "evidence": (f"{s.get('cors_probes_sent', 0)} preflight(s) delivered; "
                     "ACAO header was present but never reflected our probe "
                     "Origin (evil.com, null, file://, mistype, suffix-bypass) "
                     "and never returned wildcard '*' with credentials."),
        "remediation": ("Keep the allowlist tight — review every new "
                        "subdomain / partner addition for whether an "
                        "attacker controls a similar string. Re-test "
                        "after any CORS middleware upgrade."),
        "cwe": "CWE-942",
        "owasp": "A05:2021",
    }


CORS_PREFLIGHT_AUDIT_FINDING_RULES = [
    rule_wildcard_with_creds,
    rule_reflected_with_creds,
    rule_null_with_creds,
    rule_reflected_no_creds,
    rule_null_no_creds,
    rule_mistype_or_bypass,
    rule_http_downgrade,
    rule_probe_failed,
    rule_no_acao,
    rule_positive,
]
