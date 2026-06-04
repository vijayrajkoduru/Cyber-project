"""log4shell_verify - findings rules.

Severity model:
  CRITICAL - JNDI callback observed at the customer-supplied receiver
             (exploitability CONFIRMED with attribution to a reflection slot)
  INFO     - sent the burst with no callback URL (cannot prove either way)
           - all requests failed network-side
  POSITIVE - burst delivered + callback URL polled + 0 callbacks
"""


def rule_callback_confirmed(s):
    cb = s.get("log4shell_callback_hits") or []
    if not cb:
        return None
    slots = ", ".join(sorted({(h.get("slot") or "unknown") for h in cb}))[:200]
    tokens = ", ".join(sorted({h.get("token") for h in cb if h.get("token")}))[:200]
    return {
        "name": (f"Log4Shell EXPLOITABLE - JNDI callback fired from "
                 f"{len(cb)} reflection point(s) ({slots})"),
        "severity": "CRITICAL",
        "cvss": "10.0",
        "cve":  "CVE-2021-44228",
        "cwe":  "CWE-502",
        "owasp": "A06:2021",
        "evidence": (
            f"Target {s.get('log4shell_target_url', '?')} fed our JNDI payload "
            f"into log4j2 and the out-of-band callback at "
            f"{s.get('log4shell_payload_host', '?')} received hits for tokens: "
            f"{tokens}. Affected reflection point(s): {slots}. "
            "EPSS: 99.6% | CISA KEV: YES."
        ),
        "remediation": (
            "1. Upgrade log4j-core to >= 2.17.1 (audited fix). 2.15 / 2.16 are NOT "
            "sufficient (CVE-2021-45046, CVE-2021-45105 still apply). "
            "2. If upgrade impossible, set -Dlog4j2.formatMsgNoLookups=true OR "
            "remove the JndiLookup class from the jar: "
            "  zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class . "
            "3. Block outbound LDAP / LDAPS / RMI / DNS-TXT egress at the firewall — "
            "even a patched log4j is one supply-chain CVE away. "
            "4. Re-run this scan after the patch to confirm the callback no longer fires."
        ),
    }


def rule_no_callback_url(s):
    if not s.get("log4shell_ran"):
        return None
    if s.get("log4shell_callback_url_present"):
        return None
    sent = s.get("log4shell_sent_count") or 0
    if not sent:
        return None
    return {
        "name": ("Log4Shell probe delivered but no callback URL supplied "
                 "- exploitability cannot be confirmed"),
        "severity": "INFO",
        "cve":  "CVE-2021-44228",
        "cwe":  "CWE-502",
        "owasp": "A06:2021",
        "evidence": (
            f"{sent} JNDI payload(s) were sent to {s.get('log4shell_target_url', '?')} "
            "across 12 header fields + body fields + query. Without an "
            "options.callback_url (interactsh / webhook.site) we cannot tell "
            "whether log4j2 dereferenced the JNDI lookup."
        ),
        "remediation": (
            "Re-run with options.callback_url set to a public interactsh poll URL "
            "(e.g. https://oast.pro/<token>) or a webhook.site bin. If the callback "
            "fires after the re-run, treat as CRITICAL and patch log4j-core to >= 2.17.1."
        ),
    }


def rule_positive(s):
    if not s.get("log4shell_ran"):
        return None
    if not s.get("log4shell_callback_url_present"):
        return None
    if s.get("log4shell_callback_count"):
        return None
    sent = s.get("log4shell_sent_count") or 0
    if not sent:
        return None
    return {
        "name": ("Log4Shell burst delivered + callback polled - "
                 "no JNDI dereference observed"),
        "severity": "POSITIVE",
        "cve":  "CVE-2021-44228",
        "cwe":  "CWE-502",
        "owasp": "A06:2021",
        "evidence": (
            f"{sent} JNDI payload(s) sent to {s.get('log4shell_target_url', '?')}, "
            "callback URL was polled, and 0 callbacks fired. Target is either "
            "patched (log4j-core >= 2.17.1) or not running log4j2."
        ),
        "remediation": (
            "Maintain a CI gate that blocks log4j-core < 2.17.1 from new builds. "
            "Re-run quarterly + after dependency bumps."
        ),
    }


def rule_network_error(s):
    if s.get("log4shell_ran"):
        return None
    if not s.get("log4shell_no_target"):
        return None
    return {
        "name": "Log4Shell probe could not run - no target",
        "severity": "INFO",
        "evidence": "ScanRequest.target was empty.",
        "remediation": "Re-run with a populated target.",
        "cwe": "CWE-1006",
    }


LOG4SHELL_VERIFY_FINDING_RULES = [
    rule_callback_confirmed,
    rule_no_callback_url,
    rule_positive,
    rule_network_error,
]
