"""exfil_dns_test - findings rules.

Severity model:
  HIGH      >= 5 markers in DNS logs (exfil channel + no alerting telemetry)
  MEDIUM    1-4 markers in DNS logs (partial channel)
  POSITIVE  markers were delivered but NONE appeared in logs (alerting OK
            or logs filtered before grep) — needs verification
  POSITIVE  markers were NOT delivered (port closed / egress denied / no
            recursive resolver — best case)
  INFO      DNS port not responsive
  INFO      SSH creds missing — exfil sent but couldn't verify logs
  INFO      Auth failed / connection error
"""


def rule_high_exfil_no_telemetry(s):
    in_logs = s.get("exfil_dns_markers_in_logs") or []
    if len(in_logs) < 5:
        return None
    sent = s.get("exfil_dns_markers_sent") or 0
    return {
        "name": (f"DNS exfil channel proven with no alerting telemetry "
                 f"({len(in_logs)} of {sent} markers appeared in DNS logs "
                 "without triggering)"),
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "mitre": "T1048.003",
        "evidence": (
            f"Scanner sent {sent} unsolicited DNS TXT queries to the target "
            f"and {len(in_logs)} marker tokens were found in the target's "
            "DNS logs after the test. Examples: "
            f"{', '.join(in_logs[:6])}. No alert/blocking action interrupted "
            "the flow - this is exactly the substrate dnscat2 / iodine / DNS "
            "tunnels need."
        ),
        "remediation": (
            "1. Egress-filter outbound DNS to only the corporate resolver(s) "
            "(deny 53/udp + 53/tcp from production hosts to the internet). "
            "2. On the corporate resolver, enable Response Policy Zones "
            "(RPZ) with feeds for known C2/DGA domains. 3. Forward DNS query "
            "logs to SIEM and alert on: (a) TXT-record query volume per "
            "client > 100/min, (b) qname entropy > 4.0 bits/char (indicates "
            "encoded data), (c) qname length > 50 chars on non-standard TLDs. "
            "4. Block direct DNS to non-corporate resolvers at the firewall."
        ),
    }


def rule_medium_partial(s):
    in_logs = s.get("exfil_dns_markers_in_logs") or []
    if not (1 <= len(in_logs) <= 4):
        return None
    sent = s.get("exfil_dns_markers_sent") or 0
    return {
        "name": (f"Partial DNS exfil channel detected "
                 f"({len(in_logs)} of {sent} markers reached DNS logs)"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "mitre": "T1048.003",
        "evidence": (
            f"{len(in_logs)} of {sent} unsolicited queries were logged. "
            "Either DNS logging is partial (rate-limited or sample-based), "
            "or some kind of filtering caught a subset. Either way, an "
            "exfil channel exists with imperfect coverage."
        ),
        "remediation": (
            "1. Audit the DNS logging configuration on the target — ensure "
            "every query is captured (no log sampling). 2. Add the RPZ + "
            "SIEM controls from the HIGH-severity remediation. 3. Egress-"
            "filter so unsolicited DNS from the scanner network never "
            "reaches the resolver in the first place."
        ),
    }


def rule_creds_missing(s):
    if not s.get("exfil_dns_creds_missing"):
        return None
    sent = s.get("exfil_dns_markers_answered") or 0
    if not sent:
        return None
    return {
        "name": ("DNS exfil queries delivered but log audit skipped "
                 "(SSH credentials not supplied)"),
        "severity": "MEDIUM",
        "cvss": "4.3",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "mitre": "T1048.003",
        "evidence": (
            f"{sent} unsolicited DNS TXT queries successfully reached the "
            "target's DNS service. This already proves an inbound DNS path "
            "exists. We could not verify whether the queries were logged or "
            "alerted because options.username + options.password (or "
            "options.ssh_key) were not supplied."
        ),
        "remediation": (
            "1. Provide SSH creds via options.username + options.password "
            "(or ssh_key) and re-run to get the full HIGH/MEDIUM/POSITIVE "
            "scoring. 2. Independently, verify that your DNS infrastructure "
            "logs every query to a SIEM with alerting on TXT volume and "
            "qname entropy (the inbound channel is half the problem; "
            "telemetry on the channel is the other half)."
        ),
    }


def rule_no_service(s):
    if not s.get("exfil_dns_no_service"):
        return None
    sent = s.get("exfil_dns_markers_sent") or 0
    timeout = s.get("exfil_dns_markers_timeout") or 0
    err = s.get("exfil_dns_markers_error") or 0
    return {
        "name": "Target DNS port not responsive (no exfil channel possible)",
        "severity": "POSITIVE",
        "cwe": "CWE-200",
        "owasp": "A05:2021",
        "mitre": "T1048.003",
        "evidence": (
            f"All {sent} unsolicited DNS TXT queries were dropped "
            f"({timeout} timeout, {err} error). The target is not running a "
            "DNS service reachable from the scanner network OR a firewall "
            "is dropping inbound 53/udp. Either way, no inbound DNS-tunnel "
            "substrate exists."
        ),
        "remediation": (
            "Maintain current egress-filtering posture. Re-run quarterly to "
            "confirm no new DNS exposure is introduced (e.g. accidental "
            "publication of an authoritative DNS server)."
        ),
    }


def rule_auth_failed(s):
    if not s.get("exfil_dns_ssh_auth_failed"):
        return None
    return {
        "name": "SSH authentication failed during DNS log audit",
        "severity": "INFO",
        "evidence": ("paramiko returned AuthenticationException. DNS markers "
                     "were sent but log presence could not be confirmed."),
        "remediation": ("Verify the SSH credential; re-run to score the "
                        "full HIGH/MEDIUM/POSITIVE."),
        "cwe": "CWE-287",
    }


def rule_dnspython_missing(s):
    if "dnspython not installed" not in str(s.get("exfil_dns_test_error") or ""):
        return None
    return {
        "name": "dnspython library not installed on scanner host",
        "severity": "INFO",
        "evidence": "import dns.resolver failed.",
        "remediation": "pip install dnspython (in requirements.txt as 2.7.0).",
        "cwe": "CWE-1006",
    }


def rule_log_audit_error(s):
    err = str(s.get("exfil_dns_log_audit_error") or "")
    if not err:
        return None
    return {
        "name": "DNS log audit step errored (markers were sent successfully)",
        "severity": "INFO",
        "evidence": f"Log audit error: {err}.",
        "remediation": ("Re-run once SSH connectivity is restored to verify "
                        "log presence. Independently, confirm the corporate "
                        "DNS resolver logs every query."),
        "cwe": "CWE-1006",
    }


def rule_positive_no_markers_logged(s):
    if s.get("exfil_dns_test_total"):
        return None
    if s.get("exfil_dns_no_service"):
        return None
    if s.get("exfil_dns_creds_missing"):
        return None
    if s.get("exfil_dns_ssh_auth_failed"):
        return None
    if s.get("exfil_dns_log_audit_error"):
        return None
    if not s.get("exfil_dns_markers_answered"):
        return None
    sent = s.get("exfil_dns_markers_answered") or 0
    return {
        "name": ("DNS queries delivered but NONE appeared in target DNS "
                 "logs - filtering / log scrubbing / no DNS logging at all"),
        "severity": "POSITIVE",
        "evidence": (
            f"{sent} unsolicited DNS TXT queries reached the resolver, but "
            "none of the marker tokens appeared in syslog / messages / "
            "named.log / journalctl on the target. This is consistent with "
            "either: (a) the resolver doesn't log at all (also bad - flag "
            "manually), or (b) it logs to a destination not searched here. "
            "Best case: alerting blocked the channel before it produced a "
            "log entry."
        ),
        "remediation": (
            "Confirm via the DNS admin which case applies. Ideal posture: "
            "logs ARE captured AND alerting fires on unsolicited inbound "
            "TXT volume. If logs aren't captured at all, enable query "
            "logging (BIND: `querylog yes;` + RFC 8499-style structured "
            "logging into your SIEM)."
        ),
        "cwe": "CWE-200",
        "owasp": "A05:2021",
    }


EXFIL_DNS_TEST_FINDING_RULES = [
    rule_high_exfil_no_telemetry,
    rule_medium_partial,
    rule_creds_missing,
    rule_no_service,
    rule_auth_failed,
    rule_dnspython_missing,
    rule_log_audit_error,
    rule_positive_no_markers_logged,
]
