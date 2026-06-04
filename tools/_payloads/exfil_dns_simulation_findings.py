"""exfil_dns_simulation - findings rules.

Severity model:
  INFO     - exfil chunks emitted; customer must verify SIEM caught the burst
  LOW      - 50+ chunks emitted (definite per-host DNS query volume anomaly)
  POSITIVE - all queries reached resolver (delivery path clean)
"""


def rule_exfil_rollup(s):
    total = int(s.get("exfil_dns_total") or 0)
    ok = int(s.get("exfil_dns_ok") or 0)
    nx = int(s.get("exfil_dns_nxdomain") or 0)
    if total == 0:
        return None
    payload_bytes = int(s.get("exfil_dns_payload_size") or 0)
    chunks = int(s.get("exfil_dns_chunk_count") or 0)
    domain = s.get("exfil_dns_domain") or "?"
    resolver = s.get("exfil_dns_resolver") or "?"
    sess = s.get("exfil_dns_session_id") or "?"

    sev = "LOW" if total >= 50 else "INFO"
    return {
        "name": (f"Simulated DNS exfiltration: {ok}/{total} chunked queries "
                  f"sent to *.{domain} (payload {payload_bytes}B / {chunks} chunks; "
                  f"session={sess})"),
        "severity": sev,
        "cwe": "CWE-693",
        "owasp": "A09:2021",
        "evidence": (
            f"VulnusLab encoded a {payload_bytes}-byte benign payload as base32 "
            f"and emitted it as {chunks} subdomain queries against {domain}, "
            f"using resolver {resolver}. "
            f"{ok}/{total} queries reached the resolver ({nx} got NXDOMAIN, "
            "which is the expected response for a benign exfil chunk). "
            "Each chunk's FQDN format: <base32>.<seq>.<session>.<domain>. "
            "Payload prefix 'VL-EXFIL-TEST|<unix_ts>' is grep-able in your DNS logs."
        ),
        "remediation": (
            "1. In your DNS monitoring / SIEM, alert on the test window: filter "
            f"src=scanner-egress-IP, query suffix={domain}. Expected: {total} queries "
            "in <60s from one source — a per-host DNS query volume anomaly. "
            "2. If no alert fired, deploy one of: (a) Splunk DNS query-rate per-host "
            "threshold (e.g. >50 queries/min same-suffix); (b) Sigma "
            "dns_query_random_subdomain.yml; (c) Zeek dns.log + statistical baseline. "
            "3. Long random subdomain labels (>40 chars) + high entropy is a strong "
            "signal — add label-length detection to your sigma rules. "
            "4. Re-run quarterly. Each run uses a fresh session ID."
        ),
        "mitre_techniques": ["T1071.004", "T1048.003", "T1041"],
        "references": [
            "https://attack.mitre.org/techniques/T1071/004/",
            "https://attack.mitre.org/techniques/T1048/003/",
            "https://github.com/SigmaHQ/sigma/tree/master/rules/dns",
        ],
    }


def rule_input_missing(s):
    if not s.get("exfil_input_missing"):
        return None
    return {
        "name": "DNS exfil simulation skipped - exfil_dns_domain not supplied",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": ("options.exfil_dns_domain is required. This must be a DNS "
                     "zone the customer's monitoring owns (e.g. delegated "
                     "subdomain pointing at a logging-enabled NS)."),
        "remediation": (
            "Delegate a subdomain (e.g. dnsexfil.<your-domain>.com) to a "
            "logging-enabled DNS server (CoreDNS / PowerDNS with query logging). "
            "Pass that subdomain as options.exfil_dns_domain. Customer-side log "
            "should show ALL chunked subdomain queries arriving."
        ),
    }


def rule_input_invalid(s):
    err = s.get("exfil_input_invalid")
    if not err:
        return None
    return {
        "name": f"DNS exfil simulation skipped - invalid input: {err[:80]}",
        "severity": "INFO",
        "cwe": "CWE-1287",
        "evidence": f"Validation error: {err}",
        "remediation": "Re-run with options.exfil_dns_domain = valid FQDN you control.",
    }


def rule_lib_missing(s):
    err = s.get("exfil_lib_missing")
    if not err:
        return None
    return {
        "name": "DNS exfil simulation skipped - dnspython missing",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": err,
        "remediation": "Install dnspython: pip install dnspython (already in image; rebuild VPS).",
    }


def rule_positive(s):
    total = int(s.get("exfil_dns_total") or 0)
    ok = int(s.get("exfil_dns_ok") or 0)
    if not total:
        return None
    if s.get("exfil_input_missing") or s.get("exfil_input_invalid"):
        return None
    if ok < total:
        return None
    return {
        "name": f"All {total} DNS exfil chunks reached resolver",
        "severity": "POSITIVE",
        "cwe": "CWE-693",
        "owasp": "A09:2021",
        "evidence": (f"100% query-success rate against resolver "
                     f"{s.get('exfil_dns_resolver')}. Transport path is open; "
                     "delivery worked end-to-end."),
        "remediation": (
            "Transport path open = good for testing. Now confirm SIEM / DNS-firewall "
            "alerts actually fired on the burst pattern. If not, it's a detection "
            "gap, not a transport gap. Consider deploying a DNS sinkhole "
            "(Cisco Umbrella / Cloudflare Gateway) for the production exit path."
        ),
    }


EXFIL_DNS_SIMULATION_FINDING_RULES = [
    rule_exfil_rollup,
    rule_input_missing,
    rule_input_invalid,
    rule_lib_missing,
    rule_positive,
]
