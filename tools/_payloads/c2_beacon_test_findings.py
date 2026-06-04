"""c2_beacon_test - findings rules.

Severity model:
  INFO     - beaconing pattern emitted; customer must verify SIEM caught it
  LOW      - DNS C2 component succeeded too (broader detection surface)
  POSITIVE - all beacons reached customer-owned receiver
"""


def rule_c2_beacon_rollup(s):
    https_sent = int(s.get("c2_beacon_https_sent") or 0)
    https_ok = int(s.get("c2_beacon_https_ok") or 0)
    dns_sent = int(s.get("c2_beacon_dns_sent") or 0)
    dns_ok = int(s.get("c2_beacon_dns_ok") or 0)
    if (https_sent + dns_sent) == 0:
        return None
    beacon_id = s.get("c2_beacon_id") or "?"
    url = s.get("c2_beacon_callback_url") or "?"
    dns_zone = s.get("c2_beacon_dns_domain")
    base_int = s.get("c2_beacon_interval_sec") or "?"
    jit = s.get("c2_beacon_jitter_pct") or "?"

    sev = "LOW" if (dns_ok > 0 and dns_sent > 0) else "INFO"
    name = (f"Simulated C2 beacon pattern emitted: "
             f"{https_ok}/{https_sent} HTTPS + {dns_ok}/{dns_sent} DNS beacons "
             f"(beacon_id={beacon_id})")
    evidence_parts = [
        f"Beacon ID: {beacon_id}",
        f"HTTPS callback: {url}",
        f"Beacons sent: {https_sent}; succeeded: {https_ok}",
        f"Base interval: {base_int}s; jitter +/-{jit}%",
        "Payload format: Fernet-encrypted (AES-128-CBC + HMAC-SHA256), base64-encoded.",
        "User-Agent rotation: Chrome / Safari / Firefox per beacon.",
    ]
    if dns_zone:
        evidence_parts.append(f"DNS C2 zone queried: {dns_zone} via TXT records ({dns_ok}/{dns_sent} resolved).")
    evidence_parts.append("Source IP: VulnusLab scanner egress IP (correlate in SIEM).")

    return {
        "name": name,
        "severity": sev,
        "cwe": "CWE-693",
        "owasp": "A09:2021",
        "evidence": " ".join(evidence_parts),
        "remediation": (
            "1. In your SIEM, filter on the beacon time window + VulnusLab egress IP. "
            "Expected alerts: (a) periodic POSTs to single FQDN with low jitter, "
            "(b) consistent body-size +/- 10%, (c) rotating User-Agent header per request. "
            "2. If no alert fired, build/import a Sigma rule for 'high-frequency POSTs "
            "to single host' (e.g. Sigma proc_creation_win_nslookup_recon.yml family). "
            "3. For DNS C2: detection should flag bursts of TXT queries to same zone "
            "from a single source. Splunk SPL: index=dns query_type=TXT | "
            "stats count by src_ip query_zone | where count > 5. "
            "4. Re-run this scanner monthly. Beacon ID rotates so each run is unique."
        ),
        "mitre_techniques": ["T1071.001", "T1071.004", "T1572", "T1573.001"],
        "references": [
            "https://attack.mitre.org/techniques/T1071/",
            "https://github.com/SigmaHQ/sigma",
            "https://www.elastic.co/guide/en/security/current/prebuilt-rules.html",
        ],
    }


def rule_input_missing(s):
    if not s.get("c2_input_missing"):
        return None
    return {
        "name": "C2 beacon test skipped - no callback URL supplied",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": ("Probe needs options.c2_callback_url = https endpoint the "
                     "customer's monitoring stack owns. Optional: "
                     "options.c2_dns_domain for DNS C2 layer."),
        "remediation": (
            "Spin up a tiny HTTPS receiver in your SIEM/test environment "
            "(any 200-OK responder is fine). Pass its URL as "
            "options.c2_callback_url. For DNS C2, delegate a subdomain you "
            "control (e.g. c2.example.com) to a server with logging."
        ),
    }


def rule_input_invalid(s):
    err = s.get("c2_input_invalid")
    if not err:
        return None
    return {
        "name": f"C2 beacon test skipped - invalid input: {err[:80]}",
        "severity": "INFO",
        "cwe": "CWE-1287",
        "evidence": f"Validation error: {err}",
        "remediation": "Re-run with options.c2_callback_url that starts with https:// (preferred) or http://.",
    }


def rule_lib_missing(s):
    err = s.get("c2_lib_missing")
    if not err:
        return None
    return {
        "name": "C2 beacon test skipped - httpx library missing",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": err,
        "remediation": "Install httpx: pip install httpx (already in image; rebuild VPS).",
    }


def rule_positive(s):
    https_ok = int(s.get("c2_beacon_https_ok") or 0)
    https_sent = int(s.get("c2_beacon_https_sent") or 0)
    if not https_sent:
        return None
    if https_ok != https_sent:
        return None
    if s.get("c2_input_missing") or s.get("c2_input_invalid"):
        return None
    return {
        "name": f"All {https_sent} C2 beacons reached customer receiver successfully",
        "severity": "POSITIVE",
        "cwe": "CWE-693",
        "owasp": "A09:2021",
        "evidence": (f"100% beacon delivery rate. Network path scanner -> "
                     f"{s.get('c2_beacon_callback_url')} is unfiltered. "
                     "Detection visibility is now the customer's responsibility."),
        "remediation": (
            "Beacon path open = good for testing. Now confirm SIEM alerts "
            "actually fired. If they didn't, this is a detection-engineering gap "
            "(not a transport gap)."
        ),
    }


C2_BEACON_TEST_FINDING_RULES = [
    rule_c2_beacon_rollup,
    rule_input_missing,
    rule_input_invalid,
    rule_lib_missing,
    rule_positive,
]
