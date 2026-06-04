"""ssh_terrapin_verify - findings rules.

Severity model:
  MEDIUM   - vulnerable cipher set offered AND kex-strict extension NOT advertised
             (CVE-2023-48795 - Terrapin prefix-truncation downgrade is possible)
  LOW      - vulnerable cipher set offered BUT kex-strict extension IS advertised
             (mitigated; cipher could still be removed for hardening)
  INFO     - probe failed / no banner / paramiko missing
  POSITIVE - clean cipher set OR vulnerable ciphers gated behind kex-strict
"""


def rule_terrapin_vulnerable(s):
    if not s.get("terrapin_vulnerable"):
        return None
    detail = []
    if s.get("terrapin_has_chacha20"):
        detail.append("chacha20-poly1305@openssh.com cipher offered")
    if s.get("terrapin_cbc_etm_combo"):
        detail.append("*-cbc cipher offered alongside *-etm@openssh.com MAC")
    if not s.get("terrapin_has_strict"):
        detail.append("kex-strict-{c,s}-v00@openssh.com NOT advertised "
                       "(no Terrapin mitigation extension)")
    banner = s.get("terrapin_banner") or "unknown"
    return {
        "name": "SSH Terrapin downgrade EXPLOITABLE - chacha20-poly1305 / CBC-ETM offered without kex-strict",
        "severity": "MEDIUM",
        "cvss": "5.9",
        "cve":  "CVE-2023-48795",
        "cwe":  "CWE-222",
        "owasp": "A02:2021",
        "evidence": (
            f"{s.get('terrapin_target', '?')} banner '{banner[:80]}' offered "
            f"vulnerability indicators: {'; '.join(detail)}. An on-path attacker "
            "can prefix-truncate the initial KEX sequence and silently downgrade "
            "the negotiated extensions (RFC 8308 extension info). "
            "EPSS: 55.4% | CISA KEV: no."
        ),
        "remediation": (
            "1. Upgrade the SSH stack to a Terrapin-mitigated version: "
            "OpenSSH >= 9.6p1, PuTTY >= 0.80, libssh >= 0.10.6 / 0.9.8, "
            "AsyncSSH >= 2.14.2, paramiko >= 3.4.0. "
            "2. Until you can upgrade, disable the vulnerable cipher set in sshd_config: "
            "  Ciphers -chacha20-poly1305@openssh.com,*-cbc "
            "  MACs    -*-etm@openssh.com "
            "and restart sshd. (Trade-off: drops cipher diversity.) "
            "3. After the upgrade the server should advertise "
            "kex-strict-s-v00@openssh.com in its KEXINIT — re-run this scan to "
            "confirm. "
            "Reference: https://terrapin-attack.com/"
        ),
    }


def rule_terrapin_mitigated(s):
    # Vulnerable cipher offered but kex-strict extension IS present.
    if not s.get("terrapin_ran"):
        return None
    if s.get("terrapin_vulnerable"):
        return None
    if not s.get("terrapin_has_strict"):
        return None
    vuln_cipher = s.get("terrapin_has_chacha20") or s.get("terrapin_cbc_etm_combo")
    if not vuln_cipher:
        return None
    return {
        "name": "SSH Terrapin mitigated - kex-strict extension present alongside vulnerable cipher offers",
        "severity": "LOW",
        "cvss": "3.7",
        "cve":  "CVE-2023-48795",
        "cwe":  "CWE-222",
        "owasp": "A02:2021",
        "evidence": (
            f"{s.get('terrapin_target', '?')} advertises kex-strict (Terrapin "
            "mitigation extension) so the downgrade is blocked. However the "
            "underlying vulnerable cipher / MAC suites are still listed for "
            "back-compat. Older clients without kex-strict will still negotiate "
            "them — an opportunistic attacker can fall back to a "
            "kex-strict-blind client to mount the attack."
        ),
        "remediation": (
            "Optional hardening: drop the vulnerable cipher families from "
            "sshd_config so legacy clients are forced onto safe primitives. "
            "Ciphers -chacha20-poly1305@openssh.com,*-cbc "
            "MACs    -*-etm@openssh.com"
        ),
    }


def rule_no_banner(s):
    if s.get("terrapin_ran") and s.get("terrapin_banner"):
        return None
    err = s.get("terrapin_error") or "unknown"
    return {
        "name": "SSH Terrapin probe could not read banner",
        "severity": "INFO",
        "evidence": (f"Probe target {s.get('terrapin_target', '?')} returned "
                     f"error: {err}. Port may be filtered, target down, or not SSH."),
        "remediation": ("Confirm the SSH service is listening on the expected port "
                        "and reachable from the scanner host. If the SSH banner "
                        "is intentionally hidden, run this scan from an internal "
                        "trusted host."),
        "cwe": "CWE-1006",
    }


def rule_paramiko_missing(s):
    if s.get("terrapin_error") != "paramiko not installed":
        return None
    return {
        "name": "paramiko not installed on scanner host",
        "severity": "INFO",
        "evidence": "import paramiko failed. SSH banner capture cannot run.",
        "remediation": "pip install paramiko (>=3.4.0 for Terrapin mitigation).",
        "cwe": "CWE-1006",
    }


def rule_positive(s):
    if not s.get("terrapin_ran"):
        return None
    if s.get("terrapin_vulnerable"):
        return None
    if s.get("terrapin_has_chacha20") or s.get("terrapin_cbc_etm_combo"):
        return None
    return {
        "name": "SSH passed Terrapin downgrade verification",
        "severity": "POSITIVE",
        "cve":  "CVE-2023-48795",
        "cwe":  "CWE-222",
        "owasp": "A02:2021",
        "evidence": (
            f"{s.get('terrapin_target', '?')} banner '{(s.get('terrapin_banner') or '')[:80]}' "
            "did not offer chacha20-poly1305@openssh.com or any *-cbc / *-etm@ combo. "
            "Cipher set is Terrapin-clean."
        ),
        "remediation": ("Keep your SSH stack current; new cipher CVEs land roughly "
                        "every 18 months. Re-run after every OpenSSH upgrade."),
    }


SSH_TERRAPIN_VERIFY_FINDING_RULES = [
    rule_terrapin_vulnerable,
    rule_terrapin_mitigated,
    rule_paramiko_missing,
    rule_no_banner,
    rule_positive,
]
