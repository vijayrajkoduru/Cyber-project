"""bmc_component_audit - findings rules.

ZERO-FP contract: detection-only. The single graded finding (LOW, default
credentials) fires strictly when a literal known default-cred marker string
was found in the bytes. Platform + component versions are INFO inventory for
CVE matching (no demonstrated exploit).
"""


def rule_not_bmc(s):
    if s.get("bmc_is_bmc"):
        return None
    if s.get("bmc_component_audit_total") is None:
        return None
    return {"name": "Not a BMC / management-controller firmware image",
            "severity": "INFO",
            "evidence": "No iLO/iDRAC/OpenBMC/MegaRAC/IPMI/Redfish/Aspeed markers found",
            "remediation": ("This image does not appear to be BMC firmware. The BMC checks (iLO/"
                            "iDRAC CVE matching, IPMI cipher-0, MegaRAC BMC&C) do not apply."),
            "cwe": "CWE-200"}


def rule_platform_inventory(s):
    if not s.get("bmc_is_bmc"):
        return None
    platforms = s.get("bmc_platforms") or []
    comps = s.get("bmc_components") or {}
    comp_str = ", ".join(f"{k}={v}" for k, v in comps.items()) or "no version strings parsed"
    return {"name": f"BMC firmware detected ({', '.join(platforms[:3]) or 'IPMI/Redfish surface'})",
            "severity": "INFO",
            "evidence": (f"platforms={platforms[:4]}; components: {comp_str}; "
                         f"mgmt-surface={s.get('bmc_has_mgmt_surface')}"),
            "remediation": ("BMC firmware is high-value: it has out-of-band power/console control. "
                            "Cross-reference each component version (kernel/busybox/dropbear/openssl/"
                            "lighttpd/U-Boot) and the platform (iLO/iDRAC/MegaRAC) against vendor "
                            "PSIRT + NVD — the MegaRAC BMC&C family (CVE-2023-34329 et al.), iLO "
                            "auth bypasses, and IPMI cipher-0 are common. Isolate the BMC network, "
                            "disable IPMI if unused, and require Redfish over TLS. (Version-only "
                            "advisory — not exploited.)"),
            "cwe": "CWE-1104", "owasp": "A06:2021"}


def rule_default_creds(s):
    creds = s.get("bmc_default_creds") or []
    if not creds:
        return None
    # A default-cred MARKER string in firmware config text (e.g. "root:calvin")
    # is NOT proof of an exploitable, active account — it could be a doc string,
    # a comment, a default that the provisioning flow overwrites, or a disabled
    # account. We cannot confirm it is active without a live authentication
    # probe (out of static-analysis scope) -> INFO, not a graded LOW.
    return {"name": f"BMC default-credential marker(s) present in firmware bytes ({len(creds)}) — NOT confirmed active",
            "severity": "INFO",
            "cwe": "CWE-1392", "owasp": "A07:2021",
            "evidence": ("Found in bytes: " + "; ".join(creds[:5])
                         + ". Static string match only — presence in firmware does not prove the "
                           "account is active/reachable; that needs a live authentication probe."),
            "remediation": ("Literal default-credential strings were found in the firmware (e.g. "
                            "iDRAC root:calvin, ADMIN:ADMIN). If these are the shipped factory "
                            "defaults and remain unchanged, the BMC would be trivially accessible. "
                            "Verify on the live BMC whether the account is actually active before "
                            "grading; then force a credential change on first boot, disable the "
                            "default account, and never ship a fixed password.")}


BMC_COMPONENT_AUDIT_FINDING_RULES = [rule_not_bmc, rule_platform_inventory, rule_default_creds]
