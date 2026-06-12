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
    return {"name": f"BMC firmware ships with default-credential markers ({len(creds)})",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-1392", "owasp": "A07:2021",
            "evidence": "Found: " + "; ".join(creds[:5]),
            "remediation": ("Literal default-credential strings were found in the firmware. If these "
                            "are the shipped factory defaults (e.g. iDRAC root:calvin, ADMIN:ADMIN), "
                            "the BMC is trivially accessible until an operator changes them. Force a "
                            "credential change on first boot, disable the default account, and never "
                            "ship a fixed password. Confirmed from bytes — verify the account is "
                            "actually active on the live BMC.")}


BMC_COMPONENT_AUDIT_FINDING_RULES = [rule_not_bmc, rule_platform_inventory, rule_default_creds]
