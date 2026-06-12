"""uboot_version_audit - findings rules.

ZERO-FP contract: the CVE-era flag is INFO (version-only, no demonstrated
exploit). Graded findings fire only on a confirmed marker: an unsigned FIT
boot image, or a writable interactive bootdelay prompt — both literally
parsed from the bytes.
"""


def rule_not_present(s):
    if s.get("uboot_present"):
        return None
    if s.get("uboot_version_audit_total") is None:
        return None
    return {"name": "No U-Boot bootloader detected in firmware",
            "severity": "INFO",
            "evidence": "No 'U-Boot <version>' banner and no uImage/FIT image magic found",
            "remediation": ("This image may not contain the bootloader stage (common when only the "
                            "application partition was supplied), or it uses a different bootloader "
                            "(GRUB/coreboot/proprietary). Supply the full SPI/eMMC dump to audit the "
                            "boot chain."),
            "cwe": "CWE-200"}


def rule_version_inventory(s):
    if not s.get("uboot_present"):
        return None
    ver = s.get("uboot_version")
    era = s.get("uboot_cve_era")
    # Pure version/CVE-era inventory — advisory INFO, never graded on version alone.
    ev = f"version={ver or 'unparsed'}"
    if era:
        ev += f"; era={era}"
    ev += (f"; uImage={s.get('uboot_has_uimage')}, FIT={s.get('uboot_has_fit')}, "
           f"FIT-signature-node={s.get('uboot_has_signature_node')}")
    return {"name": f"U-Boot bootloader detected{(' ' + ver) if ver else ''}",
            "severity": "INFO",
            "evidence": ev,
            "remediation": ("Cross-reference the detected U-Boot version against the current NVD "
                            "U-Boot CVE list (System Exploit module #10 with the version string). "
                            "Pre-2020 U-Boot has multiple public network-stack and filesystem "
                            "parsing CVEs. Plan a bootloader upgrade if the version is end-of-life. "
                            "(Version-only advisory — exploitability not demonstrated against the "
                            "live device.)"),
            "cwe": "CWE-1104", "owasp": "A06:2021"}


def rule_unsigned_fit(s):
    if not s.get("uboot_unsigned_fit"):
        return None
    return {"name": "FIT boot image present without a signature node (unsigned boot)",
            "severity": "MEDIUM", "cvss": "6.5",
            "cwe": "CWE-347", "owasp": "A08:2021",
            "evidence": ("FDT/FIT image magic found but no `signature {` node — the kernel/DTB FIT "
                         "is not cryptographically verified by U-Boot at boot"),
            "remediation": ("Enable U-Boot FIT image verification (CONFIG_FIT_SIGNATURE) and sign "
                            "the FIT with an RSA/ECDSA key whose public key is embedded in a "
                            "write-protected U-Boot. Without a signature node, an attacker who can "
                            "write the boot partition (SPI/eMMC/OTA) can boot arbitrary kernels. "
                            "Confirmed from the firmware bytes — not exploited.")}


def rule_interactive_prompt(s):
    if not s.get("uboot_interactive_prompt"):
        return None
    return {"name": f"U-Boot interactive boot prompt enabled (bootdelay={s.get('uboot_bootdelay')})",
            "severity": "LOW", "cvss": "3.6",
            "cwe": "CWE-1191", "owasp": "A05:2021",
            "evidence": f"bootdelay={s.get('uboot_bootdelay')} in the U-Boot environment",
            "remediation": ("A non-zero bootdelay lets anyone with serial/UART access interrupt "
                            "boot, drop to the U-Boot shell, and tamper with bootargs (e.g. add "
                            "`init=/bin/sh` for a root shell). For production set `bootdelay=-2` (or "
                            "0 with a disabled prompt), lock the env, and gate the console behind a "
                            "U-Boot password (CONFIG_AUTOBOOT_KEYED). Confirmed from firmware env "
                            "bytes — physical UART access is required to exploit.")}


UBOOT_VERSION_AUDIT_FINDING_RULES = [rule_not_present, rule_version_inventory,
                                     rule_unsigned_fit, rule_interactive_prompt]
