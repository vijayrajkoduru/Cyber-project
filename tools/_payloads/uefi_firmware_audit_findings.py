"""uefi_firmware_audit - findings rules.

ZERO-FP contract: detection-only. The single graded finding (LOW, no
SecureBoot evidence) fires strictly when this is confirmed to be a UEFI image
AND no SecureBoot NVRAM-variable markers exist. Vendor/version are INFO.
"""


def rule_not_uefi(s):
    if s.get("uefi_is_uefi"):
        return None
    if s.get("uefi_firmware_audit_total") is None:
        return None
    return {"name": "Not a UEFI/BIOS platform-firmware image",
            "severity": "INFO",
            "evidence": "No firmware-volume (_FVH), Intel flash-descriptor, or UEFI vendor markers",
            "remediation": ("This is an embedded/IoT image, not a PC-class UEFI/BIOS dump. The UEFI/"
                            "CHIPSEC checks (CHIPSEC, UEFITool, Boot Guard) do not apply — use the "
                            "embedded-Linux scanners (binwalk/squashfs/U-Boot) instead."),
            "cwe": "CWE-200"}


def rule_inventory(s):
    if not s.get("uefi_is_uefi"):
        return None
    vendor = s.get("uefi_vendor")
    ver = s.get("uefi_bios_version")
    ev = (f"vendor={vendor or 'unknown'}, version={ver or 'unparsed'}, "
          f"FV-header={s.get('uefi_has_fv')}, flash-descriptor={s.get('uefi_has_flash_desc')}, "
          f"capsule={s.get('uefi_has_capsule')}, SMM={s.get('uefi_has_smm')}")
    return {"name": f"UEFI/BIOS image detected{(' — ' + vendor) if vendor else ''}",
            "severity": "INFO",
            "evidence": ev,
            "remediation": ("Cross-reference the BIOS vendor + version against vendor PSIRT advisories "
                            "and the NVD (CHIPSEC/UEFI CVEs, BootHole, LogoFAIL, PixieFail). For a "
                            "deep platform audit run CHIPSEC on the live host and parse the volume "
                            "tree with UEFITool. (Version-only advisory — not exploited.)"),
            "cwe": "CWE-1104", "owasp": "A06:2021"}


def rule_secureboot_present(s):
    if not s.get("uefi_is_uefi"):
        return None
    if not s.get("uefi_has_secureboot"):
        return None
    return {"name": "UEFI Secure Boot variables present",
            "severity": "POSITIVE",
            "evidence": "SecureBoot / PK / KEK / db / dbx NVRAM variable markers found",
            "remediation": ("Secure Boot key infrastructure is present. Confirm SecureBoot is "
                            "ENABLED (not just provisioned), that the dbx revocation list is current "
                            "(BootHole/LogoFAIL revocations applied), and that no test/leaked KEK is "
                            "trusted."),
            "cwe": "CWE-347"}


def rule_no_secureboot(s):
    if not s.get("uefi_no_secureboot"):
        return None
    return {"name": "UEFI image shows no Secure Boot variable evidence",
            "severity": "INFO", "cvss": "3.6",
            "cwe": "CWE-347", "owasp": "A08:2021",
            "evidence": ("SecureBoot/PK/KEK/db markers NOT found in the uploaded blob — NOT CONFIRMED "
                         "disabled (vars may reside in a separate NVRAM region not captured)"),
            "remediation": ("No Secure Boot key material was found in the image. If Secure Boot is "
                            "unprovisioned, an attacker with flash-write access can boot an unsigned "
                            "bootloader/OS. Provision PK/KEK/db, enable Secure Boot, and keep dbx "
                            "current. (NVRAM vars may live in a separate region not in this dump — "
                            "confirm on the live platform with `mokutil`/CHIPSEC. Detection-only.)")}


UEFI_FIRMWARE_AUDIT_FINDING_RULES = [rule_not_uefi, rule_inventory,
                                     rule_secureboot_present, rule_no_secureboot]
