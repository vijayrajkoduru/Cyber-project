"""physical_acquisition_advisory - findings rules.

ADVISORY-BY-DESIGN: a single INFO finding. Physical firmware acquisition needs
the device + bench tooling and cannot be SaaS-probed. Never graded.
"""


def rule_advisory(s):
    if not s.get("acq_advisory"):
        return None
    techniques = s.get("acq_techniques") or []
    return {"name": "[ADVISORY-BY-DESIGN] Physical firmware acquisition",
            "severity": "INFO",
            "evidence": (f"{len(techniques)} §1 acquisition techniques need physical possession of "
                         f"the device + bench tooling (UART, SPI clip, chip-off reader, JTAG, SDR) "
                         f"— not performable from an external SaaS"),
            "remediation": ("Endpoint is advisory-by-design, NOT a forge gap. To obtain firmware for "
                            "static analysis: dump SPI flash with a CH341A/BusPirate clip, chip-off "
                            "eMMC/NAND and read externally, or capture an OTA update over SDR. Once "
                            "you have the blob, upload it to drive the static analysis scanners "
                            "(binwalk, squashfs, ELF, secrets, U-Boot, secure-boot). Defensively: "
                            "encrypt firmware at rest, bind keys to SoC fuses/TPM, and disable flash "
                            "read-back. Vendor-download + cloud-mirror enum (the SaaS-reachable "
                            "acquisition paths) live in the Recon/Cloud modules. See playbook §1."),
            "cwe": "CWE-1278", "owasp": "A04:2021"}


PHYSICAL_ACQUISITION_ADVISORY_FINDING_RULES = [rule_advisory]
