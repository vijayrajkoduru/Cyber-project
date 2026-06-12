"""secure_boot_chain_audit - findings rules.

ZERO-FP contract: the only graded finding (MEDIUM, no-integrity-verification)
fires strictly when ZERO verified-boot markers were found across a
non-trivial image. Presence of verification is reported POSITIVE. dm-verity
and cert presence are concrete, marker-backed evidence.
"""


def rule_no_verification(s):
    if not s.get("sb_no_verification"):
        return None
    return {"name": "No firmware integrity / verified-boot evidence found",
            "severity": "MEDIUM", "cvss": "6.5",
            "cwe": "CWE-347", "owasp": "A08:2021",
            "evidence": (f"No FIT signature, PKCS#7/CMS signedData, Android AVB/vbmeta, dm-verity, "
                         f"or required-image markers found across a {s.get('sb_image_size', 0)}-byte "
                         f"image"),
            "remediation": ("The firmware shows no cryptographic boot/rootfs verification. An "
                            "attacker able to write flash (SPI/eMMC chip-off, malicious OTA, or a "
                            "writable update partition) can install a tampered image that boots "
                            "silently. Implement a signed-boot chain: U-Boot FIT signatures "
                            "(CONFIG_FIT_SIGNATURE) or Android Verified Boot (AVB) for the boot "
                            "image, plus dm-verity for the rootfs, anchored in a write-protected "
                            "root of trust. Confirmed absence from the bytes — not exploited.")}


def rule_dm_verity(s):
    if not s.get("sb_has_dm_verity"):
        return None
    return {"name": "dm-verity root-filesystem integrity verification present",
            "severity": "POSITIVE",
            "evidence": "dm-verity / veritysetup markers found in firmware",
            "remediation": ("Good — the rootfs is hash-verified at runtime, so on-disk tampering "
                            "is detected. Ensure the verity root hash is itself signed and anchored "
                            "in a verified boot stage (otherwise the hash can be swapped too)."),
            "cwe": "CWE-347"}


def rule_verification_present(s):
    if not s.get("sb_has_verification"):
        return None
    if s.get("sb_has_dm_verity") and len(s.get("sb_verify_markers") or []) == 1:
        # dm-verity-only is already reported by its own positive rule
        return None
    markers = s.get("sb_verify_markers") or []
    return {"name": "Verified-boot / image-signature evidence present",
            "severity": "POSITIVE",
            "evidence": "Markers: " + ", ".join(markers),
            "remediation": ("A signing/verification mechanism is present. Confirm the trust anchor "
                            "(public key / cert) is write-protected (OTP fuse, locked flash) and "
                            "that verification is enforced (not merely 'present but optional'). "
                            "Test rollback protection so an attacker cannot flash an older signed "
                            "but vulnerable image."),
            "cwe": "CWE-347"}


def rule_certs_inventory(s):
    if not s.get("sb_has_certs"):
        return None
    return {"name": "Embedded X.509 certificate(s) / public key(s) detected",
            "severity": "INFO",
            "evidence": "PEM certificate or public-key blocks found in firmware",
            "remediation": ("Embedded certs/keys may be TLS trust anchors, code-signing roots, or "
                            "(if PRIVATE keys are nearby) a credential leak. Confirm only PUBLIC "
                            "trust material ships in firmware and that no private key accompanies "
                            "it (see the hardcoded-credentials scanner)."),
            "cwe": "CWE-200"}


SECURE_BOOT_CHAIN_AUDIT_FINDING_RULES = [rule_no_verification, rule_dm_verity,
                                         rule_verification_present, rule_certs_inventory]
