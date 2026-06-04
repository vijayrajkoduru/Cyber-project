"""binary_entropy_audit - findings rules."""


def rule_positive(s):
    cls = s.get("entropy_classification")
    if cls != "balanced":
        return None
    return {"name": "Firmware entropy distribution is balanced",
            "severity": "POSITIVE",
            "evidence": (f"avg={s.get('entropy_avg')} bits/byte, "
                         f"high-entropy share={s.get('entropy_high_pct')}%, "
                         f"low-entropy share={s.get('entropy_low_pct')}%"),
            "remediation": ("Mix of plain code/data and packed/compressed sections is normal. "
                            "Continue using compression + signed updates."),
            "cwe": "CWE-200", "owasp": "A05:2021"}


def rule_encrypted_blob(s):
    if s.get("entropy_classification") != "encrypted_or_compressed":
        return None
    return {"name": "Firmware appears fully encrypted or compressed",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-200", "owasp": "A05:2021",
            "evidence": (f">{s.get('entropy_high_pct')}% of bytes sustained >7.5 bits/byte entropy "
                         f"(avg={s.get('entropy_avg')})"),
            "remediation": ("Good defence against trivial extraction, but static analysis is "
                            "blocked without the decryption key. Verify (a) the key is hardware-"
                            "bound (TPM / SoC fuse) — not stored alongside firmware; (b) the chosen "
                            "cipher is AES-GCM or equivalent AEAD; (c) signature verification "
                            "happens BEFORE decryption to prevent oracle attacks. Run dynamic "
                            "analysis via UART/JTAG on a live device once key derivation is "
                            "understood.")}


def rule_plaintext_blob(s):
    if s.get("entropy_classification") != "plaintext_no_encryption":
        return None
    return {"name": "Firmware has no encrypted / compressed sections",
            "severity": "LOW", "cvss": "3.1",
            "cwe": "CWE-311", "owasp": "A02:2021",
            "evidence": (f">{s.get('entropy_low_pct')}% of bytes <3.0 bits/byte entropy — "
                         f"plaintext or padding throughout"),
            "remediation": ("Firmware is shipped as raw plaintext. Any field with cleartext access "
                            "(SPI dump, eMMC chip-off, OTA capture) can read all code + secrets. "
                            "Encrypt at-rest with vendor-side AES-GCM and store key in SoC fuse / "
                            "TPM. At minimum, compress with LZMA to slow casual analysis.")}


def rule_mostly_compressed(s):
    cls = s.get("entropy_classification")
    if cls not in ("mostly_compressed", "mostly_plaintext"):
        return None
    sev = "INFO"
    label = "mostly compressed" if cls == "mostly_compressed" else "mostly plaintext"
    high_regions = s.get("entropy_high_regions") or []
    low_regions = s.get("entropy_low_regions") or []
    return {"name": f"Mixed entropy profile — firmware {label}",
            "severity": sev,
            "evidence": (f"high regions={len(high_regions)}, low regions={len(low_regions)}, "
                         f"high%={s.get('entropy_high_pct')}, low%={s.get('entropy_low_pct')}"),
            "remediation": ("Use the region offsets above as carving guides for static analysis. "
                            "Map each high-entropy region to a packed filesystem (squashfs/lzma) "
                            "and each low-entropy region to padding / config / firmware metadata."),
            "cwe": "CWE-200", "owasp": "A05:2021"}


BINARY_ENTROPY_AUDIT_FINDING_RULES = [rule_positive, rule_encrypted_blob,
                                        rule_plaintext_blob, rule_mostly_compressed]
