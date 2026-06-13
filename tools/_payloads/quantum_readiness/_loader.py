"""Quantum-readiness classification + compliance tables (VL-CORE: module-owned).

Single source of truth for what counts as quantum-vulnerable vs post-quantum,
plus the TLS named-group codepoints the raw probe needs and the compliance
controls a missing-PQC finding impacts. No cross-module imports.
"""

# Public-key primitives broken by Shor's algorithm on a cryptographically
# relevant quantum computer (CRQC). All of today's TLS/SSH key exchange and
# signatures fall here.
QUANTUM_VULNERABLE_PUBKEY = {
    "rsa", "dsa", "ecdsa", "eddsa", "ed25519", "ed448",
    "ecdh", "x25519", "x448", "dh", "diffie-hellman",
}

# Post-quantum / hybrid key exchange identifiers.
PQC_TLS_GROUPS = {"x25519mlkem768", "secp256r1mlkem768", "x25519kyber768"}
PQC_SSH_KEX = {
    "mlkem768x25519-sha256", "mlkem768x25519-sha256@openssh.com",
    "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
}

# TLS supported_groups codepoints (IANA) used by the raw ClientHello probe.
GROUP_CODEPOINTS = {
    0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1",
    0x0019: "secp521r1", 0x0100: "ffdhe2048", 0x0101: "ffdhe3072",
    0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768",
    0x6399: "X25519Kyber768Draft00",
}
PQC_CODEPOINTS = {0x11EC, 0x11EB, 0x6399}


def symmetric_margin(cipher_name, bits):
    """Grover's algorithm halves the effective key strength of a symmetric
    cipher. Returns (effective_bits, verdict)."""
    name = (cipher_name or "").upper()
    b = bits or 0
    if b >= 256 or "AES_256" in name or "AES-256" in name or "CHACHA20" in name:
        return (b // 2 if b else 128), "safe"      # AES-256 -> 128-bit, fine
    if b:
        return b // 2, "weak"                       # AES-128 -> ~64-bit margin
    return 0, "unknown"


def host_key_is_vulnerable(algo: str) -> bool:
    a = (algo or "").lower()
    return any(v in a for v in ("rsa", "ecdsa", "ed25519", "ed448", "dss"))


# Controls impacted by quantum-vulnerable transport crypto / missing PQC.
PQC_COMPLIANCE = "NIST IR 8547 - NSA CNSA 2.0 - NIST FIPS 203 - NIST SC-13 - BSI TR-02102"
