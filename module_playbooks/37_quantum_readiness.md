# Quantum Readiness — Module Playbook (canon)

**Module key:** `quantum_readiness`  **Type:** VA (passive, detection-only)
**Target:** a domain / host / IP / URL (same intake as Recon).

## Purpose
Measure a target's exposure to the post-quantum threat — primarily
**harvest-now-decrypt-later (HNDL)**: traffic encrypted today with classical
key exchange (RSA / ECDH / X25519 / DH) can be recorded now and decrypted once
a cryptographically-relevant quantum computer (CRQC) exists. The module reports
what quantum-vulnerable crypto is in use, whether post-quantum (PQC) key
exchange is offered, and maps it to the migration frameworks auditors ask about.

## Severity policy
Everything is **advisory / LOW / INFO**. A CRQC does not exist today, so this is
a *future* risk and is **never graded High**. Positive PQC support is reported
as POSITIVE. Probes are conservative — any ambiguity reports "not observed",
never a false positive.

## Isolation (VL-CORE)
Self-contained. Owns `tools/_payloads/quantum_readiness/_loader.py` (algorithm
classification + codepoints + compliance map). No imports from any other module
(`tools/recon/...` etc.). Uses only the shared framework (`tools/_shared`,
`tools/_vl_core`) and Python stdlib + `cryptography` (already in the image) —
**no new dependency** (the PQC-hybrid check is a hand-rolled TLS 1.3 probe, so it
needs neither OpenSSL 3.5 nor sslyze).

## Tiers & scanners

### tier1_tls — `tls_quantum_exposure`  [LIVE]
- stdlib `ssl` handshake → negotiated cipher, TLS version, peer cert.
- `cryptography` → cert signature algorithm + public-key type/size.
- Raw TLS 1.3 ClientHello probe offering `X25519MLKEM768` (0x11EC) → does the
  server select the PQC hybrid?
- Findings: HNDL exposure (no PQC) · PQC offered (POSITIVE) · quantum-vulnerable
  cert key · symmetric cipher below long-term Grover margin (AES-128).

### tier3_ssh — `ssh_quantum_exposure`  [LIVE]
- Reads the SSH banner + `SSH_MSG_KEXINIT` off the socket (no login).
- Findings: no PQC SSH KEX · PQC SSH KEX offered (POSITIVE) · quantum-vulnerable
  host keys.

### Future (advisory, not in v1)
- tier2 mail/DB TLS surfaces · tier4 VPN/IPsec/WireGuard · tier5 cert-inventory
  crypto-agility · tier6 source/SBOM Crypto-BOM (CBOM) · tier7 per-asset HNDL
  scoring + CycloneDX CBOM export.

## Compliance mapping
Findings carry `compliance = "NIST IR 8547 - NSA CNSA 2.0 - NIST FIPS 203 -
NIST SC-13 - BSI TR-02102"` plus CWE-327 / CWE-326, so the PDF maps them to the
PQC-migration controls.

## Orchestrator
`endpoints/quantum_readiness_orchestrator.py` auto-discovers `tier*_*` scanners
(mirrors Recon). Endpoint: `POST /api/quantum_readiness/run_all`. Frontend tile
routes through `_autoMod` → `ModuleAutoPanel`; PDF via `generateUniversalVLReport`.
