"""tier10_provenance - real code-signing & SLSA provenance verification (playbook §5).

Upgrades the previously advisory-only cosign / SLSA techniques to real checks
that run when the customer supplies an image_ref: signature/attestation presence
discovery via cosign (always observable), with full keyless trust verification
when a certificate identity/issuer policy is provided.
"""
