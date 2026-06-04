"""Customer Credential Vault - encrypted per-tenant storage for scan-target creds.

AWS keys, Azure service principals, AD domain users, K8s kubeconfigs, OAuth
tokens, API keys. Per-customer, encrypted at rest with AES-256-GCM. Used by
the AD / Cloud / SSPM / Auth Attacks / Hybrid Identity / Post-Exploit /
Privesc modules when their probes need authorization to scan customer
infra.

Master key: CREDENTIAL_VAULT_MASTER_KEY env var (32 bytes, base64).
Per-user subkey: HKDF(master_key, user_id) -> 32 bytes.

This file is the package marker; actual logic in _vault.py + endpoint
file lives in endpoints/credentials_orchestrator.py.
"""
