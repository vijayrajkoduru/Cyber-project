"""supply_chain module - OSS supply-chain audit (per module_playbooks/25_supply_chain.md).

8 sections, 106 techniques. Starter set covers §1 SBOM + §2 SCA + §7 container
image supply chain via the pre-installed Anchore/Aquasec/Gitleaks stack
(trivy, grype, syft, osv-scanner, gitleaks). Customer-provided inputs include
ScanRequest.image_ref (OCI image), ScanRequest.repo_url (git clone URL), or
ScanRequest.target (local path / hostname).
"""
