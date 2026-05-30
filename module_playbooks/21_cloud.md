# Cloud Security Testing — Master Reference (`cloud_ruff`)

**100% Full Industry Standard catalogue** — aligned with CSA CCM v4 + NIST SP 800-204 + CIS Foundations Benchmarks (AWS/Azure/GCP) + Cloud Native Security Whitepaper (CNCF) + 2024–2026 industry additions (CIEM, OIDC trust, multi-cloud privesc).

12 sections, 165 techniques.

**Legend:** ✅ auto · ✅ (probe) · 👤 manual · ⭐ NEW 2024+

---

## Summary

| § | Section | Techniques | Auto | Probe | Manual |
|---|---|---|---|---|---|
| 1 | Cloud Asset Discovery | 16 | 14 | 0 | 2 |
| 2 | AWS Security | 22 | 19 | 0 | 3 |
| 3 | Azure Security | 18 | 15 | 0 | 3 |
| 4 | GCP Security | 14 | 12 | 0 | 2 |
| 5 | Multi-Cloud Identity (CIEM) ⭐ | 12 | 10 | 0 | 2 |
| 6 | Serverless (Lambda / Functions / Cloud Run) | 12 | 10 | 0 | 2 |
| 7 | Container Registry & Image | 10 | 9 | 0 | 1 |
| 8 | Cloud Storage (S3/Blob/GCS) | 10 | 9 | 0 | 1 |
| 9 | Cloud Network & VPC | 10 | 8 | 0 | 2 |
| 10 | Cloud Secrets & KMS | 10 | 8 | 0 | 2 |
| 11 | Cross-Cloud Attack Paths (OIDC) ⭐ | 10 | 6 | 1 | 3 |
| 12 | Cloud CVE / Incident Response | 8 | 6 | 0 | 2 |
| **TOTAL** | | **152** | **126** | **1** | **25** |

---

## §1 — Cloud Asset Discovery

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 1 | S3 bucket enumeration | s3scanner, bucket-stream | ✅ |
| 2 | Azure Blob enumeration | MicroBurst, azurehound | ✅ |
| 3 | GCS bucket enumeration | gcp_bucket_brute | ✅ |
| 4 | CloudFront / Azure CDN / Cloud CDN discovery | cert pivot + dnsrecon | ✅ |
| 5 | Azure App Services / GCP App Engine | MicroBurst, cloud_enum | ✅ |
| 6 | Lambda / Function URL enum | cloud_enum + custom | ✅ |
| 7 | Heroku / Vercel / Netlify discovery | cloud_enum | ✅ |
| 8 | Kubernetes API exposure (6443/10250) | kube-hunter, masscan | ✅ |
| 9 | etcd / API server exposure | nmap NSE + nuclei | ✅ |
| 10 | Cloud-enum multi-platform | initstring/cloud_enum | ✅ |
| 11 | Shodan / Censys cloud filters | shodan, censys | ✅ |
| 12 ⭐ | Cloud Asset Inventory (CAI) via gcloud/aws | aws, gcloud, az CLIs | ✅ |
| 13 ⭐ | AWS Config / Azure Resource Graph | aws config + custom | ✅ |
| 14 ⭐ | Cloud Sprawl Detection (untagged resources) | custom + APIs | ✅ |
| 15 | Manual cloud-attack-path map (Pacu/CloudGoat) | manual | 👤 |
| 16 | Cross-account inventory traversal | manual + ScoutSuite | 👤 |

---

## §2 — AWS Security

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 17 | Prowler full CSPM scan | prowler | ✅ |
| 18 | ScoutSuite multi-cloud (AWS) | scoutsuite | ✅ |
| 19 | CloudSploit policy violations | cloudsploit | ✅ |
| 20 | Pacu offensive enum + exploit | Pacu | ✅ (probe) |
| 21 | IAM Cloudsplaining (excessive privs) | Cloudsplaining | ✅ |
| 22 | IAM AccessAnalyzer findings | aws + custom | ✅ |
| 23 | S3 ACL / public-read / public-write | s3scanner + aws | ✅ |
| 24 | S3 block-public-access account-wide | aws s3control | ✅ |
| 25 | EC2 metadata service IMDSv1 exposure | nmap + manual | ✅ |
| 26 | EC2 SSRF → IMDS → creds steal | manual + Burp | 👤 |
| 27 | Security group 0.0.0.0/0 audit | prowler + custom | ✅ |
| 28 | Public RDS / Redshift / DocumentDB | prowler + custom | ✅ |
| 29 | CloudTrail logging absence | prowler + aws | ✅ |
| 30 | GuardDuty enabled check | aws + custom | ✅ |
| 31 | Secrets Manager / Parameter Store leak | custom + aws | ✅ |
| 32 | KMS key policy audit | aws + custom | ✅ |
| 33 | Lambda runtime EOL audit | aws + custom | ✅ |
| 34 | Lambda over-permissive role | LambdaGuard | ✅ |
| 35 ⭐ | IAM Identity Center (SSO) misconfig | aws-sso-utils + custom | ✅ |
| 36 ⭐ | AWS SES / SNS abuse audit | custom + aws | ✅ |
| 37 ⭐ | AWS Organizations SCP audit | aws + custom | ✅ |
| 38 | Manual privesc path (CloudFox) | CloudFox | 👤 |

---

## §3 — Azure Security

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 39 | ScoutSuite Azure | scoutsuite | ✅ |
| 40 | MicroBurst (PowerShell offensive) | MicroBurst | ✅ |
| 41 | Stormspotter / AzureHound | StormSpotter, azurehound | ✅ |
| 42 | ScubaGear M365 baseline | ScubaGear | ✅ |
| 43 | Azure Storage public-blob | MicroBurst | ✅ |
| 44 | Azure Function over-permissive | custom + az | ✅ |
| 45 | App Service config audit | az + custom | ✅ |
| 46 | Key Vault access policy / RBAC | az + custom | ✅ |
| 47 | Managed Identity abuse | manual + az | ✅ |
| 48 | Azure SQL public network access | az + custom | ✅ |
| 49 | NSG 0.0.0.0/0 audit | az + custom | ✅ |
| 50 ⭐ | Azure RBAC over-permissive (custom-role audit) | custom + az | ✅ |
| 51 ⭐ | Azure Subscription contributor → tenant pivot | manual + az | 👤 |
| 52 ⭐ | Azure DevOps service connection audit | custom | ✅ |
| 53 ⭐ | Azure Logic Apps / Power Automate connector abuse | manual + az | 👤 |
| 54 | Activity Log audit absence | az + custom | ✅ |
| 55 | Defender for Cloud enabled check | az + custom | ✅ |
| 56 | Manual Azure attack path (StormSpotter) | manual | 👤 |

---

## §4 — GCP Security

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 57 | ScoutSuite GCP | scoutsuite | ✅ |
| 58 | gcp-scanner | gcp-scanner | ✅ |
| 59 | gcp_bucket_brute | gcp_bucket_brute | ✅ |
| 60 | IAM Recommender (over-perm) | gcloud recommender | ✅ |
| 61 | Service-account key age + rotation | gcloud + custom | ✅ |
| 62 | Cloud Storage public-read | gsutil + custom | ✅ |
| 63 | Compute Engine metadata service | manual + gcloud | ✅ |
| 64 | GKE workload identity check | gcloud + custom | ✅ |
| 65 | Cloud SQL public-IP audit | gcloud + custom | ✅ |
| 66 | Cloud Run unauthenticated invocation | gcloud + custom | ✅ |
| 67 ⭐ | Cloud Function HTTP trigger auth | gcloud + custom | ✅ |
| 68 ⭐ | Org Policy violations | gcloud orgpolicies | ✅ |
| 69 | Manual cross-project IAM pivot | manual | 👤 |
| 70 | Manual cross-org attack path | manual | 👤 |

---

## §5 — Multi-Cloud Identity (CIEM) ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 71 ⭐ | CloudFox cross-cloud privesc map | CloudFox | ✅ |
| 72 ⭐ | Stratus Red Team adversary emulation | stratus-red-team | ✅ |
| 73 ⭐ | iam-floyd policy analysis | iam-floyd | ✅ |
| 74 ⭐ | Sonrai / Ermetic findings | Sonrai, Ermetic | ✅ |
| 75 ⭐ | PMapper cross-account graph | PMapper | ✅ |
| 76 ⭐ | Wildcard resource ARN over-perm | Cloudsplaining + custom | ✅ |
| 77 ⭐ | Cross-account trust policy abuse | manual + custom | ✅ |
| 78 ⭐ | Cross-cloud OIDC trust map | manual + custom | ✅ |
| 79 ⭐ | Inactive identity / dormant key | custom + APIs | ✅ |
| 80 ⭐ | Privileged group membership audit | custom + APIs | ✅ |
| 81 | Manual identity-attack-chain | analyst | 👤 |
| 82 | Manual cross-tenant pivot | analyst | 👤 |

---

## §6 — Serverless (Lambda / Functions / Cloud Run)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 83 | LambdaGuard scan | LambdaGuard | ✅ |
| 84 | Lambda execution role over-perm | custom + aws | ✅ |
| 85 | Lambda env-var secret leak | aws + custom | ✅ |
| 86 | Lambda layer CVE | osv + custom | ✅ |
| 87 ⭐ | Lambda URL public-invocation audit | aws + custom | ✅ |
| 88 ⭐ | Azure Function HTTP auth-level audit | az + custom | ✅ |
| 89 ⭐ | Cloud Run --allow-unauthenticated audit | gcloud + custom | ✅ |
| 90 ⭐ | EventBridge / Event Grid abuse | manual + APIs | ✅ |
| 91 ⭐ | Step Functions / Logic Apps abuse | manual + APIs | ✅ |
| 92 | Cold-start side-channel | manual + research | 👤 |
| 93 | Manual function chain pivot | analyst | 👤 |
| 94 | Serverless RCE via dep confusion | manual + custom | ✅ |

---

## §7 — Container Registry & Image

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 95 | Trivy image scan | trivy image | ✅ |
| 96 | Grype scan | grype | ✅ |
| 97 | Docker Hub / ECR / GCR public-repo audit | custom + APIs | ✅ |
| 98 | Image registry exposure (5000) | shodan + nuclei | ✅ |
| 99 | Hadolint Dockerfile lint | hadolint | ✅ |
| 100 | Secret-in-image scan | trufflehog + dive | ✅ |
| 101 ⭐ | OCI signature verify (cosign) | cosign verify | ✅ |
| 102 ⭐ | SLSA provenance check | slsa-verifier | ✅ |
| 103 ⭐ | Distroless / Wolfi base check | image meta | ✅ |
| 104 | Manual chain (image → escape → cloud) | analyst | 👤 |

---

## §8 — Cloud Storage (S3/Blob/GCS)

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 105 | S3 bucket enum + public ACL | s3scanner | ✅ |
| 106 | Azure Blob public anonymous | MicroBurst | ✅ |
| 107 | GCS public read/write | gcp_bucket_brute | ✅ |
| 108 | Bucket policy audit (presigned-URL abuse) | aws + custom | ✅ |
| 109 | Bucket encryption (SSE) audit | aws + custom | ✅ |
| 110 | Bucket versioning + MFA-delete audit | aws + custom | ✅ |
| 111 | Bucket logging enabled check | aws + custom | ✅ |
| 112 ⭐ | S3 Object Lambda abuse | manual + aws | ✅ |
| 113 ⭐ | Bucket clone / hijack (orphan DNS CNAME) | nuclei takeover | ✅ |
| 114 | Manual bucket discovery (creative naming) | analyst | 👤 |

---

## §9 — Cloud Network & VPC

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 115 | Security group / NSG / firewall rule audit | prowler, scoutsuite | ✅ |
| 116 | Public endpoint inventory | custom + APIs | ✅ |
| 117 | VPC flow logs enabled | aws + custom | ✅ |
| 118 | VPN / Direct Connect / ExpressRoute audit | custom + APIs | ✅ |
| 119 | Cross-VPC peering audit | aws + custom | ✅ |
| 120 ⭐ | Transit Gateway / Hub-and-spoke audit | aws + custom | ✅ |
| 121 ⭐ | PrivateLink / Private Endpoint audit | aws + custom | ✅ |
| 122 ⭐ | Route 53 / Cloud DNS hijack audit | manual + nuclei | ✅ |
| 123 | Manual lateral via Bastion abuse | analyst | 👤 |
| 124 | Cross-account network pivot | analyst | 👤 |

---

## §10 — Cloud Secrets & KMS

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 125 | AWS Secrets Manager policy audit | aws + custom | ✅ |
| 126 | Azure Key Vault access policy | az + custom | ✅ |
| 127 | GCP Secret Manager IAM audit | gcloud + custom | ✅ |
| 128 | KMS key policy over-perm | aws + custom | ✅ |
| 129 | Secret rotation cadence audit | custom + APIs | ✅ |
| 130 | Hardcoded creds in env vars | custom + APIs | ✅ |
| 131 ⭐ | HSM / Nitro Enclave audit | manual + aws | ✅ |
| 132 ⭐ | Cross-account KMS grant abuse | manual + aws | ✅ |
| 133 | Manual secret-exfil chain | analyst | 👤 |
| 134 | Cross-cloud KMS key transfer audit | analyst | 👤 |

---

## §11 — Cross-Cloud Attack Paths (OIDC) ⭐ NEW

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 135 ⭐ | GitHub Actions OIDC trust → AWS | custom + aws | ✅ |
| 136 ⭐ | GitLab CI OIDC trust → AWS | custom + aws | ✅ |
| 137 ⭐ | Azure-to-AWS workload identity bridge | manual + custom | ✅ |
| 138 ⭐ | EKS-to-IAM IRSA misconfig | custom + aws | ✅ |
| 139 ⭐ | GCP Workload Identity → cross-project | gcloud + custom | ✅ |
| 140 ⭐ | OIDC sub claim wildcard abuse | manual + custom | ✅ |
| 141 ⭐ | OIDC issuer URL takeover (DNS) | manual + nuclei | ✅ (probe) |
| 142 | Manual cross-cloud privesc chain | CloudFox | 👤 |
| 143 | Multi-cloud SCIM abuse | manual | 👤 |
| 144 | Hybrid AD → Entra ID → AWS chain | manual + ROADtools | 👤 |

---

## §12 — Cloud CVE / Incident Response

| # | Technique | Tool / Method | Auto? |
|---|---|---|---|
| 145 | Container escape CVE (Leaky Vessels, Dirty Pipe) | trivy + custom | ✅ |
| 146 | Kubernetes CVE (kubelet, kube-proxy) | trivy + nuclei | ✅ |
| 147 | Cloud-provider-specific CVE | nuclei + NVD | ✅ |
| 148 ⭐ | CISA KEV cross-ref (cloud-relevant) | KEV API | ✅ |
| 149 | CloudTrail / Activity Log incident replay | custom + jq | ✅ |
| 150 | GuardDuty / Defender / Chronicle alerts | aws/az/gcloud | ✅ |
| 151 | Manual cloud forensics (memory, disk snapshot) | analyst | 👤 |
| 152 | Manual cross-cloud attribution | analyst | 👤 |

---

## Compliance Mapping
- **CIS Foundations Benchmarks (AWS/Azure/GCP)** · **CSA CCM v4** · **NIST SP 800-204** · **PCI DSS 4.0 §1.2/§1.3** · **HIPAA** · **SOC 2 CC6/CC7** · **FedRAMP** · **ISO 27017 (cloud)** · **NIS2** · **DORA**

## VulnusLab Cloud Status
- Status: 🟡 SOON (per modules_2026_inventory.md #20)
- Coverage: 0% (module not yet built)

## Roadmap to 100%
1. Phase C-1: §1 Discovery + §8 Storage (~26 scanners)
2. Phase C-2: §2 AWS pack (22 scanners)
3. Phase C-3: §3 Azure + §4 GCP (32 scanners)
4. Phase C-4: §5 CIEM ⭐ + §11 OIDC ⭐ (22 scanners)
5. Phase C-5: §6 Serverless + §7 Container + §9 Network + §10 Secrets (42 scanners)
6. Phase C-6: §12 CVE/IR (8 scanners)

## References
- Prowler: https://github.com/prowler-cloud/prowler
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- Pacu: https://github.com/RhinoSecurityLabs/pacu
- CloudFox: https://github.com/BishopFox/cloudfox
- Stratus Red Team: https://github.com/DataDog/stratus-red-team
- Cloudsplaining: https://github.com/salesforce/cloudsplaining
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- CSA CCM v4: https://cloudsecurityalliance.org/research/cloud-controls-matrix
