"""§21 Cloud Security — 124 endpoints per 21_cloud.md.
12 sections: discovery, AWS, Azure, GCP, multi-cloud CIEM, serverless,
container registry, storage, network/VPC, secrets/KMS, OIDC cross-cloud, compliance.

VL-FORGE upgrade 2026-05-30: tier8 Cloud Storage (S3/Azure Blob/GCS public
bucket checks) upgraded to LIVE PROBES. tier11 OIDC discovery upgraded to
LIVE PROBES. Other tiers correctly remain advisory (AWS/Azure/GCP audits
require provider credentials which external SaaS can't have).
"""
import socket
import urllib.request
import urllib.error
import json
from tools._pack_common import make_advisory_router, _adv_response
from tools._shared import wrap_finding


def _host(target: str) -> str:
    s = target.split("://", 1)[-1].split("/")[0].split(":")[0]
    return s.strip().lower() or target


def _http_get(url: str, timeout: float = 5.0) -> tuple:
    """Returns (status_code, body_first_2k, headers_dict)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnusLab/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(2048).decode("utf-8", errors="ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        try: body = e.read(2048).decode("utf-8", errors="ignore")
        except Exception: body = ""
        return e.code, body, dict(e.headers) if e.headers else {}
    except Exception:
        return 0, "", {}


def _probe_s3_public(target, req):
    """Check S3 bucket for public read access. Target = bucket name OR full URL."""
    host = _host(target)
    bucket = host.replace(".s3.amazonaws.com", "").replace(".s3.us-east-1.amazonaws.com", "").split(".")[0]
    urls = [
        f"https://{bucket}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket}/",
    ]
    findings = []
    for url in urls:
        code, body, _ = _http_get(url, timeout=4)
        if code == 200 and "<ListBucketResult" in body:
            findings.append(wrap_finding(
                f"S3 bucket '{bucket}' publicly listable — anonymous LIST succeeded",
                "CRITICAL", cvss="9.0", cwe="CWE-200", owasp="A05:2021",
                remediation="Apply BlockPublicAccess at account level; remove public ACLs.",
                evidence_marker=f"GET {url} → 200 with ListBucketResult"))
            break
        if code == 200 and "<?xml" in body and "<Error>" not in body:
            findings.append(wrap_finding(
                f"S3 bucket '{bucket}' returned XML (likely listable)",
                "HIGH", cvss="7.5", cwe="CWE-200",
                remediation="BlockPublicAccess + remove public ACLs.",
                evidence_marker=f"GET {url} → 200 XML"))
            break
        if code == 403 and "AccessDenied" in body:
            findings.append(wrap_finding(
                f"S3 bucket '{bucket}' exists but access denied (good)",
                "POSITIVE", cvss="0.0", cwe="N/A",
                remediation="Continue least-privilege bucket policy.",
                evidence_marker=f"GET {url} → 403 AccessDenied"))
            break
    if not findings:
        findings.append(wrap_finding(
            f"No S3 bucket found at name '{bucket}' (NXDOMAIN or 404)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Confirm bucket naming convention; check other regions.",
            evidence_marker=f"No listable bucket at standard S3 hostnames"))
    return {"tool":"s3_bucket_public_static_site","target":target,"scan_time":0,
            "vulnerable": any(f.get("severity") in ("CRITICAL","HIGH") for f in findings),
            "severity": findings[0].get("severity","INFO"),
            "findings": findings, "tests_performed": len(urls),
            "tests_summary": f"S3 public access check on bucket '{bucket}'",
            "raw_data": {"bucket": bucket, "urls_tested": urls}}


def _probe_azure_blob_public(target, req):
    """Check Azure Blob storage account for anonymous read access."""
    host = _host(target)
    account = host.replace(".blob.core.windows.net", "").split(".")[0]
    url = f"https://{account}.blob.core.windows.net/?comp=list"
    code, body, _ = _http_get(url, timeout=4)
    findings = []
    if code == 200 and "<EnumerationResults" in body:
        findings.append(wrap_finding(
            f"Azure Blob storage account '{account}' allows anonymous container listing",
            "CRITICAL", cvss="9.0", cwe="CWE-200", owasp="A05:2021",
            remediation="Disable anonymous access at storage account level.",
            evidence_marker=f"GET {url} → 200 with EnumerationResults"))
    elif code in (403, 401):
        findings.append(wrap_finding(
            f"Azure Blob '{account}' exists, anonymous access correctly denied",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue private access posture.",
            evidence_marker=f"GET {url} → {code}"))
    else:
        findings.append(wrap_finding(
            f"Azure Blob storage account '{account}' not found (NXDOMAIN or unreachable)",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify account name.",
            evidence_marker=f"GET {url} → {code}"))
    return {"tool":"azure_blob_public_anon","target":target,"scan_time":0,
            "vulnerable": code == 200 and "<EnumerationResults" in body,
            "severity": findings[0].get("severity","INFO"),
            "findings": findings, "tests_performed": 1,
            "tests_summary": f"Azure Blob anonymous check on {account}",
            "raw_data": {"account": account, "url": url, "status": code}}


def _probe_gcs_bucket_public(target, req):
    """Check GCS bucket for public read access."""
    host = _host(target)
    bucket = host.replace(".storage.googleapis.com", "").split(".")[0]
    url = f"https://storage.googleapis.com/{bucket}/"
    code, body, _ = _http_get(url, timeout=4)
    findings = []
    if code == 200 and ("<ListBucketResult" in body or '<?xml' in body):
        findings.append(wrap_finding(
            f"GCS bucket '{bucket}' publicly listable",
            "CRITICAL", cvss="9.0", cwe="CWE-200", owasp="A05:2021",
            remediation="Remove allUsers/allAuthenticatedUsers from bucket IAM.",
            evidence_marker=f"GET {url} → 200 listable"))
    elif code in (401, 403):
        findings.append(wrap_finding(
            f"GCS bucket '{bucket}' exists, access denied (good)",
            "POSITIVE", cvss="0.0", cwe="N/A",
            remediation="Continue least-privilege.",
            evidence_marker=f"GET {url} → {code}"))
    else:
        findings.append(wrap_finding(
            f"GCS bucket '{bucket}' not found",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="Verify bucket name.",
            evidence_marker=f"GET {url} → {code}"))
    return {"tool":"gcs_bucket_acl_legacy","target":target,"scan_time":0,
            "vulnerable": code == 200,
            "severity": findings[0].get("severity","INFO"),
            "findings": findings, "tests_performed": 1,
            "tests_summary": f"GCS public check on {bucket}",
            "raw_data": {"bucket": bucket, "url": url, "status": code}}


def _probe_oidc_discovery(target, req):
    """Fetch /.well-known/openid-configuration to audit OIDC posture."""
    host = _host(target)
    urls = [
        f"https://{host}/.well-known/openid-configuration",
        f"https://login.{host}/.well-known/openid-configuration",
    ]
    findings = []; data = {}
    for url in urls:
        code, body, _ = _http_get(url, timeout=4)
        if code == 200 and body.strip().startswith("{"):
            try:
                cfg = json.loads(body)
                data = cfg
                issues = []
                if cfg.get("token_endpoint_auth_methods_supported") and \
                   "none" in (cfg.get("token_endpoint_auth_methods_supported") or []):
                    issues.append("token_endpoint_auth_methods includes 'none' (public client allowed)")
                if not cfg.get("code_challenge_methods_supported"):
                    issues.append("PKCE (code_challenge_methods_supported) NOT advertised")
                if cfg.get("response_types_supported") and \
                   "token" in (cfg.get("response_types_supported") or []) and \
                   "id_token token" in (cfg.get("response_types_supported") or []):
                    issues.append("implicit flow (response_type=token) still supported")
                if issues:
                    findings.append(wrap_finding(
                        f"OIDC discovery — {len(issues)} posture issue(s)",
                        "MEDIUM", cvss="5.5", cwe="CWE-287",
                        remediation="Enforce PKCE; disable implicit flow; require client auth.",
                        evidence_marker="; ".join(issues)))
                else:
                    findings.append(wrap_finding(
                        "OIDC discovery present, posture looks healthy",
                        "POSITIVE", cvss="0.0", cwe="N/A",
                        remediation="Continue OIDC best practices.",
                        evidence_marker=f"Issuer: {cfg.get('issuer','?')}"))
                break
            except Exception:
                pass
    if not findings:
        findings.append(wrap_finding(
            "No OIDC discovery endpoint at standard paths",
            "INFO", cvss="0.0", cwe="N/A",
            remediation="If OIDC is in use, ensure discovery endpoint is reachable.",
            evidence_marker=f"Tried {len(urls)} URLs"))
    return {"tool":"oidc_provider_thumbprint_audit","target":target,"scan_time":0,
            "vulnerable": findings[0].get("severity") in ("MEDIUM","HIGH"),
            "severity": findings[0].get("severity","INFO"),
            "findings": findings, "tests_performed": len(urls),
            "tests_summary": "OIDC discovery posture audit",
            "raw_data": data}


PROBES = {
    "s3_bucket_public_static_site": _probe_s3_public,
    "azure_blob_public_anon":       _probe_azure_blob_public,
    "gcs_bucket_acl_legacy":        _probe_gcs_bucket_public,
    "oidc_provider_thumbprint_audit": _probe_oidc_discovery,
}

T = [
    # §1 Cloud Asset Discovery (14)
    ("cloudfox_aws_all", "CloudFox aws all-checks.", "MEDIUM", "5.5"),
    ("cloudfox_azure", "CloudFox azure.", "MEDIUM", "5.5"),
    ("cloudfox_gcp", "CloudFox gcp.", "MEDIUM", "5.5"),
    ("scoutsuite_aws", "ScoutSuite AWS.", "MEDIUM", "5.5"),
    ("scoutsuite_azure", "ScoutSuite Azure.", "MEDIUM", "5.5"),
    ("scoutsuite_gcp", "ScoutSuite GCP.", "MEDIUM", "5.5"),
    ("prowler_aws_check", "Prowler AWS check.", "MEDIUM", "5.5"),
    ("prowler_azure_check", "Prowler Azure check.", "MEDIUM", "5.5"),
    ("prowler_gcp_check", "Prowler GCP check.", "MEDIUM", "5.5"),
    ("steampipe_query", "Steampipe SQL queries.", "MEDIUM", "5.5"),
    ("cartography_graph", "Cartography graph dump.", "MEDIUM", "5.5"),
    ("recon_cloud_dns", "Cloud DNS recon (ASN/cloud-detect).", "INFO", "0.0"),
    ("manual_cloud_discovery", "Manual cloud discovery.", "INFO", "0.0"),
    ("manual_cloud_asset_inventory", "Manual cloud asset inventory.", "INFO", "0.0"),
    # §2 AWS Security (19)
    ("aws_iam_overpermissive", "AWS IAM overpermissive policies.", "HIGH", "7.5"),
    ("aws_iam_user_keys_old", "AWS IAM user keys older than 90 days.", "MEDIUM", "5.5"),
    ("aws_root_account_usage", "AWS root account usage.", "HIGH", "7.5"),
    ("aws_mfa_not_enforced", "AWS MFA not enforced.", "HIGH", "7.5"),
    ("aws_cloudtrail_disabled", "AWS CloudTrail disabled.", "HIGH", "7.5"),
    ("aws_cloudtrail_log_validation", "AWS CloudTrail log validation off.", "MEDIUM", "5.5"),
    ("aws_config_disabled", "AWS Config disabled.", "MEDIUM", "5.5"),
    ("aws_guardduty_disabled", "AWS GuardDuty disabled.", "MEDIUM", "5.5"),
    ("aws_s3_bucket_public", "AWS S3 bucket public.", "CRITICAL", "9.0"),
    ("aws_s3_bucket_acl_misconfig", "AWS S3 bucket ACL misconfig.", "HIGH", "8.0"),
    ("aws_s3_bucket_unencrypted", "AWS S3 bucket unencrypted.", "MEDIUM", "5.5"),
    ("aws_ec2_sg_open", "AWS EC2 security group open to 0.0.0.0/0.", "HIGH", "8.0"),
    ("aws_ec2_imds_v1_enabled", "AWS EC2 IMDSv1 enabled.", "HIGH", "7.5"),
    ("aws_rds_public_access", "AWS RDS public access.", "HIGH", "8.0"),
    ("aws_lambda_resource_policy", "AWS Lambda resource policy open.", "HIGH", "7.5"),
    ("aws_kms_key_rotation_off", "AWS KMS key rotation off.", "MEDIUM", "5.5"),
    ("aws_efs_unencrypted", "AWS EFS unencrypted.", "MEDIUM", "5.5"),
    ("aws_eks_endpoint_public", "AWS EKS endpoint public.", "HIGH", "7.5"),
    ("aws_secrets_manager_audit", "AWS Secrets Manager audit.", "MEDIUM", "5.5"),
    # §3 Azure Security (15)
    ("azure_aad_pim_audit", "Azure AAD PIM audit.", "MEDIUM", "5.5"),
    ("azure_conditional_access_audit", "Conditional Access audit.", "HIGH", "7.5"),
    ("azure_managed_identity_audit", "Managed Identity audit.", "MEDIUM", "5.5"),
    ("azure_keyvault_public_access", "KeyVault public access.", "HIGH", "8.0"),
    ("azure_storage_public", "Storage account public.", "CRITICAL", "9.0"),
    ("azure_storage_unencrypted", "Storage unencrypted.", "MEDIUM", "5.5"),
    ("azure_vm_disk_unencrypted", "VM disk unencrypted.", "MEDIUM", "5.5"),
    ("azure_nsg_open_inbound", "NSG open inbound rules.", "HIGH", "8.0"),
    ("azure_sql_public_access", "SQL public access.", "HIGH", "8.0"),
    ("azure_app_service_https_only", "App Service HTTPS-only off.", "MEDIUM", "5.5"),
    ("azure_app_registration_unused", "App registration unused.", "MEDIUM", "5.5"),
    ("azure_service_principal_secrets", "SP secret rotation.", "MEDIUM", "5.5"),
    ("azure_aks_endpoint_public", "AKS endpoint public.", "HIGH", "7.5"),
    ("azure_diagnostic_settings_off", "Diagnostic settings off.", "MEDIUM", "5.5"),
    ("azure_defender_off", "Microsoft Defender for Cloud off.", "MEDIUM", "5.5"),
    # §4 GCP Security (12)
    ("gcp_org_policy_audit", "GCP org policy audit.", "MEDIUM", "5.5"),
    ("gcp_iam_overpermissive", "GCP IAM overpermissive.", "HIGH", "7.5"),
    ("gcp_sa_key_age", "GCP SA key age >90 days.", "MEDIUM", "5.5"),
    ("gcp_gcs_bucket_public", "GCS bucket public.", "CRITICAL", "9.0"),
    ("gcp_gcs_uniform_access", "GCS uniform bucket-level access off.", "MEDIUM", "5.5"),
    ("gcp_firewall_open", "GCP firewall open 0.0.0.0/0.", "HIGH", "8.0"),
    ("gcp_sql_public_access", "Cloud SQL public access.", "HIGH", "8.0"),
    ("gcp_gke_endpoint_public", "GKE endpoint public.", "HIGH", "7.5"),
    ("gcp_cloud_kms_audit", "Cloud KMS audit.", "MEDIUM", "5.5"),
    ("gcp_audit_logs_off", "GCP audit logs off.", "MEDIUM", "5.5"),
    ("gcp_secret_manager_audit", "Secret Manager audit.", "MEDIUM", "5.5"),
    ("gcp_workload_identity_audit", "Workload Identity audit.", "MEDIUM", "5.5"),
    # §5 Multi-Cloud CIEM (10) ⭐
    ("ciem_overpermissive_paths", "⭐ CIEM overpermissive identity paths.", "HIGH", "7.5"),
    ("ciem_cross_account_trust", "⭐ Cross-account trust audit.", "HIGH", "7.5"),
    ("ciem_oidc_federation_audit", "⭐ OIDC federation audit.", "HIGH", "7.5"),
    ("ciem_unused_access_keys", "⭐ Unused access keys.", "MEDIUM", "5.5"),
    ("ciem_privilege_escalation_paths", "⭐ Privesc paths.", "HIGH", "8.0"),
    ("ciem_zombie_users", "⭐ Zombie users (no login >90d).", "MEDIUM", "5.5"),
    ("ciem_excessive_perm_diff", "⭐ Excessive perms vs least-priv baseline.", "MEDIUM", "5.5"),
    ("ciem_service_account_creep", "⭐ Service account perm creep.", "MEDIUM", "5.5"),
    ("manual_ciem_review", "Manual CIEM review.", "INFO", "0.0"),
    ("manual_iam_lateral_chain", "Manual IAM lateral chain.", "INFO", "0.0"),
    # §6 Serverless (10)
    ("lambdaguard_advisory", "LambdaGuard advisory.", "MEDIUM", "5.5"),
    ("lambda_env_secrets_leak", "Lambda env secrets leak.", "HIGH", "7.5"),
    ("lambda_role_overpermissive", "Lambda role overpermissive.", "HIGH", "7.5"),
    ("azure_function_secrets_leak", "Azure Function secrets leak.", "HIGH", "7.5"),
    ("azure_function_managed_id", "Azure Function managed-ID overpermissive.", "HIGH", "7.5"),
    ("cloud_run_audit", "Cloud Run audit.", "MEDIUM", "5.5"),
    ("cloud_functions_overpermissive", "Cloud Functions overpermissive.", "HIGH", "7.5"),
    ("serverless_cold_start_oracle", "Serverless cold-start oracle.", "MEDIUM", "5.5"),
    ("manual_serverless_review", "Manual serverless review.", "INFO", "0.0"),
    ("manual_serverless_chain", "Manual serverless chain.", "INFO", "0.0"),
    # §7 Container Registry & Image (9)
    ("ecr_public_access", "ECR public access.", "HIGH", "7.5"),
    ("acr_anonymous_pull", "ACR anonymous pull enabled.", "HIGH", "7.5"),
    ("gcr_public_access", "GCR public access.", "HIGH", "7.5"),
    ("docker_hub_public_image_secrets", "Docker Hub image with embedded secrets.", "HIGH", "8.0"),
    ("image_unsigned_no_cosign", "Image unsigned (no cosign signature).", "MEDIUM", "5.5"),
    ("image_vuln_critical_count", "Image critical vulnerability count.", "HIGH", "7.5"),
    ("image_baseimage_age", "Base image age >90 days.", "MEDIUM", "5.5"),
    ("image_runtime_provenance", "Runtime provenance check.", "MEDIUM", "5.5"),
    ("manual_image_review", "Manual image review.", "INFO", "0.0"),
    # §8 Cloud Storage (9)
    ("s3_bucket_public_static_site", "S3 public static site.", "HIGH", "7.5"),
    ("s3_bucket_lifecycle_audit", "S3 lifecycle policy audit.", "MEDIUM", "5.5"),
    ("s3_bucket_versioning_off", "S3 versioning off.", "MEDIUM", "5.5"),
    ("s3_bucket_logging_off", "S3 logging off.", "MEDIUM", "5.5"),
    ("azure_blob_public_anon", "Azure Blob public anonymous.", "HIGH", "7.5"),
    ("gcs_bucket_acl_legacy", "GCS legacy ACL.", "MEDIUM", "5.5"),
    ("gcs_bucket_logging_off", "GCS logging off.", "MEDIUM", "5.5"),
    ("storage_secret_in_object", "Secret detected in object content.", "CRITICAL", "9.0"),
    ("manual_storage_review", "Manual storage review.", "INFO", "0.0"),
    # §9 Cloud Network & VPC (8)
    ("vpc_flow_logs_off", "VPC flow logs off.", "MEDIUM", "5.5"),
    ("nat_gateway_public_egress", "NAT gateway public egress audit.", "MEDIUM", "5.5"),
    ("vpc_endpoints_audit", "VPC endpoints audit.", "MEDIUM", "5.5"),
    ("transit_gateway_audit", "Transit Gateway audit.", "MEDIUM", "5.5"),
    ("peering_overpermissive", "VPC peering overpermissive.", "HIGH", "7.0"),
    ("ipv6_egress_audit", "IPv6 egress audit.", "MEDIUM", "5.5"),
    ("vpn_endpoint_public", "VPN endpoint public.", "MEDIUM", "5.5"),
    ("manual_network_review", "Manual VPC review.", "INFO", "0.0"),
    # §10 Cloud Secrets & KMS (8)
    ("kms_key_rotation_off", "KMS key rotation off.", "MEDIUM", "5.5"),
    ("secrets_manager_versioning_off", "Secrets Manager versioning off.", "MEDIUM", "5.5"),
    ("parameter_store_secret_unencrypted", "Parameter Store secret unencrypted.", "HIGH", "7.5"),
    ("keyvault_purge_protection_off", "Azure KeyVault purge protection off.", "MEDIUM", "5.5"),
    ("kms_customer_managed_audit", "Customer-managed KMS keys audit.", "MEDIUM", "5.5"),
    ("kms_grants_audit", "KMS grants audit.", "MEDIUM", "5.5"),
    ("hsm_backed_keys_audit", "HSM-backed keys audit.", "MEDIUM", "5.5"),
    ("manual_secret_review", "Manual secret review.", "INFO", "0.0"),
    # §11 Cross-Cloud OIDC (6) ⭐
    ("oidc_provider_thumbprint_audit", "⭐ OIDC provider thumbprint audit.", "HIGH", "7.5"),
    ("gha_oidc_role_audit", "⭐ GitHub Actions OIDC role audit.", "HIGH", "7.5"),
    ("cross_cloud_oidc_trust_audit", "⭐ Cross-cloud OIDC trust audit.", "HIGH", "7.5"),
    ("oidc_subject_claim_wildcard", "⭐ OIDC subject claim wildcard.", "CRITICAL", "9.0"),
    ("manual_oidc_audit", "Manual OIDC audit.", "INFO", "0.0"),
    ("manual_cross_cloud_chain", "Manual cross-cloud chain.", "INFO", "0.0"),
    # §12 Cloud Compliance (4)
    ("compliance_cis_aws_benchmark", "CIS AWS benchmark check.", "MEDIUM", "5.5"),
    ("compliance_cis_azure_benchmark", "CIS Azure benchmark check.", "MEDIUM", "5.5"),
    ("compliance_cis_gcp_benchmark", "CIS GCP benchmark check.", "MEDIUM", "5.5"),
    ("compliance_pci_dss_cloud", "PCI DSS 4.0 cloud controls.", "HIGH", "7.0"),
]

router = make_advisory_router("cloud", T,
    playbook_ref="See module_playbooks/21_cloud.md.",
    probes=PROBES)


def register(app):
    app.include_router(router)
