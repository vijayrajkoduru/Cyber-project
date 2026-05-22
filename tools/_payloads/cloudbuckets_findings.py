"""Cloud Bucket Finder — findings rules library."""


def rule_open_buckets(s):
    n = len(s.get("open_buckets") or [])
    if n == 0: return None
    return {"name": f"Open cloud bucket(s) ({n}) — public read access",
            "severity": "CRITICAL",
            "cwe": "CWE-732",
            "evidence": "Public: " + ", ".join((s.get("open_buckets") or [])[:3]),
            "remediation": "Public cloud buckets are the #1 data-leak vector (Capital One, Verizon, FedEx, etc.). Remove public-read ACL; switch to signed URLs for any required external access."}


def rule_existing_buckets(s):
    eb = s.get("existing_buckets") or []
    if not eb: return None
    return {"name": f"{len(eb)} cloud bucket(s) exist (auth required)",
            "severity": "INFO",
            "evidence": "Reachable: " + ", ".join(
                str(b.get("url", b))[:80] for b in eb[:3]),
            "remediation": "Bucket existence confirmed via HTTP 403. Auditing bucket policy + ACL recommended to ensure least-privilege."}


def rule_no_buckets_found(s):
    if (s.get("open_buckets") or []) or (s.get("existing_buckets") or []):
        return None
    if (s.get("patterns_tested") or 0) == 0:
        return None
    return {"name": "No cloud buckets discovered via name permutation",
            "severity": "POSITIVE",
            "evidence": f"Tested {s.get('patterns_tested', 0)} bucket-name variants across 7 providers"}


def rule_multi_provider_exposure(s):
    providers = s.get("providers_found") or []
    if len(providers) < 2: return None
    return {"name": f"Buckets across multiple providers ({len(providers)})",
            "severity": "INFO",
            "evidence": "Providers: " + ", ".join(providers),
            "remediation": "Multi-cloud bucket footprint — audit each provider's access policy consistently."}


def rule_aws_s3_exposed(s):
    s3 = [b for b in (s.get("open_buckets") or []) if "s3.amazonaws" in str(b)]
    if not s3: return None
    return {"name": f"AWS S3 bucket(s) publicly readable ({len(s3)})",
            "severity": "CRITICAL",
            "cwe": "CWE-732",
            "evidence": ", ".join(s3[:3]),
            "remediation": "Block Public Access at S3 bucket level + at account level. Default-deny ACL. Use S3 presigned URLs for time-limited external sharing."}


def rule_gcs_exposed(s):
    gcs = [b for b in (s.get("open_buckets") or []) if "storage.googleapis" in str(b)]
    if not gcs: return None
    return {"name": f"GCS bucket(s) publicly readable ({len(gcs)})",
            "severity": "CRITICAL",
            "cwe": "CWE-732",
            "evidence": ", ".join(gcs[:3]),
            "remediation": "Remove allUsers / allAuthenticatedUsers from bucket IAM. Use signed URLs."}


def rule_azure_exposed(s):
    az = [b for b in (s.get("open_buckets") or []) if "blob.core.windows" in str(b)]
    if not az: return None
    return {"name": f"Azure Blob container(s) publicly readable ({len(az)})",
            "severity": "CRITICAL",
            "cwe": "CWE-732",
            "evidence": ", ".join(az[:3]),
            "remediation": "Set container access level to Private. Use SAS tokens for limited-time access."}


CLOUDBUCKETS_FINDING_RULES = [
    rule_open_buckets, rule_existing_buckets, rule_no_buckets_found,
    rule_multi_provider_exposure, rule_aws_s3_exposed, rule_gcs_exposed,
    rule_azure_exposed,
]
