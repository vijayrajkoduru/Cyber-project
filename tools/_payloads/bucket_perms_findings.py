"""Bucket Permission Audit — findings rules library."""


def rule_public_listable(s):
    pl = [b for b in (s.get("permission_details") or []) if b.get("public_list")]
    if not pl: return None
    return {"name": f"Publicly listable bucket(s) ({len(pl)})",
            "severity": "CRITICAL",
            "cwe": "CWE-200",
            "evidence": "Listable: " + "; ".join(
                f"{b['bucket']} ({b.get('provider', '?')}) — "
                f"sample: {(b.get('sample_objects') or ['?'])[0]}"
                for b in pl[:3]),
            "remediation": "Anonymous bucket listing exposes ALL filenames. Apply private bucket policy. AWS: Block Public Access + bucket policy deny s3:List*; GCS: IAM restrict allUsers; Azure: set container access to Private."}


def rule_public_readable(s):
    pr = [b for b in (s.get("permission_details") or []) if b.get("public_read")]
    if not pr: return None
    return {"name": f"Publicly readable bucket(s) ({len(pr)})",
            "severity": "CRITICAL",
            "cwe": "CWE-732",
            "evidence": ", ".join(b.get("bucket", "?") for b in pr[:3]),
            "remediation": "Anyone can download files. Remove allUsers / public-read ACL immediately."}


def rule_buckets_exist(s):
    n = s.get("buckets_exist") or 0
    if n == 0: return None
    return {"name": f"{n} bucket(s) exist for this target",
            "severity": "INFO",
            "evidence": f"Of {s.get('buckets_tested', 0)} candidate names tested, {n} buckets confirmed reachable"}


def rule_no_buckets(s):
    if (s.get("buckets_exist") or 0) > 0: return None
    if (s.get("buckets_tested") or 0) == 0: return None
    return {"name": "No buckets to audit",
            "severity": "POSITIVE",
            "evidence": f"Tested {s.get('buckets_tested', 0)} candidates — none exist"}


def rule_buckets_private(s):
    bs = s.get("permission_details") or []
    if not bs: return None
    private_only = [b for b in bs
                    if not b.get("public_list") and not b.get("public_read")]
    if not private_only: return None
    return {"name": f"{len(private_only)} bucket(s) properly private",
            "severity": "POSITIVE",
            "evidence": "Confirmed buckets are auth-required (no public list/read)"}


BUCKET_PERMS_FINDING_RULES = [
    rule_public_listable, rule_public_readable, rule_buckets_exist,
    rule_no_buckets, rule_buckets_private,
]
