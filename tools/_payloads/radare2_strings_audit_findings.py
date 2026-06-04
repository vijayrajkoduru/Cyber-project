"""radare2_strings_audit - findings rules."""


def rule_positive(s):
    if s.get("radare2_strings_audit_total"):
        return None
    if s.get("radare2_strings_audit_error"):
        return None
    return {"name": "No suspicious strings matched by radare2",
            "severity": "POSITIVE",
            "evidence": "iz pass for secret/password/api_key/aws_/private/token returned no hits",
            "remediation": ("Continue avoiding string-form secrets in firmware. Bind any required "
                            "creds at provisioning time (TPM-sealed / fuse-burned)."),
            "cwe": "CWE-798", "owasp": "A07:2021"}


def rule_suspicious_strings(s):
    counts = s.get("r2_bucket_counts") or {}
    total = s.get("r2_total_strings_matched", 0)
    if not total:
        return None
    nonempty = sorted([(k, v) for k, v in counts.items() if v], key=lambda x: -x[1])[:6]
    breakdown = ", ".join(f"{k}={v}" for k, v in nonempty)
    return {"name": f"{total} suspicious strings extracted by radare2",
            "severity": "MEDIUM", "cvss": "5.3",
            "cwe": "CWE-200", "owasp": "A05:2021",
            "evidence": f"Buckets: {breakdown}",
            "remediation": ("Audit every flagged string in source. Replace any embedded credential "
                            "with a runtime-fetched value (provisioning server or TPM-sealed blob). "
                            "Re-run after rebuild; target zero hits in `creds`, `api_keys`, "
                            "`private_keys` buckets.")}


def rule_high_value_secrets(s):
    counts = s.get("r2_bucket_counts") or {}
    high = [c for c in ("aws", "github", "google", "private_keys") if counts.get(c)]
    if not high:
        return None
    return {"name": f"High-value secret patterns found in firmware: {', '.join(high)}",
            "severity": "CRITICAL", "cvss": "9.1",
            "cwe": "CWE-798", "owasp": "A07:2021",
            "evidence": f"radare2 string buckets non-empty: {', '.join(high)} "
                        f"({', '.join(f'{c}={counts[c]}' for c in high)})",
            "remediation": ("Treat any AWS/GitHub/Google key or private key in firmware as an "
                            "already-compromised secret. (1) Rotate the credential immediately. "
                            "(2) Audit access logs for unauthorised use. (3) Replace with "
                            "runtime-fetched token via mTLS to provisioning server. "
                            "(4) Add pre-release gate: fail CI if any of these patterns appears in "
                            "the firmware artifact.")}


RADARE2_STRINGS_AUDIT_FINDING_RULES = [rule_positive, rule_suspicious_strings,
                                         rule_high_value_secrets]
