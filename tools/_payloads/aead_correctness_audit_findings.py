"""aead_correctness_audit - findings rules."""


def rule_positive_emit(s):
    if s.get("aead_correctness_audit_total"):
        return None
    return {"name": "AEAD usage looks correct",
            "severity": "POSITIVE",
            "evidence": (f"GCM users={len(s.get('gcm_users') or [])} "
                         f"ChaCha20-Poly1305={len(s.get('chacha_users') or [])} "
                         f"CCM={len(s.get('ccm_users') or [])} "
                         f"AAD callers={s.get('aad_users', 0)}"),
            "remediation": "Continue using 128-bit GCM tag + AAD on every AEAD encrypt.",
            "cwe": "CWE-310", "owasp": "M10:2023"}


def rule_gcm_short_tag(s):
    sh = s.get("gcm_short_tags") or []
    if not sh:
        return None
    sample = ", ".join(f"{e['file']}:{e['tag_bits']}b" for e in sh[:4])
    return {"name": f"GCM tag length < 128 bits in {len(sh)} call(s)",
            "severity": "MEDIUM", "cvss": "5.5",
            "cwe": "CWE-310", "owasp": "M10:2023",
            "evidence": f"Calls: {sample}",
            "remediation": "Pass 128 to GCMParameterSpec(tLen, iv). Shorter tags weaken integrity."}


def rule_no_aad(s):
    if not (s.get("gcm_users") or s.get("chacha_users")):
        return None
    if s.get("aad_users", 0) > 0:
        return None
    return {"name": "AEAD callers ship without associated-data binding",
            "severity": "LOW", "cvss": "3.7",
            "cwe": "CWE-310", "owasp": "M10:2023",
            "evidence": (f"GCM + ChaCha20 callers: {len(s.get('gcm_users') or []) + len(s.get('chacha_users') or [])}; "
                         "no updateAAD / setAAD detected"),
            "remediation": "Bind protocol metadata (version, recipient, sequence) via updateAAD() before plaintext."}


AEAD_CORRECTNESS_AUDIT_FINDING_RULES = [rule_positive_emit, rule_gcm_short_tag, rule_no_aad]
