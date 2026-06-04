"""jwt_secret_audit - findings rules.

Severity model:
  CRITICAL - any successful forgery: weak secret crack / alg=none / RS->HS
  HIGH     - kid present (injection variants supplied for manual replay)
  MEDIUM   - expired token still presented (alg + drift visible w/o verify)
  INFO     - missing input / malformed JWT / PyJWT unavailable
  POSITIVE - probe ran, none of the attacks landed
"""


def rule_critical_weak_secret(s):
    redacted = s.get("jwt_weak_secret_redacted")
    if not redacted:
        return None
    return {
        "name": f"JWT HMAC secret cracked from top-{s.get('jwt_weak_secrets_tried', 100)} list",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-326",
        "owasp": "A02:2021",
        "evidence": (
            f"The token's HS-family signature ({s.get('jwt_header_alg', 'HS?')}) "
            f"verified against a known-weak secret: {redacted}. "
            f"Any attacker who knows or guesses this secret can forge arbitrary "
            f"JWTs with claim names {s.get('jwt_claim_names') or '[]'}."
        ),
        "remediation": (
            "1. Rotate the signing secret immediately - existing tokens are forgeable. "
            "2. Generate a fresh secret of >=32 bytes from os.urandom / openssl rand -hex 32 / AWS KMS. "
            "3. Store the secret in a secret manager (Vault / AWS Secrets Manager / Azure Key Vault), NEVER in config files / env-var defaults. "
            "4. Add this scan to CI - any test JWT signed with a weak secret must fail the build. "
            "5. Consider migrating to RS256 / EdDSA so the secret cannot be brute-forced offline."
        ),
    }


def rule_critical_alg_none(s):
    if not s.get("jwt_alg_none_accepted"):
        return None
    return {
        "name": "JWT alg=none forgery succeeds against PyJWT-style decoder",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "evidence": (
            "A forged token built with header {\"alg\":\"none\"} and the original "
            f"payload (claims: {s.get('jwt_claim_names') or '[]'}) decodes "
            "successfully when the verifier accepts 'none' as an algorithm. "
            "Any service that accepts client-chosen alg is fully forgeable."
        ),
        "remediation": (
            "1. Pin the algorithm in the verifier - `jwt.decode(t, key, algorithms=['HS256'])` NEVER `algorithms=jwt.algorithms.get_default_algorithms()`. "
            "2. Reject any token whose header.alg differs from what the application expects (server-side allowlist, not header-trust). "
            "3. Upgrade PyJWT to >=2.0.0 (default-deny on alg=none for empty key). "
            "4. Add a regression test that asserts an alg=none token returns 401."
        ),
    }


def rule_critical_rs_hs_confusion(s):
    if not s.get("jwt_rs_to_hs_confusion"):
        return None
    return {
        "name": "JWT RS256 -> HS256 algorithm confusion succeeds",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "evidence": (
            "A forged token whose header was swapped from RS256 to HS256 and "
            "whose HMAC key is the application's public RSA key verified "
            f"successfully. Original claims: {s.get('jwt_claim_names') or '[]'}. "
            "The public key is, by definition, public - the attacker can mint "
            "valid admin tokens."
        ),
        "remediation": (
            "1. Pin algorithms STRICTLY: `jwt.decode(t, public_key, algorithms=['RS256'])` - never accept a list that contains both RS* and HS*. "
            "2. Bind the key to the algorithm in code so the verifier never tries HMAC with an RSA key. "
            "3. Treat the public key as sensitive in test-suites (it isn't a secret, but exposing it widens attack surface). "
            "4. Patch PyJWT (>=1.5.0) and equivalent libs in other languages."
        ),
    }


def rule_high_kid_injection(s):
    kid = s.get("jwt_kid_present")
    variants = s.get("jwt_kid_injection_variants") or []
    if not kid or not variants:
        return None
    return {
        "name": f"JWT kid header is attacker-controllable ({len(variants)} injection variants ready)",
        "severity": "HIGH",
        "cvss": "8.1",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "evidence": (
            f"The token carries a kid (key ID) header: {kid!r}. If the verifier "
            "looks up the key by reading kid from disk / DB the following payloads "
            "are likely accepted: path traversal (/dev/null -> empty-string HMAC), "
            "SQLi (' OR '1'='1), and /proc/self/environ leakage. Replay each "
            f"variant against the live verifier and check for 200 OK ({len(variants)} variants supplied)."
        ),
        "remediation": (
            "1. Treat kid as untrusted input - validate against an allowlist of expected key IDs (UUIDs or hashes only). "
            "2. NEVER use kid as a filesystem path or SQL parameter. "
            "3. If keys ARE on disk, store them with random-UUID filenames and resolve via a hashmap, not a join. "
            "4. Log+alert on any kid value that fails the allowlist."
        ),
    }


def rule_medium_expired_accepted(s):
    drift = s.get("jwt_expired_seconds")
    if not drift:
        return None
    return {
        "name": f"JWT supplied is expired by {drift}s but was still in use",
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-613",
        "owasp": "A07:2021",
        "evidence": (
            f"The token's exp claim is {drift} seconds in the past. If the "
            "verifier does not enforce exp, replay is trivial. Confirm by "
            "replaying this exact token against the live API."
        ),
        "remediation": (
            "1. Always pass `verify_exp=True` (PyJWT default >= 1.5). "
            "2. Add a regression test that an expired token returns 401. "
            "3. Tighten exp on token issuance: 15 min access + 7 day refresh is industry baseline. "
            "4. Consider sliding-session revocation via a small Redis blocklist."
        ),
    }


def rule_input_missing(s):
    if not s.get("jwt_input_missing"):
        return None
    return {
        "name": "JWT secret audit skipped - no token supplied",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "This probe requires options.jwt_token on the scan request. Without "
            "a sample token from the customer's live app, no audit can run."
        ),
        "remediation": (
            "Re-run with options.jwt_token populated from a recent login response. "
            "Optional: options.public_key (PEM) enables the RS->HS confusion test, "
            "options.weak_secret_list overrides the built-in top-100 secret list."
        ),
    }


def rule_pyjwt_missing(s):
    if not s.get("jwt_pyjwt_missing"):
        return None
    return {
        "name": "PyJWT library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import jwt` failed - the PyJWT library is required for cryptographic probes.",
        "remediation": "pip install pyjwt cryptography >=2.8 inside the scanner container.",
    }


def rule_malformed(s):
    err = s.get("jwt_malformed_error")
    if not err:
        return None
    return {
        "name": "Supplied JWT could not be decoded (malformed)",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": f"PyJWT raised: {err}. The string does not appear to be a valid 3-segment JWT.",
        "remediation": "Re-issue a fresh token from the live app, paste it into options.jwt_token, and re-run.",
    }


def rule_positive(s):
    if s.get("jwt_input_missing"):
        return None
    if s.get("jwt_pyjwt_missing"):
        return None
    if s.get("jwt_malformed_error"):
        return None
    # Any positive attack landed -> no POSITIVE
    if (s.get("jwt_weak_secret_redacted") or
            s.get("jwt_alg_none_accepted") or
            s.get("jwt_rs_to_hs_confusion") or
            s.get("jwt_kid_present") or
            s.get("jwt_expired_seconds")):
        return None
    alg = s.get("jwt_header_alg") or "?"
    return {
        "name": f"JWT withstood weak-secret + alg=none + RS->HS + kid probes (alg={alg})",
        "severity": "POSITIVE",
        "cwe": "CWE-326",
        "owasp": "A02:2021",
        "evidence": (
            f"Tested {s.get('jwt_weak_secrets_tried', 0)} weak secrets, alg=none forgery, "
            "RS->HS confusion, and kid injection variants. None landed."
        ),
        "remediation": (
            "Keep the signing key in a secret manager, rotate quarterly, and re-run with "
            "a fresh token after every dependency upgrade (PyJWT / jose / node-jsonwebtoken)."
        ),
    }


JWT_SECRET_AUDIT_FINDING_RULES = [
    rule_critical_weak_secret,
    rule_critical_alg_none,
    rule_critical_rs_hs_confusion,
    rule_high_kid_injection,
    rule_medium_expired_accepted,
    rule_input_missing,
    rule_pyjwt_missing,
    rule_malformed,
    rule_positive,
]
