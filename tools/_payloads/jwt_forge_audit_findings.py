"""jwt_forge_audit - finding rules (VL-METHOD aware).

Reads methodology state populated by JwtForgeAudit's 7-stage flow:
  - methodology_findings : list of forged-token + cracked-secret findings
  - fingerprint          : {algorithm, has_kid, has_jku, has_x5u, claims,
                             payload_has_role, payload_has_admin_flag,
                             expires_at}
  - quick_probe_attempts : int (always 5)
  - quick_probe_hits     : int
  - jwt_brute_attempts   : int (deep_scan HMAC dictionary size)
  - chain_next           : list of follow-up scanner names

Severity derives from (kind, confidence, privilege) tuple. CONFIRMED
admin-tier forges are CRITICAL CVSS 9.8; cracked HMAC secrets are
CRITICAL 9.1; SUSPECTED degrade to LOW pending manual re-test.
"""


INTEL_FIELDS = [
    ("Target URL",                  "target"),
    ("JWT Header",                  "jwt_header"),
    ("JWT Payload",                 "jwt_payload"),
    ("JWT Fingerprint",             "fingerprint"),
    ("Quick-probe attacks tried",   "quick_probe_attempts"),
    ("Quick-probe hits",            "quick_probe_hits"),
    ("Deep brute attempts",         "jwt_brute_attempts"),
    ("Stage timings (ms)",          "stage_timings"),
    ("Stage errors",                "stage_errors"),
    ("Chain ID",                    "chain_id"),
]


def _findings_by_attack_type(s) -> dict:
    """Group methodology_findings by their attack 'kind' so each
    rule_* function can grab its own bucket."""
    buckets: dict[str, list[dict]] = {
        "alg_none": [],
        "empty_sig": [],
        "alg_confusion": [],
        "kid_traversal": [],
        "expired_replay": [],
        "jwt_secret_cracked": [],
        "other": [],
    }
    for f in (s.get("methodology_findings") or []):
        kind = f.get("kind") or ""
        if kind in buckets:
            buckets[kind].append(f)
        else:
            buckets["other"].append(f)
    return buckets


def _confirmed(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("confidence") == "CONFIRMED"]


def _suspected(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("confidence") == "SUSPECTED"]


def rule_input_missing(s):
    reason = s.get("skipped_reason") or ""
    if "requires target URL + options.jwt_token" not in reason:
        return None
    return {
        "name": "JWT forge audit skipped - required inputs missing",
        "severity": "INFO",
        "evidence": ("Scanner requires a base URL (target) AND a sample JWT "
                     "(options.jwt_token) AND a protected endpoint "
                     "(options.test_endpoint) to actually probe acceptance. "
                     "Paste a token from your browser DevTools (Network tab "
                     "-> Authorization: Bearer ...) and the path that requires "
                     "it (e.g. /api/me)."),
        "remediation": ("Re-run with options.jwt_token=<paste-token> and "
                        "options.test_endpoint=/api/me (or any path that "
                        "401s without a token). Optional: provide "
                        "options.jwt_secret if you already know it (we'll "
                        "skip the dictionary attack)."),
        "cwe": "CWE-1006",
    }


def rule_malformed_token(s):
    reason = s.get("skipped_reason") or ""
    if "jwt_token malformed" not in reason:
        return None
    return {
        "name": "Supplied jwt_token is malformed",
        "severity": "INFO",
        "evidence": ("Expected three base64url-encoded segments separated by "
                     "dots: <header>.<payload>.<signature>. The provided "
                     "token did not parse. Most likely you pasted only the "
                     "Bearer prefix or a session cookie instead of the JWT."),
        "remediation": ("Re-copy from browser DevTools Network tab; the "
                        "Authorization header value is 'Bearer eyJ...'. Drop "
                        "the 'Bearer ' prefix and paste only the eyJ... "
                        "portion as options.jwt_token."),
        "cwe": "CWE-1006",
    }


def rule_pyjwt_missing(s):
    if not s.get("jwt_lib_missing"):
        return None
    return {
        "name": "PyJWT library not installed - JWT forge audit unavailable",
        "severity": "INFO",
        "evidence": ("The PyJWT package is required to decode + re-sign JWT "
                     "tokens for forge testing. Install with: pip install "
                     "PyJWT cryptography."),
        "remediation": ("Add PyJWT + cryptography to the backend Dockerfile "
                        "(both are pure-python with optional C deps). Once "
                        "installed, this scanner can perform alg-none + "
                        "kid-traversal + HMAC-brute forge tests."),
        "cwe": "CWE-1006",
    }


def rule_no_expiration(s):
    fp = s.get("fingerprint") or {}
    if "expires_at" not in fp:
        return None
    if fp.get("expires_at") is not None:
        return None
    return {
        "name": "JWT has no exp claim - tokens never expire",
        "severity": "MEDIUM", "cvss": "5.3",
        "cwe": "CWE-613", "owasp": "A07:2021",
        "evidence": ("Decoded JWT payload contains no 'exp' (expiration) "
                     "claim. Tokens issued without an expiration timestamp "
                     "remain valid until the signing key is rotated, which "
                     "extends the window of compromise on a stolen token "
                     "from minutes to indefinitely."),
        "remediation": ("Set a reasonable 'exp' claim on every issued token "
                        "(typically 15 minutes for access tokens, 7 days for "
                        "refresh tokens). For long-lived sessions, prefer "
                        "rotation via short-lived access + long-lived "
                        "refresh tokens, validated server-side every issue."),
    }


def rule_no_kid_no_jku_uses_static_secret(s):
    fp = s.get("fingerprint") or {}
    alg = (fp.get("algorithm") or "").upper()
    if alg not in ("HS256", "HS384", "HS512"):
        return None
    if fp.get("has_kid") or fp.get("has_jku"):
        return None
    # No forge findings -> hint only
    if (s.get("methodology_total") or 0) > 0:
        return None
    return {
        "name": "JWT uses static HMAC secret without kid/jku rotation hints",
        "severity": "INFO",
        "evidence": (f"Algorithm is {alg} (symmetric HMAC) and the header "
                     "carries no 'kid' (key id) or 'jku' (JWK Set URL) "
                     "indicator. This usually means a single shared secret "
                     "with no rotation strategy - if the secret leaks "
                     "(env file, GitHub commit, customer support email) "
                     "every issued token is forgeable until manual "
                     "rotation."),
        "remediation": ("For new builds, prefer RS256/ES256 with a JWKS "
                        "endpoint + 'kid' header so individual signing keys "
                        "can be rotated without invalidating every session. "
                        "If sticking with HS256, set a 'kid' header and "
                        "support multi-key verification so rotation is "
                        "incremental."),
        "cwe": "CWE-321",
    }


def rule_clean(s):
    if (s.get("methodology_total") or 0) > 0:
        return None
    qp = s.get("quick_probe_attempts") or 0
    hits = s.get("quick_probe_hits") or 0
    if qp < 5 or hits > 0:
        return None
    # Must have actually fingerprinted the token (else INFO already fired)
    if not (s.get("fingerprint") or {}).get("algorithm"):
        return None
    return {
        "name": "JWT implementation rejects all common forge attempts",
        "severity": "POSITIVE",
        "evidence": (f"Tested {qp} known JWT forge attacks (alg:none "
                     "stripping, empty signature, kid path traversal, "
                     "RS256->HS256 confusion, expired-token replay) - all "
                     "rejected by the protected endpoint. Signature "
                     "verification appears correct."),
        "remediation": ("Maintain current JWT validation logic. Periodically "
                        "re-run this audit after library upgrades (PyJWT, "
                        "jose, jsonwebtoken) since these have shipped "
                        "CVEs in the past where strict checks regressed."),
        "cwe": "CWE-345",
        "owasp": "A07:2021",
    }


def rule_confirmed_alg_none_accepted(s):
    g = _findings_by_attack_type(s)
    hits = _confirmed(g["alg_none"])
    if not hits:
        return None
    return {
        "name": "CRITICAL: JWT alg:none stripping accepted by endpoint",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "evidence": ("Forged a JWT with header {'alg':'none'} and an empty "
                     "signature segment, then sent to the protected "
                     "endpoint. Endpoint returned HTTP 200 - signature "
                     "verification is bypassed. This is the CVE-2015-9235 "
                     "class vulnerability (jsonwebtoken, jose, ruby-jwt and "
                     "many others have shipped patches; an accepting "
                     "endpoint indicates either an unpatched library or "
                     "an option like {algorithms: ['none', 'HS256']})."),
        "remediation": ("Explicitly pin the accepted algorithm in your "
                        "verify call: jwt.decode(token, key, "
                        "algorithms=['HS256']) - never accept 'none'. "
                        "Upgrade PyJWT >= 2.0, jsonwebtoken >= 9.0, "
                        "ruby-jwt >= 2.0. Rotate the signing secret since "
                        "any attacker observing the JWT could mint tokens "
                        "while this bug was live."),
    }


def rule_confirmed_empty_sig(s):
    g = _findings_by_attack_type(s)
    hits = _confirmed(g["empty_sig"])
    if not hits:
        return None
    return {
        "name": "CRITICAL: JWT with empty signature accepted by endpoint",
        "severity": "CRITICAL", "cvss": "9.4",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "evidence": ("Sent a JWT signed with alg=HS256 but an empty signature "
                     "segment (eyJ...eyJ...). Endpoint returned HTTP 200. "
                     "The verification path is short-circuiting on empty "
                     "signature instead of treating it as a verification "
                     "failure - a known footgun in early jose/jsonwebtoken "
                     "configurations."),
        "remediation": ("Audit the JWT verify call site - it must REJECT "
                        "tokens with empty/missing signature segments "
                        "before any algorithm check. Pin algorithms list "
                        "AND require non-empty signature in the decoder. "
                        "Rotate the signing secret since unsigned tokens "
                        "may have been issued."),
    }


def rule_confirmed_alg_confusion(s):
    g = _findings_by_attack_type(s)
    hits = _confirmed(g["alg_confusion"])
    if not hits:
        return None
    return {
        "name": "CRITICAL: JWT RS256->HS256 algorithm confusion succeeded",
        "severity": "CRITICAL", "cvss": "9.4",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "evidence": ("Original token uses RS256 (asymmetric). Forged a new "
                     "token with alg=HS256, using the server's PUBLIC key "
                     "as the HMAC secret. Endpoint accepted it - verifier "
                     "is using a single key for both algorithms instead of "
                     "separate RSA-public and HMAC-secret slots. Classic "
                     "CVE pattern in node jsonwebtoken pre-9.0 and many "
                     "tutorials."),
        "remediation": ("Pin algorithms to exactly ['RS256'] (or ['ES256']) "
                        "in the verify call. NEVER pass an RSA public key "
                        "to a verifier configured to also accept HS*. "
                        "Better: separate the key store - RSA keys live in "
                        "one bucket, HMAC secrets in another, mismatch "
                        "throws an exception. Rotate the RSA keypair since "
                        "the public key has been effectively repurposed "
                        "as a forgery oracle."),
    }


def rule_confirmed_kid_traversal(s):
    g = _findings_by_attack_type(s)
    hits = _confirmed(g["kid_traversal"])
    if not hits:
        return None
    return {
        "name": "HIGH: JWT kid path traversal accepted by endpoint",
        "severity": "HIGH", "cvss": "8.1",
        "cwe": "CWE-22", "owasp": "A02:2021",
        "evidence": ("Forged a JWT with header.kid set to a path-traversal "
                     "string like '../../../dev/null' and signed with empty "
                     "HMAC bytes. Endpoint accepted - the verifier is "
                     "reading the kid value as a file path or DB lookup key "
                     "without sanitization, then using the file contents "
                     "as the HMAC secret. /dev/null produces empty bytes, "
                     "which we used as the HMAC key, so signature matches."),
        "remediation": ("The kid header MUST be treated as a key ID, not a "
                        "filesystem path. Validate kid against an explicit "
                        "allowlist of registered key IDs. Never use the kid "
                        "value directly in a file path, SQL query, or "
                        "system call. If your KID lookup hits a filesystem, "
                        "use a fixed prefix + os.path.basename() to strip "
                        "any traversal."),
    }


def rule_confirmed_expired_replay(s):
    g = _findings_by_attack_type(s)
    hits = _confirmed(g["expired_replay"])
    if not hits:
        return None
    return {
        "name": "HIGH: Expired JWT token replay accepted by endpoint",
        "severity": "HIGH", "cvss": "7.5",
        "cwe": "CWE-613", "owasp": "A07:2021",
        "evidence": ("Forged a JWT with exp claim set to a date 1 year in "
                     "the future, re-signed with an empty HMAC secret. "
                     "Endpoint accepted the token - the verifier is not "
                     "checking the signature OR is checking exp without "
                     "verifying the signing key. Either way, a stolen "
                     "token can be extended indefinitely by the attacker."),
        "remediation": ("Ensure the JWT decode path verifies the signature "
                        "BEFORE checking exp (default in most libraries, "
                        "but custom implementations skip it). Pin the "
                        "algorithm + supply the correct secret. Rotate "
                        "secret if this scanner found it accepted forged "
                        "tokens since any past issued token may have been "
                        "replayed beyond its intended expiration."),
    }


def rule_confirmed_weak_hmac_secret(s):
    g = _findings_by_attack_type(s)
    hits = _confirmed(g["jwt_secret_cracked"])
    if not hits:
        return None
    secret_count = len(hits)
    return {
        "name": f"CRITICAL: JWT HMAC secret cracked via dictionary attack ({secret_count})",
        "severity": "CRITICAL", "cvss": "9.1",
        "cwe": "CWE-521", "owasp": "A07:2021",
        "evidence": (f"Cracked {secret_count} HMAC secret(s) by re-signing "
                     "the token's payload with each candidate from the "
                     "top-1000 leaked secrets list and comparing to the "
                     "original signature. A matching signature means the "
                     "candidate IS the signing secret. With the secret "
                     "known, an attacker can mint arbitrary JWTs - "
                     "including admin tokens, password-reset tokens, "
                     "session escalation, and tenant impersonation."),
        "remediation": ("ROTATE the JWT signing secret IMMEDIATELY - this "
                        "invalidates every issued token and forces re-auth. "
                        "Replace with a >=256-bit random secret from "
                        "secrets.token_urlsafe(32) or openssl rand -base64 32. "
                        "Migrate to RS256/ES256 (asymmetric) so the secret "
                        "isn't co-located with the verifier. Audit logs for "
                        "the window the weak secret was in use - any "
                        "external party who saw a single token could have "
                        "forged tokens for any user."),
    }


def rule_confirmed_admin_forge(s):
    # Group all forge findings where privilege=admin and CONFIRMED
    admin_forges: list[dict] = []
    for f in (s.get("methodology_findings") or []):
        if (f.get("confidence") == "CONFIRMED"
                and f.get("privilege") == "admin"
                and f.get("kind") != "jwt_secret_cracked"):
            admin_forges.append(f)
    if not admin_forges:
        return None
    return {
        "name": f"CRITICAL: Forged admin-tier JWT accepted ({len(admin_forges)} attack(s))",
        "severity": "CRITICAL", "cvss": "9.8",
        "cwe": "CWE-347", "owasp": "A01:2021",
        "evidence": ("Forged JWTs carrying admin-tier claims (role=admin / "
                     "admin=true / scope=admin:*) were accepted by the "
                     "protected endpoint. This is account takeover on the "
                     "highest-privilege tier - an attacker can mint a "
                     "token claiming to be any administrator, with no "
                     "knowledge of the real admin password. Attack vectors "
                     "exercised: " + ", ".join(sorted({f.get("kind","") for f in admin_forges}))),
        "remediation": ("Fix the underlying signature-verification bypass "
                        "first (see attack-specific findings above). "
                        "Beyond that: NEVER trust payload claims like 'role' "
                        "or 'admin' without server-side re-check against a "
                        "trusted source (database). Even a properly-signed "
                        "token can carry stale or escalated claims if the "
                        "issuer was compromised. Audit access logs for "
                        "admin actions performed in the window the bug was "
                        "live."),
    }


def rule_confirmed_user_forge(s):
    user_forges: list[dict] = []
    for f in (s.get("methodology_findings") or []):
        if (f.get("confidence") == "CONFIRMED"
                and f.get("privilege") == "user"
                and f.get("kind") != "jwt_secret_cracked"):
            user_forges.append(f)
    if not user_forges:
        return None
    return {
        "name": f"MEDIUM: Forged user-tier JWT accepted ({len(user_forges)} attack(s))",
        "severity": "MEDIUM", "cvss": "6.5",
        "cwe": "CWE-347", "owasp": "A01:2021",
        "evidence": ("Forged JWTs carrying regular-user claims were accepted "
                     "by the protected endpoint. Even at user tier this is "
                     "account-impersonation: attacker can act as any "
                     "registered user without their password. Combined "
                     "with stored XSS or an open redirect, this becomes "
                     "trivial mass takeover. Attack vectors: " +
                     ", ".join(sorted({f.get("kind","") for f in user_forges}))),
        "remediation": ("Fix the signature-verification bypass (see "
                        "attack-specific findings above). Rotate the "
                        "signing secret. Force-logout all active sessions "
                        "so existing valid-looking forged tokens are "
                        "invalidated."),
    }


def rule_suspected_forge(s):
    suspected_total: list[dict] = []
    for f in (s.get("methodology_findings") or []):
        if (f.get("confidence") == "SUSPECTED"
                and f.get("kind") != "jwt_secret_cracked"):
            suspected_total.append(f)
    if not suspected_total:
        return None
    return {
        "name": f"LOW: SUSPECTED JWT forge - manual verification recommended ({len(suspected_total)})",
        "severity": "LOW", "cvss": "3.7",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "evidence": ("One or more forge attempts triggered ambiguous "
                     "responses from the protected endpoint (not a clean "
                     "200, not a clean 401/403). This could indicate "
                     "partial acceptance, a rate-limit guard kicking in, "
                     "or a non-JWT auth path being exercised. Manual "
                     "verification recommended. Attack vectors: " +
                     ", ".join(sorted({f.get("kind","") for f in suspected_total}))),
        "remediation": ("Reproduce manually via curl + the forged tokens "
                        "logged in the scan report. If endpoint returns "
                        "200 for any forged token, treat as CONFIRMED of "
                        "the matching severity tier. If endpoint always "
                        "returns 401, ignore as scanner noise."),
    }


def rule_chain_handoff(s):
    chain_next = s.get("chain_next") or []
    if not chain_next:
        return None
    return {
        "name": "Cross-scanner chain handoff suggested",
        "severity": "INFO",
        "evidence": ("Confirmed JWT forge enables downstream scanners: " +
                     ", ".join(chain_next) + ". These will inherit the "
                     "forged-token capability via the VL-METHOD chaining "
                     "engine and probe for session-hijack + privilege "
                     "escalation paths."),
        "remediation": ("Re-run the scan with chain expansion enabled (the "
                        "orchestrator does this automatically). Each "
                        "downstream scanner produces its own findings list "
                        "referencing the same chain_id so the report can "
                        "render the attack tree."),
        "cwe": "CWE-1006",
    }


JWT_FORGE_AUDIT_FINDING_RULES = [
    rule_input_missing,
    rule_malformed_token,
    rule_pyjwt_missing,
    rule_no_expiration,
    rule_no_kid_no_jku_uses_static_secret,
    rule_clean,
    rule_confirmed_alg_none_accepted,
    rule_confirmed_empty_sig,
    rule_confirmed_alg_confusion,
    rule_confirmed_kid_traversal,
    rule_confirmed_expired_replay,
    rule_confirmed_weak_hmac_secret,
    rule_confirmed_admin_forge,
    rule_confirmed_user_forge,
    rule_suspected_forge,
    rule_chain_handoff,
]
