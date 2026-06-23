"""hardcoded_jwt_secret_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("hardcoded_jwt_secret_audit_total", 0)
    if n > 0 or s.get("uses_jwt_lib"): return None
    return {"name": "No JWT library or embedded tokens detected",
            "severity": "POSITIVE",
            "cwe": "CWE-321", "owasp": "M9:2023",
            "evidence": f"scanned {s.get('files_scanned', 0)} files",
            "remediation": "App doesn't perform client-side JWT handling — no client-side "
                           "JWT-forgery risk surface."}


def rule_embedded_jwt(s):
    jwts = s.get("embedded_jwts") or []
    if not jwts: return None
    return {"name": f"EMBEDDED JWT(s) found in bundle ({len(jwts)})",
            "severity": "HIGH", "cvss": "7.5",
            "cwe": "CWE-798", "owasp": "M9:2023",
            "evidence": " | ".join(jwts[:3]),
            "remediation": "Embedded JWTs bundled in APK/IPA = leaked. Anyone extracting "
                           "the binary can read claims + replay (if not yet expired). "
                           "JWTs in source code are usually demo / dev tokens but verify: "
                           "(1) decode each at jwt.io and check exp/scope, (2) revoke any "
                           "still-valid ones server-side, (3) move to runtime fetch via OAuth."}


def rule_jwt_lib_in_use(s):
    if not s.get("uses_jwt_lib"): return None
    libs = s.get("jwt_libs_found") or []
    return {"name": "App uses JWT library — verify signing keys aren't embedded",
            "severity": "INFO",
            "cwe": "CWE-321", "owasp": "M3:2023",
            "evidence": "libs: " + ", ".join(libs[:5]),
            "remediation": "Apps SHOULD validate JWTs from a server (RS256 with the "
                           "server's public key bundled is OK). Apps SHOULD NOT sign "
                           "JWTs themselves (no HS256 secret in client). Audit DEX for "
                           "setSigningKey / HMAC256 calls — those need a secret that "
                           "shouldn't be in the binary."}


HARDCODED_JWT_SECRET_AUDIT_FINDING_RULES = [
    rule_positive_emit,
    rule_embedded_jwt,
    rule_jwt_lib_in_use,
]
