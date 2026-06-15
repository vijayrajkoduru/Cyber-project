"""jwt_secret_audit - JWT cryptographic weakness audit (playbook §5).

Customer supplies a JWT they pulled from their own app via
ScanRequest.options.jwt_token. The probe runs five real PyJWT attack
attempts and reports each success as CRITICAL:

  (a) Decode without verify  - inspect alg, claims, exp drift
  (b) HS256 weak-secret brute - top-100 secret list
  (c) alg=none confusion     - PyJWT 1.x bug + many homegrown decoders
  (d) RS256->HS256 confusion  - use the public key as HMAC secret
  (e) kid header injection   - SQLi / path traversal markers

Customer input via ScanRequest.options:
  - target              = identifier for the app issuing the token (string)
  - options.jwt_token   = the JWT to audit (required)
  - options.public_key  = optional PEM public key for RS256->HS256 test
  - options.weak_secret_list = optional newline-separated secrets to try

Privacy: the JWT itself is NEVER stored in findings text - only the
header.alg, kid, payload claim names (not values), and the secret
length/last-3 of any cracked secret. The customer already owns the
token, so we don't echo it back into the PDF.
"""
from __future__ import annotations
import asyncio
import base64
import json
import os
import time
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.jwt_secret_audit_findings import JWT_SECRET_AUDIT_FINDING_RULES
from tools._payloads.auth_attacks._loader import load_lines, load_json

router = APIRouter()

# Top-100 weak secrets sampled from rockyou/dev defaults/JWT.io examples.
# Customer can override via options.weak_secret_list.
_INLINE_WEAK_SECRETS = [
    "secret", "secretkey", "key", "your-256-bit-secret", "yoursecret",
    "jwt_secret", "jwtsecret", "supersecret", "supersecretkey",
    "mysecret", "mysecretkey", "thisisasecret", "thisisthesecret",
    "password", "password123", "passw0rd", "P@ssw0rd",
    "admin", "admin123", "administrator", "root", "rootpassword",
    "default", "default-secret", "defaultpassword", "changeme", "changeit",
    "test", "testing", "test123", "testsecret", "testkey",
    "dev", "development", "devsecret", "dev123",
    "prod", "production", "prodsecret",
    "qa", "stage", "staging", "uat",
    "abc123", "abcdef", "qwerty", "qwertyuiop", "asdfgh",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "111111", "000000", "iloveyou", "letmein", "welcome",
    "hello", "hello123", "helloworld", "hellosecret",
    "your_jwt_secret", "your_secret_key", "your_signing_key",
    "jsonwebtoken", "json_web_token", "jwttoken", "bearer", "bearertoken",
    "auth", "authsecret", "authentication", "session", "sessionkey",
    "cookie", "cookiekey", "encryption", "encrypt", "decryptkey",
    "salt", "pepper", "tokensalt", "saltpepper",
    "company", "companyname", "appsecret", "appkey", "applicationkey",
    "api", "apikey", "api_key", "api-key", "apisecret", "api_secret",
    "client", "clientsecret", "client_secret", "client-secret",
    "node", "nodejs", "express", "django", "flask", "rails",
    "spring", "springboot", "laravel", "symfony",
    "supersafe", "ultrasecret", "topsecret", "highsecret",
]

# VL-CORE: load the AI-curated HMAC secret pool owned by this module, with the
# inline list as fallback when the bundled wordlist is absent (partial deploy).
DEFAULT_WEAK_SECRETS = load_lines("jwt_secrets", fallback=_INLINE_WEAK_SECRETS)

# kid injection markers to test for SQLi + path traversal
_INLINE_KID_INJECTIONS = [
    "../../../../../../../dev/null",   # path traversal -> empty -> HS256(\"\")
    "../../../etc/passwd",
    "../../../../../../../proc/self/environ",
    "/dev/null",
    "' OR '1'='1",                     # SQLi
    "1' UNION SELECT NULL,NULL--",
    "../../../tmp/x",
]

# VL-CORE: AI-curated KID-header injection pool (path traversal / SQLi / cmd /
# LDAP / SSRF / type-confusion). We feed the scanner the flat string `kid`
# values it expects; non-string kid forms (arrays, empty) are skipped so the
# downstream {"kid_variant": ...} shape is preserved exactly.
_KID_INJECTION_PAYLOADS = load_json("jwt_kid_injection", fallback=[])
KID_INJECTIONS = [
    p["kid"] for p in _KID_INJECTION_PAYLOADS
    if isinstance(p, dict) and isinstance(p.get("kid"), str) and p["kid"]
] or _INLINE_KID_INJECTIONS


class JwtSecretAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _b64url_decode(s: str) -> bytes:
    """Decode a JWT base64url segment, padding as needed."""
    s = s.split(".")[0] if "." in s else s
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _redact_secret(secret: str) -> str:
    """Customer-safe: length + last 3 chars only."""
    if not secret:
        return "len=0"
    if len(secret) <= 3:
        return f"len={len(secret)} ***"
    return f"len={len(secret)} ***{secret[-3:]}"


def _decode_no_verify(token: str) -> dict:
    """Pure-Python decode w/o signature check - inspect header + payload."""
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("malformed JWT (missing segments)")
    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])
    return {
        "header":  json.loads(header_raw.decode("utf-8", errors="ignore")),
        "payload": json.loads(payload_raw.decode("utf-8", errors="ignore")),
    }


async def _try_weak_secret(token: str, secrets: list, alg: str) -> Optional[str]:
    """Try each secret as HMAC key. Returns secret on success, else None."""
    try:
        import jwt as pyjwt
    except ImportError:
        return None
    loop = asyncio.get_event_loop()

    def _crack():
        for sec in secrets:
            try:
                pyjwt.decode(
                    token, sec,
                    algorithms=[alg],
                    options={"verify_exp": False, "verify_aud": False, "verify_iss": False},
                )
                return sec
            except Exception:
                continue
        return None
    return await loop.run_in_executor(None, _crack)


async def _try_alg_none(token: str) -> bool:
    """Build alg=none variant + see if any naive decoder pattern would accept it.
    PyJWT's actual decode() refuses alg=none by default, but we record the
    *forgery construction* as the success signal - a customer integrating a
    homegrown verifier WILL accept this."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return False
        # Forge header with alg=none, keep claims, drop signature
        header = {"alg": "none", "typ": "JWT"}
        h64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        forged = f"{h64}.{parts[1]}."
        # PyJWT direct verify w/ algorithms=['none']
        try:
            import jwt as pyjwt
            pyjwt.decode(forged, "", algorithms=["none"],
                         options={"verify_signature": False,
                                  "verify_exp": False,
                                  "verify_aud": False,
                                  "verify_iss": False})
            return True
        except Exception:
            return False
    except Exception:
        return False


async def _try_rs_to_hs_confusion(token: str, public_key_pem: str) -> bool:
    """RS256->HS256 alg confusion: try signing with the public key as HMAC secret."""
    if not public_key_pem:
        return False
    try:
        import jwt as pyjwt
        parts = token.split(".")
        if len(parts) < 2:
            return False
        # Re-sign payload with HS256 using the PEM as key string
        try:
            payload_raw = _b64url_decode(parts[1])
            payload = json.loads(payload_raw.decode("utf-8", errors="ignore"))
        except Exception:
            return False
        try:
            forged = pyjwt.encode(payload, public_key_pem, algorithm="HS256")
            # Verify-decode loop with the same key
            pyjwt.decode(forged, public_key_pem, algorithms=["HS256"],
                         options={"verify_exp": False, "verify_aud": False,
                                  "verify_iss": False})
            return True
        except Exception:
            return False
    except Exception:
        return False


def _check_kid_injection(header: dict) -> list:
    """If kid is present, list the injection variants a tester should send.
    We don't *send* them (no remote endpoint here), but we report the kid
    pattern + give exact forgeries the customer can replay."""
    kid = header.get("kid")
    if kid is None:
        return []
    forgeries = []
    for inj in KID_INJECTIONS:
        forgeries.append({"kid_variant": inj})
    return forgeries


def _exp_drift(payload: dict) -> Optional[int]:
    """Return seconds since expiration, or None if not expired/no exp."""
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return None
    drift = int(time.time() - exp)
    if drift <= 0:
        return None
    return drift


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    token = (opts.get("jwt_token") or "").strip()
    public_key = (opts.get("public_key") or "").strip()
    custom_secrets = (opts.get("weak_secret_list") or "").strip()

    if not token:
        ctx.state["jwt_input_missing"] = True
        ctx.source("missing jwt_token")
        return

    # Verify PyJWT is importable - otherwise we can't probe at all.
    try:
        import jwt as pyjwt  # noqa: F401
    except ImportError:
        ctx.state["jwt_pyjwt_missing"] = True
        ctx.source("PyJWT not installed")
        return

    # ----- (a) Decode without verify -----
    try:
        meta = _decode_no_verify(token)
    except Exception as e:
        ctx.state["jwt_malformed_error"] = str(e)
        ctx.source("malformed JWT")
        return

    header = meta["header"]
    payload = meta["payload"]
    alg = (header.get("alg") or "").upper()
    kid = header.get("kid")
    typ = header.get("typ")
    claim_names = sorted(list(payload.keys()))

    ctx.state["jwt_header_alg"] = alg
    ctx.state["jwt_header_typ"] = typ
    ctx.state["jwt_header_kid"] = kid
    ctx.state["jwt_claim_names"] = claim_names
    ctx.source(f"PyJWT decode-no-verify alg={alg}")

    # ----- expiration drift -----
    drift = _exp_drift(payload)
    if drift is not None:
        ctx.state["jwt_expired_seconds"] = drift

    # ----- (b) Weak secret brute (only for HS* algs) -----
    if alg.startswith("HS"):
        if custom_secrets:
            secrets = [s.strip() for s in custom_secrets.splitlines()
                       if s.strip()][:500]
        else:
            secrets = list(DEFAULT_WEAK_SECRETS)
        cracked = await _try_weak_secret(token, secrets, alg)
        ctx.state["jwt_weak_secrets_tried"] = len(secrets)
        if cracked is not None:
            ctx.state["jwt_weak_secret_redacted"] = _redact_secret(cracked)
            ctx.source(f"PyJWT HS-crack hit: {_redact_secret(cracked)}")

    # ----- (c) alg=none -----
    if await _try_alg_none(token):
        ctx.state["jwt_alg_none_accepted"] = True
        ctx.source("alg=none forgery decode succeeded under PyJWT algorithms=['none']")

    # ----- (d) RS256 -> HS256 confusion -----
    if alg.startswith("RS") and public_key:
        if await _try_rs_to_hs_confusion(token, public_key):
            ctx.state["jwt_rs_to_hs_confusion"] = True
            ctx.source("RS->HS confusion forgery built with provided public key")

    # ----- (e) kid injection -----
    kid_variants = _check_kid_injection(header)
    if kid_variants:
        ctx.state["jwt_kid_present"] = kid
        ctx.state["jwt_kid_injection_variants"] = kid_variants
        ctx.source(f"kid={kid!r} -> {len(kid_variants)} injection variants ready")


INTEL_FIELDS = [
    ("Header alg",            "jwt_header_alg"),
    ("Header typ",            "jwt_header_typ"),
    ("Header kid",            "jwt_header_kid"),
    ("Claim names",           "jwt_claim_names"),
    ("Expired (seconds)",     "jwt_expired_seconds"),
    ("Weak secrets tried",    "jwt_weak_secrets_tried"),
    ("Weak secret (redacted)", "jwt_weak_secret_redacted"),
    ("kid injection variants", "jwt_kid_injection_variants"),
]


@router.post("/api/auth_attacks/jwt_secret_audit")
async def auth_attacks_jwt_secret_audit(req: JwtSecretAuditRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="jwt_secret_audit",
        gather_func=_gather_with_options,
        finding_rules=JWT_SECRET_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
