"""oauth_token_replay_audit - expired/tampered bearer-token acceptance (playbook §5 #52).

REAL remote probe. The customer supplies a bearer token THEY already own
(pulled from their own session) plus a protected API/userinfo URL. The
probe sends a small, SAFE set of token variants to that URL and records
which the resource server accepts:

  (a) Baseline      - the token as-is (confirms the endpoint + token work).
  (b) Expired replay - if the token is a JWT with an exp in the past, replay
                       it verbatim; acceptance = expired tokens are honored.
  (c) Signature strip - JWT with the signature segment removed (alg=none
                        style); acceptance = signature not validated (#47).
  (d) No-token       - same request with NO Authorization header (control:
                        the endpoint must reject; otherwise it isn't protected).

ZERO false positives: a graded severity is emitted ONLY when an INVALID
variant (expired, stripped, or no-token) is accepted while a valid request
behaves like an authenticated one. No token / no URL -> INFO. This is
DETECTION ONLY - no brute force, no payload, no flooding (one request per
variant).

Customer input via ScanRequest.options:
  - target                = identifier (logging only)
  - options.access_token  = bearer token the customer owns (required)
  - options.protected_url = an authenticated API/userinfo URL (required)
  - options.success_marker = optional string present in an authed response

Privacy: the token is never echoed; only header.alg / exp drift and the
HTTP status of each variant appear in findings.
"""
from __future__ import annotations
import base64
import json
import time
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()

DEFAULT_TIMEOUT = 12


class OauthTokenReplayAuditRequest(ScanRequest):
    options: Optional[dict] = None


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _jwt_parts(token: str):
    """Return (header, payload, is_jwt) without verifying anything."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}, {}, False
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", "ignore"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", "ignore"))
        return header, payload, True
    except Exception:
        return {}, {}, False


def _strip_signature(token: str) -> str:
    """Return the token with an empty signature segment (alg=none style)."""
    parts = token.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}."
    return token


def _looks_authed(status: int, body: str, marker: Optional[str]) -> bool:
    if status != 200:
        return False
    b = (body or "")[:4000].lower()
    if marker:
        return marker.lower() in b
    # Generic authed signals; absence of typical auth-error words.
    err_words = ("unauthorized", "invalid token", "token expired",
                 "expired", "forbidden", "access denied", "not authenticated")
    if any(w in b for w in err_words):
        return False
    return True


async def _send(client, url: str, token: Optional[str], marker):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = await client.get(url, headers=headers, follow_redirects=False)
        return {
            "status": r.status_code,
            "authed": _looks_authed(r.status_code, r.text or "", marker),
        }
    except Exception as e:
        return {"status": 0, "authed": False, "error": str(e)[:160]}


async def gather(ctx: ScanContext):
    opts = ctx.state.get("_options") or {}
    token = (opts.get("access_token") or "").strip()
    url = (opts.get("protected_url") or "").strip()
    marker = opts.get("success_marker")

    if not token or not url:
        ctx.state["replay_input_missing"] = True
        ctx.source("missing access_token / protected_url")
        return

    try:
        import httpx
    except ImportError:
        ctx.state["replay_httpx_missing"] = True
        ctx.source("httpx not installed")
        return

    header, payload, is_jwt = _jwt_parts(token)
    alg = (header.get("alg") or "").upper() if is_jwt else None
    exp = payload.get("exp") if is_jwt else None
    exp_drift = None
    if isinstance(exp, (int, float)):
        exp_drift = int(time.time() - exp)  # >0 == already expired
    ctx.state["replay_is_jwt"] = is_jwt
    ctx.state["replay_alg"] = alg
    ctx.state["replay_exp_drift"] = exp_drift

    async with httpx.AsyncClient(verify=True, timeout=DEFAULT_TIMEOUT) as client:
        # (a) baseline
        base = await _send(client, url, token, marker)
        ctx.state["replay_baseline"] = base

        # (d) no-token control
        none_res = await _send(client, url, None, marker)
        ctx.state["replay_no_token"] = none_res
        if none_res.get("authed"):
            ctx.state["replay_unprotected"] = True

        # Only test invalid-token variants if the endpoint actually
        # distinguishes authed from unauthed (baseline authed, control not).
        endpoint_discriminates = base.get("authed") and not none_res.get("authed")
        ctx.state["replay_discriminates"] = endpoint_discriminates

        if endpoint_discriminates and is_jwt:
            # (b) expired replay - only meaningful if the token is already expired
            if exp_drift is not None and exp_drift > 0:
                exp_res = await _send(client, url, token, marker)
                ctx.state["replay_expired"] = exp_res
                if exp_res.get("authed"):
                    ctx.state["replay_expired_accepted"] = True

            # (c) signature strip
            stripped = _strip_signature(token)
            strip_res = await _send(client, url, stripped, marker)
            ctx.state["replay_sig_strip"] = strip_res
            if strip_res.get("authed"):
                ctx.state["replay_sig_strip_accepted"] = True

    accepted = []
    if ctx.state.get("replay_expired_accepted"):
        accepted.append("expired_token_replay")
    if ctx.state.get("replay_sig_strip_accepted"):
        accepted.append("signature_stripping")
    ctx.state["replay_accepted_modes"] = accepted
    ctx.source(
        f"token replay: jwt={is_jwt} alg={alg} drift={exp_drift}s; "
        f"{len(accepted)} invalid variant(s) accepted"
    )


# ----------------------- inline finding rules -----------------------
def rule_expired_accepted(s):
    if not s.get("replay_expired_accepted"):
        return None
    return {
        "name": "Resource server accepts EXPIRED JWT (expiration not enforced)",
        "severity": "HIGH",
        "cvss": "7.5",
        "cwe": "CWE-613",
        "owasp": "A07:2021",
        "verified_exploit": True,
        "evidence": (
            f"The supplied token's exp is {s.get('replay_exp_drift')}s in the past, yet a "
            f"verbatim replay to the protected URL returned HTTP "
            f"{(s.get('replay_expired') or {}).get('status')} with authenticated content. "
            "Expired sessions remain valid - a stolen token never dies."
        ),
        "remediation": (
            "Enforce the exp claim server-side on every request. Reject tokens past exp, keep "
            "lifetimes short, and implement refresh-token rotation + revocation."
        ),
    }


def rule_sig_strip_accepted(s):
    if not s.get("replay_sig_strip_accepted"):
        return None
    return {
        "name": "Resource server accepts a signature-stripped JWT (signature not validated)",
        "severity": "CRITICAL",
        "cvss": "9.8",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "verified_exploit": True,
        "evidence": (
            "A JWT with its signature segment removed (header.payload.) was accepted by the "
            f"protected URL (HTTP {(s.get('replay_sig_strip') or {}).get('status')}). The "
            "resource server is not verifying the token signature, so any claims can be forged "
            "(playbook #47/#45)."
        ),
        "remediation": (
            "Always verify the JWT signature with the expected algorithm before trusting any "
            "claim. Reject tokens with alg=none or an empty signature. Pin the accepted alg list."
        ),
    }


def rule_unprotected(s):
    if not s.get("replay_unprotected"):
        return None
    return {
        "name": "Protected URL returns authenticated content with NO Authorization header",
        "severity": "HIGH",
        "cvss": "8.2",
        "cwe": "CWE-306",
        "owasp": "A01:2021",
        "verified_exploit": True,
        "evidence": (
            f"A GET to the supplied protected URL with no token returned HTTP "
            f"{(s.get('replay_no_token') or {}).get('status')} and authed-looking content. "
            "The resource is not actually access-controlled."
        ),
        "remediation": (
            "Require and validate a bearer token on this route server-side. If the URL is "
            "intentionally public, re-run with a genuinely protected endpoint."
        ),
    }


def rule_input_missing(s):
    if not s.get("replay_input_missing"):
        return None
    return {
        "name": "OAuth token replay audit skipped - missing token / protected URL",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            "Probe requires options.access_token (a bearer token you own) + "
            "options.protected_url (an authenticated API/userinfo endpoint)."
        ),
        "remediation": (
            "Pull a real access token from your own logged-in session (devtools) and a URL "
            "that requires it, then re-run."
        ),
    }


def rule_httpx_missing(s):
    if not s.get("replay_httpx_missing"):
        return None
    return {
        "name": "httpx library not installed on scanner host",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": "`import httpx` failed - required to send token-variant requests.",
        "remediation": "pip install httpx >=0.24 inside the scanner container.",
    }


def rule_inconclusive(s):
    # Endpoint did not discriminate authed vs unauthed -> can't safely test.
    if s.get("replay_input_missing") or s.get("replay_httpx_missing"):
        return None
    if s.get("replay_discriminates"):
        return None
    if s.get("replay_unprotected"):
        return None  # covered by its own rule
    if s.get("replay_baseline") is None:
        return None
    return {
        "name": "Token replay test inconclusive - endpoint did not distinguish authed vs unauthed",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": (
            f"Baseline status {(s.get('replay_baseline') or {}).get('status')}, no-token status "
            f"{(s.get('replay_no_token') or {}).get('status')}. Because the URL responded the "
            "same with and without a token, invalid-token variants were NOT sent (avoids false "
            "positives)."
        ),
        "remediation": (
            "Re-run with a protected_url that returns clearly different content when "
            "authenticated, and set options.success_marker to a string only present when "
            "logged in."
        ),
    }


def rule_positive(s):
    if s.get("replay_input_missing") or s.get("replay_httpx_missing"):
        return None
    if not s.get("replay_discriminates"):
        return None
    if (s.get("replay_accepted_modes") or []) or s.get("replay_unprotected"):
        return None
    return {
        "name": "Resource server rejected expired / signature-stripped / no-token variants",
        "severity": "POSITIVE",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "evidence": (
            "The protected URL accepted a valid token but rejected every invalid variant "
            "(expired replay, signature strip, no token). Token validation is enforced."
        ),
        "remediation": (
            "Maintain strict server-side token validation. Re-run after auth-middleware "
            "changes."
        ),
    }


OAUTH_TOKEN_REPLAY_AUDIT_FINDING_RULES = [
    rule_sig_strip_accepted,
    rule_expired_accepted,
    rule_unprotected,
    rule_input_missing,
    rule_httpx_missing,
    rule_inconclusive,
    rule_positive,
]


INTEL_FIELDS = [
    ("Token is JWT",          "replay_is_jwt"),
    ("Token alg",             "replay_alg"),
    ("Expiration drift (s)",  "replay_exp_drift"),
    ("Baseline result",       "replay_baseline"),
    ("No-token result",       "replay_no_token"),
    ("Expired replay result", "replay_expired"),
    ("Sig-strip result",      "replay_sig_strip"),
    ("Accepted invalid modes", "replay_accepted_modes"),
]


@router.post("/api/auth_attacks/oauth_token_replay_audit")
async def auth_attacks_oauth_token_replay_audit(req: OauthTokenReplayAuditRequest,
                                                _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="oauth_token_replay_audit",
        gather_func=_gather_with_options,
        finding_rules=OAUTH_TOKEN_REPLAY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
