"""mobile_crypto module orchestrator — §4 CRYPTO (in-depth crypto audit).

7 static scanners covering OWASP MASVS-CRYPTO controls. Reuses
/api/mobile_static/upload (same SHA-256-keyed binary_cache) so customers
don't re-upload between modules.

Tier 1 — Algorithm strength:
  - weak_algo_audit              (#46  DES / 3DES / RC4 / MD5 / SHA-1 / ECB hints)
  - aes_ecb_mode_audit           (#47  AES/ECB or CBC/NoPadding)
  - insecure_prng_audit          (#49  java.util.Random in security context)
  - custom_crypto_audit          (#50  homebrew XOR + non-JCA encrypt methods)

Tier 2 — Keys & TLS:
  - hardcoded_keys_audit         (#48  SecretKeySpec + entropy heuristic)
  - tls_version_audit            (#51  TLSv1.0/1.1 + NSC + minSdk gate)
  - cert_validation_bypass_audit (#52  TrustAll + ALLOW_ALL_HOSTNAME)
"""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from tools._shared import verify_scan_quota
from tools._framework.orchestrator import (
    run_module_parallel, run_module_streaming,
)

router = APIRouter()


MOBILE_CRYPTO_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    "tier1_algo_strength": [
        ("weak_algo_audit",                 "/api/mobile_crypto/weak_algo_audit"),
        ("aes_ecb_mode_audit",              "/api/mobile_crypto/aes_ecb_mode_audit"),
        ("insecure_prng_audit",             "/api/mobile_crypto/insecure_prng_audit"),
        ("custom_crypto_audit",             "/api/mobile_crypto/custom_crypto_audit"),
    ],
    "tier2_keys_and_tls": [
        ("hardcoded_keys_audit",            "/api/mobile_crypto/hardcoded_keys_audit"),
        ("tls_version_audit",               "/api/mobile_crypto/tls_version_audit"),
        ("cert_validation_bypass_audit",    "/api/mobile_crypto/cert_validation_bypass_audit"),
    ],
}


def _all_tools() -> list[tuple[str, str]]:
    out = []
    for tier in MOBILE_CRYPTO_TOOLS_BY_TIER.values():
        out.extend(tier)
    return out


class MobileCryptoRunAllRequest(BaseModel):
    target: str
    tiers: Optional[list[str]] = None
    concurrency: Optional[int] = 4
    options: Optional[dict] = None


def _resolve(req, request: Request):
    if req.tiers:
        tools = []
        for tier in req.tiers:
            if tier in MOBILE_CRYPTO_TOOLS_BY_TIER:
                tools.extend(MOBILE_CRYPTO_TOOLS_BY_TIER[tier])
    else:
        tools = _all_tools()
    auth = request.headers.get("authorization") or ""
    jwt = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else None
    return tools, (req.options or {}), jwt


@router.post("/api/mobile_crypto/run_all")
async def mobile_crypto_run_all(req: MobileCryptoRunAllRequest, request: Request,
                                  _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    gen = run_module_streaming(
        target=req.target, tools=tools, module_name="mobile_crypto",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt,
    )
    return StreamingResponse(gen, media_type="application/x-ndjson",
        headers={"X-Accel-Buffering": "no",
                  "Cache-Control": "no-store, no-transform",
                  "Connection": "keep-alive"})


@router.post("/api/mobile_crypto/run_all_buffered")
async def mobile_crypto_run_all_buffered(req: MobileCryptoRunAllRequest, request: Request,
                                            _=Depends(verify_scan_quota)):
    tools, extra, jwt = _resolve(req, request)
    concurrency = max(1, min(req.concurrency or 4, 8))
    return await run_module_parallel(
        target=req.target, tools=tools, module_name="mobile_crypto",
        concurrency=concurrency, extra_body=extra or None, jwt_token=jwt)


@router.get("/api/mobile_crypto/run_all/tiers")
async def mobile_crypto_run_all_tiers():
    return {
        "tiers": [{"id": tid, "tools": [n for n, _ in t], "count": len(t)}
                  for tid, t in MOBILE_CRYPTO_TOOLS_BY_TIER.items()],
        "total_tools": sum(len(t) for t in MOBILE_CRYPTO_TOOLS_BY_TIER.values()),
    }


def register(app):
    app.include_router(router)
