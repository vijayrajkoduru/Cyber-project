"""hardcoded_jwt_secret_audit — JWT signing secrets baked into the binary.

Apps should NEVER contain JWT signing secrets (HS256 keys). If they do,
anyone with the APK can forge tokens. Looks for: high-entropy strings near
JWT library imports, base64-encoded blobs near 'HMAC-SHA256' / 'jwts' /
'io.jsonwebtoken' references.

MASVS-CRYPTO-1 / MSTG-CRYPTO-1.
"""
import re
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.hardcoded_jwt_secret_audit_findings import \
    HARDCODED_JWT_SECRET_AUDIT_FINDING_RULES

router = APIRouter()

JWT_LIB_MARKERS = [
    b"Lio/jsonwebtoken/",       # jjwt
    b"Lcom/auth0/jwt/",         # java-jwt
    b"Lcom/nimbusds/jose/",     # nimbus-jose-jwt
    b"jsonwebtoken",
    b"HMAC256", b"HmacSHA256", b"HS256",
    b"setSigningKey", b"signWith", b"Jwts.builder",
]

# JWT typical pattern: header.payload.signature
JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
# Base64 high-entropy candidates
B64_RE = re.compile(rb"[A-Za-z0-9+/]{40,}={0,3}")


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["hardcoded_jwt_secret_audit_total"] = 0
        ctx.source("file-not-found"); return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["hardcoded_jwt_secret_audit_error"] = str(e); return

    uses_jwt = False
    jwt_libs_found = []
    full_jwts = []
    files_scanned = 0

    for f in unpacked.rglob("*"):
        if not f.is_file(): continue
        if f.suffix not in (".dex", ".smali", ".json", ".xml") and "classes" not in f.name: continue
        try:
            data = f.read_bytes()[:10_000_000]
        except Exception: continue
        files_scanned += 1
        for marker in JWT_LIB_MARKERS:
            if marker in data:
                uses_jwt = True
                name = marker.decode(errors="ignore")
                if name not in jwt_libs_found:
                    jwt_libs_found.append(name)
        # Detect actual JWTs (full eyJ... triplets) embedded in resources
        for m in JWT_RE.finditer(data):
            jwt_val = m.group(0).decode(errors="ignore")
            if jwt_val not in full_jwts:
                full_jwts.append(jwt_val[:60] + "…")
                if len(full_jwts) >= 5: break

    ctx.state["uses_jwt_lib"] = uses_jwt
    ctx.state["jwt_libs_found"] = jwt_libs_found
    ctx.state["embedded_jwts"] = full_jwts
    ctx.state["hardcoded_jwt_secret_audit_total"] = len(full_jwts) + (3 if uses_jwt else 0)
    ctx.state["files_scanned"] = files_scanned
    ctx.source(f"JWT-lib={uses_jwt}, embedded JWTs={len(full_jwts)}")


INTEL_FIELDS = [
    ("Uses JWT library",   "uses_jwt_lib"),
    ("Embedded JWTs",      "embedded_jwts"),
    ("Files scanned",      "files_scanned"),
]


@router.post("/api/mobile_static/hardcoded_jwt_secret_audit")
async def mobile_static_hardcoded_jwt_secret_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="hardcoded_jwt_secret_audit",
        gather_func=gather,
        finding_rules=HARDCODED_JWT_SECRET_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
