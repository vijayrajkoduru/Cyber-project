"""CUSTOMER-mode target profile CRUD (TARGET-PROFILE-V1).

All routes require verify_token. Every read/write is filtered by the
authenticated user's id (no IDOR): a profile that belongs to someone else is
indistinguishable from one that does not exist (404). Admins may LIST all
profiles (?all=true) and read any single profile (masked); they cannot modify
or scan with another user's profile.

Secrets are never returned: every secret field comes back as "********" plus
a has_<field> boolean. Sending "********" (or omitting the field) on update
keeps the stored secret; sending "" clears it.

Routes:
    GET    /api/profiles/meta                provider catalogue + defaults
    GET    /api/profiles                     list own (admin: ?all=true)
    POST   /api/profiles                     create
    GET    /api/profiles/{id}                read (masked)
    PUT    /api/profiles/{id}                full replace
    PATCH  /api/profiles/{id}                partial update
    DELETE /api/profiles/{id}                delete
    POST   /api/profiles/{id}/test_auth      log in a role, report session status
    POST   /api/profiles/{id}/check_scope    dry-run scope decisions for URLs
    PUT    /api/profiles/{id}/openapi        store an OpenAPI spec (text or URL)
    GET    /api/profiles/{id}/openapi        fetch the stored spec
    POST   /api/profiles/{id}/logo           upload report logo (png/jpeg)
"""
import asyncio
import datetime
import hashlib
import json
import logging

from fastapi import APIRouter, Body, Depends, File, HTTPException, Request, UploadFile

from tools._shared import verify_token, writable_base, is_safe_external_url, read_capped
from tools._core import target_profile as tp

log = logging.getLogger("vulnuslab.profiles")
router = APIRouter()


def _uid(payload) -> str:
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(401, "Invalid token subject")
    return str(sub)


def _is_admin(payload) -> bool:
    return bool(payload.get("_role_verified")) and payload.get("role") in ("admin", "superadmin")


def _audit(request: Request, payload, action: str, target: str, detail: str = ""):
    try:
        from tools.auth._db import record_audit
        record_audit(action, actor_id=payload.get("sub"), actor_name=payload.get("username"),
                     target=target, ip=request.client.host if request.client else None,
                     detail=detail[:500])
    except Exception:
        pass


def _run(fn, *a, **kw):
    """DB / crypto work off the event loop; map domain errors to HTTP."""
    async def _inner():
        try:
            return await asyncio.to_thread(fn, *a, **kw)
        except tp.ProfileError as e:
            raise HTTPException(422, str(e))
        except RuntimeError as e:
            if "VAULT_KEY" in str(e):
                raise HTTPException(503, "Credential encryption is not configured (VAULT_KEY); "
                                         "cannot store or use profile secrets.")
            raise
    return _inner()


@router.get("/api/profiles/meta")
async def profiles_meta(payload=Depends(verify_token)):
    return {
        "providers": {
            "form_login": {"required": ["login_url", "username", "password"],
                           "optional": ["username_field", "password_field", "extra_fields",
                                        "success_text", "logged_in_indicator", "extra_headers",
                                        "session_ttl_sec"]},
            "bearer_token": {"required": ["token"], "optional": ["logged_in_indicator", "extra_headers"]},
            "api_key_header": {"required": ["header_name", "api_key"],
                               "optional": ["logged_in_indicator", "extra_headers"]},
            "cookie": {"required": ["cookie"], "optional": ["logged_in_indicator", "extra_headers"]},
            "basic_auth": {"required": ["username", "password"],
                           "optional": ["logged_in_indicator", "extra_headers"]},
            "oauth2_client_credentials": {"required": ["token_url", "client_id", "client_secret"],
                                          "optional": ["oauth_scope", "audience",
                                                       "logged_in_indicator", "extra_headers"]},
        },
        "secret_fields": list(tp.SECRET_FIELDS),
        "mask": tp.MASK,
        "default_safety": tp.DEFAULT_SAFETY,
        "scope_pattern_syntax": {
            "host_glob": "*.example.com  |  app.example.com:8443/api",
            "url_prefix": "https://app.example.com/api/",
            "cidr_or_ip": "203.0.113.0/24  |  203.0.113.7",
            "regex": "re:^https://app\\.example\\.com/(api|admin)/",
            "rule": "out_of_scope wins; primary_targets are in scope host-wide",
        },
        "time_window_days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
    }


@router.get("/api/profiles")
async def list_profiles(all: bool = False, limit: int = 100, offset: int = 0,
                        payload=Depends(verify_token)):
    if all and not _is_admin(payload):
        raise HTTPException(403, "Admin role required to list all profiles")
    owner = None if all else _uid(payload)
    recs = await _run(tp.list_profiles, owner, limit, offset)
    items = [tp.public_view(r) for r in recs]
    return {"profiles": items, "count": len(items), "limit": limit, "offset": offset}


@router.post("/api/profiles", status_code=201)
async def create_profile(request: Request, data: dict = Body(...), payload=Depends(verify_token)):
    rec = await _run(tp.create_profile, _uid(payload), data)
    _audit(request, payload, "profile.create", rec["id"], f"name={rec['config']['name']}")
    return tp.public_view(rec)


async def _owned(profile_id: str, payload) -> dict:
    rec = await _run(tp.get_profile_record, profile_id, _uid(payload))
    if rec is None:
        raise HTTPException(404, "Profile not found")
    return rec


@router.get("/api/profiles/{profile_id}")
async def get_profile(profile_id: str, payload=Depends(verify_token)):
    rec = await _run(tp.get_profile_record, profile_id, _uid(payload))
    if rec is None and _is_admin(payload):
        rec = await _run(tp.get_profile_record, profile_id, None)
    if rec is None:
        raise HTTPException(404, "Profile not found")
    return tp.public_view(rec)


@router.put("/api/profiles/{profile_id}")
async def replace_profile(profile_id: str, request: Request, data: dict = Body(...),
                          payload=Depends(verify_token)):
    rec = await _run(tp.update_profile, profile_id, _uid(payload), data, False)
    if rec is None:
        raise HTTPException(404, "Profile not found")
    _audit(request, payload, "profile.update", profile_id, "replace")
    return tp.public_view(rec)


@router.patch("/api/profiles/{profile_id}")
async def patch_profile(profile_id: str, request: Request, data: dict = Body(...),
                        payload=Depends(verify_token)):
    rec = await _run(tp.update_profile, profile_id, _uid(payload), data, True)
    if rec is None:
        raise HTTPException(404, "Profile not found")
    _audit(request, payload, "profile.update", profile_id, "patch:" + ",".join(sorted(data.keys()))[:200])
    return tp.public_view(rec)


@router.delete("/api/profiles/{profile_id}")
async def delete_profile(profile_id: str, request: Request, payload=Depends(verify_token)):
    ok = await _run(tp.delete_profile, profile_id, _uid(payload))
    if not ok:
        raise HTTPException(404, "Profile not found")
    _audit(request, payload, "profile.delete", profile_id)
    return {"deleted": True, "id": profile_id}


@router.post("/api/profiles/{profile_id}/test_auth")
async def test_auth(profile_id: str, request: Request, data: dict = Body(default={}),
                    payload=Depends(verify_token)):
    """Log in with one role (default role if omitted) and report the session
    status. Runs under the profile's scope guard (login URL must be in scope;
    a configured external token_url/login host is allowed for the login)."""
    from tools._core import scope_guard, session_manager as sm
    rt = await _run(tp.get_runtime_profile, profile_id, _uid(payload))
    if rt is None:
        raise HTTPException(404, "Profile not found")
    role = (data or {}).get("role")
    if role and rt.role(role) is None:
        raise HTTPException(400, f"Profile has no auth role {role!r}")
    if not rt.cfg.get("auth_configs"):
        return {"ok": True, "session": {"authenticated": False}, "detail": "profile has no auth roles"}
    ctx = scope_guard.ScanContext(rt, _uid(payload), request.url.path)
    tok = scope_guard.activate(ctx)
    try:
        m = await asyncio.to_thread(sm.get_auth, rt, role, bool((data or {}).get("force", True)))
        result = {"ok": True, "session": sm.public_status(m)}
    except sm.AuthError as e:
        result = {"ok": False, "error": str(e)}
    finally:
        scope_guard.deactivate(tok)
    result["scope_enforcement"] = ctx.summary()
    _audit(request, payload, "profile.test_auth", profile_id,
           f"role={role or 'default'} ok={result['ok']}")
    return result


@router.post("/api/profiles/{profile_id}/check_scope")
async def check_scope(profile_id: str, data: dict = Body(...), payload=Depends(verify_token)):
    from tools._core import scope_guard
    rt = await _run(tp.get_runtime_profile, profile_id, _uid(payload))
    if rt is None:
        raise HTTPException(404, "Profile not found")
    urls = (data or {}).get("urls") or []
    if not isinstance(urls, list) or len(urls) > 100:
        raise HTTPException(422, "urls must be a list of <= 100 strings")
    ctx = scope_guard.ScanContext(rt, _uid(payload), (data or {}).get("module_path") or "")

    def _decide():
        out = []
        for u in urls:
            u = str(u)[:2048]
            ok, cat, why = scope_guard.classify(u, ctx)
            out.append({"url": u, "allowed": ok, "category": cat, "reason": why})
        return out
    results = await asyncio.to_thread(_decide)
    return {"results": results,
            "within_time_window": tp.within_time_window(rt.safety.get("time_window"))}


@router.put("/api/profiles/{profile_id}/openapi")
async def put_openapi(profile_id: str, request: Request, data: dict = Body(...),
                      payload=Depends(verify_token)):
    await _owned(profile_id, payload)
    text = (data or {}).get("spec_text")
    url = ((data or {}).get("spec_url") or "").strip()
    if not text and not url:
        raise HTTPException(422, "Provide spec_text or spec_url")
    if not text:
        ok, why = await asyncio.to_thread(is_safe_external_url, url)
        if not ok:
            raise HTTPException(422, f"spec_url rejected: {why}")

        def _fetch():
            import requests
            r = requests.get(url, timeout=20, stream=True, allow_redirects=False,
                             headers={"Accept": "application/json, application/yaml, */*"})
            read_capped(r, tp.MAX_SPEC_BYTES)
            return r
        try:
            r = await asyncio.to_thread(_fetch)
        except Exception as e:
            raise HTTPException(502, f"Could not fetch spec: {type(e).__name__}")
        if r.status_code >= 400:
            raise HTTPException(502, f"Spec URL returned HTTP {r.status_code}")
        if getattr(r, "vl_truncated", False):
            raise HTTPException(413, "Spec exceeds 5 MB")
        text = r.text
    if not isinstance(text, str) or len(text.encode()) > tp.MAX_SPEC_BYTES:
        raise HTTPException(413, "Spec must be a string <= 5 MB")
    try:
        doc = json.loads(text)
    except Exception:
        try:
            import yaml
            doc = yaml.safe_load(text)
        except Exception:
            raise HTTPException(422, "Spec is neither valid JSON nor YAML")
    if not isinstance(doc, dict) or not (doc.get("openapi") or doc.get("swagger")):
        raise HTTPException(422, "Document is not an OpenAPI/Swagger spec (no openapi/swagger key)")
    meta = {"has_spec": True, "spec_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "uploaded_at": datetime.datetime.utcnow().isoformat() + "Z",
            "spec_version": str(doc.get("openapi") or doc.get("swagger"))[:20],
            "path_count": len(doc.get("paths") or {})}
    if url:
        meta["source_url"] = url
    await _run(tp.set_server_fields, profile_id, _uid(payload), spec_text=text, spec_meta=meta)
    _audit(request, payload, "profile.openapi", profile_id, f"paths={meta['path_count']}")
    return {"ok": True, "openapi": meta}


@router.get("/api/profiles/{profile_id}/openapi")
async def get_openapi(profile_id: str, payload=Depends(verify_token)):
    await _owned(profile_id, payload)
    text = await _run(tp.get_openapi_spec, profile_id, _uid(payload))
    if not text:
        raise HTTPException(404, "No OpenAPI spec stored for this profile")
    return {"spec_text": text}


_LOGO_MAX = 2 * 1024 * 1024


@router.post("/api/profiles/{profile_id}/logo")
async def upload_logo(profile_id: str, request: Request, file: UploadFile = File(...),
                      payload=Depends(verify_token)):
    await _owned(profile_id, payload)
    raw = await file.read(_LOGO_MAX + 1)
    if len(raw) > _LOGO_MAX:
        raise HTTPException(413, "Logo must be <= 2 MB")
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        ext = "png"
    elif raw.startswith(b"\xff\xd8\xff"):
        ext = "jpg"
    else:
        raise HTTPException(422, "Logo must be a PNG or JPEG image")
    d = writable_base("VL_UPLOAD_DIR", "/uploads") / "profile_logos"
    await asyncio.to_thread(d.mkdir, parents=True, exist_ok=True)
    # profile_id is a server-generated UUID verified by _owned(); no traversal.
    path = d / f"{profile_id}.{ext}"
    await asyncio.to_thread(path.write_bytes, raw)
    await _run(tp.set_server_fields, profile_id, _uid(payload), logo_path=str(path))
    _audit(request, payload, "profile.logo", profile_id, f"bytes={len(raw)}")
    return {"ok": True, "logo_path": str(path)}


@router.get("/api/profiles/{profile_id}/logo")
async def get_logo(profile_id: str, payload=Depends(verify_token)):
    """Return the uploaded report logo (owner only) so the browser-side PDF
    generator can brand the report. Path comes from the server-controlled
    reporting.logo_path and must live under the profile_logos directory."""
    from fastapi.responses import Response as _Resp
    rec = await _owned(profile_id, payload)
    lp = ((rec.get("config") or {}).get("reporting") or {}).get("logo_path") or ""
    if not lp:
        raise HTTPException(404, "No logo uploaded for this profile")
    from pathlib import Path
    base = (writable_base("VL_UPLOAD_DIR", "/uploads") / "profile_logos").resolve()
    try:
        path = Path(lp).resolve()
        path.relative_to(base)
    except Exception:
        raise HTTPException(404, "No logo uploaded for this profile")
    if not path.is_file():
        raise HTTPException(404, "No logo uploaded for this profile")
    raw = await asyncio.to_thread(path.read_bytes)
    media = "image/png" if raw.startswith(b"\x89PNG") else "image/jpeg"
    return _Resp(content=raw, media_type=media, headers={"Cache-Control": "private, no-store"})


def register(app):
    app.include_router(router)
