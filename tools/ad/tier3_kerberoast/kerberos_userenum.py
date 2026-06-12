"""kerberos_userenum - Kerberos username enumeration (playbook §3 #40 / §1).

For each candidate username, sends a pre-auth-less Kerberos AS-REQ and classifies
the principal by the KDC's reply:
  - KRB5KDC_ERR_PREAUTH_REQUIRED      -> the username EXISTS (reported VALID)
  - KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN   -> no such username (NOT reported)
  - AS-REP returned                   -> exists AND AS-REP roastable (reported VALID)

This is pure ENUMERATION, not authentication: no password is ever sent, so it
cannot lock accounts out (a pre-auth-less AS-REQ is not a logon attempt). Detection
only (VA-not-PT).

ZERO-FP: a username is only reported VALID when the KDC's error code proves the
principal exists on the live target. No userlist -> INFO advisory.

Customer input via ScanRequest.options:
  - target           = DC IP/hostname (required)
  - options.domain   = AD domain FQDN (required)
  - options.userlist = candidate usernames, newline-separated (required, max 300)
"""
from __future__ import annotations
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ad_kerberos_userenum_findings import AD_KERBEROS_USERENUM_FINDING_RULES

router = APIRouter()
HARD_MAX_USERS = 300


class KerberosUserenumRequest(ScanRequest):
    options: Optional[dict] = None


def _split_users(s: str, limit: int) -> list[str]:
    out: list[str] = []
    seen: set = set()
    for raw in (s or "").splitlines():
        u = raw.strip()
        if not u or u.startswith("#") or u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= limit:
            break
    return out


def _classify(domain: str, username: str, dc_ip: str):
    """Returns 'valid' | 'unknown' | 'error' | 'import_error'."""
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
    except Exception:
        return "import_error"
    try:
        client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        getKerberosTGT(client, "", domain, None, None, None, kdcHost=dc_ip)
        # No pre-auth required AND a TGT returned -> principal definitely exists.
        return "valid"
    except KerberosError as e:
        try:
            code = e.getErrorCode()
        except Exception:
            code = None
        try:
            if code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                return "valid"
            if code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                return "unknown"
        except Exception:
            pass
        return "error"
    except Exception:
        return "error"


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["ad_kuserenum_total"] = 0
        ctx.source("no-target")
        return
    try:
        import impacket  # noqa: F401
        from impacket.krb5 import kerberosv5  # noqa: F401
    except Exception:
        ctx.state["ad_kuserenum_error"] = "impacket not installed"
        ctx.source("impacket missing")
        return

    opts = ctx.state.get("_options") or {}
    domain = (opts.get("domain") or "").strip()
    users = _split_users(opts.get("userlist", ""), HARD_MAX_USERS)

    if not domain or not users:
        ctx.state["ad_kuserenum_input_missing"] = True
        ctx.state["ad_kuserenum_total"] = 0
        ctx.source("input required (domain + userlist)")
        return

    valid: list[str] = []
    unknown = 0
    errors = 0
    loop = asyncio.get_event_loop()
    for u in users:
        try:
            res = await asyncio.wait_for(
                loop.run_in_executor(None, _classify, domain, u, target),
                timeout=10)
        except Exception:
            errors += 1
            continue
        if res == "valid":
            valid.append(u)
        elif res == "unknown":
            unknown += 1
        elif res == "import_error":
            ctx.state["ad_kuserenum_error"] = "impacket not installed"
            ctx.source("impacket missing")
            return
        else:
            errors += 1

    ctx.state["ad_kuserenum_valid"] = valid
    ctx.state["ad_kuserenum_tested"] = len(users) - errors
    ctx.state["ad_kuserenum_unknown"] = unknown
    ctx.state["ad_kuserenum_errors"] = errors
    ctx.state["ad_kuserenum_total"] = len(valid)
    ctx.source(f"tried {len(users)} names -> {len(valid)} valid, "
               f"{unknown} unknown, {errors} errors")


INTEL_FIELDS = [("Valid usernames", "ad_kuserenum_valid"),
                ("Names tried", "ad_kuserenum_tested"),
                ("Unknown (count)", "ad_kuserenum_unknown")]


@router.post("/api/ad/kerberos_userenum")
async def ad_kerberos_userenum(req: KerberosUserenumRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}
    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)
    return await run_scanner(host=req.target, tool="kerberos_userenum",
        gather_func=_gather_with_options, finding_rules=AD_KERBEROS_USERENUM_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
