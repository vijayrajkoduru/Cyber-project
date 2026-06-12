"""asrep_roast - AS-REP roastable account DETECTION (playbook §3 #36).

For each supplied username, sends a Kerberos AS-REQ WITHOUT pre-authentication
(impacket low-level KDC_ERR / AS-REP path, same primitive as GetNPUsers.py). If
the KDC answers with an AS-REP (a TGT) instead of KRB5KDC_ERR_PREAUTH_REQUIRED,
the account has UF_DONT_REQUIRE_PREAUTH set and is AS-REP roastable.

This is DETECTION ONLY (VA-not-PT):
  - we record THAT the account is roastable;
  - we do NOT save or crack the returned hash;
  - no password is ever guessed.

ZERO-FP: HIGH is emitted only for accounts the live KDC actually answered with
a TGT. Unknown users, pre-auth-required users, and unreachable KDCs never produce
a graded finding. No userlist -> INFO advisory (input required).

Customer input via ScanRequest.options:
  - target           = DC IP/hostname (required)
  - options.domain   = AD domain FQDN (required, e.g. corp.example.com)
  - options.userlist = newline-separated sAMAccountNames (required, max 200)
"""
from __future__ import annotations
import asyncio
from typing import Optional
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ad_asrep_roast_findings import AD_ASREP_ROAST_FINDING_RULES

router = APIRouter()
HARD_MAX_USERS = 200


class AsrepRoastRequest(ScanRequest):
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


def _check_user(domain: str, username: str, dc_ip: str):
    """Returns one of: 'roastable', 'preauth_required', 'unknown', 'error'.

    Sends a no-preauth AS-REQ. The KDC's response disambiguates the account:
      - AS-REP returned                       -> 'roastable' (DONT_REQ_PREAUTH)
      - KRB5KDC_ERR_PREAUTH_REQUIRED          -> 'preauth_required' (valid, safe)
      - KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN       -> 'unknown' (no such user)
    """
    try:
        from impacket.krb5.asn1 import AS_REP
        from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
    except Exception:
        return "import_error"

    try:
        client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        # Empty password / hashes — we only care about the KDC's pre-auth decision.
        getKerberosTGT(client, "", domain, None, None, None, kdcHost=dc_ip)
        # A TGT came back with NO pre-auth -> the account is AS-REP roastable.
        return "roastable"
    except KerberosError as e:
        try:
            code = e.getErrorCode()
        except Exception:
            code = None
        try:
            if code == constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
                return "preauth_required"
            if code == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                return "unknown"
        except Exception:
            pass
        # Some impacket builds raise KerberosError carrying the AS-REP when
        # pre-auth is not required; treat an explicit "no pre-auth" message as
        # roastable, otherwise treat as a benign non-roastable outcome.
        msg = str(e).lower()
        if "preauth" in msg and ("not" in msg or "without" in msg):
            return "roastable"
        return "preauth_required"
    except Exception:
        return "error"


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["ad_asrep_roast_total"] = 0
        ctx.source("no-target")
        return

    try:
        import impacket  # noqa: F401
        from impacket.krb5 import kerberosv5  # noqa: F401
    except Exception:
        ctx.state["ad_asrep_error"] = "impacket not installed"
        ctx.source("impacket missing")
        return

    opts = ctx.state.get("_options") or {}
    domain = (opts.get("domain") or "").strip()
    users = _split_users(opts.get("userlist", ""), HARD_MAX_USERS)

    if not domain or not users:
        ctx.state["ad_asrep_input_missing"] = True
        ctx.state["ad_asrep_roast_total"] = 0
        ctx.source("input required (domain + userlist)")
        return

    roastable: list[str] = []
    preauth_required = 0
    unknown = 0
    errors = 0

    loop = asyncio.get_event_loop()
    for u in users:
        try:
            res = await asyncio.wait_for(
                loop.run_in_executor(None, _check_user, domain, u, target),
                timeout=12)
        except asyncio.TimeoutError:
            errors += 1
            continue
        except Exception:
            errors += 1
            continue
        if res == "roastable":
            roastable.append(u)
        elif res == "preauth_required":
            preauth_required += 1
        elif res == "unknown":
            unknown += 1
        elif res == "import_error":
            ctx.state["ad_asrep_error"] = "impacket not installed"
            ctx.source("impacket missing")
            return
        else:
            errors += 1

    tested = len(users) - unknown - errors
    ctx.state["ad_asrep_roastable"] = roastable
    ctx.state["ad_asrep_users_tested"] = max(0, tested)
    ctx.state["ad_asrep_preauth_required"] = preauth_required
    ctx.state["ad_asrep_unknown_users"] = unknown
    ctx.state["ad_asrep_errors"] = errors
    ctx.state["ad_asrep_roast_total"] = len(roastable)
    ctx.source(f"tested {len(users)} users -> {len(roastable)} roastable, "
               f"{preauth_required} preauth-required, {unknown} unknown")


INTEL_FIELDS = [("Roastable accounts", "ad_asrep_roastable"),
                ("Accounts tested", "ad_asrep_users_tested"),
                ("Pre-auth required (count)", "ad_asrep_preauth_required"),
                ("Unknown usernames (count)", "ad_asrep_unknown_users")]


@router.post("/api/ad/asrep_roast")
async def ad_asrep_roast(req: AsrepRoastRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}
    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)
    return await run_scanner(host=req.target, tool="asrep_roast",
        gather_func=_gather_with_options, finding_rules=AD_ASREP_ROAST_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
