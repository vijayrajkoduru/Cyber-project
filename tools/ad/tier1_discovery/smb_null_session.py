"""smb_null_session - null-session SMB/RPC detection (playbook §1 #6).

Pure-impacket probe: attempts an anonymous (null) SMB login (empty username +
empty password) against the target. If the login is accepted, anonymous RPC/SMB
enumeration is possible without any credentials. If shares can additionally be
listed over that null session, they are recorded.

This is the credential-less equivalent of `rpcclient -U "" -N` / null session
enumeration. Detection only (VA-not-PT): we list share NAMES but never read,
write, or download share contents.

ZERO-FP: the null-session HIGH fires only when the anonymous login actually
succeeds on the live target; the shares finding fires only when shares are
actually returned. Unreachable / refused -> POSITIVE or clean INFO.

Customer input: ScanRequest.target = host IP/hostname. No creds needed.
"""
from __future__ import annotations
import asyncio
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ad_smb_null_session_findings import AD_SMB_NULL_SESSION_FINDING_RULES

router = APIRouter()


def _null_session(target: str):
    """Returns (allowed: bool, shares: list[str], err: str|None).
    Never raises. Detection only — login + read-only share LIST."""
    try:
        from impacket.smbconnection import SMBConnection
    except Exception:
        return (False, [], "impacket not installed")

    conn = None
    for port in (445, 139):
        try:
            conn = SMBConnection(target, target, sess_port=port, timeout=8)
            break
        except Exception:
            conn = None
            continue
    if conn is None:
        return (None, [], "unreachable")

    allowed = False
    shares: list[str] = []
    try:
        # Anonymous / null login: empty user + empty password.
        conn.login("", "")
        allowed = True
        try:
            for sh in conn.listShares():
                try:
                    name = sh["shi1_netname"][:-1] if isinstance(sh.get("shi1_netname"), (bytes, bytearray)) \
                        else str(sh["shi1_netname"]).rstrip("\x00")
                except Exception:
                    name = str(sh.get("shi1_netname", "")).rstrip("\x00")
                if name:
                    shares.append(name)
        except Exception:
            pass
    except Exception:
        allowed = False
    finally:
        try: conn.logoff()
        except Exception: pass
        try: conn.close()
        except Exception: pass
    return (allowed, shares, None)


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["ad_smb_null_session_total"] = 0
        ctx.source("no-target")
        return
    try:
        from impacket.smbconnection import SMBConnection  # noqa: F401
    except Exception:
        ctx.state["ad_nullsess_error"] = "impacket not installed"
        ctx.source("impacket missing")
        return

    loop = asyncio.get_event_loop()
    try:
        allowed, shares, err = await asyncio.wait_for(
            loop.run_in_executor(None, _null_session, target), timeout=30)
    except asyncio.TimeoutError:
        ctx.state["ad_nullsess_unreachable"] = True
        ctx.state["ad_smb_null_session_total"] = 0
        ctx.source("timeout")
        return

    if err == "impacket not installed":
        ctx.state["ad_nullsess_error"] = err
        ctx.source("impacket missing")
        return
    if allowed is None or err == "unreachable":
        ctx.state["ad_nullsess_unreachable"] = True
        ctx.state["ad_smb_null_session_total"] = 0
        ctx.source("445+139 unreachable")
        return

    ctx.state["ad_nullsess_probed"] = True
    ctx.state["ad_nullsess_allowed"] = bool(allowed)
    ctx.state["ad_nullsess_shares"] = shares
    # total = graded conditions actually detected.
    ctx.state["ad_smb_null_session_total"] = (1 if allowed else 0) + (1 if shares else 0)
    ctx.source(f"null login allowed={allowed}; shares={len(shares)}")


INTEL_FIELDS = [("Null session allowed", "ad_nullsess_allowed"),
                ("Shares (null session)", "ad_nullsess_shares")]


@router.post("/api/ad/smb_null_session")
async def ad_smb_null_session(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="smb_null_session",
        gather_func=gather, finding_rules=AD_SMB_NULL_SESSION_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
