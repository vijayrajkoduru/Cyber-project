"""smb_os_fingerprint - SMB OS/dialect fingerprint + SMBv1 detection (playbook §1 #13).

Pure-impacket probe of the target's SMB service (445, fallback 139). Reads the
negotiate response WITHOUT credentials to grab:
  - server OS banner / build string
  - negotiated dialect (and whether legacy SMBv1 is offered)
  - server NetBIOS name + domain

ZERO-FP: SMBv1 HIGH is emitted ONLY when an SMBv1 negotiate actually succeeds
on the live target. Everything else (OS build -> CVE exposure) is INFO advisory,
because remote patch-level confirmation requires host/credentialed scanning.

Customer input: ScanRequest.target = DC IP/hostname. No creds needed.
VA-not-PT: detection only — no EternalBlue trigger, no exploitation.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ad_smb_os_fingerprint_findings import AD_SMB_OS_FINGERPRINT_FINDING_RULES

router = APIRouter()


def _probe_smbv1(target: str) -> bool:
    """Try a dedicated SMBv1-preferred negotiate. Returns True ONLY if the
    target actually completed an SMBv1 (NT LM 0.12) negotiation. Any error
    -> False (never a false positive). Detection only — no tree connect."""
    try:
        from impacket.smbconnection import SMBConnection, SMB_DIALECT
    except Exception:
        return False
    for port in (445, 139):
        conn = None
        try:
            conn = SMBConnection(target, target, sess_port=port,
                                 preferredDialect=SMB_DIALECT, timeout=6)
            # If this returned without raising, the server spoke SMBv1.
            dialect = conn.getDialect() if hasattr(conn, "getDialect") else None
            try: conn.close()
            except Exception: pass
            return dialect == SMB_DIALECT
        except Exception:
            try:
                if conn: conn.close()
            except Exception:
                pass
            continue
    return False


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.state["ad_smb_os_fingerprint_total"] = 0
        ctx.source("no-target")
        return
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        ctx.state["ad_smb_os_fingerprint_error"] = "impacket not installed"
        ctx.source("impacket missing")
        return

    conn = None
    try:
        conn = SMBConnection(target, target, sess_port=445, timeout=8)
    except Exception:
        try:
            conn = SMBConnection(target, target, sess_port=139, timeout=8)
        except Exception as e2:
            ctx.state["ad_smb_os_fingerprint_total"] = 0
            ctx.state["ad_smb_unreachable"] = True
            ctx.source(f"445+139 closed: {str(e2)[:80]}")
            return

    info = {}
    try:
        info = {
            "server_os": (conn.getServerOS() or "unknown")[:160],
            "server_name": conn.getServerName() or "",
            "server_domain": conn.getServerDomain() or "",
            "dialect": str(conn.getDialect()) if hasattr(conn, "getDialect") else "",
            "signing_required": bool(conn.isSigningRequired()),
        }
    except Exception as e:
        ctx.state["ad_smb_os_fingerprint_error"] = f"negotiate read failed: {str(e)[:120]}"
    finally:
        try: conn.close()
        except Exception: pass

    # Separate, explicit SMBv1-preferred negotiate (only this proves SMBv1 ON).
    smbv1 = _probe_smbv1(target)

    ctx.state["ad_smb_os_info"] = info
    ctx.state["ad_smbv1_enabled"] = bool(smbv1)
    # "total" counts only graded conditions actually detected.
    ctx.state["ad_smb_os_fingerprint_total"] = 1 if smbv1 else 0
    ctx.source(f"SMB negotiate OK; dialect={info.get('dialect')}; smbv1={smbv1}")


INTEL_FIELDS = [("SMB server info", "ad_smb_os_info"),
                ("SMBv1 offered", "ad_smbv1_enabled")]


@router.post("/api/ad/smb_os_fingerprint")
async def ad_smb_os_fingerprint(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="smb_os_fingerprint",
        gather_func=gather, finding_rules=AD_SMB_OS_FINGERPRINT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
