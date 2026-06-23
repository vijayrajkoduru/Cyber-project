"""smb_signing_check - SMB signing not required (playbook §1 #13).

Probes target's SMB port (445) using impacket SMBConnection and reads the
negotiate response to check if signing is required. SMB signing NOT required
on a DC is a HIGH finding — enables NTLM relay attacks (PetitPotam, DFSCoerce,
ntlmrelayx chains).

Customer input (ScanRequest.target = DC IP). No creds needed.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.smb_signing_check_findings import SMB_SIGNING_CHECK_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["smb_signing_check_total"] = 0
        ctx.source("no-target")
        return
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        ctx.state["smb_signing_check_error"] = "impacket not installed"
        ctx.source("impacket missing")
        return

    result = {}
    try:
        # Try port 445 first (preferred)
        conn = SMBConnection(target, target, sess_port=445, timeout=8)
    except Exception as e:
        try:
            conn = SMBConnection(target, target, sess_port=139, timeout=8)
        except Exception as e2:
            ctx.state["smb_signing_check_total"] = 0
            ctx.state["smb_unreachable"] = True
            ctx.source(f"445+139 closed: {str(e2)[:80]}")
            return

    try:
        # The flag is set during negotiate (no auth needed)
        signing_required = bool(conn.isSigningRequired())
        server_os = conn.getServerOS() or "unknown"
        server_domain = conn.getServerDomain() or ""
        server_name = conn.getServerName() or ""
        result = {
            "signing_required": signing_required,
            "server_os": server_os[:120],
            "server_domain": server_domain,
            "server_name": server_name,
            "dialect": str(conn.getDialect()) if hasattr(conn, "getDialect") else "",
        }
    except Exception as e:
        ctx.state["smb_signing_check_error"] = f"negotiate failed: {str(e)[:120]}"
    finally:
        try: conn.close()
        except Exception: pass

    findings = []
    # Only the "signing NOT required" case is a finding. "Signing required" is
    # the POSITIVE/hardened case and is surfaced by rule_positive from
    # smb_server_info.signing_required - emitting it here too would double-report
    # the same fact (once as a finding row, once as a POSITIVE).
    if "signing_required" in result and result["signing_required"] is False:
        findings.append({"check": "smb_signing_not_required", "server": result.get("server_name", "")})

    ctx.state["smb_signing_findings"] = findings
    ctx.state["smb_server_info"] = result
    ctx.state["smb_signing_check_total"] = sum(1 for f in findings if f["check"] == "smb_signing_not_required")
    ctx.source(f"SMB negotiate OK; signing_required={result.get('signing_required')}")


INTEL_FIELDS = [("SMB server info", "smb_server_info"),
                ("Signing findings", "smb_signing_findings")]


@router.post("/api/ad/smb_signing_check")
async def ad_smb_signing_check(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="smb_signing_check",
        gather_func=gather, finding_rules=SMB_SIGNING_CHECK_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
