"""ldap_anon_enum - Anonymous LDAP bind enumeration (playbook §1 #2).

Connects to the DC's LDAP port (389) WITHOUT any credentials and tries
to read the root DSE + base DN entries. A successful anonymous read of
domain naming context is a HIGH finding — modern AD should require
authenticated bind for any meaningful queries.

Customer input (ScanRequest.target = DC IP/hostname). No creds needed.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.ldap_anon_enum_findings import LDAP_ANON_ENUM_FINDING_RULES

router = APIRouter()


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["ldap_anon_enum_total"] = 0
        ctx.source("no-target")
        return
    try:
        import ldap3
        from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError
    except ImportError:
        ctx.state["ldap_anon_enum_error"] = "ldap3 library not installed"
        ctx.source("ldap3 missing")
        return

    findings = []
    try:
        server = ldap3.Server(target, port=389, get_info=ldap3.DSA, connect_timeout=8)
        conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS, auto_bind=True,
                                receive_timeout=8)
    except LDAPSocketOpenError as e:
        ctx.state["ldap_anon_enum_total"] = 0
        ctx.state["ldap_unreachable"] = True
        ctx.source(f"port 389 closed/unreachable: {str(e)[:80]}")
        return
    except LDAPException as e:
        ctx.state["ldap_anon_enum_total"] = 0
        ctx.state["anonymous_bind_rejected"] = True
        ctx.source(f"anonymous bind rejected: {str(e)[:80]}")
        return

    # Anonymous bind succeeded — now try to read meaningful data
    root_dse = {}
    try:
        if server.info:
            root_dse = {
                "naming_contexts": list(server.info.naming_contexts or [])[:5],
                "supported_ldap_versions": list(server.info.supported_ldap_versions or []),
                "supported_controls": len(server.info.supported_controls or []),
                "vendor_name": server.info.vendor_name or "",
                "vendor_version": (server.info.vendor_version or "")[:80],
            }
    except Exception:
        pass
    findings.append({"check": "anonymous_bind_allowed", "succeeded": True})
    if root_dse.get("naming_contexts"):
        findings.append({"check": "root_dse_readable", "ncs": root_dse["naming_contexts"]})

    # Try a base-level search on the first naming context
    try:
        base = root_dse.get("naming_contexts", [""])[0] if root_dse.get("naming_contexts") else ""
        if base:
            conn.search(search_base=base, search_filter="(objectClass=*)",
                       search_scope=ldap3.BASE, attributes=["*"])
            if conn.entries:
                findings.append({"check": "base_dn_anonymous_read",
                               "object_classes": str(conn.entries[0].get("objectClass") or "")[:200]})
    except Exception:
        pass

    try: conn.unbind()
    except Exception: pass

    ctx.state["ldap_anon_findings"] = findings
    ctx.state["root_dse"] = root_dse
    ctx.state["ldap_anon_enum_total"] = len(findings)
    ctx.source(f"{len(findings)} anonymous-readable items")


INTEL_FIELDS = [("Anonymous-readable items", "ldap_anon_findings"),
                ("Root DSE", "root_dse")]


@router.post("/api/ad/ldap_anon_enum")
async def ad_ldap_anon_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="ldap_anon_enum",
        gather_func=gather, finding_rules=LDAP_ANON_ENUM_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
