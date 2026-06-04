"""certipy_find - AD CS template enumeration via Certipy (playbook §6 #69).

Wraps Certipy 'find' command to enumerate every certificate template + CA
configuration in the domain, then flags templates vulnerable to ESC1-ESC15
abuse. Most critical 2024+ AD attack surface — AD CS misconfigs are the #1
path from low-priv user to Domain Admin in modern pentests.

Customer input via ScanRequest.options:
  - target = DC IP/hostname (required)
  - options.domain = AD domain name (required for auth queries; if absent,
    falls back to anonymous LDAP enum which works on most CAs)
  - options.username + options.password = optional creds for full enum

Without creds: probes anonymous LDAP for pKIEnrollmentService entries.
With creds: full Certipy find with vulnerability detection.
"""
from __future__ import annotations
import asyncio
import shutil
import json
import tempfile
import os
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.certipy_find_findings import CERTIPY_FIND_FINDING_RULES

router = APIRouter()
CERTIPY_BIN = shutil.which("certipy") or shutil.which("certipy-ad")
TIMEOUT = 90


class CertipyFindRequest(ScanRequest):
    options: Optional[dict] = None


async def _certipy_authenticated(ctx, target, domain, username, password):
    """Run certipy find with creds; returns parsed JSON output or None."""
    out_dir = tempfile.mkdtemp(prefix="certipy_")
    try:
        cmd = [CERTIPY_BIN, "find", "-u", f"{username}@{domain}", "-p", password,
               "-dc-ip", target, "-stdout", "-json", "-output", out_dir + "/find"]
        proc = await asyncio.create_subprocess_exec(*cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            return {"error": f"timeout after {TIMEOUT}s"}
        # certipy writes to out_dir/find_<timestamp>.json — search for it
        for f in os.listdir(out_dir):
            if f.endswith(".json"):
                with open(os.path.join(out_dir, f)) as fh:
                    return json.load(fh)
        # Fallback: parse stdout JSON if -stdout was honored
        if stdout:
            try: return json.loads(stdout.decode("utf-8", errors="ignore"))
            except Exception: pass
        return {"error": "no JSON output"}
    finally:
        try: shutil.rmtree(out_dir, ignore_errors=True)
        except Exception: pass


async def _anonymous_ca_probe(ctx, target):
    """Anonymous LDAP probe for AD CS Enrollment Services."""
    try:
        import ldap3
    except ImportError:
        return {"error": "ldap3 not installed"}
    try:
        server = ldap3.Server(target, port=389, get_info=ldap3.DSA, connect_timeout=8)
        conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS, auto_bind=True,
                                receive_timeout=8)
    except Exception as e:
        return {"error": f"anon LDAP bind failed: {str(e)[:80]}"}
    try:
        config_nc = None
        if server.info and server.info.naming_contexts:
            for nc in server.info.naming_contexts:
                if "configuration" in str(nc).lower():
                    config_nc = str(nc); break
        if not config_nc:
            try: conn.unbind()
            except Exception: pass
            return {"error": "no Configuration naming context (need creds)"}
        # Enrollment services live at CN=Enrollment Services,CN=Public Key Services
        base = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}"
        conn.search(search_base=base, search_filter="(objectClass=pKIEnrollmentService)",
                   search_scope=ldap3.SUBTREE, attributes=["cn", "dNSHostName", "cACertificate"])
        cas = [{"cn": str(e.cn), "dns": str(e.get("dNSHostName") or "")} for e in conn.entries]
        try: conn.unbind()
        except Exception: pass
        return {"cas": cas, "method": "anonymous_ldap"}
    except Exception as e:
        try: conn.unbind()
        except Exception: pass
        return {"error": f"anon CA probe: {str(e)[:80]}"}


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["certipy_find_total"] = 0
        ctx.source("no-target")
        return
    if not CERTIPY_BIN:
        ctx.state["certipy_find_error"] = "certipy binary not installed"
        ctx.source("certipy missing")
        return

    opts = ctx.state.get("_options") or {}
    domain = opts.get("domain") or ""
    username = opts.get("username") or ""
    password = opts.get("password") or ""

    if username and password and domain:
        result = await _certipy_authenticated(ctx, target, domain, username, password)
        ctx.state["certipy_auth_mode"] = "authenticated"
    else:
        result = await _anonymous_ca_probe(ctx, target)
        ctx.state["certipy_auth_mode"] = "anonymous"

    if "error" in result:
        ctx.state["certipy_find_error"] = result["error"]
        ctx.state["certipy_find_total"] = 0
        ctx.source(f"error: {result['error']}")
        return

    findings = []
    cas = result.get("cas") or result.get("Certificate Authorities") or []
    templates = result.get("Certificate Templates") or result.get("templates") or []
    vulnerable_templates = []
    for t in (templates if isinstance(templates, list) else []):
        if not isinstance(t, dict): continue
        vulns = t.get("Vulnerabilities") or t.get("vulnerabilities") or []
        name = t.get("Template Name") or t.get("cn") or "?"
        if vulns:
            vulnerable_templates.append({"template": name, "vulns": vulns if isinstance(vulns, list) else [vulns]})
            findings.append({"check": "vulnerable_template", "name": name,
                           "escs": vulns if isinstance(vulns, list) else [str(vulns)]})

    ctx.state["certipy_cas"] = cas if isinstance(cas, list) else []
    ctx.state["certipy_templates_count"] = len(templates) if isinstance(templates, list) else 0
    ctx.state["certipy_vulnerable_templates"] = vulnerable_templates
    ctx.state["certipy_findings"] = findings
    ctx.state["certipy_find_total"] = len(vulnerable_templates)
    if not vulnerable_templates and cas:
        ctx.state["certipy_ca_inventory_only"] = True
    ctx.source(f"mode={ctx.state['certipy_auth_mode']}; {len(cas) if isinstance(cas, list) else 0} CA(s), "
               f"{len(vulnerable_templates)} vulnerable template(s)")


INTEL_FIELDS = [("Auth mode", "certipy_auth_mode"),
                ("Certificate Authorities", "certipy_cas"),
                ("Template count", "certipy_templates_count"),
                ("Vulnerable templates", "certipy_vulnerable_templates"),
                ("Findings", "certipy_findings")]


@router.post("/api/ad/certipy_find")
async def ad_certipy_find(req: CertipyFindRequest, _=Depends(verify_scan_quota)):
    options = req.options or {}
    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)
    return await run_scanner(host=req.target, tool="certipy_find",
        gather_func=_gather_with_options, finding_rules=CERTIPY_FIND_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
