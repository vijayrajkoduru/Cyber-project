"""enum4linux_ng_audit - enum4linux-ng null session enumeration (playbook §1 #5).

Wraps the enum4linux-ng tool (cloned to /opt/enum4linux-ng) to do null-session
SMB/RPC enumeration: users, groups, shares, password policy, OS info. Critical
recon - null session enum should not work on a hardened DC. If it does, attacker
gets user list + group memberships + password policy WITHOUT any credentials.

Customer input: ScanRequest.target = DC IP/hostname. No creds needed.
"""
from __future__ import annotations
import asyncio
import json
import shutil
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.enum4linux_ng_audit_findings import ENUM4LINUX_NG_AUDIT_FINDING_RULES

router = APIRouter()
ENUM4LINUX_BIN = shutil.which("enum4linux-ng") or "/usr/local/bin/enum4linux-ng"
TIMEOUT = 90


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["enum4linux_ng_audit_total"] = 0
        ctx.source("no-target")
        return
    if not shutil.which("enum4linux-ng") and not __import__("os").path.exists(ENUM4LINUX_BIN):
        ctx.state["enum4linux_ng_audit_error"] = "enum4linux-ng binary not found"
        ctx.source("enum4linux-ng missing")
        return

    # Run enum4linux-ng with -A (all) + -oJ (JSON output) to a tempfile
    import tempfile
    import os
    out_path = tempfile.mktemp(suffix=".json")
    try:
        proc = await asyncio.create_subprocess_exec(
            ENUM4LINUX_BIN, "-A", "-oJ", out_path, target,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
        except asyncio.TimeoutError:
            proc.kill()
            ctx.state["enum4linux_ng_audit_error"] = f"timeout after {TIMEOUT}s"
            ctx.source("timeout")
            return
    except Exception as e:
        ctx.state["enum4linux_ng_audit_error"] = f"subprocess: {str(e)[:120]}"
        ctx.source(f"subprocess failed: {str(e)[:80]}")
        return

    # enum4linux-ng writes JSON to <out_path>.json
    actual_path = out_path if os.path.exists(out_path) else out_path + ".json"
    if not os.path.exists(actual_path):
        ctx.state["enum4linux_ng_audit_total"] = 0
        ctx.source("no output file")
        return

    try:
        with open(actual_path) as f:
            data = json.load(f)
    except Exception as e:
        ctx.state["enum4linux_ng_audit_error"] = f"parse: {str(e)[:120]}"
        return
    finally:
        try: os.unlink(actual_path)
        except Exception: pass

    # Summarize the JSON
    findings = []
    users = data.get("users") or {}
    groups = data.get("groups") or {}
    shares = data.get("shares") or {}
    password_policy = data.get("password_policy") or {}
    os_info = data.get("os_info") or {}

    # Null session anything = no creds reqd
    null_session_ok = bool(data.get("sessions", {}).get("null_session_possible"))
    if null_session_ok:
        findings.append({"check": "null_session_possible", "details": "anonymous SMB session accepted"})
    if isinstance(users, dict) and len(users) > 0:
        findings.append({"check": "users_via_null_session", "count": len(users),
                        "sample": list(users.keys())[:8]})
    if isinstance(groups, dict) and len(groups) > 0:
        findings.append({"check": "groups_via_null_session", "count": len(groups),
                        "sample": list(groups.keys())[:8]})
    pwd_summary = {}
    if isinstance(password_policy, dict):
        pwd_summary = {
            "min_length": password_policy.get("Minimum password length"),
            "max_age": password_policy.get("Maximum password age"),
            "lockout_threshold": password_policy.get("Account lockout threshold"),
            "complexity": password_policy.get("Password complexity"),
        }
        if any(v is not None for v in pwd_summary.values()):
            findings.append({"check": "password_policy_leaked", "policy": pwd_summary})

    ctx.state["enum4linux_findings"] = findings
    ctx.state["enum4linux_os_info"] = os_info if isinstance(os_info, dict) else {}
    ctx.state["enum4linux_user_count"] = len(users) if isinstance(users, dict) else 0
    ctx.state["enum4linux_group_count"] = len(groups) if isinstance(groups, dict) else 0
    ctx.state["enum4linux_share_count"] = len(shares) if isinstance(shares, dict) else 0
    ctx.state["enum4linux_password_policy"] = pwd_summary
    ctx.state["enum4linux_ng_audit_total"] = len(findings)
    ctx.source(f"{len(findings)} null-session items, {len(users) if isinstance(users, dict) else 0} users, "
               f"{len(groups) if isinstance(groups, dict) else 0} groups")


INTEL_FIELDS = [("Null-session findings", "enum4linux_findings"),
                ("OS info", "enum4linux_os_info"),
                ("User count", "enum4linux_user_count"),
                ("Group count", "enum4linux_group_count"),
                ("Share count", "enum4linux_share_count"),
                ("Password policy", "enum4linux_password_policy")]


@router.post("/api/ad/enum4linux_ng_audit")
async def ad_enum4linux_ng_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="enum4linux_ng_audit",
        gather_func=gather, finding_rules=ENUM4LINUX_NG_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
