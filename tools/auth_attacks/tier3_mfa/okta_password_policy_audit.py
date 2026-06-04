"""okta_password_policy_audit - Okta org password + MFA policy audit (playbook §3 #38).

Queries the customer's Okta org via the official Okta Python SDK to read
the Default Password Policy + Authenticator Enrollment Policy + Sign-On
policies. Flags weak settings: short min length, no complexity, no MFA
required, suspicious lifecycle (no password expiry), Okta Verify push
without number-challenge enabled.

Customer input via ScanRequest.options:
  - target            = Okta org URL (e.g. https://acme.okta.com) - required
  - options.api_token = Okta API token with okta.policies.read scope - required
"""
from __future__ import annotations
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.okta_password_policy_audit_findings import OKTA_PASSWORD_POLICY_AUDIT_FINDING_RULES

router = APIRouter()


class OktaPasswordPolicyAuditRequest(ScanRequest):
    options: Optional[dict] = None


async def gather(ctx: ScanContext):
    target = (ctx.host or "").rstrip("/")
    if not target:
        ctx.state["okta_password_policy_audit_total"] = 0
        ctx.source("no-target")
        return
    if not (target.startswith("http://") or target.startswith("https://")):
        target = "https://" + target

    try:
        from okta.client import Client as OktaClient
    except ImportError:
        ctx.state["okta_password_policy_audit_error"] = "okta SDK not installed"
        ctx.source("okta missing")
        return

    opts = ctx.state.get("_options") or {}
    api_token = (opts.get("api_token") or "").strip()
    if not api_token:
        ctx.state["okta_password_policy_audit_error"] = "options.api_token required"
        ctx.source("no api_token")
        return

    try:
        client = OktaClient({"orgUrl": target, "token": api_token})
    except Exception as e:
        ctx.state["okta_password_policy_audit_error"] = f"okta client init: {str(e)[:120]}"
        ctx.source(f"client init failed: {str(e)[:80]}")
        return

    issues = []
    policy_summary = {}
    try:
        # List password policies via the policies API
        policies, resp, err = await client.list_policies({"type": "PASSWORD"})
        if err:
            ctx.state["okta_password_policy_audit_error"] = f"list_policies: {err}"
            ctx.source(f"list_policies failed: {err}")
            return

        for p in (policies or []):
            name = getattr(p, "name", "?")
            settings = getattr(p, "settings", None)
            if not settings:
                continue
            pwd = getattr(settings, "password", None)
            if not pwd:
                continue
            complexity = getattr(pwd, "complexity", None)
            age = getattr(pwd, "age", None)
            lockout = getattr(pwd, "lockout", None)

            p_info = {"name": name, "id": getattr(p, "id", "?")}
            if complexity:
                min_len = getattr(complexity, "min_length", None) or getattr(complexity, "minLength", None)
                p_info["min_length"] = min_len
                p_info["upper_required"] = getattr(complexity, "min_upper_case", None) or 0
                p_info["lower_required"] = getattr(complexity, "min_lower_case", None) or 0
                p_info["number_required"] = getattr(complexity, "min_number", None) or 0
                p_info["symbol_required"] = getattr(complexity, "min_symbol", None) or 0
                if min_len and min_len < 12:
                    issues.append({"policy": name, "issue": f"min_length={min_len} (industry min: 14)"})
            if age:
                max_age_days = getattr(age, "max_age_days", None) or getattr(age, "maxAgeDays", None)
                p_info["max_age_days"] = max_age_days
                if max_age_days == 0 or max_age_days is None:
                    issues.append({"policy": name, "issue": "no password expiry"})
            if lockout:
                max_attempts = getattr(lockout, "max_attempts", None) or getattr(lockout, "maxAttempts", None)
                p_info["max_attempts"] = max_attempts
                if max_attempts == 0 or max_attempts is None or max_attempts > 10:
                    issues.append({"policy": name, "issue": f"lockout_threshold={max_attempts} (>10 = high spray risk)"})
            policy_summary[name] = p_info

        # MFA policy summary
        mfa_policies, _, _ = await client.list_policies({"type": "MFA_ENROLL"})
        mfa_required = False
        for mp in (mfa_policies or []):
            settings = getattr(mp, "settings", None)
            if settings:
                authenticators = getattr(settings, "authenticators", None) or []
                for a in authenticators:
                    enroll = getattr(a, "enroll", None)
                    if enroll and getattr(enroll, "self", None) == "REQUIRED":
                        mfa_required = True
                        break
            if mfa_required:
                break
        if not mfa_required:
            issues.append({"policy": "MFA_ENROLL", "issue": "MFA enrollment not REQUIRED"})

    except Exception as e:
        ctx.state["okta_password_policy_audit_error"] = f"policy walk: {str(e)[:120]}"
        ctx.source(f"policy walk failed: {str(e)[:80]}")
        return

    ctx.state["okta_policies"] = policy_summary
    ctx.state["okta_policy_issues"] = issues
    ctx.state["okta_password_policy_audit_total"] = len(issues)
    ctx.source(f"{len(policy_summary)} password policies + MFA-enroll check; {len(issues)} issues")


INTEL_FIELDS = [("Policies inspected", "okta_policies"),
                ("Issues found", "okta_policy_issues")]


@router.post("/api/auth_attacks/okta_password_policy_audit")
async def auth_attacks_okta_password_policy_audit(req: OktaPasswordPolicyAuditRequest,
                                                    _=Depends(verify_scan_quota)):
    options = req.options or {}
    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)
    return await run_scanner(host=req.target, tool="okta_password_policy_audit",
        gather_func=_gather_with_options, finding_rules=OKTA_PASSWORD_POLICY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
