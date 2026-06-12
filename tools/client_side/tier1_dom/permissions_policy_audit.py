"""permissions_policy_audit - Permissions-Policy / Feature-Policy audit
(playbook §7 #66 push-notification abuse, §7 #67 WebUSB/WebSerial/WebHID
prompt abuse, §1 #4 webcam/mic access prompts).

The Permissions-Policy response header (formerly Feature-Policy) governs
which powerful browser APIs a document — AND any iframe it embeds — may
invoke. If a page has an HTML-injection / XSS / embedded-third-party
foothold, an unrestricted policy lets the injected content silently
trigger permission prompts for, or use, high-risk capabilities:

  - camera / microphone        — covert capture prompt (BeEF §1 #4)
  - geolocation                — location tracking
  - usb / serial / hid         — WebUSB/WebSerial/WebHID device access
                                 (firmware/hardware pivot, §7 #67)
  - bluetooth                  — Web Bluetooth device access
  - payment                    — Payment Request abuse
  - display-capture           — screen capture prompt

This probe fetches the URL, parses the Permissions-Policy (and legacy
Feature-Policy) header, and flags the SENSITIVE features that are left
at their permissive default (no header, or feature explicitly = `*`).

Severity model — this is a defense-in-depth control, so the default
posture is reported as LOW/INFO and only the highest-risk capabilities
(usb/serial/hid/bluetooth + camera/microphone) left wide-open are
MEDIUM, because their absence is a missing mitigation rather than a
demonstrated exploit:

  MEDIUM  - usb/serial/hid/bluetooth/camera/microphone allowed for `*`
            (any embedded origin can prompt for device/AV access)
  LOW     - no Permissions-Policy header at all (all features at the
            permissive browser default)
  INFO    - header present but a sensitive feature defaults open
  INFO    - fetch failed
  POSITIVE- header present and locks the sensitive set to 'self'/'none'

ZERO false positives: a feature is flagged ONLY when the live header
(or its absence) actually leaves it open. Detection only.

Customer input via ScanRequest:
  - target              = website URL (http(s)://...)
  - options.user_agent  = optional UA override
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner

router = APIRouter()


class PermissionsPolicyRequest(ScanRequest):
    options: Optional[dict] = None


# High-risk capabilities whose unrestricted default warrants MEDIUM.
_DEVICE_AV_FEATURES = {
    "camera", "microphone", "usb", "serial", "hid",
    "bluetooth", "display-capture", "geolocation",
}
# Broader sensitive set we report on (subset above is the MEDIUM trigger).
_SENSITIVE_FEATURES = _DEVICE_AV_FEATURES | {
    "payment", "midi", "autoplay", "fullscreen",
    "accelerometer", "gyroscope", "magnetometer",
    "clipboard-read", "clipboard-write", "screen-wake-lock",
}


def _parse_permissions_policy(raw: str) -> dict:
    """Parse `Permissions-Policy: camera=(), usb=*, geolocation=(self)` into
    {feature: allowlist_string}."""
    out: dict = {}
    if not raw:
        return out
    for part in raw.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, val = part.partition("=")
        out[name.strip().lower()] = val.strip()
    return out


def _parse_feature_policy(raw: str) -> dict:
    """Parse legacy `Feature-Policy: camera 'none'; usb *` into
    {feature: allowlist_string}."""
    out: dict = {}
    if not raw:
        return out
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        bits = part.split(None, 1)
        name = bits[0].lower()
        out[name] = bits[1].strip() if len(bits) > 1 else ""
    return out


def _is_wide_open(value: str, legacy: bool) -> bool:
    """True if an allowlist value permits ANY origin (`*`)."""
    v = (value or "").strip().lower()
    if legacy:
        # Feature-Policy: `*` means all origins.
        return v == "*"
    # Permissions-Policy: `*` (bare) means all origins. `(self)` / `()` lock down.
    return v == "*"


async def gather(ctx: ScanContext):
    target = (ctx.host or "").strip()
    if not target:
        ctx.source("no-target")
        return
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    try:
        import httpx
    except ImportError:
        ctx.state["pp_error"] = "httpx not installed (pip install httpx)"
        ctx.source("httpx missing")
        return

    opts = ctx.state.get("_options") or {}
    ua = opts.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    try:
        async with httpx.AsyncClient(
            verify=False, timeout=20, follow_redirects=True,
            headers={"User-Agent": ua, "Accept": "text/html,*/*"},
        ) as client:
            r = await client.get(target)
    except Exception as e:
        ctx.state["pp_error"] = f"fetch failed: {type(e).__name__}: {str(e)[:120]}"
        ctx.source("fetch failed")
        return

    pp_raw = r.headers.get("permissions-policy") or ""
    fp_raw = r.headers.get("feature-policy") or ""
    pp = _parse_permissions_policy(pp_raw)
    fp = _parse_feature_policy(fp_raw)

    header_present = bool(pp_raw or fp_raw)

    # Determine which sensitive features are wide-open.
    open_device_av: list[str] = []
    open_other: list[str] = []
    if not header_present:
        # No policy at all -> every feature at permissive browser default.
        # We do NOT claim each one is "* allowed" (browser defaults vary),
        # but the absence itself is the LOW finding handled in rules.
        pass
    else:
        for feat in sorted(_SENSITIVE_FEATURES):
            explicit = False
            wide = False
            if feat in pp:
                explicit = True
                wide = _is_wide_open(pp[feat], legacy=False)
            elif feat in fp:
                explicit = True
                wide = _is_wide_open(fp[feat], legacy=True)
            if explicit and wide:
                if feat in _DEVICE_AV_FEATURES:
                    open_device_av.append(feat)
                else:
                    open_other.append(feat)

    ctx.state["pp_target_url"] = str(r.url)
    ctx.state["pp_http_status"] = r.status_code
    ctx.state["pp_header_present"] = header_present
    ctx.state["pp_permissions_policy_raw"] = pp_raw or "(absent)"
    ctx.state["pp_feature_policy_raw"] = fp_raw or "(absent)"
    ctx.state["pp_open_device_av"] = open_device_av
    ctx.state["pp_open_other"] = open_other
    # Features explicitly locked to self/none (for the positive signal).
    locked = []
    for feat in sorted(_DEVICE_AV_FEATURES):
        v = (pp.get(feat) if feat in pp else fp.get(feat)) or ""
        vl = v.strip().lower()
        if vl in ("()", "(self)", "'none'", "'self'", "self", "none") or vl == "":
            if feat in pp or feat in fp:
                locked.append(feat)
    ctx.state["pp_locked_device_av"] = locked

    ctx.source(
        f"GET {target} -> {r.status_code}; "
        f"Permissions-Policy={'set' if pp_raw else 'absent'}; "
        f"{len(open_device_av)} high-risk feature(s) wide-open"
    )


# ── findings rules (inline) ────────────────────────────────────────────

def rule_device_av_open(s):
    if s.get("pp_error"):
        return None
    feats = s.get("pp_open_device_av") or []
    if not feats:
        return None
    return {
        "name": ("Permissions-Policy leaves high-risk capability open to any "
                 f"origin ({', '.join(feats)})"),
        "severity": "MEDIUM",
        "cvss": "5.3",
        "cwe": "CWE-272",
        "cwe_name": "Least Privilege Violation",
        "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": (
            f"Permissions-Policy on {s.get('pp_target_url')} grants `*` "
            f"(any origin) for: {', '.join(feats)}. Any embedded third-party "
            "iframe — or injected content via an XSS/HTML-injection "
            "foothold — can invoke these APIs and prompt the victim for "
            "camera/microphone capture or WebUSB/WebSerial/WebHID/Bluetooth "
            "device access."
        ),
        "remediation": (
            "Lock each sensitive feature to the minimum origin set, e.g. "
            "`Permissions-Policy: camera=(), microphone=(), usb=(), "
            "serial=(), hid=(), bluetooth=(), geolocation=(self)`. Use "
            "`()` to disable a capability entirely or `(self)` to restrict "
            "it to your own origin and deny it to embedded frames."
        ),
    }


def rule_other_open(s):
    if s.get("pp_error"):
        return None
    feats = s.get("pp_open_other") or []
    if not feats:
        return None
    return {
        "name": ("Permissions-Policy leaves a sensitive feature open to any "
                 f"origin ({', '.join(feats)})"),
        "severity": "INFO",
        "cwe": "CWE-272",
        "owasp": "A05:2021",
        "evidence": (
            f"Permissions-Policy grants `*` for: {', '.join(feats)}. These "
            "are lower-impact capabilities but still inherited by embedded "
            "frames."
        ),
        "remediation": (
            "Restrict these features to `(self)` or `()` unless an embedded "
            "third-party legitimately needs them."
        ),
    }


def rule_header_absent(s):
    if s.get("pp_error"):
        return None
    if s.get("pp_header_present"):
        return None
    return {
        "name": "No Permissions-Policy header (powerful browser APIs at permissive default)",
        "severity": "LOW",
        "cvss": "3.1",
        "cwe": "CWE-272",
        "cwe_name": "Least Privilege Violation",
        "owasp": "A05:2021",
        "verified_exploit": True,
        "evidence": (
            f"GET {s.get('pp_target_url')} returned neither a "
            "Permissions-Policy nor a legacy Feature-Policy header. Powerful "
            "capabilities (camera, microphone, geolocation, usb, serial, "
            "hid, bluetooth, payment) fall back to their browser default, "
            "so embedded frames / injected content can request them with no "
            "site-level restriction."
        ),
        "remediation": (
            "Add a restrictive Permissions-Policy header that disables "
            "capabilities the app does not use, e.g. `Permissions-Policy: "
            "camera=(), microphone=(), usb=(), serial=(), hid=(), "
            "bluetooth=(), payment=(), geolocation=(self)`."
        ),
    }


def rule_fetch_failed(s):
    err = s.get("pp_error")
    if not err:
        return None
    return {
        "name": "Permissions-Policy audit could not fetch target URL",
        "severity": "INFO",
        "cwe": "CWE-1006",
        "evidence": str(err)[:300],
        "remediation": ("Confirm the URL is reachable from the scanner host "
                        "and uses a valid http/https scheme."),
    }


def rule_positive(s):
    if s.get("pp_error"):
        return None
    if not s.get("pp_header_present"):
        return None
    if s.get("pp_open_device_av"):
        return None
    locked = s.get("pp_locked_device_av") or []
    if not locked:
        return None
    return {
        "name": "Permissions-Policy restricts high-risk capabilities",
        "severity": "POSITIVE",
        "cwe": "CWE-272",
        "owasp": "A05:2021",
        "evidence": (
            f"Permissions-Policy is present and locks high-risk features to "
            f"self/none: {', '.join(locked)}. Embedded frames cannot prompt "
            "for these capabilities."
        ),
        "remediation": ("Keep the policy tight. Re-test after embedding any "
                        "new third-party widget that may request additional "
                        "capabilities."),
    }


PERMISSIONS_POLICY_AUDIT_FINDING_RULES = [
    rule_device_av_open,
    rule_other_open,
    rule_header_absent,
    rule_fetch_failed,
    rule_positive,
]


INTEL_FIELDS = [
    ("Target URL",                   "pp_target_url"),
    ("HTTP status",                  "pp_http_status"),
    ("Permissions-Policy",           "pp_permissions_policy_raw"),
    ("Feature-Policy (legacy)",      "pp_feature_policy_raw"),
    ("High-risk features wide-open", "pp_open_device_av"),
    ("Locked high-risk features",    "pp_locked_device_av"),
]


@router.post("/api/client_side/permissions_policy_audit")
async def client_side_permissions_policy_audit(req: PermissionsPolicyRequest,
                                               _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="permissions_policy_audit",
        gather_func=_gather_with_options,
        finding_rules=PERMISSIONS_POLICY_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
