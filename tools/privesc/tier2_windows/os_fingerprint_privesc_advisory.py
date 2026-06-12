"""os_fingerprint_privesc_advisory - HTTP OS fingerprint + advisory catalogue.

REAL, credential-LESS remote probe. Issues a single HTTP(S) request to the
target and reads the OS-identifying response headers the server volunteers:

  - Server            (e.g. "Microsoft-IIS/10.0", "Apache/2.4.41 (Ubuntu)")
  - X-Powered-By      (e.g. "ASP.NET", "PHP/8.1.2")
  - X-AspNet-Version  (e.g. "4.0.30319")

From those it INFERS the OS family (Windows / Linux / macOS / unknown). The
inferred OS family selects WHICH on-host privesc playbook applies — it is NOT
itself a vulnerability, so this scanner NEVER emits a graded severity.

The §2 (Windows), §3 (macOS), §5 (memory-corruption) and §6 (DLL-hijack)
techniques in module_playbooks/12_privesc.md all require a foothold on the
host or local binary analysis. They cannot be confirmed from an external SaaS
scan, so they are surfaced as honest [ADVISORY-BY-DESIGN] INFO keyed to the
inferred OS family. See tools/_payloads/os_fingerprint_privesc_advisory_findings.py.

This probe reads ONLY response headers. It sends no payloads, does not
authenticate, exploit, or chain into another scanner. On any error it degrades
to a clean INFO via the finding rules.

Customer input via ScanRequest.options:
  - target              = host / IP / URL (ctx.host)
  - options.timeout_sec = HTTP timeout (default 10, clamped 3..20)
  - options.scheme      = force "http" or "https" (default: try https then http)
"""
from __future__ import annotations
import asyncio
import re
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.os_fingerprint_privesc_advisory_findings import (
    OS_FINGERPRINT_PRIVESC_ADVISORY_FINDING_RULES,
)

router = APIRouter()

DEFAULT_TIMEOUT = 10

# Substrings in the Server / X-Powered-By header that imply an OS family.
_WINDOWS_HINTS = ("microsoft-iis", "asp.net", "win32", "win64", "windows")
_MAC_HINTS = ("darwin", "mac os", "macos")
_LINUX_HINTS = (
    "ubuntu", "debian", "centos", "red hat", "redhat", "fedora", "alpine",
    "amazon", "unix", "gentoo", "suse", "linux",
)


class OsFingerprintPrivescAdvisoryRequest(ScanRequest):
    options: Optional[dict] = None


def _normalize_url(target: str, scheme: Optional[str]) -> list[str]:
    """Return an ordered list of candidate URLs to try."""
    t = (target or "").strip()
    if t.startswith("http://") or t.startswith("https://"):
        return [t]
    t = t.rstrip("/")
    if scheme in ("http", "https"):
        return [f"{scheme}://{t}"]
    return [f"https://{t}", f"http://{t}"]


def _fetch_headers(url: str, timeout: float):
    """Blocking GET that returns (status, headers_dict) or raises.
    Call inside run_in_executor. Follows redirects, ignores TLS validation
    so self-signed / internal hosts still fingerprint.
    """
    import requests
    resp = requests.get(
        url,
        timeout=timeout,
        verify=False,
        allow_redirects=True,
        headers={"User-Agent": "VulnusLab/1.0 (privesc-os-fingerprint)"},
    )
    # Lower-case header keys for stable lookup.
    headers = {k.lower(): v for k, v in resp.headers.items()}
    return resp.status_code, headers


def _infer_os_family(server: str, powered_by: str, aspnet: str) -> str:
    blob = f"{server} {powered_by} {aspnet}".lower()
    if any(h in blob for h in _WINDOWS_HINTS):
        return "Windows"
    if any(h in blob for h in _MAC_HINTS):
        return "macOS"
    if any(h in blob for h in _LINUX_HINTS):
        return "Linux"
    return "unknown"


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["osfp_no_target"] = True
        ctx.source("no-target")
        return

    try:
        import requests  # noqa: F401
    except ImportError:
        ctx.state["osfp_error"] = "requests library not installed"
        ctx.source("requests missing")
        return

    # Silence the insecure-request warning (verify=False is intentional for
    # internal / self-signed hosts; we only read headers).
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    opts = ctx.state.get("_options") or {}
    timeout = min(max(float(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 3), 20)
    scheme = (opts.get("scheme") or "").lower() or None
    if scheme not in ("http", "https", None):
        scheme = None

    candidates = _normalize_url(target, scheme)
    loop = asyncio.get_event_loop()

    status = None
    headers = None
    used_url = None
    last_err = None
    for url in candidates:
        try:
            status, headers = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch_headers, url, timeout),
                timeout=timeout + 5,
            )
            used_url = url
            break
        except asyncio.TimeoutError:
            last_err = f"timeout after {timeout}s"
            continue
        except Exception as e:
            last_err = str(e)[:160]
            continue

    ctx.state["osfp_ran"] = True
    ctx.state["osfp_target_url"] = used_url or candidates[0]

    if headers is None:
        ctx.state["osfp_error"] = last_err or "no HTTP response"
        ctx.source(f"no HTTP response: {last_err}")
        return

    ctx.state["osfp_status"] = status
    server = headers.get("server") or ""
    powered_by = headers.get("x-powered-by") or ""
    aspnet = headers.get("x-aspnet-version") or headers.get("x-aspnetmvc-version") or ""

    if server:
        ctx.state["osfp_server"] = server[:160]
    if powered_by:
        ctx.state["osfp_powered_by"] = powered_by[:160]
    if aspnet:
        ctx.state["osfp_aspnet_version"] = aspnet[:80]

    ctx.state["osfp_os_family"] = _infer_os_family(server, powered_by, aspnet)

    ctx.source(
        f"{used_url} -> {status}; Server='{server[:50] or '-'}', "
        f"OS family={ctx.state['osfp_os_family']}"
    )


INTEL_FIELDS = [
    ("Fingerprint URL",       "osfp_target_url"),
    ("HTTP status",           "osfp_status"),
    ("Server header",         "osfp_server"),
    ("X-Powered-By",          "osfp_powered_by"),
    ("ASP.NET version",       "osfp_aspnet_version"),
    ("Inferred OS family",    "osfp_os_family"),
]


@router.post("/api/privesc/os_fingerprint_privesc_advisory")
async def privesc_os_fingerprint_privesc_advisory(
        req: OsFingerprintPrivescAdvisoryRequest,
        _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="os_fingerprint_privesc_advisory",
        gather_func=_gather_with_options,
        finding_rules=OS_FINGERPRINT_PRIVESC_ADVISORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
