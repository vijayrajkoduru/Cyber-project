"""ai_endpoint_guesser v3 - VL-FORGE - Claude-assisted, probe-verified endpoint discovery.

Claude proposes candidate paths from the target's real surface; every candidate
is then VERIFIED with a live HTTP probe. Only reachable paths become findings
(zero false positives). A catch-all/SPA guard suppresses probing when a random
path returns 200. Degrades to a clean SKIPPED when ANTHROPIC_API_KEY is unset.
"""
import asyncio
import random
import ssl
import string
import urllib.error
import urllib.request

from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host, web_url
from tools._framework import run_scanner
from tools.recon._llm import ask_claude_list_async, llm_available

router = APIRouter()

_UA = "Mozilla/5.0 (VulnusLab Recon)"
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE

_SENSITIVE = ("/.env", "/.git", "/.aws", "/.ssh", "/.svn", "/config", "/backup",
              "/dump", "/actuator", "/server-status", "/server-info", "/phpinfo",
              "/debug", "/metrics", "/admin", "/wp-admin", "/phpmyadmin", "/swagger",
              "/api-docs", "/.htaccess", "/web.config", "/credentials", "/secret")


def _is_sensitive(p):
    pl = p.lower()
    return any(k in pl for k in _SENSITIVE)


def _probe(url, timeout=6):
    """Return HTTP status code (or None). Follows redirects via default opener."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
            r.read(2048)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


async def gather(ctx):
    host = str(ctx.host)
    ctx.state["llm_configured"] = llm_available()
    if not llm_available():
        ctx.state["skipped_reason"] = (
            "ai_endpoint_guesser: set ANTHROPIC_API_KEY to enable AI-assisted "
            "endpoint discovery (no-op without a key)")
        return

    base = web_url(host).rstrip("/")
    home_status = await asyncio.to_thread(_probe, base + "/")
    ctx.source("http")

    rand = "/" + "".join(random.choice(string.ascii_lowercase) for _ in range(24))
    catchall = (await asyncio.to_thread(_probe, base + rand)) == 200
    ctx.state["spa_catchall"] = catchall

    prompt = (
        f"You are assisting an authorized security recon of the domain '{host}'. "
        f"The site returned HTTP {home_status} on '/'. List up to 30 likely sensitive "
        "or interesting URL PATHS (admin panels, API routes, config/backup files, "
        "debug/monitoring endpoints, framework defaults) that may exist. Return ONLY "
        "a JSON array of path strings each starting with '/'. No prose.")
    candidates = await ask_claude_list_async(prompt, max_tokens=900, cap=30)
    ctx.state["ai_candidates"] = candidates
    ctx.state["ai_candidates_count"] = len(candidates)
    if candidates:
        ctx.source("claude")

    if catchall or not candidates:
        ctx.state["confirmed"] = []
        ctx.state["confirmed_count"] = 0
        return

    confirmed = []
    sem = asyncio.Semaphore(12)

    async def _check(p):
        if not p.startswith("/"):
            p = "/" + p
        async with sem:
            st = await asyncio.to_thread(_probe, base + p)
        if st in (200, 401, 403, 405):
            confirmed.append({"path": p, "status": st})

    await asyncio.gather(*[_check(p) for p in candidates])
    confirmed.sort(key=lambda c: c["path"])
    ctx.state["confirmed"] = confirmed
    ctx.state["confirmed_count"] = len(confirmed)


def _r_catchall(s):
    if not s.get("spa_catchall"):
        return None
    return {"name": "Catch-all server detected (path probing suppressed)", "severity": "INFO",
            "evidence": ("A random nonexistent path returned HTTP 200, so endpoint existence "
                         "cannot be inferred from status codes. AI-suggested candidates are "
                         "listed under intel for manual review."),
            "remediation": "Informational; use authenticated/manual review for SPA route discovery."}


def _r_exposed(s):
    if s.get("spa_catchall"):
        return None
    hits = [c for c in (s.get("confirmed") or []) if _is_sensitive(c["path"]) and c["status"] == 200]
    if not hits:
        return None
    ev = ", ".join(f"{c['path']} (HTTP {c['status']})" for c in hits[:12])
    return {"name": f"Sensitive path exposed ({len(hits)})", "severity": "MEDIUM",
            "evidence": ev, "cwe": "CWE-200",
            "remediation": "Restrict or remove publicly reachable sensitive paths (config/backup/debug/admin)."}


def _r_protected(s):
    if s.get("spa_catchall"):
        return None
    hits = [c for c in (s.get("confirmed") or []) if _is_sensitive(c["path"]) and c["status"] in (401, 403)]
    if not hits:
        return None
    ev = ", ".join(f"{c['path']} (HTTP {c['status']})" for c in hits[:12])
    return {"name": f"Sensitive path present but access-controlled ({len(hits)})", "severity": "INFO",
            "evidence": ev}


def _r_inventory(s):
    if s.get("spa_catchall"):
        return None
    others = [c for c in (s.get("confirmed") or []) if not _is_sensitive(c["path"])]
    if not others:
        return None
    ev = ", ".join(f"{c['path']} (HTTP {c['status']})" for c in others[:20])
    return {"name": f"Live endpoints discovered via AI-assisted probing ({len(others)})", "severity": "INFO",
            "evidence": ev}


def _r_clean(s):
    if not s.get("llm_configured") or s.get("spa_catchall"):
        return None
    if (s.get("confirmed") or []) or not (s.get("ai_candidates") or []):
        return None
    return {"name": "No AI-predicted sensitive endpoints were reachable", "severity": "POSITIVE",
            "evidence": f"Probed {len(s.get('ai_candidates') or [])} AI-suggested paths; none returned a reachable status."}


FINDING_RULES = [_r_catchall, _r_exposed, _r_protected, _r_inventory, _r_clean]
INTEL_FIELDS = [("LLM configured", "llm_configured"), ("AI candidates", "ai_candidates_count"),
                ("Confirmed endpoints", "confirmed_count"), ("Catch-all server", "spa_catchall")]


@router.post("/api/recon/ai_endpoint_guesser")
async def f(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=recon_host(req.target), tool="ai_endpoint_guesser",
                             gather_func=gather, finding_rules=FINDING_RULES,
                             intel_fields=INTEL_FIELDS,
                             flat_field_keys=["confirmed", "ai_candidates"])


def register(app):
    app.include_router(router)
