"""GitHub Leaks v1 — VL-FORGE pattern.

Route: /api/recon/github_leaks

Searches GitHub's public code index for the target domain + common secret
patterns. Unauthenticated calls have rate limits but work for spot recon.

Sources (parallel):
  1. GitHub Search API — repos referencing domain
  2. GitHub Code Search — secret-pattern matches mentioning domain
  3. GitHub Org metadata (if domain looks like a company name)
"""
import asyncio
import re
from urllib.parse import quote

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier6_findings import GITHUB_LEAKS_FINDING_RULES

router = APIRouter()


_SECRET_PATTERNS = [
    ("AWS access key",       r"AKIA[0-9A-Z]{16}"),
    ("Google API key",       r"AIza[0-9A-Za-z\-_]{35}"),
    ("GitHub PAT (ghp)",     r"ghp_[a-zA-Z0-9]{30,}"),
    ("Slack token",          r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}"),
    ("Stripe secret key",    r"sk_live_[0-9a-zA-Z]{24}"),
    ("OpenAI / SK token",    r"sk-[a-zA-Z0-9]{20,}"),
    ("Private RSA key",      r"-----BEGIN RSA PRIVATE KEY-----"),
    ("Generic password=",    r"password\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"),
]


def _gh_get(url, params=None):
    """GitHub unauthenticated GET. Rate-limited to 10 req/min for code search."""
    try:
        r = requests.get(url, params=params or {}, timeout=8,
                          headers={"User-Agent": "VulnusLab/1.0",
                                    "Accept": "application/vnd.github.v3+json"})
        if r.status_code == 200:
            return r.json()
        return None
    except Exception:
        return None


def _search_repos_mentioning(domain):
    """Find repos with domain in description/readme/code."""
    domain_short = domain.split(".")[0]  # company name guess
    data = _gh_get("https://api.github.com/search/repositories",
                    params={"q": f"{domain} OR {domain_short}", "per_page": 30})
    if not data: return []
    repos = []
    for r in (data.get("items") or [])[:30]:
        repos.append({
            "full_name":   r.get("full_name", "?"),
            "description": (r.get("description") or "")[:140],
            "stars":       r.get("stargazers_count", 0),
            "url":         r.get("html_url", ""),
        })
    return repos


def _search_org(domain):
    """Try to find a GitHub org matching the domain's company name."""
    org_name = domain.split(".")[0]
    data = _gh_get(f"https://api.github.com/orgs/{org_name}")
    if not data or data.get("message"): return None
    return {
        "org_name":    org_name,
        "public_repos": data.get("public_repos", 0),
        "members":     data.get("followers", 0),
        "description": (data.get("description") or "")[:140],
    }


def _search_secrets(domain):
    """Run targeted code search for secret patterns mentioning domain.
    Without auth, GitHub limits us to 10 req/min — pick the top 3 patterns
    most likely to yield real leaks (AWS, GitHub PAT, generic password).
    """
    hits = []
    top_patterns = [
        ("AWS access key", "AKIA"),
        ("Google API key", "AIza"),
        ("Generic .env",   ".env"),
    ]
    for kind, needle in top_patterns:
        data = _gh_get("https://api.github.com/search/code",
                        params={"q": f"{needle} {domain}", "per_page": 10})
        if not data: continue
        for item in (data.get("items") or [])[:10]:
            hits.append({
                "kind":     kind,
                "repo":     (item.get("repository") or {}).get("full_name", "?"),
                "path":     item.get("path", "?"),
                "url":      item.get("html_url", ""),
            })
            if len(hits) >= 20: break
        if len(hits) >= 20: break
    return hits


async def gather(ctx: ScanContext):
    host = ctx.host
    ctx.state["api_reachable"] = True

    repos_task   = asyncio.to_thread(_search_repos_mentioning, host)
    org_task     = asyncio.to_thread(_search_org, host)
    secrets_task = asyncio.to_thread(_search_secrets, host)
    repos, org, secrets = await asyncio.gather(repos_task, org_task, secrets_task)

    ctx.state["matched_repos"] = repos
    ctx.state["secret_hits"]   = secrets
    if org:
        ctx.state["org_found"]        = True
        ctx.state["org_name"]         = org.get("org_name")
        ctx.state["public_repo_count"] = org.get("public_repos", 0)
        ctx.state["member_count"]     = org.get("members", 0)

    ctx.source("github-search-repos")
    ctx.source("github-search-secrets")
    if org: ctx.source("github-org-metadata")


INTEL_FIELDS = [
    ("GitHub org",            "github_org_display"),
    ("Matched repos",          "repos_display"),
    ("Possible secrets",       "secrets_display"),
    ("Top matches",            "top_matches_display"),
]


@router.post("/api/recon/github_leaks")
async def recon_github_leaks(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        if ctx.state.get("org_found"):
            ctx.state["github_org_display"] = (
                f"{ctx.state.get('org_name')} ({ctx.state.get('public_repo_count',0)} public repos)")
        r = ctx.state.get("matched_repos") or []
        if r: ctx.state["repos_display"] = f"{len(r)} repo(s) mention domain"
        s = ctx.state.get("secret_hits") or []
        if s: ctx.state["secrets_display"] = (
            f"{len(s)} secret-pattern hit(s): " +
            ", ".join(set(x.get("kind","?") for x in s[:5])))
        top = (r or [])[:5]
        if top: ctx.state["top_matches_display"] = ", ".join(
            f"{t.get('full_name','?')} ({t.get('stars',0)}★)" for t in top)

    return await run_scanner(
        host=host, tool="github_leaks",
        gather_func=gather_with_display,
        finding_rules=GITHUB_LEAKS_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["matched_repos", "secret_hits", "org_name"],
    )


def register(app):
    app.include_router(router)
