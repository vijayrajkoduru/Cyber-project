"""Git Repo Exposure v2 — VL-FORGE pattern.

Route: /api/recon/git_recon

Conservative: DETECTS exposure + reads .git/config + .git/HEAD metadata.
Does NOT attempt full repository reconstruction (avoids overload + scope creep).

Sources (parallel):
  1. .git/* path probes (HEAD, config, index, logs/HEAD, refs)
  2. .svn/* path probes
  3. .hg/, .bzr/ alt VCS probes
  4. .git/config parsing — extract remote URL if accessible
"""
import asyncio
import re

import requests

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.tier5_findings import GIT_RECON_FINDING_RULES

router = APIRouter()


_GIT_PATHS = [
    ".git/HEAD", ".git/config", ".git/index",
    ".git/logs/HEAD", ".git/packed-refs",
    ".git/refs/heads/main", ".git/refs/heads/master",
    ".git/description", ".git/info/exclude",
]

_SVN_PATHS = [
    ".svn/entries", ".svn/wc.db", ".svn/format",
]

_OTHER_VCS_PATHS = [
    ".hg/hgrc", ".hg/store/00manifest.i",
    ".bzr/README", ".bzr/branch/conf",
]


def _probe(url):
    try:
        r = requests.get(url, timeout=6, verify=False, allow_redirects=False,
                          headers={"User-Agent": "VulnusLab/1.0"})
        if r.status_code == 200 and len(r.content) > 0:
            return {"status": 200, "length": len(r.content),
                    "text_preview": (r.text or "")[:500]}
    except Exception:
        pass
    return None


def _validate_git_head(text):
    """A real .git/HEAD looks like: ref: refs/heads/main"""
    return bool(text and re.match(r"^(ref:\s+refs/|[a-f0-9]{40})", text.strip()))


def _validate_git_config(text):
    """A real .git/config has [core] or [remote] sections"""
    return bool(text and ("[core]" in text or "[remote" in text))


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")
    ctx.state["base_reachable"] = True

    all_paths = _GIT_PATHS + _SVN_PATHS + _OTHER_VCS_PATHS
    results = await asyncio.gather(*[
        asyncio.to_thread(_probe, base + "/" + p) for p in all_paths
    ])

    exposed_files = []
    svn_exposed = False
    git_head_valid = False
    git_config_valid = False
    git_index_present = False
    remote_url = None

    for path, result in zip(all_paths, results):
        if not result: continue
        # Validate content matches expected VCS file signature
        text = result.get("text_preview", "")
        if path == ".git/HEAD" and _validate_git_head(text):
            exposed_files.append(path)
            git_head_valid = True
        elif path == ".git/config" and _validate_git_config(text):
            exposed_files.append(path)
            git_config_valid = True
            # Extract remote URL
            m = re.search(r"url\s*=\s*(\S+)", text)
            if m: remote_url = m.group(1)
        elif path == ".git/index" and len(text) > 0:
            exposed_files.append(path)
            git_index_present = True
        elif path.startswith(".git/"):
            exposed_files.append(path)
        elif path.startswith(".svn/"):
            exposed_files.append(path)
            svn_exposed = True
        else:
            exposed_files.append(path)

    ctx.state["exposed_files"] = exposed_files
    ctx.state["svn_exposed"] = svn_exposed
    ctx.state["git_full_exposure"] = git_head_valid and git_config_valid and git_index_present
    ctx.state["paths_tested"] = len(all_paths)
    if remote_url:
        ctx.state["remote_url"] = remote_url

    ctx.source(f"vcs-path-probe ({len(all_paths)})")
    if exposed_files:
        ctx.source(f"content-validation ({len(exposed_files)})")


INTEL_FIELDS = [
    ("Paths probed",          "paths_tested"),
    ("VCS files exposed",     "exposed_count_display"),
    ("Git remote URL",         "remote_url"),
    ("Full repo exposure",    "full_exposure_display"),
]


@router.post("/api/recon/git_recon")
async def recon_git_recon(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        ef = ctx.state.get("exposed_files") or []
        if ef:
            ctx.state["exposed_count_display"] = (
                f"{len(ef)} files: " + ", ".join(ef[:5]))
        if ctx.state.get("git_full_exposure"):
            ctx.state["full_exposure_display"] = (
                "YES — HEAD + config + index all readable; "
                "full repo extractable via git-dumper")

    return await run_scanner(
        host=host, tool="git_recon",
        gather_func=gather_with_display,
        finding_rules=GIT_RECON_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["exposed_files"],
    )


def register(app):
    app.include_router(router)
