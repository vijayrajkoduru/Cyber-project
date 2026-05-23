"""Directory Enumeration v2 — VL-FORGE pattern.

Route: /api/recon/gobuster

Sources (parallel):
  1. AI-curated wordlist (~3339 paths) — if tools/_payloads/recon/consolidated_paths.txt exists
  2. Built-in fallback wordlist (~200 high-impact paths)
  3. Soft-404 fingerprint (3 random probes — calibrates baseline)
  4. Host header fallback (handles Apache Host-mismatch on lab containers)

Findings (~9 rules in tools/_payloads/directory_findings.py):
  CRITICAL: secrets/credential files exposed (.env / .aws / SSH keys)
  HIGH    : git/svn exposed, config files exposed, backup files
  MEDIUM  : admin panels discovered
  LOW     : IDE files (.vscode/.idea/.DS_Store)
  INFO    : total count, soft-404 warning
  POSITIVE: no paths found (strong content security)
"""
import asyncio
import hashlib
import pathlib

from fastapi import APIRouter, Depends

from tools._shared import (ScanRequest, verify_scan_quota, recon_host,
                            safe_get, web_url)
from tools._framework import ScanContext, run_scanner
from tools._payloads.directory_findings import (
    DIRECTORY_FINDING_RULES, classify_path,
)

router = APIRouter()


# Built-in fallback wordlist (used if AI-curated payload not present)
_BUILTIN_WORDLIST = [
    # Auth
    "admin", "administrator", "wp-admin", "wp-login.php", "phpmyadmin", "pma",
    "adminer", "manage", "manager", "dashboard", "console", "control", "panel",
    # Secrets / config
    ".env", ".env.local", ".env.production", ".env.dev", ".env.backup",
    "config.php", "config.json", "config.yaml", "config.xml",
    "configuration.php", "settings.php", "wp-config.php", "web.config",
    "appsettings.json", "db.config", "secrets.json", "credentials.json",
    ".aws/credentials", ".aws/config", ".ssh/id_rsa", ".docker/config.json",
    "master.key",
    # Source control
    ".git/HEAD", ".git/config", ".git/index", ".git/logs/HEAD",
    ".svn/entries", ".hg/hgrc", ".bzr/README",
    # Backups
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "backup.bak",
    "site.zip", "www.zip", "old.zip", "old.tar.gz",
    "dump.sql", "db.sql", "database.sql", "data.sql",
    # IDE / OS
    ".vscode/settings.json", ".idea/workspace.xml", ".DS_Store", "Thumbs.db",
    # Logs
    "logs", "log", "error.log", "access.log", "debug.log",
    # Common
    "robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
    "phpinfo.php", "info.php", "test.php", "test.html", "test",
    # API / docs
    "api", "api/v1", "api/v2", "swagger", "api-docs", "openapi.json",
    "graphql", "graphiql",
    # Framework
    "console", "actuator", "jolokia", "prometheus", "grafana", "kibana",
    "jenkins", "jenkins/script",
    # Install / setup
    "install", "install.php", "setup", "setup.php", "update.php",
    "tmp/install.php",
]


def _load_ai_wordlist():
    """Load AI-curated path wordlist if present."""
    try:
        # After tier restructure this file is at tools/recon/tier4_web/ — three
        # .parent hops reach tools/ where _payloads/ lives.
        p = pathlib.Path(__file__).resolve().parent.parent.parent / "_payloads" / "recon" / "consolidated_paths.txt"
        if p.exists():
            return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines()
                    if ln.strip() and not ln.startswith("#")]
    except Exception:
        pass
    return None


_AI_WORDLIST = _load_ai_wordlist()
# Cap at 800 paths — full 3338-path AI list exceeds frontend's 300s scan budget
# on Cloudflare-fronted targets that rate-limit. 800 high-impact paths covers
# the same critical attack surface (secrets/config/admin/backups) in budget.
_ACTIVE_WORDLIST = (_AI_WORDLIST or _BUILTIN_WORDLIST)[:800]


async def gather(ctx: ScanContext):
    base = web_url(ctx.host).rstrip("/")

    # Soft-404 fingerprint — probe 3 random paths to calibrate baseline
    def _probe_random(extra_headers):
        results = []
        for i in range(3):
            probe_key = hashlib.sha1(f"{ctx.host}-{i}-vlfp".encode()).hexdigest()[:16]
            rp = safe_get(f"{base}/{probe_key}-nonexistent-zzz",
                          headers=extra_headers or {}, allow_redirects=False)
            if rp is None: continue
            loc = (rp.headers.get("Location", "") or "")[:200]
            results.append((rp.status_code, len(rp.content), loc))
        return results

    headers_used = {}
    fingerprints = _probe_random(headers_used)
    # Apache lab fallback — retry with Host: localhost if Host-mismatch
    if fingerprints and all(s == 400 for s, _, _ in fingerprints):
        headers_used = {"Host": "localhost"}
        fingerprints = _probe_random(headers_used)

    if not fingerprints:
        return  # framework's skip_if_empty will mark as failed-reach

    ctx.source("soft-404-baseline")
    ctx.state["soft_404_baseline"] = fingerprints

    # Detect custom-404 condition (server returns 200 with custom error page)
    custom_404 = any(s == 200 for s, _, _ in fingerprints)
    ctx.state["custom_404_detected"] = custom_404

    def _is_soft_404(status, length, loc):
        for fs, fl, floc in fingerprints:
            if status == fs and abs(length - fl) < 96 and loc == floc:
                return True
        return False

    wordlist = _ACTIVE_WORDLIST
    found = []

    def _probe(path):
        # Aggressive timeout — 3338-path wordlist × 15s default would exceed
        # the 300s frontend budget. 4s/no-retries fits within budget on slow targets.
        r = safe_get(f"{base}/{path}", headers=headers_used or {},
                     allow_redirects=False, timeout=4, retries=0)
        if r is None or r.status_code == 404:
            return None
        loc = (r.headers.get("Location", "") or "")[:200]
        if _is_soft_404(r.status_code, len(r.content), loc):
            return None
        hit = {"path": "/" + path, "status": r.status_code,
                "length": len(r.content),
                "category": classify_path(path)}
        if loc:
            hit["redirect_to"] = loc
        return hit

    # 40 in-flight requests via threadpool
    BATCH = 40
    for i in range(0, len(wordlist), BATCH):
        batch = wordlist[i:i+BATCH]
        results = await asyncio.gather(
            *[asyncio.to_thread(_probe, p) for p in batch],
            return_exceptions=False,
        )
        for hit in results:
            if hit is not None:
                found.append(hit)

    ctx.state["found"] = found
    ctx.state["found_count"] = len(found)
    ctx.state["paths_probed"] = len(wordlist)
    if wordlist:
        ctx.source(f"wordlist-{len(wordlist)}-paths")

    # Category counts for intel
    cat_counts = {}
    for f in found:
        cat = f.get("category") or "other"
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    ctx.state["category_counts"] = cat_counts


INTEL_FIELDS = [
    ("Paths probed",       "paths_probed_display"),
    ("Paths found",        "found_count_display"),
    ("Category breakdown", "category_breakdown_display"),
    ("Soft-404 detected",  "custom_404_display"),
    ("Wordlist source",    "wordlist_source_display"),
]


@router.post("/api/recon/gobuster")
async def recon_gobuster(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)

    async def gather_with_display(ctx):
        await gather(ctx)
        ctx.state["paths_probed_display"] = (
            f"{ctx.state.get('paths_probed', 0)} paths probed")
        n = ctx.state.get("found_count", 0)
        if n > 0:
            ctx.state["found_count_display"] = f"{n} accessible paths"
        cc = ctx.state.get("category_counts") or {}
        if cc:
            ctx.state["category_breakdown_display"] = ", ".join(
                f"{cat}: {cnt}" for cat, cnt in sorted(
                    cc.items(), key=lambda kv: -kv[1])[:5])
        if ctx.state.get("custom_404_detected"):
            ctx.state["custom_404_display"] = "Yes — results may include false positives"
        ctx.state["wordlist_source_display"] = (
            f"AI-curated ({len(_ACTIVE_WORDLIST)} paths)" if _AI_WORDLIST
            else f"built-in ({len(_ACTIVE_WORDLIST)} paths)")

    return await run_scanner(
        host=host, tool="gobuster",
        gather_func=gather_with_display,
        finding_rules=DIRECTORY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=["found", "found_count"],
    )


def register(app):
    app.include_router(router)
