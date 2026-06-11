"""Wayback Machine robots.txt history — playbook §2 (deep wayback).

Pulls every archived snapshot of <domain>/robots.txt over time. Diff
reveals deprecated paths the org used to advertise but no longer does —
which often correspond to forgotten admin panels still live on the
server but removed from the public sitemap.

Real probe. Zero false positives — only emits what Wayback archived.
"""
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import (ScanRequest, verify_scan_quota,
                            safe_get, wrap_finding, standard_response)
from tools._vl_core.verify import vl_verify

router = APIRouter()
WALL_CLOCK_S = 25


def _clean(t: str) -> str:
    t = t.replace("http://", "").replace("https://", "").rstrip("/")
    if "/" in t: t = t.split("/", 1)[0]
    return t.lower()


def _do_scan(req: ScanRequest) -> dict:
    domain = _clean((req.target or "").strip())
    if not domain or "." not in domain:
        return standard_response(
            tool="wayback_robots_history", target=req.target, findings=[],
            tests_performed=0, vulnerable=False,
            skipped_reason="invalid domain")

    H = {"User-Agent": "VulnusLab-OSINT/1.0"}

    # 1. Get CDX of all robots.txt snapshots (collapsed by digest = unique versions)
    cdx_url = (f"https://web.archive.org/cdx/search/cdx?url={domain}/robots.txt"
                "&output=json&collapse=digest&fl=timestamp,digest,statuscode&limit=80")
    r = safe_get(cdx_url, req=req, timeout=15, headers=H)
    if r is None or r.status_code != 200:
        return standard_response(
            tool="wayback_robots_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"CDX status {r.status_code if r else 'no-conn'}")

    try:
        rows = r.json()
    except Exception:
        return standard_response(
            tool="wayback_robots_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason="non-JSON CDX")

    if len(rows) < 2:
        return standard_response(
            tool="wayback_robots_history", target=req.target,
            findings=[wrap_finding(
                f"Wayback has no robots.txt snapshots for {domain}",
                severity="POSITIVE", cwe="CWE-200",
                remediation="Either robots.txt never existed or Wayback didn't capture.",
                evidence_marker="CDX returned no rows (CONFIRMED)")],
            tests_performed=1, vulnerable=False,
            tests_summary="No robots history")

    # 2. Sample oldest, middle, newest snapshots and union their Disallow paths
    snapshots = rows[1:]  # skip header
    sample_idx = [0, len(snapshots) // 2, len(snapshots) - 1]
    sample_idx = sorted(set(sample_idx))

    # VL-TURBO deep: fetch all sample snapshots in parallel.
    # Was 3 sequential snapshot fetches at 8s each = 24s worst case.
    # Now ~8s for all 3 in parallel.
    def _fetch_snapshot(idx):
        ts = snapshots[idx][0]
        snap_url = f"https://web.archive.org/web/{ts}/{domain}/robots.txt"
        sr = safe_get(snap_url, req=req, timeout=8, headers=H)
        if sr is None or sr.status_code != 200:
            return (ts, [])
        paths = []
        for line in (sr.text or "").splitlines()[:200]:
            line = line.strip()
            m = re.match(r"^Disallow:\s*(/.*?)$", line, re.IGNORECASE)
            if m:
                p = m.group(1).strip().split("#")[0].strip()
                if p and p != "/":
                    paths.append(p)
        return (ts, paths)

    all_paths = set()
    snapshot_paths = {}
    with ThreadPoolExecutor(max_workers=len(sample_idx)) as pool:
        for ts, paths in pool.map(_fetch_snapshot, sample_idx, timeout=15):
            for p in paths:
                all_paths.add(p)
            snapshot_paths[ts[:8]] = paths[:30]

    if not all_paths:
        return standard_response(
            tool="wayback_robots_history", target=req.target,
            findings=[wrap_finding(
                f"Wayback robots history for {domain} — 0 Disallow paths across {len(sample_idx)} snapshots",
                severity="POSITIVE", cwe="CWE-200",
                remediation="No paths advertised in robots.txt history.",
                evidence_marker=f"{len(snapshots)} versions, 0 Disallow paths (CONFIRMED)")],
            tests_performed=1+len(sample_idx), vulnerable=False,
            tests_summary="No Disallow paths")

    interesting = [p for p in all_paths if any(k in p.lower() for k in
                    ("admin", "internal", "test", "dev", "staging", "api",
                     "swagger", "graphql", "private", "backup", "config",
                     "/.git", "/.env", "wp-admin", "phpinfo"))]

    findings = []
    if interesting:
        findings.append(wrap_finding(
            f"INTERESTING robots-disallowed paths ({len(interesting)})",
            severity="MEDIUM", cwe="CWE-200", cvss="5.3", owasp="A05:2021",
            remediation="Each Disallow entry told search engines 'don't index this' "
                        "but the URL was LIVE at some point. Test each — many will "
                        "still be reachable today. Customer's modern robots.txt may "
                        "have removed them but the endpoints often remain.",
            evidence_marker=" | ".join(sorted(interesting)[:15])))

    findings.append(wrap_finding(
        f"Wayback robots.txt: {len(snapshots)} versions, {len(all_paths)} unique paths",
        severity="POSITIVE" if not interesting else "INFO", cwe="CWE-200",
        remediation="Sample paths: " + ", ".join(sorted(all_paths)[:6]),
        evidence_marker=(
            f"snapshots_sampled={len(sample_idx)} | "
            f"path_union={len(all_paths)} | "
            f"oldest={snapshots[0][0][:8]} | newest={snapshots[-1][0][:8]}"
        )))

    return standard_response(
        tool="wayback_robots_history", target=req.target, findings=findings,
        tests_performed=1+len(sample_idx),
        vulnerable=bool(interesting),
        tests_summary=f"{len(snapshots)} robots versions / {len(all_paths)} paths",
        raw_data={"all_paths": sorted(all_paths), "interesting": interesting,
                   "snapshot_count": len(snapshots),
                   "sample_snapshots": snapshot_paths})


@router.post("/api/osint/wayback_robots_history")
@vl_verify()
async def scan_wayback_robots_history(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_do_scan, req), timeout=WALL_CLOCK_S)
    except asyncio.TimeoutError:
        return standard_response(
            tool="wayback_robots_history", target=req.target, findings=[],
            tests_performed=1, vulnerable=False,
            skipped_reason=f"timeout after {WALL_CLOCK_S}s")


def register(app):
    app.include_router(router)
