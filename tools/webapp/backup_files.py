"""Webapp: backup file hunter (.bak/.old/.swp/.orig/.copy/~).

VL-TURBO deep: probes parallelized via ThreadPoolExecutor (20 workers).
Previously sequential — worst case 200 probes x 6s = 20 minutes,
killed at 60s wall-clock by VL-TURBO leaving most paths unprobed.
Now ~10s for all 200 paths.
"""
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()

_TARGETS = ["index","config","wp-config","settings","database","db","admin","login","app","main","auth","secret","credentials","backup","dump","users","api"]
_EXTS = [".bak",".old",".swp",".orig",".copy","~",".tmp",".save",".inc","-bak","-old","-backup",".1",".2"]
_BASE_EXTS = [".php",".html",".aspx",".jsp",".py",".rb",".js",".json",".yml",".xml",".env",".sql",".txt",".conf"]


def _probe(base, req, spa_baseline, path):
    r = safe_get(base + path, req=req, allow_redirects=False, timeout=6)
    if r is None or r.status_code != 200 or len(r.content) < 30:
        return None
    if spa_baseline and abs(len(r.content) - spa_baseline["size"]) < 50 \
            and (r.text or "")[:300] == spa_baseline["head"]:
        return None
    ct = r.headers.get("Content-Type", "").lower()
    if "html" in ct and ("not found" in (r.text or "").lower()[:500]
                          or "404" in (r.text or "")[:200]):
        return None
    return {"path": path, "size": len(r.content), "type": ct.split(";")[0],
            "ct_raw": ct}


@router.post("/api/webapp/backup_files")
@vl_verify(check_spa=True)
async def webapp_backup_files(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    paths = set()
    for t in _TARGETS:
        for b in _BASE_EXTS:
            for ext in _EXTS:
                paths.add(f"/{t}{b}{ext}")
        for ext in _EXTS:
            paths.add(f"/{t}{ext}")
    paths = sorted(paths)[:200]

    # Baseline: probe a definitely-404 nonce to detect SPA catch-all
    import secrets as _sec
    bnonce = "/__vl404_" + _sec.token_hex(8) + ".nope"
    br = safe_get(base + bnonce, req=req, allow_redirects=False, timeout=6)
    spa_baseline = None
    if br is not None and br.status_code == 200 and len(br.content) > 30:
        spa_baseline = {"size": len(br.content), "head": (br.text or "")[:300]}

    # VL-TURBO deep: 20-way parallel probes via ThreadPoolExecutor
    exposed = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        for hit in pool.map(lambda p: _probe(base, req, spa_baseline, p), paths,
                             timeout=45):
            if hit:
                exposed.append(hit)

    findings = []
    for hit in exposed:
        findings.append(wrap_finding(
            f"Backup file exposed: {hit['path']} ({hit['size']} bytes)",
            "HIGH", cvss="7.5", cwe="CWE-530",
            cwe_name="Exposure of Backup File to an Unauthorized Control Sphere",
            owasp="A05:2021",
            remediation=(f"Delete {hit['path']} from the web root, or block it "
                          "at the web server (e.g. nginx: deny access to *.bak, "
                          "*.old, *.swp, *.orig, *~)."),
            evidence_marker=(f"GET {hit['path']} returned HTTP 200 with "
                              f"{hit['size']} bytes, content-type: "
                              f"{hit['ct_raw'] or 'unknown'}"),
        ))

    if not findings and paths:
        findings.append(wrap_finding(
            "No exposed backup/archive files — probed paths returned no recoverable artifacts",
            "POSITIVE", cwe="CWE-530",
            remediation="Maintain. Keep backups outside the web root and block "
                        "archive/SQL/config extensions at the server. Re-test after "
                        "deploy-tooling changes.",
            evidence_marker=f"probed {len(paths)} backup path(s); none returned a "
                            "downloadable backup/archive"))
    return standard_response(
        tool="backup_files", target=req.target,
        findings=findings, tests_performed=len(paths),
        tests_summary=f"Probed {len(paths)} backup paths in parallel; {len(exposed)} exposed",
        raw_data={"backup_files": {"exposed": exposed}},
    )


def register(app):
    app.include_router(router)
