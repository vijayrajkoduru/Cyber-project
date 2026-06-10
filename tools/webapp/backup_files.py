"""Webapp: backup file hunter (.bak/.old/.swp/.orig/.copy/~)."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.verify import vl_verify

router = APIRouter()

_TARGETS = ["index","config","wp-config","settings","database","db","admin","login","app","main","auth","secret","credentials","backup","dump","users","api"]
_EXTS = [".bak",".old",".swp",".orig",".copy","~",".tmp",".save",".inc","-bak","-old","-backup",".1",".2"]
_BASE_EXTS = [".php",".html",".aspx",".jsp",".py",".rb",".js",".json",".yml",".xml",".env",".sql",".txt",".conf"]


@router.post("/api/webapp/backup_files")
@vl_verify(check_spa=True)
async def webapp_backup_files(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings = []
    tests = 0
    exposed = []
    # Build paths: /target.php.bak, /target.html.bak, /target~, etc.
    paths = set()
    for t in _TARGETS:
        for b in _BASE_EXTS:
            for ext in _EXTS:
                paths.add(f"/{t}{b}{ext}")
        # Also /target~ /target.bak (no base ext)
        for ext in _EXTS:
            paths.add(f"/{t}{ext}")
    paths = sorted(paths)[:200]  # cap to 200 probes max
    import secrets as _sec
    bnonce = "/__vl404_" + _sec.token_hex(8) + ".nope"
    br = safe_get(base + bnonce, req=req, allow_redirects=False, timeout=6)
    spa_baseline = None
    if br is not None and br.status_code == 200 and len(br.content) > 30:
        spa_baseline = {"size": len(br.content), "head": (br.text or "")[:300]}
    for path in paths:
        tests += 1
        r = safe_get(base + path, req=req, allow_redirects=False, timeout=6)
        if r is None or r.status_code != 200 or len(r.content) < 30:
            continue
        if spa_baseline and abs(len(r.content) - spa_baseline["size"]) < 50 and (r.text or "")[:300] == spa_baseline["head"]:
            continue
        # Skip if response looks like the 404 page (heuristic via content type or HTML)
        ct = r.headers.get("Content-Type","").lower()
        if "html" in ct and ("not found" in (r.text or "").lower()[:500] or "404" in (r.text or "")[:200]):
            continue
        size = len(r.content)
        exposed.append({"path": path, "size": size, "type": ct.split(";")[0]})
        findings.append(wrap_finding(
            f"Backup file exposed: {path} ({size} bytes)",
            "HIGH",
            cvss="7.5", cwe="CWE-530",
            cwe_name="Exposure of Backup File to an Unauthorized Control Sphere",
            owasp="A05:2021",
            remediation=f"Delete {path} from the web root, or block it at the web server (e.g., nginx: deny access to *.bak, *.old, *.swp, *.orig, *~).",
            evidence_marker=f"GET {path} returned HTTP 200 with {size} bytes, content-type: {ct or 'unknown'}",
        ))

    return standard_response(
        tool="backup_files", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Probed {tests} common backup-file paths; {len(exposed)} exposed",
        raw_data={"backup_files": {"exposed": exposed}},
    )


def register(app):
    app.include_router(router)
