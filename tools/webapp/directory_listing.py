"""Webapp: auto-index directory listing detector.

VL-VERIFY: probes 28 common dirs and matches '<a href="../">'/'Index of /'
patterns. SPA shells often include relative-path anchors that match the
'<a href="../"' pattern. Canary suppresses those FPs and stamps spa_catchall.
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, web_url, safe_get, wrap_finding, standard_response
from tools._vl_core.spa_canary import detect_spa_catchall_sync, is_same_as_canary

router = APIRouter()

_DIRS = ["/","/uploads/","/files/","/images/","/img/","/static/","/assets/","/css/","/js/","/scripts/","/backup/","/backups/","/old/","/tmp/","/temp/","/data/","/private/","/admin/","/admin/files/","/api/","/.git/","/.svn/","/.well-known/","/test/","/dev/","/staging/","/logs/","/log/"]

_LISTING_RE = re.compile(
    r"<title>Index of /|"
    r"<h1>Index of /|"
    r"Directory listing for /|"
    r'<a href="\.\./"',
    re.I,
)


@router.post("/api/webapp/directory_listing")
async def webapp_directory_listing(req: ScanRequest, payload=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    spa = detect_spa_catchall_sync(base)
    findings = []
    tests = 0
    exposed = []
    spa_suppressed = []
    for d in _DIRS:
        tests += 1
        r = safe_get(base + d, req=req, allow_redirects=False, timeout=6)
        if r is None or r.status_code != 200:
            continue
        body = (r.text or "")[:20000]
        # SPA catch-all: body matches canary -> not a real directory listing
        if spa["is_spa"] and is_same_as_canary(body, spa["canary_body"]):
            spa_suppressed.append(d)
            continue
        if not _LISTING_RE.search(body):
            continue
        # Count visible entries
        entries = len(re.findall(r'<a href="[^"]+">[^<]+</a>', body))
        exposed.append({"dir": d, "entries": entries})
        findings.append(wrap_finding(
            f"Directory listing enabled at {d} ({entries} file/folder entries visible)",
            "MEDIUM",
            cvss="5.3", cwe="CWE-548",
            cwe_name="Exposure of Information Through Directory Listing",
            owasp="A05:2021",
            remediation=("Disable directory auto-indexing. Apache: 'Options -Indexes' in .htaccess. "
                         "Nginx: remove 'autoindex on;'. Add an index.html stub to suppress listing."),
            evidence_marker=f"GET {d} returned auto-index page with {entries} entries",
        ))

    return standard_response(
        tool="directory_listing", target=req.target,
        findings=findings, tests_performed=tests,
        tests_summary=f"Probed {tests} common directories; {len(exposed)} expose auto-index",
        raw_data={"directory_listing": {"exposed": exposed,
                                          "spa_catchall": spa["is_spa"],
                                          "spa_suppressed_paths": spa_suppressed}},
    )


def register(app):
    app.include_router(router)
