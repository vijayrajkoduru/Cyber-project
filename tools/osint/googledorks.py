"""Google dorks generator — 20 curated queries for the target."""
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, recon_host

router = APIRouter()


@router.post("/api/osint/googledorks")
async def osint_googledorks(req: ScanRequest, _=Depends(verify_scan_quota)):
    d = recon_host(req.target)
    dorks = [
        ("Sensitive files",       f"site:{d} ext:env OR ext:sql OR ext:bak OR ext:log"),
        ("Login pages",           f"site:{d} inurl:login OR inurl:admin OR inurl:signin"),
        ("Backup files",          f"site:{d} inurl:backup OR inurl:bak OR inurl:old"),
        ("Directory listings",    f"site:{d} intitle:\"index of\""),
        ("phpinfo output",        f"site:{d} ext:php intext:\"phpinfo()\""),
        ("Error messages",        f"site:{d} \"SQL syntax\" OR \"Warning:\" OR \"Notice:\""),
        ("WordPress paths",       f"site:{d} inurl:wp-content OR inurl:wp-admin"),
        ("Subdomain hunt",        f"site:*.{d}"),
        ("PDF documents",         f"site:{d} ext:pdf"),
        ("Excel spreadsheets",    f"site:{d} ext:xls OR ext:xlsx OR ext:csv"),
        ("Word documents",        f"site:{d} ext:doc OR ext:docx"),
        ("API endpoints",         f"site:{d} inurl:api OR inurl:swagger OR inurl:graphql"),
        ("Non-standard ports",    f"site:{d} inurl:\":8080\" OR inurl:\":3000\" OR inurl:\":8000\""),
        ("GitHub code leaks",     f"site:github.com \"{d}\""),
        ("Pastebin leaks",        f"site:pastebin.com \"{d}\""),
        ("Stack Overflow",        f"site:stackoverflow.com \"{d}\""),
        ("LinkedIn employees",    f"site:linkedin.com/in \"{d}\""),
        ("Twitter mentions",      f"site:twitter.com \"{d}\""),
        ("Job postings",          f"site:{d} inurl:careers OR inurl:jobs"),
        ("Trello / Notion leaks", f"site:trello.com OR site:notion.so \"{d}\""),
    ]
    return {"ok": True, "target": d,
            "dorks": [{"category": c, "query": q} for c, q in dorks],
            "total": len(dorks),
            "note": "Paste each query into Google for manual investigation."}


def register(app):
    app.include_router(router)
