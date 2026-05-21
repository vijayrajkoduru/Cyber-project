"""recon_wpjson_enum — WordPress REST API enumeration."""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, safe_get, web_url

router = APIRouter()


@router.post("/api/recon/wpjson_enum")
async def recon_wpjson_enum(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, users, posts, wp_version = [], [], [], None

    # Check WP REST API root
    r = safe_get(f"{base}/wp-json/", req=req)
    if r is None or r.status_code != 200:
        return {"ok": True, "vulnerable": False,
                "skipped_reason": "Not a WordPress site (no /wp-json/ found)"}

    # Confirm it's WordPress
    body = (r.text or "")[:5000]
    if "wp-json" not in body.lower() and "wordpress" not in body.lower():
        return {"ok": True, "vulnerable": False,
                "skipped_reason": "No WordPress signature in /wp-json/ response"}

    # Try to extract WP version from generator or meta
    home_r = safe_get(base, req=req)
    if home_r:
        m = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+\.\d+)', home_r.text or "")
        if m:
            wp_version = m.group(1)

    # User enumeration via REST API
    r = safe_get(f"{base}/wp-json/wp/v2/users", req=req)
    if r and r.status_code == 200:
        try:
            users_data = r.json()
            if isinstance(users_data, list):
                for u in users_data[:30]:
                    users.append({"id": u.get("id"), "name": u.get("name"),
                                  "slug": u.get("slug"), "link": u.get("link")})
        except Exception:
            pass

    if users:
        findings.append({"title": f"WordPress user enumeration — {len(users)} users exposed via /wp-json/wp/v2/users",
            "severity": "MEDIUM", "cvss": 5.3, "cwe": "CWE-200", "owasp": "A01:2021",
            "evidence": f"Users discovered: {', '.join(u.get('slug') or u.get('name','?') for u in users[:5])}",
            "remediation": "Disable REST API user enumeration. Use a plugin like 'Hide WP-JSON' or restrict via .htaccess."})

    # Try ?author=N user enumeration (alternative method)
    for author_id in range(1, 6):
        r = safe_get(f"{base}/?author={author_id}", req=req, allow_redirects=False)
        if r and r.status_code in (301, 302):
            loc = r.headers.get("Location", "")
            m = re.search(r"/author/([a-zA-Z0-9_-]+)", loc)
            if m:
                slug = m.group(1)
                if not any(u.get("slug") == slug for u in users):
                    users.append({"id": author_id, "slug": slug,
                                  "source": "?author= redirect"})

    # Get posts
    r = safe_get(f"{base}/wp-json/wp/v2/posts", req=req)
    if r and r.status_code == 200:
        try:
            posts_data = r.json()
            if isinstance(posts_data, list):
                posts = [{"id": p.get("id"), "slug": p.get("slug"),
                          "title": (p.get("title") or {}).get("rendered","")[:80]}
                         for p in posts_data[:10]]
        except Exception:
            pass

    # WP version disclosure
    if wp_version:
        # Heuristic check for known-old versions
        major, minor, patch = (int(p) for p in wp_version.split("."))
        if major < 6:
            findings.append({"title": f"Outdated WordPress version disclosed: {wp_version}",
                "severity": "HIGH", "cvss": 7.5, "cwe": "CWE-1395", "owasp": "A06:2021",
                "evidence": f"WordPress version {wp_version} detected via meta generator tag",
                "remediation": f"Upgrade WordPress to latest stable. {wp_version} likely has unpatched CVEs."})
        else:
            findings.append({"title": f"WordPress version disclosed: {wp_version}",
                "severity": "LOW", "cvss": 3.1, "cwe": "CWE-200", "owasp": "A05:2021",
                "evidence": f"Generator: WordPress {wp_version}",
                "remediation": "Hide WP version via plugin or remove <meta generator> tag."})

    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "wp_version": wp_version, "users": users, "posts": posts,
            "users_count": len(users), "posts_sample_count": len(posts),
            "engine": "WordPress wp-json REST API + ?author= redirect enumeration"}


def register(app):
    app.include_router(router)
