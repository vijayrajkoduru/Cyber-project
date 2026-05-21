"""recon_git_recon — detect exposed .git/ directories + extract metadata.

Conservative: detects exposure + parses .git/config and .git/HEAD for
repo info. Does NOT attempt full repository reconstruction (responsibility
boundary — could destabilize target server with object enumeration).
"""
import re
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota, safe_get, web_url

router = APIRouter()

GIT_PATHS = [
    "/.git/HEAD", "/.git/config", "/.git/index", "/.git/description",
    "/.git/info/refs", "/.git/logs/HEAD", "/.git/COMMIT_EDITMSG",
    "/.git/packed-refs", "/.git/ORIG_HEAD", "/.git/FETCH_HEAD",
]


async def recon_git_recon_impl(req: ScanRequest, _=Depends(verify_scan_quota)):
    base = web_url(req.target).rstrip("/")
    findings, exposed_files, metadata = [], [], {}

    for path in GIT_PATHS:
        r = safe_get(f"{base}{path}", req=req, allow_redirects=False)
        if r is None or r.status_code != 200 or len(r.content) < 5:
            continue
        # Validate it's actually git content, not a 200-on-everything site
        content_preview = (r.text or "")[:500]
        is_git = False
        if path.endswith("HEAD") and "ref:" in content_preview:
            is_git = True
            metadata["current_branch"] = content_preview.replace("ref:", "").strip().split()[-1] if "ref:" in content_preview else None
        elif path.endswith("config") and ("[core]" in content_preview or "[remote" in content_preview):
            is_git = True
            m = re.search(r'url\s*=\s*(.+)', content_preview)
            if m:
                metadata["remote_url"] = m.group(1).strip()
        elif path.endswith("index") and r.content.startswith(b"DIRC"):
            is_git = True
            metadata["index_size"] = len(r.content)
        elif path.endswith("description"):
            is_git = True
        elif path.endswith("refs") and ("refs/heads" in content_preview or "refs/tags" in content_preview):
            is_git = True
        elif "EDITMSG" in path or "ORIG_HEAD" in path or "FETCH_HEAD" in path:
            is_git = True

        if is_git:
            exposed_files.append({
                "path": path, "url": f"{base}{path}",
                "size": len(r.content),
                "preview": content_preview[:200],
            })

    # If we found .git files, this is a critical exposure
    if exposed_files:
        findings.append({
            "title": f".git/ repository exposed — full source code reconstructable",
            "severity": "CRITICAL", "cvss": 9.1, "cwe": "CWE-538", "owasp": "A05:2021",
            "evidence": (f"Found {len(exposed_files)} .git/ files exposed at {base}/.git/ "
                         f"including {', '.join(f['path'].split('/')[-1] for f in exposed_files[:5])}. "
                         f"Tools like git-dumper can reconstruct the entire repository, including "
                         f"deleted secrets, commit history, and source code."),
            "remediation": ("URGENT: Block public access to /.git/ at web server level. "
                            "Apache: `<DirectoryMatch \\.git>Require all denied</DirectoryMatch>`. "
                            "Nginx: `location ~ /\\.git { deny all; }`. "
                            "Rotate any secrets that may have been committed historically.")
        })

    # Also check for common backup/Git-related files
    backup_paths = ["/.gitignore", "/.git-rewrite", "/HEAD"]
    backup_found = []
    for path in backup_paths:
        r = safe_get(f"{base}{path}", req=req, allow_redirects=False)
        if r is not None and r.status_code == 200 and len(r.content) > 5 and len(r.content) < 10000:
            backup_found.append({"path": path, "size": len(r.content)})

    return {"ok": True, "vulnerable": len(findings) > 0, "findings": findings,
            "exposed_files": exposed_files,
            "git_metadata": metadata,
            "backup_files": backup_found,
            "paths_probed": len(GIT_PATHS) + len(backup_paths),
            "total_exposed": len(exposed_files),
            "engine": f".git/ probe ({len(GIT_PATHS)} core files) + metadata parser"}



# VLERR-WRAP-V1
@router.post("/api/recon/git_recon")
async def recon_git_recon(req: ScanRequest, _=Depends(verify_scan_quota)):
    try:
        return await recon_git_recon_impl(req, _)
    except Exception as _e:
        return {"ok": False,
                 "skipped_reason": f"git_recon scanner failed: {type(_e).__name__}: {str(_e)[:200]}",
                 "error": f"{type(_e).__name__}: {str(_e)[:300]}"}

def register(app):
    app.include_router(router)
