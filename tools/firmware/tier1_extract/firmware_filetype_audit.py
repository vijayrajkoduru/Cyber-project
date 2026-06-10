"""firmware_filetype_audit - File-type inventory inside firmware (playbook §3 #28).

Uses libmagic via python-magic to walk every file inside the customer's
firmware blob (after extraction via binwalk -e) and report a histogram of
detected file types. Useful for prioritizing analysis: bunch of ELFs =
focus on binary auditing; lots of Python source = focus on code review;
shadow file present = focus on credential extraction.

Customer input: ScanRequest.target = path to firmware blob on disk.
"""
from __future__ import annotations
import shutil
import subprocess
import tempfile
from pathlib import Path
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.firmware_filetype_audit_findings import FIRMWARE_FILETYPE_AUDIT_FINDING_RULES

router = APIRouter()
BINWALK_BIN = shutil.which("binwalk")
SCAN_MAX_FILES = 5000


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target or not Path(target).is_file():
        ctx.state["firmware_filetype_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        import magic
    except ImportError:
        ctx.state["firmware_filetype_audit_error"] = "python-magic not installed"
        ctx.source("python-magic missing")
        return
    if not BINWALK_BIN:
        ctx.state["firmware_filetype_audit_error"] = "binwalk binary not installed"
        ctx.source("binwalk missing")
        return

    tmpdir = tempfile.mkdtemp(prefix="vlfwtype_")
    try:
        # Extract with binwalk (quiet, into tmpdir)
        try:
            subprocess.run([BINWALK_BIN, "-e", "-q", "-C", tmpdir, target],
                          timeout=180, capture_output=True, check=False)
        except subprocess.TimeoutExpired:
            ctx.state["firmware_filetype_audit_error"] = "binwalk extract timeout (180s)"
            ctx.source("binwalk timeout")
            return

        mime = magic.Magic(mime=True)
        type_counts: dict[str, int] = {}
        notable_files = []
        files_seen = 0
        sensitive_patterns = ("shadow", "passwd", "id_rsa", "id_dsa", "id_ecdsa",
                              "authorized_keys", "ssh_host_", ".netrc", "wpa_supplicant.conf",
                              "hostapd.conf", ".aws/credentials", ".env", "config.json")

        for fp in Path(tmpdir).rglob("*"):
            if files_seen >= SCAN_MAX_FILES:
                break
            if not fp.is_file():
                continue
            files_seen += 1
            try:
                mt = mime.from_file(str(fp))
            except Exception:
                continue
            type_counts[mt] = type_counts.get(mt, 0) + 1

            # Flag sensitive filenames
            name_lower = fp.name.lower()
            for pat in sensitive_patterns:
                if pat in name_lower or pat in str(fp).lower():
                    notable_files.append({"path": str(fp.relative_to(tmpdir))[:120],
                                        "mime": mt, "size": fp.stat().st_size})
                    break

        # Top 10 most common MIME types
        top_types = sorted(type_counts.items(), key=lambda x: -x[1])[:10]
        type_summary = [{"mime": mt, "count": c} for mt, c in top_types]

        ctx.state["firmware_total_files"] = files_seen
        ctx.state["firmware_type_inventory"] = type_summary
        ctx.state["firmware_unique_types"] = len(type_counts)
        ctx.state["firmware_notable_files"] = notable_files[:50]
        ctx.state["firmware_elf_count"] = sum(c for mt, c in type_counts.items() if "executable" in mt)
        ctx.state["firmware_script_count"] = sum(c for mt, c in type_counts.items()
                                                   if any(x in mt for x in ("python", "shellscript", "perl", "javascript")))
        ctx.state["firmware_filetype_audit_total"] = len(notable_files)
        ctx.source(f"{files_seen} files, {len(type_counts)} unique MIME types, "
                   f"{len(notable_files)} sensitive filenames")
    finally:
        try: shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception: pass


INTEL_FIELDS = [("Total files scanned", "firmware_total_files"),
                ("Unique MIME types", "firmware_unique_types"),
                ("ELF binary count", "firmware_elf_count"),
                ("Script count", "firmware_script_count"),
                ("Top file types", "firmware_type_inventory"),
                ("Notable sensitive files", "firmware_notable_files")]


@router.post("/api/firmware/firmware_filetype_audit")
async def firmware_firmware_filetype_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(host=req.target, tool="firmware_filetype_audit",
        gather_func=gather, finding_rules=FIRMWARE_FILETYPE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[])


def register(app): app.include_router(router)
