"""commit_signing_audit - commit-signature coverage (playbook §5 #70).

Clones recent history and inspects each commit's signature flag (git log
%G?). Reports the signed-vs-unsigned ratio over the last N commits. Validity
(good/bad key) is not asserted — the scanner has no signer keyring — so the
honest signal is signature PRESENCE, which is what attribution depends on.

Customer input: ScanRequest.repo_url (a git URL with history).
"""
from __future__ import annotations
import asyncio
import os
import shutil
import tempfile
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.commit_signing_audit_findings import COMMIT_SIGNING_AUDIT_FINDING_RULES

router = APIRouter()
GIT_BIN = shutil.which("git") or "/usr/bin/git"
_DEPTH = 50


async def _git(args: list, timeout: int = 90) -> tuple[bytes, bytes, int]:
    proc = await asyncio.create_subprocess_exec(
        GIT_BIN, *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return b"", b"timeout", -1
    return out, err, proc.returncode or 0


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        if not repo_url:
            ctx.state["sign_no_input"] = True
            ctx.source("repo_url required")
            return
        if not shutil.which("git") and not os.path.exists(GIT_BIN):
            ctx.state["sign_error"] = "git not installed"
            ctx.source("git missing")
            return

        ctx.state["sign_input_value"] = repo_url
        cleanup_path = tempfile.mkdtemp(prefix="sign_repo_")
        try:
            _, err, rc = await _git(
                ["clone", "--depth", str(_DEPTH), "--no-tags", "--quiet", repo_url, cleanup_path])
            if rc != 0:
                ctx.state["sign_error"] = f"git clone rc={rc}: {err.decode('utf-8', errors='ignore')[:160]}"
                ctx.source("clone failed")
                return

            out, err, rc = await _git(
                ["-C", cleanup_path, "log", f"-{_DEPTH}", "--pretty=%G?%x09%an"])
            if rc != 0 or not out:
                ctx.state["sign_error"] = f"git log rc={rc}: {err.decode('utf-8', errors='ignore')[:160]}"
                ctx.source("git log failed")
                return

            total = signed = unsigned = 0
            sig_flags: dict[str, int] = {}
            unsigned_authors: dict[str, int] = {}
            for line in out.decode("utf-8", errors="ignore").splitlines():
                if not line.strip():
                    continue
                parts = line.split("\t", 1)
                flag = parts[0].strip() or "N"
                author = parts[1].strip() if len(parts) > 1 else "?"
                total += 1
                sig_flags[flag] = sig_flags.get(flag, 0) + 1
                # 'N' = no signature. Anything else (G/U/X/Y/R/B/E) = a signature
                # is present (validity aside).
                if flag == "N":
                    unsigned += 1
                    unsigned_authors[author] = unsigned_authors.get(author, 0) + 1
                else:
                    signed += 1

            ctx.state["sign_total"] = total
            ctx.state["sign_signed"] = signed
            ctx.state["sign_unsigned"] = unsigned
            ctx.state["sign_flag_breakdown"] = sig_flags
            ctx.state["sign_pct"] = round(100.0 * signed / total, 1) if total else 0
            ctx.state["sign_top_unsigned_authors"] = dict(
                sorted(unsigned_authors.items(), key=lambda x: -x[1])[:5])
            ctx.source(f"commit signing: {signed}/{total} signed ({ctx.state['sign_pct']}%)")
        finally:
            try:
                shutil.rmtree(cleanup_path, ignore_errors=True)
            except Exception:
                pass
    return gather


INTEL_FIELDS = [("Scan input", "sign_input_value"),
                ("Commits inspected", "sign_total"),
                ("Signed commits", "sign_signed"),
                ("Unsigned commits", "sign_unsigned"),
                ("Signed %", "sign_pct"),
                ("Signature flag breakdown", "sign_flag_breakdown"),
                ("Top unsigned authors", "sign_top_unsigned_authors")]


@router.post("/api/supply_chain/commit_signing_audit")
async def supply_chain_commit_signing_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="commit_signing_audit",
        gather_func=_make_gather(req),
        finding_rules=COMMIT_SIGNING_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
