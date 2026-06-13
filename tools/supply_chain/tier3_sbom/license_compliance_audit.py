"""license_compliance_audit - SBOM licence compliance via syft (playbook §1 #6).

Runs `syft <source> -o syft-json` and classifies every component's SPDX
licence into permissive / weak-copyleft / strong-copyleft / network-copyleft
(AGPL) / unknown. This is a DISTRIBUTION-RISK audit (EU CRA + NIST SSDF
require licence provenance), not a vulnerability scan.

Customer input precedence (same as the other SBOM scanners):
  1. ScanRequest.image_ref
  2. ScanRequest.repo_url   (shallow clone -> syft dir)
  3. ScanRequest.target     (if it's a usable local path)

Zero false positives: classification is driven entirely by the SPDX
expression syft emits, with a conservative substring match per family.
"""
from __future__ import annotations
import asyncio
import json
import os
import shutil
import tempfile
from fastapi import APIRouter, Depends
from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext, run_scanner
from tools._payloads.license_compliance_audit_findings import LICENSE_COMPLIANCE_AUDIT_FINDING_RULES

router = APIRouter()
SYFT_BIN = shutil.which("syft") or "/usr/local/bin/syft"
GIT_BIN = shutil.which("git") or "/usr/bin/git"
TIMEOUT = 240

# SPDX family classification. Matched case-insensitively against the SPDX
# expression / licence value. Order matters: AGPL is checked before GPL.
_NETWORK_COPYLEFT = ("agpl",)
_STRONG_COPYLEFT = ("gpl-2", "gpl-3", "gpl-1", "gplv2", "gplv3", "gpl_2", "gpl_3")
_WEAK_COPYLEFT = ("lgpl", "mpl", "epl", "cddl", "ms-rl", "osl", "eupl")


async def _shallow_clone(repo_url: str, dest: str) -> tuple[bool, str]:
    if not shutil.which("git") and not os.path.exists(GIT_BIN):
        return False, "git not installed"
    try:
        proc = await asyncio.create_subprocess_exec(
            GIT_BIN, "clone", "--depth", "1", "--no-tags", "--quiet", repo_url, dest,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=90)
        except asyncio.TimeoutError:
            proc.kill()
            return False, "git clone timeout"
    except Exception as e:
        return False, f"git clone error: {str(e)[:80]}"
    if proc.returncode != 0:
        return False, f"git clone rc={proc.returncode}: {stderr.decode('utf-8', errors='ignore')[:160]}"
    return True, ""


def _classify(expr: str) -> str:
    """Return the copyleft family for an SPDX expression, or '' if permissive."""
    e = (expr or "").lower()
    if not e or e in ("none", "noassertion", "unknown"):
        return "unknown"
    if any(t in e for t in _NETWORK_COPYLEFT):
        return "network_copyleft"
    # plain "gpl" without lgpl/agpl already handled above
    if any(t in e for t in _STRONG_COPYLEFT) or (("gpl" in e) and "lgpl" not in e and "agpl" not in e):
        return "strong_copyleft"
    if any(t in e for t in _WEAK_COPYLEFT):
        return "weak_copyleft"
    return "permissive"


def _licenses_of(artifact: dict) -> list[str]:
    """Extract SPDX expressions from a syft-json artifact (handles both the
    legacy list-of-strings and the modern list-of-objects shapes)."""
    out = []
    for lic in (artifact.get("licenses") or []):
        if isinstance(lic, str):
            if lic.strip():
                out.append(lic.strip())
        elif isinstance(lic, dict):
            val = lic.get("spdxExpression") or lic.get("value") or lic.get("expression") or ""
            if val.strip():
                out.append(val.strip())
    return out


def _make_gather(req: ScanRequest):
    async def gather(ctx: ScanContext):
        image_ref = (getattr(req, "image_ref", None) or "").strip()
        repo_url = (getattr(req, "repo_url", None) or "").strip()
        target = (ctx.host or "").strip()

        if not shutil.which("syft") and not os.path.exists(SYFT_BIN):
            ctx.state["license_error"] = "syft binary not installed"
            ctx.source("syft missing")
            return

        scan_source = ""
        cleanup_path = ""
        mode = ""
        try:
            if image_ref:
                scan_source = image_ref
                mode = "image_ref"
                ctx.state["license_input_value"] = image_ref
            elif repo_url:
                cleanup_path = tempfile.mkdtemp(prefix="lic_repo_")
                ok, err = await _shallow_clone(repo_url, cleanup_path)
                if not ok:
                    ctx.state["license_error"] = err
                    ctx.source(f"clone failed: {err}")
                    return
                scan_source = f"dir:{cleanup_path}"
                mode = "repo_url"
                ctx.state["license_input_value"] = repo_url
            elif target and os.path.isdir(target):
                scan_source = f"dir:{target}"
                mode = "local_path"
                ctx.state["license_input_value"] = target
            else:
                ctx.state["license_no_input"] = True
                ctx.source("image_ref or repo_url required")
                return

            ctx.state["license_input_mode"] = mode
            cmd = [SYFT_BIN, "scan", scan_source, "-o", "syft-json", "-q"]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TIMEOUT)
                except asyncio.TimeoutError:
                    proc.kill()
                    ctx.state["license_error"] = f"timeout after {TIMEOUT}s"
                    ctx.source("timeout")
                    return
            except Exception as e:
                ctx.state["license_error"] = f"subprocess: {str(e)[:120]}"
                ctx.source(f"subprocess failed: {str(e)[:80]}")
                return

            if proc.returncode != 0 or not stdout:
                err_text = (stderr or b"").decode("utf-8", errors="ignore")[:200]
                ctx.state["license_error"] = f"syft rc={proc.returncode}: {err_text}"
                ctx.source(f"syft rc={proc.returncode}")
                return

            try:
                data = json.loads(stdout.decode("utf-8", errors="ignore"))
            except Exception as e:
                ctx.state["license_error"] = f"json parse: {str(e)[:120]}"
                ctx.source("bad json")
                return

            artifacts = data.get("artifacts") or []
            cats = {"network_copyleft": [], "strong_copyleft": [],
                    "weak_copyleft": [], "permissive": []}
            unknown = 0
            license_histogram: dict[str, int] = {}
            for a in artifacts:
                name = a.get("name") or "?"
                ver = a.get("version") or ""
                exprs = _licenses_of(a)
                if not exprs:
                    unknown += 1
                    continue
                # A component can carry multiple licences; classify each and
                # bucket under the most restrictive family found.
                fams = [_classify(x) for x in exprs]
                for x in exprs:
                    license_histogram[x] = license_histogram.get(x, 0) + 1
                if "unknown" in fams and len(set(fams)) == 1:
                    unknown += 1
                    continue
                worst = "permissive"
                for f in ("network_copyleft", "strong_copyleft", "weak_copyleft"):
                    if f in fams:
                        worst = f
                        break
                if worst in cats:
                    cats[worst].append({"pkg": f"{name}@{ver}" if ver else name,
                                          "license": "/".join(exprs[:3])})

            ctx.state["license_total_components"] = len(artifacts)
            ctx.state["license_unknown_count"] = unknown
            ctx.state["license_categories"] = {
                k: v for k, v in cats.items() if k != "permissive"
            }
            ctx.state["license_permissive_count"] = len(cats["permissive"])
            ctx.state["license_histogram"] = dict(
                sorted(license_histogram.items(), key=lambda x: -x[1])[:20]
            )
            ctx.source(
                f"syft licences: {len(artifacts)} components, "
                f"{len(cats['network_copyleft'])} AGPL / {len(cats['strong_copyleft'])} GPL / "
                f"{len(cats['weak_copyleft'])} weak-copyleft / {unknown} unknown"
            )
        finally:
            if cleanup_path:
                try:
                    shutil.rmtree(cleanup_path, ignore_errors=True)
                except Exception:
                    pass
    return gather


INTEL_FIELDS = [("Input mode", "license_input_mode"),
                ("Scan input", "license_input_value"),
                ("Total components", "license_total_components"),
                ("Permissive components", "license_permissive_count"),
                ("Unknown/undeclared", "license_unknown_count"),
                ("Copyleft categories", "license_categories"),
                ("Licence histogram", "license_histogram")]


@router.post("/api/supply_chain/license_compliance_audit")
async def supply_chain_license_compliance_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="license_compliance_audit",
        gather_func=_make_gather(req),
        finding_rules=LICENSE_COMPLIANCE_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS, flat_field_keys=[],
    )


def register(app): app.include_router(router)
