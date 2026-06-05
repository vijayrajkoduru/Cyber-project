"""VL-METHOD base class + reusable pentest helpers.

Underscore-prefixed file so autoloader skips it. Scanners inherit
from MethodologyScanner and override the steps they implement.
The framework orchestrates the 7-step flow and handles:
  - Per-stage timing telemetry
  - Confidence labeling (CONFIRMED / SUSPECTED / INFO)
  - Verification method tracking
  - Chain ID propagation between scanners (cross-scanner chains)
  - Per-stage failure isolation (one stage breaking doesn't kill scan)
  - Privilege classification (root / sudo / user / guest / unknown)

USAGE PATTERN (scanner side):

    from tools._methodology import MethodologyScanner, helpers
    from tools._framework import ScanContext

    class HydraSshSpray(MethodologyScanner):
        name = "hydra_ssh_spray"

        async def pre_flight(self, ctx):
            if not await helpers.port_open(ctx.host, 22, timeout=3):
                ctx.state["skipped_reason"] = "ssh/22 not reachable"
                return False
            return True

        async def fingerprint(self, ctx):
            banner = await helpers.ssh_banner_grab(ctx.host, 22)
            ctx.state["fingerprint"] = {"service":"ssh","banner":banner}

        async def quick_probe(self, ctx):
            # Try 5 known defaults BEFORE customer's full wordlist
            return await helpers.try_default_creds(
                ctx.host, 22, "ssh",
                pairs=[("admin","admin"),("root","root"),...])
        # ... etc

    # Endpoint wraps the class:
    @router.post("/api/password/hydra_ssh_spray")
    async def hydra_ssh_spray_ep(req, _=Depends(verify_scan_quota)):
        scanner = HydraSshSpray()
        return await scanner.run_as_endpoint(req, finding_rules=...)
"""
from __future__ import annotations

import asyncio
import socket
import time
import uuid
from typing import Optional

from tools._framework import ScanContext, run_scanner


# ═══════════════════════════════════════════════════════════════════
#  helpers — re-usable pentest primitives every scanner needs
# ═══════════════════════════════════════════════════════════════════

class _Helpers:
    """Reusable async helpers for VL-METHOD scanners."""

    @staticmethod
    async def port_open(host: str, port: int, timeout: float = 3.0) -> bool:
        """TCP connect-test. Returns True if port accepts the SYN."""
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            return True
        except Exception:
            return False

    @staticmethod
    async def banner_grab(host: str, port: int, timeout: float = 4.0,
                           bytes_to_read: int = 256) -> str:
        """Grab the first N bytes from a TCP service. Useful for SSH/SMTP/FTP
        banner detection (service+version fingerprint)."""
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            try:
                data = await asyncio.wait_for(reader.read(bytes_to_read), timeout=timeout)
            except asyncio.TimeoutError:
                data = b""
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            return data.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    @staticmethod
    async def ssh_banner_grab(host: str, port: int = 22) -> dict:
        """SSH-specific banner parser. Extracts service + version."""
        raw = await _Helpers.banner_grab(host, port, timeout=4)
        out = {"raw": raw, "service": "", "version": "", "comments": ""}
        # SSH banner format: "SSH-<protoversion>-<software><sp><comments>"
        if raw.startswith("SSH-"):
            parts = raw.split("-", 2)
            if len(parts) >= 3:
                tail = parts[2]
                sw_parts = tail.split(" ", 1)
                sw = sw_parts[0]
                out["service"] = "ssh"
                out["version"] = sw.strip()
                if len(sw_parts) > 1:
                    out["comments"] = sw_parts[1].strip()
        return out

    @staticmethod
    async def try_default_creds(host: str, port: int, protocol: str,
                                 pairs: list[tuple[str, str]],
                                 per_attempt_timeout: float = 5.0) -> list[dict]:
        """Try a small list of (user, pwd) pairs as a quick-probe.
        Returns list of CONFIRMED login dicts. Uses raw protocol logic for
        SSH; falls back to per-protocol library for others.

        SAFETY: hard-limited to 10 pairs per call so an accidental loop
        can never lock out accounts. Caller should pass <=5 typical defaults.
        """
        if not pairs or len(pairs) > 10:
            return []
        results = []
        if protocol == "ssh":
            try:
                import paramiko
            except ImportError:
                return []
            for user, pwd in pairs[:10]:
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: client.connect(host, port=port, username=user,
                                                password=pwd,
                                                timeout=per_attempt_timeout,
                                                allow_agent=False,
                                                look_for_keys=False,
                                                banner_timeout=per_attempt_timeout))
                    # Login succeeded - confirm with whoami
                    try:
                        stdin, stdout, stderr = await asyncio.get_event_loop().run_in_executor(
                            None, lambda: client.exec_command("id", timeout=per_attempt_timeout))
                        id_output = stdout.read().decode("utf-8", errors="ignore").strip()
                    except Exception:
                        id_output = ""
                    results.append({
                        "user": user,
                        "pwd_marker": f"len={len(pwd)} ***{pwd[-2:] if len(pwd) >= 2 else ''}",
                        "id_output": id_output[:200],
                        "method": "paramiko_direct",
                    })
                    try: client.close()
                    except Exception: pass
                except paramiko.AuthenticationException:
                    pass  # bad creds - move on
                except Exception:
                    pass  # network error - move on
        return results

    @staticmethod
    def classify_privilege(id_output: str, user: str) -> str:
        """Parse `id` output to determine privilege level.
        Returns 'root' | 'sudo' | 'user' | 'guest' | 'unknown'."""
        if not id_output:
            return "unknown"
        s = id_output.lower()
        # uid=0 = root
        if "uid=0(" in s or "uid=0 " in s:
            return "root"
        # Member of sudo / wheel / admin groups
        if any(g in s for g in ("sudo)", "(wheel)", "(admin)", "(adm)")):
            return "sudo"
        # Service / system account (uid < 1000 typically)
        import re as _re
        m = _re.match(r"uid=(\d+)", s)
        if m:
            uid = int(m.group(1))
            if uid == 0: return "root"
            if uid < 1000: return "service"
        # Built-in low-priv accounts
        if user.lower() in ("guest", "nobody", "anonymous"):
            return "guest"
        return "user"


helpers = _Helpers()


# ═══════════════════════════════════════════════════════════════════
#  MethodologyScanner — the base class scanners inherit from
# ═══════════════════════════════════════════════════════════════════

class MethodologyScanner:
    """Base class for VL-METHOD scanners.

    Override only the steps your scanner needs. The framework calls them
    in order: pre_flight -> fingerprint -> quick_probe -> deep_scan ->
    verify (per finding) -> privilege_check (per finding) -> chain_handoff.

    Each stage is wrapped in try/except so one stage failure doesn't kill
    the scan. Per-stage timings are recorded in ctx.state['stage_timings'].
    """

    name: str = "methodology_scanner"  # subclass MUST override

    # ── stages (override what you need) ──────────────────────────

    async def pre_flight(self, ctx: ScanContext) -> bool:
        """Step 1: Is the target reachable + in scope? Return False to skip."""
        return True

    async def fingerprint(self, ctx: ScanContext):
        """Step 2: Identify service/version/framework. Populate ctx.state['fingerprint']."""
        pass

    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        """Step 3: 5-second triage. Return preliminary findings list."""
        return []

    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        """Step 4: Full attack (only runs if quick_probe found something OR options.always_deep=True).
        Return preliminary findings list."""
        return []

    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        """Step 5: Re-test the finding with a DIFFERENT method.
        Must set finding['confidence'] = 'CONFIRMED' | 'SUSPECTED'.
        Return finding dict (or None to drop it entirely as false-positive)."""
        finding.setdefault("confidence", "SUSPECTED")
        finding.setdefault("verification_method", "not-verified")
        return finding

    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        """Step 6: For credential / shell findings, classify privilege.
        Adds finding['privilege_level'] = 'root'|'sudo'|'user'|'guest'|'service'|'unknown'."""
        finding.setdefault("privilege_level", "unknown")
        return finding

    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        """Step 7: For confirmed findings, what other scanners should run next?
        Return list of scanner names (e.g. ['post_exploit_persistence_audit', 'privesc_linpeas']).
        Cross-scanner chaining engine will spawn these."""
        return []

    # ── orchestrator (do not override) ───────────────────────────

    async def run(self, ctx: ScanContext):
        """Execute the 7-step VL-METHOD flow. Called by the endpoint wrapper.
        Populates ctx.state with: methodology_findings, stage_timings,
        chain_id, fingerprint, skipped_reason (if pre_flight failed)."""
        chain_id = ctx.state.get("chain_id") or str(uuid.uuid4())[:8]
        ctx.state["chain_id"] = chain_id
        ctx.state["stage_timings"] = {}
        ctx.state["stage_errors"] = {}

        async def _timed(stage_name, coro):
            t0 = time.time()
            try:
                result = await coro
                return result
            except Exception as e:
                ctx.state["stage_errors"][stage_name] = f"{type(e).__name__}: {str(e)[:200]}"
                return None
            finally:
                ctx.state["stage_timings"][stage_name] = round((time.time() - t0) * 1000, 1)  # ms

        # Step 1
        ok = await _timed("pre_flight", self.pre_flight(ctx))
        if ok is False:
            ctx.state["methodology_findings"] = []
            ctx.state["methodology_total"] = 0
            return

        # Step 2
        await _timed("fingerprint", self.fingerprint(ctx))

        # Step 3
        quick = await _timed("quick_probe", self.quick_probe(ctx)) or []

        # Step 4 (gated: only if quick found OR options requested)
        opts = ctx.state.get("_options") or {}
        deep: list[dict] = []
        if quick or opts.get("always_deep"):
            deep = await _timed("deep_scan", self.deep_scan(ctx)) or []

        all_findings = quick + deep

        # Stamp chain_id on every finding for cross-scanner correlation
        for f in all_findings:
            f["chain_id"] = chain_id
            f.setdefault("source_stage",
                "quick_probe" if f in quick else "deep_scan")

        # Steps 5+6: verify + privilege per finding
        verified: list[dict] = []
        for f in all_findings:
            v = await _timed(f"verify_{len(verified)}", self.verify(ctx, f))
            if v is None:
                continue
            p = await _timed(f"privcheck_{len(verified)}", self.privilege_check(ctx, v))
            verified.append(p or v)

        # Step 7: chain hand-off suggestions
        next_scanners = await _timed("chain_handoff", self.chain_handoff(ctx, verified)) or []
        if next_scanners:
            ctx.state["chain_next"] = next_scanners

        ctx.state["methodology_findings"] = verified
        ctx.state["methodology_total"] = len(verified)

    async def run_as_endpoint(self, req, finding_rules, intel_fields):
        """Convenience wrapper that adapts MethodologyScanner.run() to the
        existing run_scanner() framework so endpoint code stays one-liner.

        Endpoint pattern:
            scanner = HydraSshSpray()
            return await scanner.run_as_endpoint(req,
                finding_rules=HYDRA_SSH_SPRAY_FINDING_RULES,
                intel_fields=INTEL_FIELDS)
        """
        options = getattr(req, "options", None) or {}
        scanner_self = self

        async def _gather_with_method(ctx: ScanContext):
            ctx.state["_options"] = options
            await scanner_self.run(ctx)

        return await run_scanner(
            host=getattr(req, "target", ""),
            tool=self.name,
            gather_func=_gather_with_method,
            finding_rules=finding_rules,
            intel_fields=intel_fields,
            flat_field_keys=[],
        )
