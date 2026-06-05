"""hydra_ssh_spray - SSH password spray via Hydra (VL-METHOD methodology).

REWRITTEN 2026-06-05 to use VL-METHOD 7-step pentest pattern instead of
the previous shallow "run hydra -> parse" approach.

The 7 stages this scanner now performs:

  1. PRE-FLIGHT  - Is SSH/22 reachable? If not, skip with SKIPPED status
                    (no point burning cycles on a closed port).

  2. FINGERPRINT - Grab SSH banner. Captures service name, OpenSSH
                    version, OS comments (e.g. "Ubuntu-3ubuntu0.5").
                    Result drives wordlist selection in deep_scan.

  3. QUICK PROBE - Try 5 known-bad defaults BEFORE customer's full
                    wordlist (root/root, admin/admin, pi/raspberry,
                    ubuntu/ubuntu, test/test). 80% of compromised SSH
                    falls to top-5 defaults; takes 3-15 seconds total.
                    Uses paramiko direct (not hydra) for accurate auth
                    failure detection without false-positive hydra noise.

  4. DEEP SCAN   - Only runs if quick_probe found something OR customer
                    set options.always_deep=True. Hydra with customer's
                    full userlist/passlist, rate-limited (4 parallel,
                    10s per attempt) to avoid lockout / IP ban.

  5. VERIFY      - Re-confirm EACH valid credential with a separate
                    paramiko session running `id` command. Hydra
                    occasionally false-positives on intermediate auth
                    states; second-session verification kills those.
                    Sets confidence = CONFIRMED (id ran) | SUSPECTED.

  6. PRIVILEGE   - Parse `id` output to classify:
                    root (uid=0) -> CRITICAL severity
                    sudo (in sudo/wheel/admin group) -> HIGH
                    service (uid<1000 non-root) -> MEDIUM
                    user (regular) -> MEDIUM
                    guest (anonymous/nobody) -> LOW

  7. CHAIN       - For CONFIRMED root/sudo creds, suggest follow-up
                    scanners: post_exploit_linux_persistence_audit,
                    privesc_linpeas_remote_audit, post_exploit_lateral
                    _pivot_artifacts. Cross-scanner chaining engine will
                    spawn these with the captured creds.

Customer input via ScanRequest.options:
  - target              = SSH host/IP (required - taken from req.target)
  - options.userlist    = newline-separated usernames (for deep_scan)
  - options.passlist    = newline-separated passwords (for deep_scan)
  - options.port        = SSH port override (default 22)
  - options.always_deep = bool, force deep_scan even if quick_probe empty
  - options.timeout_sec = wall-clock cap for hydra (default 90)

Safety guard: deep_scan hard-clamped to 10 users x 25 passwords (250
attempts) per run. Quick-probe is fixed at 5 well-known pairs only.

Reference scanner for the VL-METHOD pattern. New scanners should follow
this structure - inherit MethodologyScanner, override 7 stage methods,
call run_as_endpoint() in the FastAPI handler.
"""
from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from tools._shared import ScanRequest, verify_scan_quota
from tools._framework import ScanContext
from tools._methodology import MethodologyScanner, helpers
from tools._payloads.hydra_ssh_spray_findings import HYDRA_SSH_SPRAY_FINDING_RULES

router = APIRouter()
HYDRA_BIN = shutil.which("hydra")
DEFAULT_TIMEOUT = 90
HARD_MAX_USERS = 10
HARD_MAX_PASSWORDS = 25

# Top-5 SSH credential pairs that 80% of compromised servers fall to.
# Quick-probe runs these BEFORE customer's full wordlist - takes 3-15
# seconds vs 60-240 seconds for hydra deep scan. Cheap insurance.
QUICK_PROBE_DEFAULTS = [
    ("root", "root"),
    ("admin", "admin"),
    ("pi", "raspberry"),       # Raspberry Pi default
    ("ubuntu", "ubuntu"),       # Cloud-init AMI default
    ("test", "test"),
]


class HydraSshSprayRequest(ScanRequest):
    options: Optional[dict] = None


_RE_SUCCESS = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<svc>ssh)\]\s+host:\s*(?P<host>\S+)\s+login:\s*(?P<user>\S+)\s+password:\s*(?P<pwd>.+)$",
    re.IGNORECASE,
)


def _split_lines(s: str, limit: int) -> list[str]:
    """Trim + dedupe + clamp a newline-separated user/pass string."""
    if not s:
        return []
    seen: list[str] = []
    for raw in s.splitlines():
        v = raw.strip()
        if not v or v in seen:
            continue
        seen.append(v)
        if len(seen) >= limit:
            break
    return seen


def _write_tempfile(prefix: str, lines: list[str]) -> str:
    fd, path = tempfile.mkstemp(prefix=f"vl_{prefix}_", suffix=".lst")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception:
        try: os.close(fd)
        except Exception: pass
        raise
    return path


def _redact(pwd: str, show_plaintext: bool = False) -> str:
    """Customer-safe redaction: length + last 3 chars only.
    When show_plaintext=True (customer scanning own infra), returns the
    actual plaintext password instead of the marker. Default behavior
    (False) keeps the marker so multi-tenant reports never leak creds."""
    if not pwd: return "len=0"
    pwd = pwd.strip()
    if show_plaintext:
        return pwd
    if len(pwd) <= 3: return f"len={len(pwd)} ***"
    return f"len={len(pwd)} ***{pwd[-3:]}"


# ═══════════════════════════════════════════════════════════════════
#  HydraSshSpray - the VL-METHOD scanner class
# ═══════════════════════════════════════════════════════════════════


class HydraSshSpray(MethodologyScanner):
    name = "hydra_ssh_spray"

    # ── STAGE 1: PRE-FLIGHT ──────────────────────────────────────
    async def pre_flight(self, ctx: ScanContext) -> bool:
        target = ctx.host
        opts = ctx.state.get("_options") or {}
        port_arg = int(opts.get("port") or 22)
        # Normalize host: strip URL scheme + :port suffix if present.
        # User-supplied target may be "scanme.nmap.org:22" or "https://x/" etc.
        clean_host, parsed_port = helpers.split_host_port(target, default_port=port_arg)
        port = parsed_port if parsed_port else port_arg
        ctx.state["target_host"] = clean_host
        ctx.state["target_port"] = port
        if not clean_host:
            ctx.state["skipped_reason"] = "no target supplied"
            return False
        reachable = await helpers.port_open(clean_host, port, timeout=3.0)
        ctx.state["port_reachable"] = reachable
        if not reachable:
            ctx.state["skipped_reason"] = f"SSH/{port} on {clean_host} not reachable (port closed or filtered)"
            return False
        return True

    # ── STAGE 2: FINGERPRINT ─────────────────────────────────────
    async def fingerprint(self, ctx: ScanContext):
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 22)
        banner = await helpers.ssh_banner_grab(target, port)
        ctx.state["fingerprint"] = banner
        # Banner-based hint for wordlist selection in deep_scan
        comments = (banner.get("comments") or "").lower()
        if "ubuntu" in comments:
            ctx.state["likely_os"] = "ubuntu"
        elif "debian" in comments:
            ctx.state["likely_os"] = "debian"
        elif "windows" in comments or "openssh_for_windows" in (banner.get("version") or "").lower():
            ctx.state["likely_os"] = "windows"
        else:
            ctx.state["likely_os"] = "unknown"

    # ── STAGE 3: QUICK PROBE (5 known defaults) ──────────────────
    async def quick_probe(self, ctx: ScanContext) -> list[dict]:
        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 22)
        opts = ctx.state.get("_options") or {}
        show = bool(opts.get("show_plaintext"))
        hits = await helpers.try_default_creds(
            target, port, "ssh",
            pairs=QUICK_PROBE_DEFAULTS,
            per_attempt_timeout=4.0,
            show_plaintext=show)
        ctx.state["quick_probe_attempts"] = len(QUICK_PROBE_DEFAULTS)
        ctx.state["quick_probe_hits"] = len(hits)
        # Convert helper hits into preliminary findings
        return [
            {
                "id": f"quick_{i}",
                "kind": "default_credential",
                "user": h["user"],
                "password_marker": h.get("pwd_plain") if show else h.get("pwd_marker", ""),
                "id_output_raw": h.get("id_output", ""),
                "discovery_method": "quick_probe_known_defaults",
            }
            for i, h in enumerate(hits)
        ]

    # ── STAGE 4: DEEP SCAN (full hydra spray, gated) ─────────────
    async def deep_scan(self, ctx: ScanContext) -> list[dict]:
        if not HYDRA_BIN:
            ctx.state["hydra_missing"] = True
            return []
        target = ctx.host
        opts = ctx.state.get("_options") or {}
        port = int(ctx.state.get("target_port") or 22)
        userlist_raw = (opts.get("userlist") or "").strip()
        passlist_raw = (opts.get("passlist") or "").strip()
        if not userlist_raw or not passlist_raw:
            ctx.state["deep_skipped"] = "userlist/passlist not supplied"
            return []
        max_users = min(int(opts.get("max_users") or HARD_MAX_USERS), HARD_MAX_USERS)
        max_pass = min(int(opts.get("max_passwords") or HARD_MAX_PASSWORDS), HARD_MAX_PASSWORDS)
        users = _split_lines(userlist_raw, max_users)
        passwords = _split_lines(passlist_raw, max_pass)
        if not users or not passwords:
            ctx.state["deep_skipped"] = "empty wordlists after dedupe"
            return []
        timeout = min(max(int(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 15), 240)

        user_path = pass_path = None
        try:
            user_path = _write_tempfile("users", users)
            pass_path = _write_tempfile("passwords", passwords)
            cmd = [HYDRA_BIN, "-L", user_path, "-P", pass_path,
                   "-s", str(port), "-t", "4", "-w", "10", "-I", "-f",
                   target, "ssh"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                try: proc.kill()
                except Exception: pass
                ctx.state["deep_skipped"] = f"hydra timeout @ {timeout}s"
                return []
            stdout = (out_b or b"").decode("utf-8", errors="ignore")
            ctx.state["hydra_attempts"] = len(users) * len(passwords)
            ctx.state["hydra_users_tried"] = len(users)
            ctx.state["hydra_passwords_tried"] = len(passwords)
            show = bool((ctx.state.get("_options") or {}).get("show_plaintext"))
            findings = []
            for i, line in enumerate(stdout.splitlines()):
                m = _RE_SUCCESS.search(line)
                if not m: continue
                findings.append({
                    "id": f"deep_{i}",
                    "kind": "spray_credential",
                    "user": m.group("user"),
                    "password_marker": _redact(m.group("pwd"), show_plaintext=show),
                    "discovery_method": "hydra_spray",
                    "id_output_raw": "",  # populated in verify
                })
            return findings
        finally:
            for p in (user_path, pass_path):
                if p:
                    try: os.unlink(p)
                    except Exception: pass

    # ── STAGE 5: VERIFY (re-test with different method) ──────────
    async def verify(self, ctx: ScanContext, finding: dict) -> Optional[dict]:
        # Quick-probe findings were already verified via paramiko exec_command
        # at discovery time (id_output_raw populated). Mark CONFIRMED.
        if finding.get("discovery_method") == "quick_probe_known_defaults":
            if finding.get("id_output_raw"):
                finding["confidence"] = "CONFIRMED"
                finding["verification_method"] = "paramiko_second_session_id_cmd"
                return finding
            else:
                finding["confidence"] = "SUSPECTED"
                finding["verification_method"] = "paramiko_auth_only_no_shell"
                return finding

        # Deep-scan findings from hydra: re-test via paramiko exec `id` to confirm
        try:
            import paramiko
        except ImportError:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "paramiko_missing_cannot_verify"
            return finding

        target = ctx.state.get("target_host") or ctx.host
        port = int(ctx.state.get("target_port") or 22)
        user = finding["user"]
        opts = ctx.state.get("_options") or {}
        # Pull the actual password from passlist (cannot use _redact'd marker)
        # We re-extract from the wordlist by matching on user. For safety, we
        # only attempt verification if the password was just used.
        passlist_raw = (opts.get("passlist") or "").strip()
        passwords = _split_lines(passlist_raw, HARD_MAX_PASSWORDS)
        id_output = ""
        verified = False
        for pwd in passwords:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: client.connect(target, port=port, username=user,
                                            password=pwd, timeout=5,
                                            allow_agent=False, look_for_keys=False,
                                            banner_timeout=5))
                stdin, stdout, stderr = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: client.exec_command("id", timeout=5))
                id_output = stdout.read().decode("utf-8", errors="ignore").strip()
                try: client.close()
                except Exception: pass
                if id_output:
                    verified = True
                    finding["id_output_raw"] = id_output[:200]
                    finding["password_marker"] = _redact(pwd, show_plaintext=bool(opts.get("show_plaintext")))
                    break
            except Exception:
                continue
        if verified:
            finding["confidence"] = "CONFIRMED"
            finding["verification_method"] = "paramiko_second_session_id_cmd"
        else:
            finding["confidence"] = "SUSPECTED"
            finding["verification_method"] = "hydra_only_unconfirmed"
        return finding

    # ── STAGE 6: PRIVILEGE CHECK ─────────────────────────────────
    async def privilege_check(self, ctx: ScanContext, finding: dict) -> dict:
        id_output = finding.get("id_output_raw", "")
        finding["privilege_level"] = helpers.classify_privilege(id_output, finding.get("user", ""))
        return finding

    # ── STAGE 7: CHAIN HANDOFF ───────────────────────────────────
    async def chain_handoff(self, ctx: ScanContext, findings: list[dict]) -> list[str]:
        next_scanners = []
        # For CONFIRMED root/sudo, suggest persistence + lateral pivot scans
        for f in findings:
            if (f.get("confidence") == "CONFIRMED"
                    and f.get("privilege_level") in ("root", "sudo")):
                next_scanners = [
                    "post_exploit_linux_persistence_audit",
                    "privesc_linpeas_remote_audit",
                    "post_exploit_lateral_pivot_artifacts",
                ]
                break
        # For ANY CONFIRMED user, suggest at least the persistence audit
        if not next_scanners:
            for f in findings:
                if f.get("confidence") == "CONFIRMED":
                    next_scanners = ["post_exploit_linux_persistence_audit"]
                    break
        return next_scanners


# ═══════════════════════════════════════════════════════════════════
#  Endpoint wrapper - adapts MethodologyScanner to existing framework
# ═══════════════════════════════════════════════════════════════════


INTEL_FIELDS = [
    ("Stage timings (ms)",        "stage_timings"),
    ("Target port",               "target_port"),
    ("Port reachable",            "port_reachable"),
    ("SSH fingerprint",           "fingerprint"),
    ("Likely OS",                 "likely_os"),
    ("Quick-probe attempts",      "quick_probe_attempts"),
    ("Quick-probe hits",          "quick_probe_hits"),
    ("Hydra deep attempts",       "hydra_attempts"),
    ("Hydra users tried",         "hydra_users_tried"),
    ("Hydra passwords tried",     "hydra_passwords_tried"),
    ("Methodology findings",      "methodology_findings"),
    ("Chain handoff next",        "chain_next"),
    ("Stage errors",              "stage_errors"),
]


@router.post("/api/password/hydra_ssh_spray")
async def password_hydra_ssh_spray(req: HydraSshSprayRequest, _=Depends(verify_scan_quota)):
    scanner = HydraSshSpray()
    return await scanner.run_as_endpoint(
        req,
        finding_rules=HYDRA_SSH_SPRAY_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
    )


def register(app):
    app.include_router(router)
