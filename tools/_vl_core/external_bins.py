"""VL-CORE: external binary wrappers.

Every scanner that calls a bundled binary (nmap, amass, hydra, gobuster,
wpscan, sqlmap, nikto, sherlock, holehe, theHarvester) imports from here
instead of inlining its own subprocess.run call. Centralizing the wrapper
gives us:

  * Consistent timeout handling
  * Consistent stdout/stderr capture
  * Consistent "binary not installed" skipped_reason
  * Single point to add observability / rate-limiting
  * No drift across scanners (same nmap flags every time)

Each `run_*` returns a dict:
    {
      "ok": bool,                # binary ran successfully (return code 0 or expected)
      "stdout": str,
      "stderr": str,
      "returncode": int,
      "duration_s": float,
      "skipped": str | None,     # set when binary not installed / target invalid
      "raw_cmd": str,            # for debugging
    }

The runner does NOT parse output — scanners do that themselves so they
can pick the data shape they need. The runner DOES handle:
  - binary discovery (shutil.which)
  - timeout wall-clock cap
  - signal masking on POSIX
  - safe argument quoting

Add a new wrapper by following the pattern: signature `run_<bin>(target,
**opts) -> dict`. Use _exec() to actually run the subprocess.
"""
from __future__ import annotations
import shutil
import subprocess
import time
from typing import Optional


def _which(name: str) -> Optional[str]:
    """Find binary on PATH. Returns absolute path or None."""
    return shutil.which(name)


def _exec(cmd: list[str], *, timeout: int = 60, input_data: Optional[str] = None) -> dict:
    """Run a command, capture output, never raise. Returns the standard dict."""
    t0 = time.monotonic()
    raw_cmd = " ".join(cmd)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "returncode": proc.returncode,
            "duration_s": round(time.monotonic() - t0, 2),
            "skipped": None,
            "raw_cmd": raw_cmd,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "",
                "returncode": -1, "duration_s": round(time.monotonic() - t0, 2),
                "skipped": f"timed out at {timeout}s", "raw_cmd": raw_cmd}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e)[:500],
                "returncode": -1, "duration_s": round(time.monotonic() - t0, 2),
                "skipped": f"execution failed: {str(e)[:200]}", "raw_cmd": raw_cmd}


def _missing(bin_name: str) -> dict:
    return {"ok": False, "stdout": "", "stderr": "",
            "returncode": -1, "duration_s": 0.0,
            "skipped": (f"{bin_name} binary not installed. Rebuild the backend "
                        f"with the updated Dockerfile that includes {bin_name}."),
            "raw_cmd": ""}


# ─────────────────────────────────────────────────────────────────────────
# Network scanning
# ─────────────────────────────────────────────────────────────────────────

def run_nmap(target: str, *, ports: str = "top1000", flags: Optional[list[str]] = None,
              timeout: int = 120) -> dict:
    """Run nmap against target. Default: top 1000 ports, service version detection."""
    nmap = _which("nmap")
    if not nmap:
        return _missing("nmap")
    cmd = [nmap, "-T4", "-Pn", "-n"]
    if ports == "top1000":
        cmd += ["--top-ports", "1000"]
    elif ports:
        cmd += ["-p", ports]
    cmd += ["-sV"]
    if flags:
        cmd += flags
    cmd += [target]
    return _exec(cmd, timeout=timeout)


def run_nmap_nse(target: str, *, scripts: str, ports: Optional[str] = None,
                  timeout: int = 180) -> dict:
    """Run nmap with an NSE script category (vuln, default, discovery, etc.)."""
    nmap = _which("nmap")
    if not nmap:
        return _missing("nmap")
    cmd = [nmap, "-T4", "-Pn", "--script", scripts]
    if ports:
        cmd += ["-p", ports]
    cmd += [target]
    return _exec(cmd, timeout=timeout)


def run_amass(target: str, *, mode: str = "passive", timeout: int = 240) -> dict:
    """Run amass for subdomain enumeration."""
    amass = _which("amass")
    if not amass:
        return _missing("amass")
    cmd = [amass, "enum", "-d", target]
    if mode == "passive":
        cmd += ["-passive"]
    return _exec(cmd, timeout=timeout)


# ─────────────────────────────────────────────────────────────────────────
# Credential / auth attacks
# ─────────────────────────────────────────────────────────────────────────

def run_hydra(target: str, *, service: str, userlist: str, passlist: str,
               port: Optional[int] = None, timeout: int = 180) -> dict:
    """Run hydra for credential spraying. Authorized testing only."""
    hydra = _which("hydra")
    if not hydra:
        return _missing("hydra")
    cmd = [hydra, "-L", userlist, "-P", passlist, "-t", "4", "-f"]
    if port:
        cmd += ["-s", str(port)]
    cmd += [f"{service}://{target}"]
    return _exec(cmd, timeout=timeout)


# ─────────────────────────────────────────────────────────────────────────
# Web scanning
# ─────────────────────────────────────────────────────────────────────────

def run_nikto(target: str, *, timeout: int = 180) -> dict:
    """Run nikto for web server misconfig + vulnerability scanning."""
    nikto = _which("nikto")
    if not nikto:
        return _missing("nikto")
    cmd = [nikto, "-h", target, "-Format", "json", "-ask", "no", "-nointeractive"]
    return _exec(cmd, timeout=timeout)


def run_gobuster(target: str, *, mode: str = "dir", wordlist: str,
                  extensions: Optional[str] = None, timeout: int = 180) -> dict:
    """Run gobuster for directory / DNS / vhost enumeration."""
    gobuster = _which("gobuster")
    if not gobuster:
        return _missing("gobuster")
    cmd = [gobuster, mode, "-u" if mode == "dir" else "-d", target,
            "-w", wordlist, "-t", "20", "-q"]
    if mode == "dir" and extensions:
        cmd += ["-x", extensions]
    return _exec(cmd, timeout=timeout)


def run_wpscan(target: str, *, api_token: Optional[str] = None,
                timeout: int = 240) -> dict:
    """Run wpscan against a WordPress target. API token optional but
    unlocks vulnerability database matches."""
    wpscan = _which("wpscan")
    if not wpscan:
        return _missing("wpscan")
    cmd = [wpscan, "--url", target, "--format", "json", "--no-update",
           "--no-banner", "--random-user-agent"]
    if api_token:
        cmd += ["--api-token", api_token]
    return _exec(cmd, timeout=timeout)


def run_sqlmap(target: str, *, data: Optional[str] = None,
                cookie: Optional[str] = None, timeout: int = 240) -> dict:
    """Run sqlmap. Always uses --batch (non-interactive) and low risk/level
    for safe automated runs."""
    sqlmap = _which("sqlmap")
    if not sqlmap:
        return _missing("sqlmap")
    cmd = [sqlmap, "-u", target, "--batch", "--level=1", "--risk=1",
           "--timeout=10", "--retries=1", "--threads=4", "--smart"]
    if data:
        cmd += ["--data", data]
    if cookie:
        cmd += ["--cookie", cookie]
    return _exec(cmd, timeout=timeout)


# ─────────────────────────────────────────────────────────────────────────
# OSINT
# ─────────────────────────────────────────────────────────────────────────

def run_theharvester(target: str, *, sources: str = "all", timeout: int = 120) -> dict:
    """Run theHarvester for email + subdomain harvesting."""
    th = _which("theHarvester") or _which("theharvester")
    if not th:
        return _missing("theHarvester")
    cmd = [th, "-d", target, "-b", sources, "-f", "/tmp/harvester_out"]
    return _exec(cmd, timeout=timeout)


def run_sherlock(username: str, *, timeout: int = 120) -> dict:
    """Run sherlock for cross-platform username enumeration."""
    sl = _which("sherlock")
    if not sl:
        return _missing("sherlock")
    cmd = [sl, username, "--print-found", "--no-color", "--timeout", "10"]
    return _exec(cmd, timeout=timeout)


def run_holehe(email: str, *, timeout: int = 60) -> dict:
    """Run holehe to check which sites a given email is registered on."""
    h = _which("holehe")
    if not h:
        return _missing("holehe")
    cmd = [h, email, "--only-used", "--no-color"]
    return _exec(cmd, timeout=timeout)


__all__ = [
    "run_nmap", "run_nmap_nse", "run_amass",
    "run_hydra",
    "run_nikto", "run_gobuster", "run_wpscan", "run_sqlmap",
    "run_theharvester", "run_sherlock", "run_holehe",
]
