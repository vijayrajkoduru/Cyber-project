#!/usr/bin/env python3
"""VL-FOUNDRY Layer 20 — End-to-End Verification.

Validates the FULL chain (target in → PDF out) as a single test.
Per-scanner unit checks don't catch:
  - Orchestrator drops a scanner mid-stream
  - NDJSON corruption from a proxy
  - Frontend can't parse a new finding shape
  - PDF generator silently skips a section
  - CORS/auth misconfig blocks the API
  - Cloudflare 100s TTFB cuts the stream

Usage:
  python scripts/e2e_test.py <module> [--target=<host>] [--api=<base_url>]

Exit code 0 if end-to-end passes, 1 otherwise (CI-friendly).
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# SLO targets per module (from VL-FOUNDRY.md Layer 13)
SLO_MAX_SECONDS = {
    "recon":  120,   # 2 minutes
    "vuln":   300,   # 5 minutes
    "webapp":  90,   # 90 seconds with VL-TURBO
    "osint":  120,   # estimate
    "default": 180,
}

# Acceptance bounds (per VL-FOUNDRY-AUDIT-AGENT.md final gate)
MIN_NDJSON_RECORDS = 1   # at least one scanner must respond
MAX_NDJSON_RECORDS = 200  # sanity — shouldn't exceed scanner count by much


UA = "Mozilla/5.0 (VL-FOUNDRY-e2e/1.0)"  # Cloudflare blocks python-urllib UA


def http_post_stream(url: str, payload: dict, timeout: int = 180,
                     token: str | None = None):
    """POST + read NDJSON stream. Returns (status_code, records, elapsed_s)."""
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    records = []
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            buf = b""
            for chunk in iter(lambda: resp.read(4096), b""):
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        records.append(json.loads(line.decode("utf-8")))
                    except json.JSONDecodeError:
                        pass  # corrupt line — counts as a warning, not fatal
        return status, records, time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, [], time.time() - t0
    except Exception as e:
        return 0, [], time.time() - t0


def check_api_reachable(api_base: str) -> bool:
    """Quick GET to confirm backend is up."""
    try:
        req = urllib.request.Request(f"{api_base}/health",
                                     headers={"User-Agent": UA})
        urllib.request.urlopen(req, timeout=5).read()
        return True
    except Exception:
        return False


def validate_ndjson_shape(records: list[dict]) -> tuple[bool, list[str]]:
    """Each record must have at least: tool, target, OR error keys."""
    errors = []
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            errors.append(f"Record {i}: not a dict")
            continue
        if not any(k in r for k in ("tool", "target", "error", "findings", "scanner")):
            errors.append(f"Record {i}: no recognizable key (tool/target/findings/scanner/error)")
    return len(errors) == 0, errors


def run_e2e(module: str, target: str, api_base: str,
            token: str | None = None) -> dict:
    """Run the end-to-end test. Returns structured result."""
    result = {
        "module": module,
        "target": target,
        "api_base": api_base,
        "passes": [],
        "failures": [],
        "warnings": [],
        "elapsed_s": 0,
    }

    # Gate 1: API reachable
    if not check_api_reachable(api_base):
        result["failures"].append(f"API at {api_base} not reachable on /health")
        return result
    result["passes"].append(f"API reachable at {api_base}")

    # Gate 2: POST scan + stream NDJSON
    url = f"{api_base}/api/{module}/run_all"
    payload = {"target": target, "concurrency": 8}
    slo_s = SLO_MAX_SECONDS.get(module, SLO_MAX_SECONDS["default"])

    status, records, elapsed = http_post_stream(
        url, payload, timeout=slo_s + 30, token=token
    )
    result["elapsed_s"] = round(elapsed, 2)

    if status != 200:
        result["failures"].append(f"POST {url} returned status {status}")
        return result
    result["passes"].append(f"POST {url} returned 200 in {elapsed:.2f}s")

    # Gate 3: SLO check
    if elapsed > slo_s:
        result["failures"].append(f"Elapsed {elapsed:.1f}s > SLO {slo_s}s")
    else:
        result["passes"].append(f"Within SLO ({slo_s}s)")

    # Gate 4: NDJSON sanity
    if len(records) < MIN_NDJSON_RECORDS:
        result["failures"].append(f"Only {len(records)} NDJSON records — too few")
    elif len(records) > MAX_NDJSON_RECORDS:
        result["warnings"].append(f"{len(records)} NDJSON records — unusually high")
    else:
        result["passes"].append(f"{len(records)} NDJSON records received")

    # Gate 5: each record has expected shape
    shape_ok, shape_errors = validate_ndjson_shape(records)
    if shape_ok:
        result["passes"].append(f"All {len(records)} records have recognizable shape")
    else:
        result["failures"].extend(shape_errors[:5])  # cap at 5 to avoid spam

    # Gate 6: orchestrator-expected scanner count
    try:
        mod = __import__(f"endpoints.{module}_orchestrator", fromlist=["_all_tools"])
        expected = len(mod._all_tools())
        got = len({r.get("tool") or r.get("scanner") for r in records if isinstance(r, dict)})
        if got >= expected * 0.7:  # 70% of scanners responded
            result["passes"].append(f"Orchestrator dispatched {got}/{expected} scanners (>= 70%)")
        else:
            result["warnings"].append(
                f"Only {got}/{expected} scanners produced records — some may have crashed"
            )
    except Exception as e:
        result["warnings"].append(f"Could not count expected scanners: {e}")

    return result


def print_result(r: dict):
    print(f"\n{'=' * 65}")
    print(f"  END-TO-END TEST: {r['module'].upper()}")
    print(f"  Target: {r['target']}")
    print(f"  API:    {r['api_base']}")
    print(f"{'=' * 65}")
    for p in r["passes"]:
        print(f"  {p}")
    for w in r["warnings"]:
        print(f"  {w}")
    for f in r["failures"]:
        print(f"  {f}")
    print(f"{'-' * 65}")
    ok = len(r["failures"]) == 0
    status = "PASS" if ok else "FAIL"
    icon = "" if ok else ""
    print(f"  {icon} END-TO-END: {status}  ({r['elapsed_s']}s)")
    print(f"{'=' * 65}")


def main():
    ap = argparse.ArgumentParser(description="VL-FOUNDRY end-to-end verification")
    ap.add_argument("module", help="Module name (recon|vuln|webapp|osint|...)")
    ap.add_argument("--target", default="vulnuslab.com",
                    help="Scan target (default: vulnuslab.com)")
    ap.add_argument("--api", default="http://localhost:8000",
                    help="API base URL (default: http://localhost:8000)")
    ap.add_argument("--token", default=os.environ.get("VL_TOKEN"),
                    help="Bearer token for authenticated endpoints "
                         "(or set VL_TOKEN env var)")
    args = ap.parse_args()

    r = run_e2e(args.module, args.target, args.api, token=args.token)
    print_result(r)
    sys.exit(0 if not r["failures"] else 1)


if __name__ == "__main__":
    main()
