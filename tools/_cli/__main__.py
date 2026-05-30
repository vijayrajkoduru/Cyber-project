"""VulnusLab CLI entrypoint.

Usage:
  python -m tools._cli list                          — list all modules
  python -m tools._cli list --module recon           — list recon tier structure
  python -m tools._cli scan TARGET --module recon    — run all recon scanners on TARGET
  python -m tools._cli scan TARGET --module recon --tool dns_records  — single tool
  python -m tools._cli scan TARGET --module recon --format json       — JSON output
  python -m tools._cli scan TARGET --module recon --format pdf -o report.pdf

Examples:
  # CI/CD smoke test:
  python -m tools._cli scan https://example.com --module recon --severity-fail high

  # Sales demo:
  python -m tools._cli list

Auth: set VULNUSLAB_TOKEN env var (JWT from /api/auth/login response).
Backend: set VULNUSLAB_URL env var (default: http://localhost:8000).
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from typing import Optional


def _api(method: str, path: str, body: Optional[dict] = None,
          token: Optional[str] = None, timeout: int = 60):
    base = os.environ.get("VULNUSLAB_URL", "http://localhost:8000")
    url = base.rstrip("/") + path
    headers = {"Accept": "application/json"}
    if token: headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try: body = json.loads(e.read().decode() or "{}")
        except Exception: body = {"detail": "(non-JSON)"}
        return e.code, body


def cmd_list(args):
    code, data = _api("GET", "/api/manifest")
    if code != 200:
        print(f"manifest fetch failed: {code} {data}", file=sys.stderr); return 1
    if args.module:
        for m in data.get("modules", []):
            if m["slug"] == args.module:
                print(f"\nModule: {m['slug']}  ({m['endpoint_count']} endpoints)")
                print(f"  Playbook: module_playbooks/{m.get('playbook','?')}")
                print(f"  Streaming run_all: {'yes' if m.get('has_run_all') else 'no'}")
                print(f"\nEndpoints:")
                for ep in m.get("endpoints", [])[:50]:
                    print(f"  /api/{m['slug']}/{ep}")
                if len(m.get("endpoints",[])) > 50:
                    print(f"  ... and {len(m['endpoints'])-50} more")
                return 0
        print(f"module '{args.module}' not found", file=sys.stderr); return 1
    print(f"\nVulnusLab API v{data.get('version','?')}  —  {data.get('total_modules',0)} modules, "
          f"{data.get('total_endpoints',0)} total endpoints\n")
    for m in data.get("modules", []):
        marker = "✓" if m.get("has_run_all") else " "
        print(f"  {marker}  {m['slug']:20s}  {m['endpoint_count']:>4} endpoints  "
              f"{'module_playbooks/' + (m.get('playbook') or '?')}")
    return 0


def cmd_scan(args):
    token = os.environ.get("VULNUSLAB_TOKEN")
    if not token:
        print("error: VULNUSLAB_TOKEN env var required. Get a JWT from POST /api/auth/login.",
              file=sys.stderr); return 2

    target = args.target
    module = args.module
    body = {"target": target}

    sev_rank = {"critical":4,"high":3,"medium":2,"low":1,"info":0,"positive":0}
    fail_at = sev_rank.get((args.severity_fail or "").lower(), 100)

    if args.tool:
        code, data = _api("POST", f"/api/{module}/{args.tool}", body=body, token=token, timeout=120)
        if code != 200:
            print(f"scan failed: {code} {data}", file=sys.stderr); return 1
        if args.format == "json":
            print(json.dumps(data, indent=2))
        else:
            _print_human(data)
        # Severity gate
        sev = (data.get("severity") or "info").lower()
        if sev_rank.get(sev,0) >= fail_at:
            print(f"\n[FAIL] severity={sev.upper()} >= threshold={args.severity_fail.upper()}",
                  file=sys.stderr); return 1
        return 0

    # Bulk run via run_all (NDJSON streaming)
    code, data = _api("GET", f"/api/{module}/run_all/tiers", token=token)
    if code != 200:
        print(f"tier discovery failed: {code} {data}", file=sys.stderr); return 1
    total = data.get("total_tools", 0)
    print(f"Running {total} {module} scanners against {target}...\n", file=sys.stderr)

    base = os.environ.get("VULNUSLAB_URL", "http://localhost:8000")
    url = f"{base.rstrip('/')}/api/{module}/run_all"
    headers = {"Content-Type":"application/json", "Authorization":f"Bearer {token}", "Accept":"application/x-ndjson"}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    results = []
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            buf = ""
            for chunk in iter(lambda: r.read(8192), b""):
                if not chunk: break
                buf += chunk.decode("utf-8", errors="ignore")
                lines = buf.split("\n"); buf = lines.pop() or ""
                for line in lines:
                    if not line.strip(): continue
                    try:
                        ev = json.loads(line)
                        if ev.get("type") == "result" and ev.get("tool"):
                            sev = (ev.get("data",{}).get("severity") or "info").lower()
                            badge = sev.upper().ljust(8)
                            print(f"  [{badge}] {ev['tool']}", file=sys.stderr)
                            results.append({"tool":ev["tool"], "severity":sev,
                                             "findings":ev.get("data",{}).get("findings",[])})
                    except Exception: pass
    except Exception as e:
        print(f"stream error: {e}", file=sys.stderr); return 1

    # Aggregate severity
    counts = {s:0 for s in sev_rank}
    for r in results:
        counts[r["severity"]] = counts.get(r["severity"],0) + 1
    print(f"\n  TOTAL: {len(results)}/{total}  "
          f"CRITICAL={counts['critical']}  HIGH={counts['high']}  "
          f"MEDIUM={counts['medium']}  LOW={counts['low']}", file=sys.stderr)

    if args.format == "json":
        print(json.dumps({"target":target,"module":module,"counts":counts,"results":results}, indent=2))

    # Severity gate
    worst_rank = max((sev_rank.get(r["severity"],0) for r in results), default=0)
    if worst_rank >= fail_at:
        worst_name = next((k for k,v in sev_rank.items() if v==worst_rank), "info")
        print(f"\n[FAIL] worst severity={worst_name.upper()} >= threshold={args.severity_fail.upper()}",
              file=sys.stderr); return 1
    return 0


def _print_human(data):
    print(f"  tool:      {data.get('tool')}")
    print(f"  target:    {data.get('target')}")
    print(f"  severity:  {data.get('severity')}")
    for f in data.get("findings", []):
        print(f"\n    [{f.get('severity','?')}] {f.get('detail','')[:80]}")
        if f.get("evidence_marker"): print(f"      evidence: {f['evidence_marker'][:100]}")
        if f.get("remediation"):     print(f"      fix:      {f['remediation'][:120]}")


def main():
    p = argparse.ArgumentParser(prog="vulnuslab", description="VulnusLab CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    lst = sub.add_parser("list", help="List modules / module details")
    lst.add_argument("--module", help="Inspect a specific module's endpoints")
    lst.set_defaults(func=cmd_list)

    scan = sub.add_parser("scan", help="Run a module scan against a target")
    scan.add_argument("target", help="Target host/URL/IP")
    scan.add_argument("--module", required=True, help="Module slug (recon, vuln, network, ...)")
    scan.add_argument("--tool", help="Single tool slug (skip to run all)")
    scan.add_argument("--format", choices=["human","json"], default="human")
    scan.add_argument("--severity-fail",
                       choices=["critical","high","medium","low","info"],
                       help="Exit non-zero if any finding meets/exceeds this severity")
    scan.set_defaults(func=cmd_scan)

    args = p.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
