# Lab & Scan Reliability Strategy

Goal: a user who opens a module and starts a scan always gets a working run.
No lab down, no backend 500, no frontend break reaching the user.

This was written after `/api/scan/login` returned HTTP 500 for every request:
a helper (`_resolve_underscore`) was *called* but defined nowhere, so the
route raised `NameError` at request time. Nothing caught it before the user.
The layers below each close one gap that let that happen, newest-first.

## Layer 1 — Catch crashing code before it merges (pre-commit)

`scripts/check_undefined.py` is a dependency-free (stdlib-only) static check.
For every function it builds the set of known names (builtins + module
globals + everything bound in the function) and flags any name used but
never defined — exactly the `_resolve_underscore` / missing-`import logging`
class. It also `py_compile`s each file to catch syntax errors.

Wired into `scripts/pre-commit-check.sh` (mirrored to `.git/hooks/pre-commit`),
so a commit touching `tools/`, `endpoints/`, `agents/` or `main.py` is blocked
if it would crash at runtime.

Run manually any time:

    python3 -I scripts/check_undefined.py

## Layer 2 — Catch broken scans before users do (deploy gate)

`safe_deploy.sh b` now:
1. runs the Layer-1 static check and refuses to build if it fails;
2. builds + recreates the backend, waits for `/api/health`;
3. runs `scripts/smoke_scan.sh`, which logs in and drives the real
   `/api/scan/login` against `lab_dvwa`, asserting a structured result and
   never a 5xx;
4. auto-reverts to the previous image if health OR the scan smoke fails.

`check.sh` remains the fast always-on health probe. The scan smoke needs a
smoke account; set it in `.env` (never hardcode):

    VL_SMOKE_USER=...
    VL_SMOKE_PASS=...

Without those the smoke self-skips (non-fatal) so deploys still work.

## Layer 3 — Keep labs up (runtime)

- Every web lab (`lab_dvwa`, `lab_juiceshop`, `lab_bwapp`, `lab_mutillidae`,
  `lab_webgoat`, `lab_metasploitable`) now has `restart: unless-stopped` in
  `docker-compose.yml`, and the policy was applied live to the running
  containers. Docker restarts any lab that crashes.
- A restart policy only recovers a container that *exits*. `scripts/lab_watchdog.sh`
  also recovers a lab that is hung (running but unhealthy) or missing, and
  logs to `data/lab_watchdog.log`. It only ever touches `lab_*` containers.

### One manual step (needs operator permission)

Install the watchdog on a 5-minute cron (blocked from automation for safety):

    ( crontab -l 2>/dev/null | grep -v lab_watchdog.sh; \
      echo "*/5 * * * * /root/Cyber-project/scripts/lab_watchdog.sh >/dev/null 2>&1" ) | crontab -

## Layer 4 — Already in place (observability / degradation)

- `main.py` has a global exception handler: any unhandled error is logged
  with method + path + traceback (`log.exception`) and returns a clean JSON
  500 instead of leaking internals. Check `docker logs vulnuslab_backend`.
- `/api/health` reports `tools_loaded` / `tools_failed` / `tools_healed`, so
  a tool that fails to load is visible without a crash.

## When something still breaks

1. `./check.sh` — is the backend/frontend healthy right now?
2. `python3 -I scripts/check_undefined.py` — any undefined-name landmine?
3. `bash scripts/smoke_scan.sh` — does the scan path actually work?
4. `./scripts/lab_watchdog.sh` — bring any down/hung lab back.
5. `docker logs --tail 100 vulnuslab_backend` — read the logged traceback.
