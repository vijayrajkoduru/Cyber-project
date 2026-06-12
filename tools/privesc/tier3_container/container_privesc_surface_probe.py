"""container_privesc_surface_probe - exposed container/orchestration control plane.

REAL, credential-LESS remote probe (playbook §7 #79-85, the remotely-checkable
subset). Checks whether the target externally exposes a container or
orchestration control plane that answers WITHOUT authentication:

  - Docker Engine API   2375 (HTTP)  /version + /info
  - Docker Engine API   2376 (HTTPS) /version  (verify=False; only header read)
  - Kubernetes kubelet  10250 (HTTPS) /pods
  - Kubernetes kubelet  10255 (HTTP)  /pods  (deprecated read-only port)
  - Kubernetes API      6443 (HTTPS) /version  (anonymous-auth check)

A graded severity is emitted ONLY when the endpoint ACTUALLY returns
recognizable control-plane data without credentials:
  - Docker API returning a JSON body with "ApiVersion"/"Containers"/"Images"
    or a Docker "Server" header  -> CRITICAL (instant host root for anyone
    who can reach it), stamped verified_exploit=True.
  - kubelet/API returning a pod list or k8s version JSON -> HIGH,
    stamped verified_exploit=True.

Reachability alone (open port, TLS handshake, 401/403 response) is reported as
INFO, NEVER graded — an authenticated control plane is doing the right thing.

The IMDS->IAM, privileged-container, capability-escape, runc Leaky Vessels,
K8s RBAC and EKS IRSA techniques require an on-host / in-cluster foothold and
are surfaced as advisory-by-design INFO via the finding rules.

This probe sends only benign read-only GETs (no auth, no payloads, no
exploitation, no chaining). On any error it degrades to a clean INFO.

Customer input via ScanRequest.options:
  - target              = host / IP (ctx.host)
  - options.timeout_sec = per-endpoint timeout (default 6, clamped 2..15)
  - options.ports       = optional list[int] to override the default port set
"""
from __future__ import annotations
import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._payloads.container_privesc_surface_probe_findings import (
    CONTAINER_PRIVESC_SURFACE_PROBE_FINDING_RULES,
)

router = APIRouter()

DEFAULT_TIMEOUT = 6

# (label, scheme, port, path, kind). kind drives which finding bucket a
# positive hit lands in.
_ENDPOINTS = [
    ("docker-api-http",  "http",  2375, "/version", "docker"),
    ("docker-api-tls",   "https", 2376, "/version", "docker"),
    ("kubelet-https",    "https", 10250, "/pods",    "kubelet"),
    ("kubelet-readonly", "http",  10255, "/pods",    "kubelet"),
    ("k8s-apiserver",    "https", 6443,  "/version", "kubelet"),
]

# Markers that prove the body came from the respective control plane.
_DOCKER_MARKERS = ("apiversion", "containers", "kernelversion", "dockerrootdir")
_K8S_MARKERS = ("kind", "podlist", "gitversion", "apiversion", "metadata")


class ContainerPrivescSurfaceProbeRequest(ScanRequest):
    options: Optional[dict] = None


def _probe_endpoint(scheme: str, host: str, port: int, path: str, timeout: float):
    """Blocking unauthenticated GET. Returns a dict describing the result.
    Never raises — captures errors into the result dict. Call inside executor.

    Result keys:
      reachable : bool  (got an HTTP response or a Docker 'Server' header)
      open      : bool  (returned recognizable control-plane data w/o auth)
      status    : int or None
      detail    : short string
    """
    import requests
    url = f"{scheme}://{host}:{port}{path}"
    out = {"reachable": False, "open": False, "status": None, "detail": ""}
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
            headers={"User-Agent": "VulnusLab/1.0 (privesc-container-surface)"},
        )
    except Exception as e:
        out["detail"] = str(e)[:120]
        return out

    out["reachable"] = True
    out["status"] = resp.status_code
    body = (resp.text or "")[:8000]
    body_low = body.lower()
    server_hdr = (resp.headers.get("Server") or "").lower()

    # An auth-enforcing endpoint answers 401/403 — reachable, NOT open.
    if resp.status_code in (401, 403):
        out["detail"] = f"HTTP {resp.status_code} (auth enforced)"
        return out

    if resp.status_code == 200:
        # Confirm the body is genuine control-plane data, not a generic page.
        is_docker = ("docker" in server_hdr) or any(m in body_low for m in _DOCKER_MARKERS)
        is_k8s = any(m in body_low for m in _K8S_MARKERS)
        # Require it actually parse as JSON to avoid HTML decoy pages.
        parsed_ok = False
        try:
            json.loads(body)
            parsed_ok = True
        except Exception:
            parsed_ok = False
        if (is_docker or is_k8s) and parsed_ok:
            out["open"] = True
            tag = "docker" if is_docker else "kubernetes"
            out["detail"] = f"HTTP 200 unauth {tag} body ({len(body)}B)"
            return out

    out["detail"] = f"HTTP {resp.status_code} (no unauth control-plane data)"
    return out


async def gather(ctx: ScanContext):
    target = ctx.host
    if not target:
        ctx.state["cps_no_target"] = True
        ctx.source("no-target")
        return

    try:
        import requests  # noqa: F401
    except ImportError:
        ctx.state["cps_error"] = "requests library not installed"
        ctx.source("requests missing")
        return

    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    opts = ctx.state.get("_options") or {}
    timeout = min(max(float(opts.get("timeout_sec") or DEFAULT_TIMEOUT), 2), 15)
    port_override = opts.get("ports")
    endpoints = _ENDPOINTS
    if isinstance(port_override, list) and port_override:
        try:
            wanted = {int(p) for p in port_override}
            endpoints = [e for e in _ENDPOINTS if e[2] in wanted]
        except Exception:
            endpoints = _ENDPOINTS

    ctx.state["cps_target"] = target
    ctx.state["cps_ran"] = True

    loop = asyncio.get_event_loop()
    docker_open: list[dict] = []
    kubelet_open: list[dict] = []
    reachable_protected: list[str] = []

    for label, scheme, port, path, kind in endpoints:
        try:
            res = await asyncio.wait_for(
                loop.run_in_executor(
                    None, _probe_endpoint, scheme, target, port, path, timeout),
                timeout=timeout + 4,
            )
        except asyncio.TimeoutError:
            continue
        except Exception:
            continue

        if not res.get("reachable"):
            continue

        endpoint_str = f"{scheme}://{target}:{port}{path}"
        if res.get("open"):
            hit = {"endpoint": endpoint_str, "detail": res.get("detail", "")}
            if kind == "docker":
                docker_open.append(hit)
            else:
                kubelet_open.append(hit)
        else:
            reachable_protected.append(
                f"{endpoint_str} [{res.get('detail', 'reachable')}]")

    ctx.state["cps_docker_open"] = docker_open
    ctx.state["cps_kubelet_open"] = kubelet_open
    ctx.state["cps_reachable_protected"] = reachable_protected[:20]
    ctx.source(
        f"container surface: docker_open={len(docker_open)}, "
        f"kubelet_open={len(kubelet_open)}, "
        f"reachable_protected={len(reachable_protected)}"
    )


INTEL_FIELDS = [
    ("Target",                        "cps_target"),
    ("Exposed Docker API",            "cps_docker_open"),
    ("Exposed kubelet / k8s API",     "cps_kubelet_open"),
    ("Reachable (auth enforced)",     "cps_reachable_protected"),
]


@router.post("/api/privesc/container_privesc_surface_probe")
async def privesc_container_privesc_surface_probe(
        req: ContainerPrivescSurfaceProbeRequest,
        _=Depends(verify_scan_quota)):
    options = req.options or {}

    async def _gather_with_options(ctx: ScanContext):
        ctx.state["_options"] = options
        await gather(ctx)

    return await run_scanner(
        host=req.target,
        tool="container_privesc_surface_probe",
        gather_func=_gather_with_options,
        finding_rules=CONTAINER_PRIVESC_SURFACE_PROBE_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app):
    app.include_router(router)
