"""Container/K8s module orchestrator — 24_container_k8s.md (103 endpoints)."""
from typing import Optional
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from tools._shared import verify_scan_quota
from tools._framework.orchestrator import run_module_streaming
from tools.container_k8s.container_k8s_pack import T as TECHNIQUES

router = APIRouter()

_RANGES = [
    ("tier1_image_registry", 0, 13),
    ("tier2_dockerfile",     13, 24),
    ("tier3_runtime",        24, 36),
    ("tier4_cis_cluster",    36, 53),
    ("tier5_rbac_policy",    53, 65),
    ("tier6_network_mesh",   65, 75),
    ("tier7_secrets",        75, 84),
    ("tier8_escape_cves",    84, 93),
    ("tier9_mesh_ingress",   93, 101),
    ("tier10_ebpf_runtime",  101, 104),
]

CONTAINER_K8S_TOOLS_BY_TIER: dict[str, list[tuple[str, str]]] = {
    k: [(t[0], f"/api/container_k8s/{t[0]}") for t in TECHNIQUES[a:b]]
    for k, a, b in _RANGES
}


class ContainerK8sRunAllRequest(BaseModel):
    target: str
    concurrency: Optional[int] = 16
    auth_cookie: Optional[str] = None
    auth_bearer: Optional[str] = None
    # Advanced inputs (forwarded to every scanner via extra_body so individual
    # probes can use them — scanners that don't need a given input ignore it).
    image_ref: Optional[str] = None
    dockerfile_text: Optional[str] = None
    pod_spec_yaml: Optional[str] = None
    kubeconfig: Optional[str] = None
    repo_url: Optional[str] = None


def _all_tools():
    out = []
    for tools in CONTAINER_K8S_TOOLS_BY_TIER.values():
        out.extend(tools)
    return out


@router.post("/api/container_k8s/run_all")
async def container_k8s_run_all(req: ContainerK8sRunAllRequest, request: Request,
                                  _=Depends(verify_scan_quota)):
    jwt_token = request.headers.get("authorization", "").replace("Bearer ", "") or None
    extra = {}
    for k in ("image_ref", "dockerfile_text", "pod_spec_yaml", "kubeconfig", "repo_url"):
        v = getattr(req, k, None)
        if v:
            extra[k] = v
    return StreamingResponse(
        run_module_streaming(target=req.target, tools=_all_tools(),
            module_name="container_k8s", concurrency=max(1, min(req.concurrency or 16, 32)),
            auth_cookie=req.auth_cookie, auth_bearer=req.auth_bearer,
            extra_body=(extra or None), jwt_token=jwt_token),
        media_type="application/x-ndjson",
        headers={"X-Accel-Buffering":"no", "Cache-Control":"no-store, no-transform",
                 "Connection":"keep-alive"})


@router.get("/api/container_k8s/run_all/tiers")
async def container_k8s_run_all_tiers():
    return {"tiers":[{"id":k,"tools":[n for n,_ in t],"count":len(t)}
                     for k,t in CONTAINER_K8S_TOOLS_BY_TIER.items()],
            "total_tools": sum(len(t) for t in CONTAINER_K8S_TOOLS_BY_TIER.values())}


def register(app):
    app.include_router(router)
