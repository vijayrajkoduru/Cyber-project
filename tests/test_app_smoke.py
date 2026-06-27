"""Full-boot smoke test: the real main.py auto-discovers all tool modules.

This is the integration-level guard. It also locks in the host-portability
boot fix (commit 89da838b) so the 8 modules that previously failed to load
outside Docker can never silently regress.
"""
import pytest
from fastapi.testclient import TestClient

# Modules that failed auto-discovery before the host-portability fix.
_BOOT_FIX_MODULES = [
    "favicon_hash",
    "recon_flow",
    "recon_flow_advanced",
    "recon_prime",
    "vuln_prime",
    "osint_prime",
    "webapp_prime",
    "mobile_static_orchestrator",
]


@pytest.fixture(scope="module")
def main_app():
    import main                      # triggers full boot + auto-discovery
    return main.app


def test_app_boots_with_many_routes(main_app):
    assert len(main_app.routes) > 100


def test_health_endpoint_ok(main_app):
    c = TestClient(main_app)
    r = c.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "vulnuslab-api"


def test_auth_routes_registered(main_app):
    paths = {getattr(r, "path", "") for r in main_app.routes}
    assert "/api/auth/login" in paths
    assert "/api/auth/register" in paths


def test_boot_fix_modules_still_load(main_app):
    """Regression guard: none of the previously-broken modules may appear
    in the failed-to-load list."""
    failed = " ".join(str(f) for f in getattr(main_app.state, "tools_failed", []))
    for mod in _BOOT_FIX_MODULES:
        assert mod not in failed, f"{mod} regressed (failed to load): {failed}"
