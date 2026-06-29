"""Per-module orchestrator contract tests.

Every shippable module (the 24 tracked in .vl-foundry-scores.json) must be
wired correctly: its orchestrator imports, advertises a non-empty, well-formed
tool list under its own /api/<module>/ namespace, and registers a run_all
fan-out route. These are the failure modes that silently break a module in
production — a lost orchestrator, a broken _all_tools(), mis-namespaced routes,
or an unregistered run_all.

These run WITHOUT a database (orchestrators import cleanly — the same property
scripts/score_module.py relies on), so they're fast and deterministic. They
complement the forge-score CI gate by asserting the wiring behaviorally inside
the pytest suite, via a second independent mechanism.
"""
import importlib
import json
import pathlib

import pytest
from fastapi import FastAPI

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULES = sorted(json.loads((ROOT / ".vl-foundry-scores.json").read_text(encoding="utf-8")))


def _orch(module: str):
    return importlib.import_module(f"endpoints.{module}_orchestrator")


def test_module_list_is_complete():
    """Guard against the source-of-truth file being emptied/corrupted."""
    assert len(MODULES) >= 24, f"expected >=24 tracked modules, got {len(MODULES)}"


@pytest.mark.parametrize("module", MODULES)
def test_orchestrator_imports(module):
    mod = _orch(module)
    assert hasattr(mod, "_all_tools"), f"{module}: orchestrator has no _all_tools()"
    assert callable(mod.register), f"{module}: orchestrator has no register()"


@pytest.mark.parametrize("module", MODULES)
def test_all_tools_contract(module):
    """_all_tools() returns a non-empty list of (name, route) pairs, each route
    namespaced to the module, with no duplicate slugs."""
    tools = _orch(module)._all_tools()
    assert isinstance(tools, list) and tools, f"{module}: _all_tools() is empty"

    prefix = f"/api/{module}/"
    slugs = []
    for entry in tools:
        assert isinstance(entry, (tuple, list)) and len(entry) == 2, \
            f"{module}: tool entry is not a (name, route) pair: {entry!r}"
        name, route = entry
        assert isinstance(name, str) and name, f"{module}: empty tool name in {entry!r}"
        assert str(route).startswith(prefix), \
            f"{module}: route {route!r} is not under {prefix}"
        slugs.append(name)

    dupes = sorted({s for s in slugs if slugs.count(s) > 1})
    assert not dupes, f"{module}: duplicate tool slugs {dupes}"


@pytest.mark.parametrize("module", MODULES)
def test_run_all_route_registered(module):
    """register() mounts cleanly and exposes a run_all fan-out route."""
    app = FastAPI()
    _orch(module).register(app)  # must not raise

    paths = {getattr(r, "path", "") for r in app.routes}
    candidates = {f"/api/{module}/run_all", f"/api/{module}/scan/run_all"}
    assert paths & candidates, (
        f"{module}: no run_all route registered; "
        f"module routes seen: {sorted(p for p in paths if module in p)[:8]}"
    )
