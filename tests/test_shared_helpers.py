"""Unit tests for tools/_shared.py helpers used across the platform."""
import tempfile

from tools._shared import writable_base, web_url, recon_host, standard_response


# ── writable_base (the host-portability helper) ─────────────────────
def test_writable_base_honors_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("VL_TEST_BASE", str(tmp_path / "override"))
    p = writable_base("VL_TEST_BASE", "/app/should-be-ignored")
    assert str(p) == str(tmp_path / "override")


def test_writable_base_uses_default_when_writable(tmp_path, monkeypatch):
    monkeypatch.delenv("VL_TEST_BASE2", raising=False)
    target = tmp_path / "created"
    p = writable_base("VL_TEST_BASE2", str(target))
    assert p == target
    assert target.exists()                       # created eagerly


def test_writable_base_falls_back_when_unwritable(monkeypatch):
    # Force the container default to be uncreatable. We mock mkdir to raise
    # rather than relying on a "/nonexistent" path being unwritable — that
    # assumption is false when the process runs as root (CI/Docker), where
    # root can mkdir anywhere.
    import pathlib
    monkeypatch.delenv("VL_TEST_BASE3", raising=False)
    monkeypatch.setattr(pathlib.Path, "mkdir",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("denied")))
    p = writable_base("VL_TEST_BASE3", "/some/container/path/data")
    assert str(p).startswith(tempfile.gettempdir())   # fell back, never raised
    assert p.name == "data"


# ── URL/host normalisation ──────────────────────────────────────────
def test_web_url_adds_scheme():
    assert web_url("example.com") == "http://example.com"


def test_web_url_preserves_existing_scheme():
    assert web_url("https://example.com") == "https://example.com"
    assert web_url("http://example.com") == "http://example.com"


def test_recon_host_strips_scheme_and_path():
    assert recon_host("https://example.com/a/b?c=d") == "example.com"


def test_recon_host_passthrough_bare_host():
    assert "example.com" in recon_host("example.com")


# ── standard_response contract (frontend + PDF depend on this shape) ─
def test_standard_response_core_shape():
    r = standard_response(tool="nikto", target="example.com",
                          findings=[{"severity": "HIGH"}])
    assert r["tool"] == "nikto"
    assert r["target"] == "example.com"
    assert r["total"] == 1
    assert r["vulnerable"] is True
    required = {"scan_id", "target", "tool", "findings",
                "total", "vulnerable", "timestamp"}
    assert required <= set(r)


def test_standard_response_not_vulnerable_without_findings():
    r = standard_response(tool="x", target="t", findings=[])
    assert r["vulnerable"] is False
    assert r["total"] == 0


def test_standard_response_skipped_forces_not_vulnerable():
    r = standard_response(tool="x", target="t",
                          findings=[{"severity": "HIGH"}],
                          skipped_reason="Blocked by WAF")
    assert r["skipped_reason"] == "Blocked by WAF"
    assert r["vulnerable"] is False
