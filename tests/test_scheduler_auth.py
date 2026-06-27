"""Scheduled/batch internal runs authenticate properly (audit #13)."""
import os

from jose import jwt


def test_service_headers_mints_valid_owner_token():
    from endpoints.recon_flow import _service_headers
    h = _service_headers("user-123")
    assert h["Authorization"].startswith("Bearer ")
    assert h["x-vl-internal-fanout"]                 # internal-fanout marker present
    tok = h["Authorization"].split(" ", 1)[1]
    payload = jwt.decode(tok, os.environ["JWT_SECRET"], algorithms=["HS256"])
    assert payload["sub"] == "user-123"


def test_service_headers_empty_without_owner():
    from endpoints.recon_flow import _service_headers
    assert _service_headers("") == {}
    assert _service_headers(None) == {}
