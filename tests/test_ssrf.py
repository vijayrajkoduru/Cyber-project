"""SSRF-safe outbound URL validation for webhooks (audit #12).

Uses IP literals so no real DNS/network is needed in CI.
"""
import pytest

from tools._shared import is_safe_external_url


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/hook",                         # loopback
    "http://169.254.169.254/latest/meta-data/",      # cloud metadata (link-local)
    "http://10.0.0.5/hook",                          # private
    "http://192.168.1.10/hook",                      # private
    "http://172.16.0.1/hook",                        # private
    "file:///etc/passwd",                            # non-http scheme
    "ftp://example.com/x",                           # non-http scheme
    "",                                              # empty
    "not a url",                                     # garbage
])
def test_rejects_unsafe_urls(url):
    ok, reason = is_safe_external_url(url)
    assert ok is False
    assert reason


@pytest.mark.parametrize("url", [
    "https://8.8.8.8/hook",       # public IP literal
    "http://1.1.1.1/notify",      # public IP literal
])
def test_allows_public_urls(url):
    ok, _ = is_safe_external_url(url)
    assert ok is True
