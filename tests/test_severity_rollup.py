"""Top-level severity rollup in standard_response (audit #3)."""
from tools._shared import standard_response


def test_rollup_is_worst_finding_severity():
    r = standard_response(tool="x", target="t", findings=[
        {"severity": "LOW"}, {"severity": "CRITICAL"}, {"severity": "MEDIUM"}])
    assert r["severity"] == "CRITICAL"


def test_rollup_info_when_no_findings():
    assert standard_response(tool="x", target="t", findings=[])["severity"] == "INFO"


def test_rollup_handles_missing_and_lowercase_severity():
    r = standard_response(tool="x", target="t", findings=[
        {}, {"severity": "high"}, {"severity": None}])
    assert r["severity"] == "HIGH"


def test_rollup_present_on_every_response():
    assert "severity" in standard_response(tool="x", target="t", findings=[])
