"""Advisory severity cap (audit #9) — was silently dead due to a broken
import; these lock in that it actually fires again."""
from tools._shared import wrap_finding


def test_advisory_finding_is_capped_to_info():
    f = wrap_finding("Server may be vulnerable to CVE-2021-1234",
                     severity="HIGH", evidence_marker="version banner only")
    assert f["severity"] == "INFO"
    assert f.get("_policy") == "advisory-cap"
    assert f.get("_original_severity") == "HIGH"


def test_verified_exploit_opts_out_of_cap():
    f = wrap_finding("Server may be vulnerable to CVE-2021-1234",
                     severity="HIGH", evidence_marker="demonstrated",
                     verified_exploit=True)
    assert f["severity"] == "HIGH"


def test_non_advisory_finding_keeps_severity():
    f = wrap_finding("SQL injection — extracted DB version via UNION",
                     severity="HIGH", evidence_marker="5.7.31 returned")
    assert f["severity"] == "HIGH"
