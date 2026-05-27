"""drone_adsb_ais_passive findings."""

def rule_no_key(s):
    if s.get("_api_key_present"): return None
    return {"name":"Drone/ADS-B/AIS passive intercept requires RTL_SDR_PROBE","severity":"INFO",
            "evidence":"Set env var on backend","remediation":"Add RTL_SDR_PROBE to docker-compose env.",
            "cwe":"CWE-200","owasp":"M2:2023"}
def rule_ok(s):
    if not s.get("_api_key_present"): return None
    return {"name":"Drone/ADS-B/AIS passive intercept API enabled","severity":"POSITIVE",
            "evidence":"Key configured","remediation":"Scanner active.",
            "cwe":"CWE-200","owasp":"M2:2023"}
DRONE_ADSB_AIS_PASSIVE_FINDING_RULES = [rule_no_key, rule_ok]
