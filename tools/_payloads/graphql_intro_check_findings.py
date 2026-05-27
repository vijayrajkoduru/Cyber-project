"""graphql_intro_check findings."""

def rule_intro(s):
    if not s.get("introspection_enabled"): return None
    return {"name":"GraphQL introspection enabled (full schema exposed)","severity":"HIGH","cvss":"5.3",
            "cwe":"CWE-200","owasp":"API3:2023",
            "evidence":f"Endpoint: {s.get('endpoint','?')}",
            "remediation":"Disable introspection in production. GraphQL servers: set introspection=False in resolver config."}
def rule_no_gql(s):
    if s.get("introspection_enabled") or s.get("endpoint"): return None
    return {"name":"No GraphQL endpoint detected","severity":"POSITIVE",
            "evidence":"5 common GraphQL paths returned non-200 or no schema",
            "remediation":"No GraphQL = one fewer attack surface.",
            "cwe":"CWE-200","owasp":"API3:2023"}
GRAPHQL_INTRO_CHECK_FINDING_RULES = [rule_intro, rule_no_gql]
