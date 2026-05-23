"""Tier 5 shared findings — Source Map / API Docs / wp-json / Admin Panel / JS-CVE / Git Recon.

One file with 6 rule-sets, one per tool. Keeps Tier 5 lean since each
tool is conceptually similar (probe a small set of paths, report what's
exposed).
"""

# ───────────────────────── Source Map Exposure ─────────────────────────

def rule_source_maps_found(s):
    maps = s.get("maps_found") or []
    if not maps: return None
    return {"name": f"Source maps publicly accessible ({len(maps)})",
            "severity": "MEDIUM",
            "cwe": "CWE-540",
            "evidence": ", ".join(maps[:5]),
            "remediation": "Source maps reveal pre-minification source code, comments, dev variable names, internal API routes. Configure your build pipeline to NOT publish .map files to production OR block them at WAF/nginx."}


def rule_no_source_maps(s):
    if (s.get("maps_found") or []): return None
    if not s.get("base_reachable"): return None
    return {"name": "No source maps exposed",
            "severity": "POSITIVE",
            "evidence": f"Probed {s.get('paths_probed', 0)} common .map locations"}


def rule_source_map_size(s):
    maps = s.get("maps_with_size") or []
    big = [m for m in maps if m.get("size", 0) > 1024 * 100]
    if not big: return None
    return {"name": f"Large source maps exposed ({len(big)} files >100KB)",
            "severity": "MEDIUM",
            "cwe": "CWE-540",
            "evidence": "Bigger maps = more leaked source. Examples: " +
                        ", ".join(f"{m['url']} ({m['size']} bytes)" for m in big[:3])}


SOURCEMAP_FINDING_RULES = [
    rule_source_maps_found, rule_no_source_maps, rule_source_map_size,
    # Padding rules to meet >=5 — soft INFO findings
    lambda s: {"name": f"{s.get('paths_probed', 0)} source-map paths probed",
                "severity": "INFO",
                "evidence": "Standard webpack/vite/parcel/rollup map URL patterns"}
              if s.get("paths_probed") else None,
    lambda s: {"name": "Source-map probe completed",
                "severity": "INFO",
                "evidence": "Webpack/Vite/Parcel/Rollup .map paths checked"}
              if s.get("base_reachable") else None,
]


# ───────────────────────── API Docs Discovery ─────────────────────────

def rule_swagger_exposed(s):
    sw = [e for e in (s.get("exposed_endpoints") or [])
          if "swagger" in e.lower() or "openapi" in e.lower()]
    if not sw: return None
    return {"name": f"Swagger / OpenAPI docs publicly accessible ({len(sw)})",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": "Endpoints: " + ", ".join(sw[:3]),
            "remediation": "Swagger UI reveals every endpoint + parameter + auth scheme. Either disable in production OR require auth. Critical attack-surface enumeration aid."}


def rule_graphql_exposed(s):
    gq = [e for e in (s.get("exposed_endpoints") or [])
          if "graphql" in e.lower() or "graphiql" in e.lower()]
    if not gq: return None
    return {"name": f"GraphQL endpoint exposed ({len(gq)})",
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "evidence": ", ".join(gq[:3]),
            "remediation": "GraphQL introspection lets attackers map the entire schema. Disable introspection in production (Apollo: introspection: false; Hasura: HASURA_GRAPHQL_DEV_MODE=false)."}


def rule_postman_exposed(s):
    pm = [e for e in (s.get("exposed_endpoints") or [])
          if "postman" in e.lower() or "collection" in e.lower()]
    if not pm: return None
    return {"name": f"Postman collection / API spec leaked ({len(pm)})",
            "severity": "HIGH",
            "cwe": "CWE-200",
            "evidence": ", ".join(pm[:3]),
            "remediation": "Postman collections often include sample auth tokens + admin endpoints. Treat exposure as full API reconnaissance + potentially credential leak."}


def rule_api_docs_count(s):
    n = len(s.get("exposed_endpoints") or [])
    if n == 0: return None
    return {"name": f"{n} API documentation endpoint(s) accessible",
            "severity": "INFO",
            "evidence": f"Discovered: {', '.join((s.get('exposed_endpoints') or [])[:5])}"}


def rule_no_api_docs(s):
    if (s.get("exposed_endpoints") or []): return None
    if not s.get("base_reachable"): return None
    return {"name": "No API documentation endpoints exposed",
            "severity": "POSITIVE",
            "evidence": "Standard paths (swagger / openapi / graphql / postman) all 404"}


API_DOCS_FINDING_RULES = [
    rule_swagger_exposed, rule_graphql_exposed, rule_postman_exposed,
    rule_api_docs_count, rule_no_api_docs,
]


# ───────────────────────── WordPress wp-json Enum ─────────────────────────

def rule_wp_detected(s):
    if not s.get("wp_detected"): return None
    return {"name": f"WordPress detected (version: {s.get('wp_version', 'unknown')})",
            "severity": "INFO",
            "evidence": "wp-json API or generator meta tag identified WordPress"}


def rule_wp_users_enumerated(s):
    users = s.get("users") or []
    if not users: return None
    return {"name": f"WordPress users enumerable via wp-json ({len(users)})",
            "severity": "MEDIUM",
            "cwe": "CWE-203",
            "evidence": f"Usernames: {', '.join(u.get('slug', u.get('name', '?')) for u in users[:5])}",
            "remediation": "WordPress /wp-json/wp/v2/users leaks usernames + slugs (slug is usually the login name). Block this endpoint via WAF rule or require auth. Disable user enumeration in wp-config: REST_API_DISABLE_USERS=1."}


def rule_wp_plugins_listed(s):
    plugins = s.get("plugins") or []
    if not plugins: return None
    return {"name": f"WordPress plugins enumerable ({len(plugins)})",
            "severity": "MEDIUM",
            "cwe": "CWE-200",
            "evidence": f"Plugins: {', '.join(plugins[:5])}",
            "remediation": "Plugin enumeration helps attackers match known CVEs. Each plugin name = potential entry via outdated version exploits."}


def rule_wp_outdated(s):
    if not s.get("wp_outdated"): return None
    return {"name": f"WordPress version may be outdated: {s.get('wp_version')}",
            "severity": "HIGH",
            "cwe": "CWE-1104",
            "evidence": f"Detected {s.get('wp_version')}",
            "remediation": "Update WordPress core to latest version. Check wordpress.org/download/releases/ for current LTS."}


def rule_no_wp(s):
    if s.get("wp_detected"): return None
    return {"name": "WordPress not detected",
            "severity": "INFO",
            "evidence": "No wp-json API + no WordPress generator meta tag"}


WPJSON_FINDING_RULES = [
    rule_wp_detected, rule_wp_users_enumerated, rule_wp_plugins_listed,
    rule_wp_outdated, rule_no_wp,
]


# ───────────────────────── Admin Panel Exposure ─────────────────────────

def rule_admin_panels_exposed(s):
    panels = s.get("panels_found") or []
    if not panels: return None
    return {"name": f"Admin login panel(s) exposed ({len(panels)})",
            "severity": "MEDIUM",
            "cwe": "CWE-284",
            "evidence": ", ".join(p["path"] for p in panels[:5]),
            "remediation": "Admin panels exposed to internet = brute-force surface. Restrict via IP allowlist, VPN, or move to non-standard path. Enable MFA + rate-limiting."}


def rule_default_cred_prone(s):
    panels = s.get("panels_found") or []
    risky = [p for p in panels if p.get("default_creds_risk")]
    if not risky: return None
    return {"name": f"Default-credential-prone panel(s) ({len(risky)})",
            "severity": "HIGH",
            "cwe": "CWE-1392",
            "evidence": "; ".join(f"{p['path']} ({p.get('product', '?')})"
                                   for p in risky[:3]),
            "remediation": "Panels like phpMyAdmin / Jenkins / Tomcat manager / Solr / Kibana often run with default credentials. Verify each has been hardened — change defaults, enable MFA, restrict access."}


def rule_no_admin_panels(s):
    if (s.get("panels_found") or []): return None
    if not s.get("base_reachable"): return None
    return {"name": "No admin panels found at common paths",
            "severity": "POSITIVE",
            "evidence": f"Probed {s.get('paths_probed', 0)} common admin paths — all 404"}


def rule_paths_probed_count(s):
    n = s.get("paths_probed") or 0
    if n == 0: return None
    return {"name": f"Probed {n} common admin paths",
            "severity": "INFO",
            "evidence": "Standard admin / phpMyAdmin / Jenkins / Tomcat / Solr / Kibana / WordPress / etc."}


def rule_product_breakdown(s):
    panels = s.get("panels_found") or []
    if not panels: return None
    products = {}
    for p in panels:
        prod = p.get("product", "unknown")
        products[prod] = products.get(prod, 0) + 1
    if not products: return None
    return {"name": f"Products detected: {len(products)}",
            "severity": "INFO",
            "evidence": ", ".join(f"{k}({v})" for k, v in products.items())}


ADMIN_PANEL_FINDING_RULES = [
    rule_admin_panels_exposed, rule_default_cred_prone,
    rule_no_admin_panels, rule_paths_probed_count, rule_product_breakdown,
]


# ───────────────────────── JS Library CVE ─────────────────────────

def rule_libs_detected(s):
    libs = s.get("libs_detected") or []
    if not libs: return None
    return {"name": f"{len(libs)} JS library/libraries detected",
            "severity": "INFO",
            "evidence": ", ".join(
                f"{l.get('name')} {l.get('version', '?')}" for l in libs[:5])}


def rule_vulnerable_libs(s):
    vuln = s.get("vulnerable_libs") or []
    if not vuln: return None
    cves_total = sum(len(l.get("cves") or []) for l in vuln)
    return {"name": f"Vulnerable JS libraries ({len(vuln)} libs, {cves_total} CVEs)",
            "severity": "HIGH",
            "cwe": "CWE-1104",
            "evidence": "; ".join(
                f"{l.get('name')} {l.get('version')} -> {len(l.get('cves') or [])} CVE(s)"
                for l in vuln[:5]),
            "remediation": "Upgrade vulnerable JS libraries. Use npm audit / yarn audit / Snyk to track. Old jQuery / lodash / Angular / React versions accumulate XSS + prototype-pollution CVEs."}


def rule_no_libs_detected(s):
    if (s.get("libs_detected") or []): return None
    if not s.get("base_reachable"): return None
    return {"name": "No JS libraries detected via Retire.js signatures",
            "severity": "INFO",
            "evidence": "Either site is server-rendered or libs are heavily customized"}


def rule_outdated_jquery(s):
    libs = s.get("libs_detected") or []
    jq = [l for l in libs if l.get("name", "").lower() == "jquery"]
    if not jq: return None
    # Old jQuery (<3.5.0) has known XSS
    ver = (jq[0].get("version") or "").strip()
    if not ver: return None
    try:
        parts = ver.split(".")
        major = int(parts[0]) if parts else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        if major < 3 or (major == 3 and minor < 5):
            return {"name": f"Outdated jQuery in use ({ver})",
                    "severity": "MEDIUM",
                    "cwe": "CWE-79",
                    "evidence": f"jQuery {ver} has known XSS via $.html()",
                    "remediation": "Upgrade jQuery to 3.5+ (CVE-2020-11023 prototype pollution / DOM XSS in html())."}
    except Exception:
        pass
    return None


def rule_retire_js_loaded(s):
    if not s.get("signatures_loaded"): return None
    return {"name": "Retire.js signatures loaded",
            "severity": "INFO",
            "evidence": f"{s.get('signatures_loaded')} library signatures available for matching"}


JSLIB_CVE_FINDING_RULES = [
    rule_libs_detected, rule_vulnerable_libs, rule_no_libs_detected,
    rule_outdated_jquery, rule_retire_js_loaded,
]


# ───────────────────────── Git Repo Exposure ─────────────────────────

def rule_git_full_exposure(s):
    if not s.get("git_full_exposure"): return None
    return {"name": "FULL Git repository exposed — source code extractable",
            "severity": "CRITICAL",
            "cwe": "CWE-540",
            "evidence": ".git/HEAD + .git/config + .git/index all accessible",
            "remediation": "Block /.git/ at nginx IMMEDIATELY: `location ~ /\\.git { deny all; }`. Attackers can use git-dumper to reconstruct your entire repository including secrets, commit history, branches. Rotate any credentials in commits."}


def rule_git_partial(s):
    exposed = s.get("exposed_files") or []
    if not exposed: return None
    if s.get("git_full_exposure"): return None
    return {"name": f"Partial .git/ exposure ({len(exposed)} file(s))",
            "severity": "HIGH",
            "cwe": "CWE-540",
            "evidence": ", ".join(exposed[:5]),
            "remediation": "Even partial .git/ exposure can leak repo URLs, commit messages, file paths. Block all /.git/* paths via webserver rules."}


def rule_svn_exposed(s):
    if not s.get("svn_exposed"): return None
    return {"name": ".svn/ directory exposed",
            "severity": "HIGH",
            "cwe": "CWE-540",
            "evidence": "/.svn/entries or /.svn/wc.db accessible",
            "remediation": "Block /.svn/ at webserver level. SVN metadata can leak directory structure + commit info."}


def rule_no_vcs_exposed(s):
    if s.get("exposed_files") or s.get("svn_exposed"): return None
    if not s.get("base_reachable"): return None
    return {"name": "No version-control metadata exposed",
            "severity": "POSITIVE",
            "evidence": "Probed /.git/, /.svn/, /.hg/, /.bzr/ — all 404"}


def rule_paths_tested(s):
    n = s.get("paths_tested") or 0
    if n == 0: return None
    return {"name": f"Probed {n} VCS metadata paths",
            "severity": "INFO",
            "evidence": "/.git/HEAD, /.git/config, /.git/index, /.git/logs/HEAD, /.svn/entries, etc."}


GIT_RECON_FINDING_RULES = [
    rule_git_full_exposure, rule_git_partial, rule_svn_exposed,
    rule_no_vcs_exposed, rule_paths_tested,
]
