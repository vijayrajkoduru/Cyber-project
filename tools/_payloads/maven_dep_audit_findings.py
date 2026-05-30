"""maven_dep_audit — findings rules."""


def rule_positive_emit(s):
    n = s.get("maven_dep_audit_total", 0)
    if n > 0: return None
    return {"name": "No bundled dependency metadata detected",
            "severity": "POSITIVE",
            "cwe": "CWE-1395", "owasp": "M9:2023",
            "evidence": "no META-INF/maven/*.properties, no *.version, no .framework",
            "remediation": "Either minimal app with no 3rd-party deps, or stripped "
                           "metadata. For SBOM compliance, consider re-enabling "
                           "Gradle includeResource for META-INF dep markers."}


def rule_dep_inventory(s):
    deps = s.get("dependencies") or []
    if not deps: return None
    return {"name": f"Dependency inventory: {len(deps)} library version(s) extracted",
            "severity": "INFO",
            "cwe": "CWE-1395", "owasp": "M9:2023",
            "evidence": " | ".join(deps[:15]) + (" ..." if len(deps) > 15 else ""),
            "remediation": "Cross-reference each dep:version against the OSV.dev "
                           "vulnerability database (api.osv.dev). Tools: "
                           "Snyk Code Mobile, OWASP Dependency-Check (Android plugin), "
                           "Mend Bolt. For SBOM compliance (Executive Order 14028, "
                           "EU Cyber Resilience Act), generate CycloneDX SBOM from "
                           "this inventory."}


def rule_dep_explosion(s):
    n = s.get("maven_dep_audit_total", 0)
    if n < 80: return None
    return {"name": f"Large dependency surface: {n} libraries",
            "severity": "LOW",
            "cwe": "CWE-1395", "owasp": "M9:2023",
            "evidence": f"{n} bundled library versions (typical small/mid app: 30-60)",
            "remediation": "Each dep is a potential CVE source + supply-chain attack "
                           "vector. Audit for transitive bloat — most apps don't need "
                           "all of Guava + AndroidX + Kotlin-stdlib + 3 JSON libs. "
                           "Use './gradlew app:dependencies' to see what's actually used."}
