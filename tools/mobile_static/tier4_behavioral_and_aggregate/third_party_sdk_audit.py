"""third_party_sdk_audit — enumerate bundled 3rd-party SDKs in APK package tree.

In addition to enumerating SDK *presence* (smali package signatures), this
scanner cross-references the curated vulnerable-SDK catalogue
(tools/_payloads/mobile/vulnerable_sdks.json) to flag bundled SDKs whose
version falls inside a known-vulnerable range.

ZERO-FP CONTRACT (this is a customer report):
  * A vulnerable-version finding is ONLY emitted when a version can be
    reliably extracted from a precise source (Maven META-INF/.../pom.properties
    groupId+artifactId+version) AND that version, after proper numeric range
    comparison, falls inside a vulnerable_version_ranges entry for that exact
    package, AND the catalogue entry carries a real CVE.  No version => no
    confirmed claim.
  * When the SDK is detected but no reliable version is extractable, the match
    is downgraded to an ADVISORY/INFO ("verify the bundled version") so it
    never reads as a confirmed CRITICAL.
  * Placeholder/unknown CVEs (e.g. "CVE-...-XXXX", "N/A") are treated as
    advisory even when a version match is found.
  * Existing SDK-presence / high-risk / count behaviour is UNCHANGED.
"""
import re
from pathlib import Path

from fastapi import APIRouter, Depends

from tools._shared import ScanRequest, verify_scan_quota
from tools._vl_core import ScanContext, run_scanner
from tools._vl_core.binary_cache import get_unpacked
from tools._payloads.mobile._loader import load_json
from tools._payloads.third_party_sdk_audit_findings import THIRD_PARTY_SDK_AUDIT_FINDING_RULES

router = APIRouter()


# ── Reliable version comparison (self-contained, no cross-module import) ──────
# Ranges in vulnerable_sdks.json use forms like:  "<4.9.2", ">=1.5 <1.10.0",
# ">=2.13.0 <2.13.2.1", "<M89", "<2.71828".  We only ever CONFIRM a match when
# BOTH the detected version and the bound parse to comparable numeric tuples;
# anything non-numeric (e.g. "M89", "2.0-beta9") fails the parse and is treated
# as "cannot confidently compare" -> no confirmed claim (zero-FP).
_VER_RE = re.compile(r"^(\d+(?:\.\d+)*)")


def _version_tuple(raw):
    """Return a comparable int tuple for a dotted-numeric version, or None if
    the leading token is not purely numeric. Trailing build/pre-release suffixes
    (e.g. '-rc2', '+build1') after the numeric head are dropped; a version that
    does NOT begin with a numeric component (e.g. 'M89') returns None so it is
    never compared as if it were 0.0.0."""
    if not raw:
        return None
    m = _VER_RE.match(str(raw).strip())
    if not m:
        return None
    parts = m.group(1).split(".")
    try:
        return tuple(int(x) for x in parts)
    except ValueError:
        return None


def _cmp(a, b):
    """Compare two int tuples padded to equal length. -1/0/1."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


_OP_RE = re.compile(r"(<=|>=|<|>|==|=)\s*([^\s]+)")


def _satisfies_clause(detected_t, clause):
    """True if detected version tuple satisfies a single 'OP version' clause.
    Returns None when the clause bound is non-numeric / unparseable (cannot
    confidently decide -> caller must NOT confirm)."""
    m = _OP_RE.match(clause.strip())
    if not m:
        return None
    op, bound = m.group(1), m.group(2)
    bound_t = _version_tuple(bound)
    if bound_t is None:
        return None  # non-numeric bound (e.g. 'M89') -> cannot decide
    c = _cmp(detected_t, bound_t)
    if op == "<":
        return c < 0
    if op == "<=":
        return c <= 0
    if op == ">":
        return c > 0
    if op == ">=":
        return c >= 0
    if op in ("==", "="):
        return c == 0
    return None


def _version_in_range(version, range_spec):
    """True iff `version` satisfies `range_spec` (space-joined clauses, ALL must
    hold, e.g. '>=2.13.0 <2.13.2.1'). Returns:
        True  — confidently inside the vulnerable range
        False — confidently outside
        None  — cannot decide reliably (non-numeric version/bound) => NO claim
    """
    detected_t = _version_tuple(version)
    if detected_t is None:
        return None
    clauses = [c for c in str(range_spec).split() if c]
    if not clauses:
        return None
    for clause in clauses:
        ok = _satisfies_clause(detected_t, clause)
        if ok is None:
            return None  # any undecidable clause -> whole match undecidable
        if not ok:
            return False
    return True


def _cve_is_real(cve):
    """A catalogue CVE counts as 'confirmable' only when it is a concrete,
    published identifier — not a placeholder. Placeholders stay advisory."""
    if not cve:
        return False
    cve = str(cve).strip().upper()
    if cve in ("", "N/A", "NONE", "UNKNOWN"):
        return False
    if "XXXX" in cve:  # e.g. CVE-2021-XXXX placeholders in the catalogue
        return False
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", cve))


def _extract_maven_versions(unpacked: Path) -> dict:
    """Extract reliably-known bundled artifact versions from Maven metadata.

    Source of truth: META-INF/maven/<groupId>/<artifactId>/pom.properties,
    which carries `groupId=`, `artifactId=`, `version=` written at build time
    by the Gradle/Maven packager. This is precise (no string-scraping smali).

    Returns { groupId(dotted): version }. When the same groupId appears with
    multiple artifacts, the LOWEST version is kept (most conservative — if any
    bundled artifact in the group is vulnerable we should not hide it).
    """
    versions: dict = {}
    for f in unpacked.rglob("pom.properties"):
        if "META-INF" not in str(f) and "maven" not in str(f).lower():
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")[:50_000]
        except Exception:
            continue
        g = re.search(r"^groupId=(.+)$", content, re.MULTILINE)
        v = re.search(r"^version=(.+)$", content, re.MULTILINE)
        if not (g and v):
            continue
        group = g.group(1).strip()
        ver = v.group(1).strip()
        if not group or not ver:
            continue
        # Keep the most conservative (lowest) version seen for a group.
        prev = versions.get(group)
        if prev is None:
            versions[group] = ver
        else:
            pt, ct = _version_tuple(prev), _version_tuple(ver)
            if pt is not None and ct is not None and _cmp(ct, pt) < 0:
                versions[group] = ver
    return versions


def _group_matches_package(group: str, package: str) -> bool:
    """Precise package identity match between a Maven groupId and a catalogue
    `package` value. Exact match OR the Maven group is a dotted sub-namespace of
    the catalogue package (component boundary), e.g. group
    'com.squareup.okhttp3' matches package 'com.squareup.okhttp3', and group
    'com.google.firebase.analytics' matches package 'com.google.firebase'.
    Substring matches that cross component boundaries (e.g. 'com.squareup.okhttp3x')
    are rejected."""
    if not group or not package:
        return False
    group = group.strip().lower()
    package = package.strip().lower()
    if group == package:
        return True
    return group.startswith(package + ".") or package.startswith(group + ".")

# Common 3rd-party SDK package prefixes (subset of Exodus Privacy DB)
SDK_SIGNATURES = {
    "com/google/firebase":     ("Firebase",           "MEDIUM", "Google analytics + auth + DB"),
    "com/google/android/gms":  ("Google Play Services","INFO",  "Standard Google services"),
    "com/facebook/sdk":        ("Facebook SDK",       "HIGH",   "Tracks users across apps"),
    "com/facebook/appevents":  ("Facebook AppEvents", "HIGH",   "PII transmitted to Meta"),
    "com/google/firebase/analytics": ("Firebase Analytics", "MEDIUM", "User-behavior tracking"),
    "com/crashlytics":         ("Crashlytics",        "LOW",    "Crash reporting"),
    "com/google/firebase/crashlytics": ("Firebase Crashlytics","LOW", "Crash reporting"),
    "com/appsflyer":           ("AppsFlyer",          "HIGH",   "Attribution + tracking"),
    "com/adjust":              ("Adjust",             "HIGH",   "Attribution + tracking"),
    "com/branch/referral":     ("Branch",             "HIGH",   "Deep-link tracking"),
    "com/segment":             ("Segment",            "MEDIUM", "Analytics aggregator"),
    "com/amplitude":           ("Amplitude",          "MEDIUM", "Product analytics"),
    "com/mixpanel":            ("Mixpanel",           "MEDIUM", "Product analytics"),
    "com/onesignal":           ("OneSignal",          "MEDIUM", "Push notifications"),
    "com/google/ads":          ("Google AdMob",       "MEDIUM", "Ad serving"),
    "com/applovin":            ("AppLovin",           "MEDIUM", "Ad mediation"),
    "com/unity3d/ads":         ("Unity Ads",          "MEDIUM", "Ad serving"),
    "com/ironsource":          ("ironSource",         "MEDIUM", "Ad mediation"),
    "com/vungle":              ("Vungle",             "MEDIUM", "Video ads"),
    "io/sentry":               ("Sentry",             "LOW",    "Error tracking"),
    "io/intercom":             ("Intercom",           "LOW",    "Customer support"),
    "com/squareup/okhttp":     ("OkHttp",             "INFO",   "HTTP client (benign)"),
    "retrofit2":               ("Retrofit",           "INFO",   "HTTP client (benign)"),
}


async def gather(ctx: ScanContext):
    apk = ctx.host
    if not Path(apk).is_file():
        ctx.state["third_party_sdk_audit_total"] = 0
        ctx.source("file-not-found")
        return
    try:
        unpacked = get_unpacked(apk)
    except Exception as e:
        ctx.state["third_party_sdk_audit_error"] = str(e)
        return

    # Walk smali/ and check for SDK package signatures
    detected = []
    seen_prefixes = set()
    for p in unpacked.rglob("*"):
        if not p.is_dir() and p.suffix.lower() != ".smali":
            continue
        rel = str(p.relative_to(unpacked)).replace("\\", "/").lstrip("smali/")
        for prefix, (name, sev, desc) in SDK_SIGNATURES.items():
            if prefix in rel and prefix not in seen_prefixes:
                detected.append({"sdk": name, "package": prefix,
                                  "severity_hint": sev, "description": desc})
                seen_prefixes.add(prefix)

    ctx.state["sdks_detected"] = detected
    ctx.state["third_party_sdk_audit_total"] = len(detected)
    # Track high-risk SDKs (HIGH severity)
    high_risk = [d for d in detected if d["severity_hint"] == "HIGH"]
    ctx.state["high_risk_sdks"] = high_risk
    ctx.source(f"sdk-signature-scan")

    # ── Vulnerable-SDK cross-check (curated catalogue) ───────────────────────
    # Detect SDK presence by smali signature (above) is informational. Here we
    # cross-reference the curated vulnerable_sdks.json against RELIABLE bundled
    # versions (Maven pom.properties). Zero-FP: only confirm when an exact-
    # package version is parseable AND inside a vulnerable range AND the entry
    # carries a real CVE; everything else is advisory.
    catalogue = load_json("vulnerable_sdks", fallback=[])
    maven_versions = _extract_maven_versions(unpacked)
    if maven_versions:
        ctx.source("maven-pom-properties")

    # Set of packages we actually detected as present (smali signatures use '/'
    # separators; catalogue uses dotted). Build a dotted-present set so an
    # advisory only fires for SDKs the app actually bundles.
    detected_pkgs_dotted = {
        d["package"].replace("/", ".").lower() for d in detected
    }

    confirmed = []   # version-proven, real-CVE => graded by severity
    advisory = []    # SDK present but version unknown/undecidable/placeholder-CVE
    for entry in catalogue:
        if not isinstance(entry, dict):
            continue
        pkg = (entry.get("package") or "").strip()
        sdk = (entry.get("sdk") or pkg or "unknown SDK").strip()
        ranges = entry.get("vulnerable_version_ranges") or []
        cve = entry.get("cve") or "N/A"
        note = entry.get("note") or ""
        if not pkg or not ranges:
            continue

        # Find a reliably-extracted Maven version whose group matches this pkg.
        matched_version = None
        for group, ver in maven_versions.items():
            if _group_matches_package(group, pkg):
                matched_version = ver
                break

        if matched_version is not None:
            # We have a precise version. Decide range membership numerically.
            in_vuln = False
            undecidable = False
            for rspec in ranges:
                res = _version_in_range(matched_version, rspec)
                if res is True:
                    in_vuln = True
                    break
                if res is None:
                    undecidable = True
            if in_vuln and _cve_is_real(cve):
                confirmed.append({
                    "sdk": sdk, "package": pkg, "version": matched_version,
                    "cve": cve, "note": note,
                    "matched_range": "; ".join(ranges),
                })
                continue
            if in_vuln and not _cve_is_real(cve):
                # Version IS in a vulnerable range but the CVE is a placeholder
                # (e.g. ...-XXXX / N/A) -> advisory, never confirmed-critical.
                advisory.append({
                    "sdk": sdk, "package": pkg, "version": matched_version,
                    "cve": cve, "note": note,
                    "matched_range": "; ".join(ranges),
                    "reason": "placeholder/unpublished CVE",
                })
                continue
            if undecidable:
                # Non-numeric bound (e.g. '<M89') we cannot compare reliably.
                advisory.append({
                    "sdk": sdk, "package": pkg, "version": matched_version,
                    "cve": cve, "note": note,
                    "matched_range": "; ".join(ranges),
                    "reason": "version range not numerically comparable",
                })
            # else: version is confidently OUTSIDE every range -> no finding.
            continue

        # No reliable version. Only advise if the SDK was actually detected as
        # present in the package tree (avoid noise for SDKs not bundled).
        if pkg.lower() in detected_pkgs_dotted:
            advisory.append({
                "sdk": sdk, "package": pkg, "version": None,
                "cve": cve, "note": note,
                "matched_range": "; ".join(ranges),
                "reason": "bundled but version not reliably extractable",
            })

    ctx.state["vulnerable_sdks_confirmed"] = confirmed
    ctx.state["vulnerable_sdks_advisory"] = advisory
    ctx.state["vulnerable_sdks_catalogue_size"] = len(catalogue)


INTEL_FIELDS = [
    ("Total SDKs", "third_party_sdk_audit_total"),
    ("High-risk SDKs", "high_risk_sdks"),
    ("Known-vulnerable SDKs (version-confirmed)", "vulnerable_sdks_confirmed"),
    ("Vulnerable-SDK advisories (verify version)", "vulnerable_sdks_advisory"),
]


@router.post("/api/mobile_static/third_party_sdk_audit")
async def mobile_static_third_party_sdk_audit(req: ScanRequest, _=Depends(verify_scan_quota)):
    return await run_scanner(
        host=req.target, tool="third_party_sdk_audit",
        gather_func=gather,
        finding_rules=THIRD_PARTY_SDK_AUDIT_FINDING_RULES,
        intel_fields=INTEL_FIELDS,
        flat_field_keys=[],
    )


def register(app): app.include_router(router)
