# Phase C / D Password Attacks Lab Walkthrough

Deterministic lab targets that exercise the **Active Directory (Phase C)**
and **OAuth / SAML (Phase D)** scanners end-to-end, including the
ChainExecutor cascade where one CONFIRMED finding fans out into multiple
follow-on scanners with inherited credentials.

All three containers live in `docker-compose.yml` (commented out by default)
and join the existing `vulnuslab` bridge network, so the backend reaches
them by hostname — no published ports required.

---

## 1. Spinning up the labs

All three lab services are **opt-in**. Uncomment the three service blocks
under the "Phase C / D / E Password Attacks Labs (OPT-IN)" section of
`docker-compose.yml`, then on the VPS:

```bash
# Pull + start all three (run from project root)
docker compose up -d lab_pwd_ad lab_pwd_oauth lab_pwd_saml

# lab_pwd_ad needs ~90 s for the Samba AD DC to provision on first boot.
# Watch the logs until you see "samba-tool domain provision" completing:
docker compose logs -f lab_pwd_ad

# Once the DC is up, seed the test users (one-time, idempotent):
chmod +x labs/vl_password_range/ad_bootstrap.sh   # host-side, only once
docker compose exec lab_pwd_ad bash /bootstrap.sh

# Keycloak realm `vl-test-realm` is auto-imported from the mounted JSON.
# Verify with:
docker compose exec lab_pwd_oauth /opt/keycloak/bin/kc.sh show-config 2>/dev/null | head -20

# SimpleSAMLphp ships with two test users baked into the image (user1/user1pass,
# user2/user2pass) — no bootstrap needed.
```

Image sizes / boot times (approx):

| Container         | Image size | Boot time | Why opt-in                       |
|-------------------|-----------:|----------:|----------------------------------|
| `lab_pwd_ad`      |    ~1.5 GB |     ~90 s | Samba AD DC + domain provisioning |
| `lab_pwd_oauth`   |    ~600 MB |     ~15 s | Keycloak start-dev + realm import |
| `lab_pwd_saml`    |    ~400 MB |     ~10 s | SimpleSAMLphp PHP-FPM stack       |

---

## 2. Phase C — Active Directory (lab_pwd_ad)

Hostname (resolvable inside `vulnuslab` bridge): `dc01.vlrange.local`
Realm: `VLRANGE.LOCAL`   Domain: `VLRANGE`

### Seeded users (after `bootstrap.sh`)

| Username        | Password               | Purpose                                          |
|-----------------|------------------------|--------------------------------------------------|
| `Administrator` | `VLrange_Admin_2026!`  | Domain Admin — entry point for the AD chain       |
| `svc_mssql`     | `Password123`          | Kerberoastable — SPN `MSSQLSvc/sql01.vlrange.local:1433` |
| `svc_http`      | `Spring2024`           | Kerberoastable — SPN `HTTP/web01.vlrange.local`   |
| `jbloggs`       | `NoPreAuth!`           | AS-REP roastable — `DONT_REQUIRE_PREAUTH` UAC bit |
| `regularuser`   | `regularuser`          | Standard domain user (control)                    |

### Seed scan + expected chain_handoff cascade

```
Scan 1 — ldap_brute (the seed)
  target: dc01.vlrange.local
  options:
    userlist: ["Administrator"]
    passlist: ["VLrange_Admin_2026!"]
    always_deep: true
    domain: VLRANGE.LOCAL

  Expected result:
    CONFIRMED — Domain Admin bind succeeded
    chain_handoff = [kerberoast_audit, asreproast_audit,
                     dcsync_audit, bloodhound_audit]
```

The ChainExecutor automatically fans the inherited credentials into the
four follow-on scanners. Expected per-scanner results:

| Chained scanner        | Expected result against the seeded DC                                              |
|------------------------|------------------------------------------------------------------------------------|
| `kerberoast_audit`     | **2 TGS hashes** extracted (`svc_mssql$MSSQLSvc`, `svc_http$HTTP`) — HIGH 7.5      |
| `asreproast_audit`     | **1 AS-REP hash** extracted (`jbloggs`) — HIGH 7.5                                  |
| `dcsync_audit`         | **krbtgt NT hash** extracted via DRSUAPI replication — CRITICAL 10.0                |
| `bloodhound_audit`     | SharpHound collection — paths visualised to Domain Admin (Tier-0)                   |

### Privilege check verification

The seed `ldap_brute` finding alone should trigger the VL-METHOD
`privilege_check` stage, which (because the credential is `Administrator`)
flags the user as `Domain Admins` membership — surfaced as
`privilege_level: domain_admin` in the JSON output.

---

## 3. Phase D — OAuth / OIDC (lab_pwd_oauth, Keycloak)

Endpoint base: `http://lab_pwd_oauth:8080`
Realm: `vl-test-realm`
Discovery URL:
`http://lab_pwd_oauth:8080/realms/vl-test-realm/.well-known/openid-configuration`

### Seeded objects (auto-imported on first boot)

| Object        | Value                                                |
|---------------|------------------------------------------------------|
| Realm         | `vl-test-realm`                                       |
| Client        | `vl-test-client` (public client)                      |
| Implicit flow | **ENABLED** (deliberate vuln — should be flagged)     |
| PKCE          | **NOT enforced** (deliberate vuln — should be flagged) |
| User 1        | `alice` / `Password1!`                                |
| User 2        | `bob` / `Password2!`                                  |

### Seed scan

```
Scan — oauth_token_audit
  target: http://lab_pwd_oauth:8080
  options:
    realm: vl-test-realm
    client_id: vl-test-client
    discovery_path: /realms/vl-test-realm/.well-known/openid-configuration

  Expected findings:
    1. Implicit flow enabled         HIGH 8.1 — CWE-345 / OAuth 2.1 §2.1.2
    2. PKCE not enforced             HIGH 7.5 — CWE-310 / RFC 7636
    3. (informational) standardFlowEnabled + directAccessGrantsEnabled also
       enabled — useful as supporting evidence in the report.
```

There is no chain_handoff for `oauth_token_audit` — it's a configuration
audit, not a credential extractor. The `verify` stage hits the token
endpoint with a deliberate malformed request to confirm the flows are
actually live, not just declared.

---

## 4. Phase D — SAML (lab_pwd_saml, SimpleSAMLphp)

Base URL: `http://lab_pwd_saml:8080`
IdP metadata: `http://lab_pwd_saml:8080/simplesaml/saml2/idp/metadata.php`
SP ACS:       `http://lab_pwd_saml:8080/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp`

### Test users (image defaults)

| Username | Password   |
|----------|------------|
| `user1`  | `user1pass`|
| `user2`  | `user2pass`|

### Seed scan

`saml_signature_audit` requires a **captured valid SAML response** to
mutate (XSW variants, signature stripping, comment injection, etc.).
Capture flow:

1. From any browser (or curl) drive the SP login at
   `http://lab_pwd_saml:8080/simplesaml/module.php/core/authenticate.php?as=default-sp`
2. Authenticate as `user1 / user1pass`.
3. Intercept the SAMLResponse POST to the ACS URL (Burp / mitmproxy /
   browser devtools "copy as cURL").
4. Pass the base64'd SAMLResponse to the scanner:

```
Scan — saml_signature_audit
  target: http://lab_pwd_saml:8080/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp
  options:
    saml_response_b64: <captured>
    sp_acs_url: http://lab_pwd_saml:8080/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp

  Expected:
    SimpleSAMLphp validates signatures correctly out-of-box, so most
    XSW variants will be REJECTED — surfaced as POSITIVE control
    findings (HARDENED). Comment-injection / signature-stripping
    variants may be flagged depending on the SimpleSAMLphp version.

  Real-value of this lab: confirms the scanner correctly *negative*-tests a
  hardened SP without raising false positives.
```

There is no chain_handoff for `saml_signature_audit` either — it's a
crypto / parsing audit. The `privilege_check` stage will note that
captured assertions for `user1` map to no admin role in the IdP.

---

## 5. Tear-down

```bash
docker compose down lab_pwd_ad lab_pwd_oauth lab_pwd_saml
# To also wipe the AD database (so the next boot re-provisions a fresh domain):
docker volume rm cyber-project_lab_pwd_ad_data cyber-project_lab_pwd_ad_conf
```

---

## 6. Troubleshooting

| Symptom                                            | Fix                                                                                                      |
|----------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `ldap_brute` returns NO_CREDS                      | Wait for `lab_pwd_ad` boot (~90 s) and re-run `bootstrap.sh`.                                            |
| `kerberoast_audit` returns 0 hashes                | Bootstrap may not have set SPNs — re-run `docker compose exec lab_pwd_ad samba-tool spn list svc_mssql`. |
| `asreproast_audit` returns 0 hashes                | DONT_REQUIRE_PREAUTH bit didn't stick — re-run the `ldbmodify` block in `bootstrap.sh`.                  |
| `oauth_token_audit` says "discovery 404"           | Realm import failed — check `docker compose logs lab_pwd_oauth` for "import-realm" errors.               |
| `saml_signature_audit` says "missing SAMLResponse" | You must capture a real SAMLResponse first (see section 4 step 3).                                       |
| `lab_pwd_ad` keeps restarting                      | Needs `cap_add: SYS_ADMIN` (already set) and a writable bind to `/var/lib/samba` (volume already wired). |
