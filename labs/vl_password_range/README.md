# VL-METHOD Password Range

Self-contained test lab that exercises **all 7 stages** of every scanner in
the Password Attacks module. Each target is deterministic: known service,
known credentials, known privilege class — so you can verify the 7-stage
methodology end-to-end without false-positives or false-negatives.

## What's inside

| Target           | Hostname        | Port | Default creds   | Used by      |
|------------------|-----------------|------|-----------------|--------------|
| OpenSSH server   | `lab_pwd_ssh`   | 22   | `admin / admin` | Hydra        |
| Samba SMB share  | `lab_pwd_smb`   | 445  | `admin / admin` | Medusa       |
| Flask login form | `lab_pwd_web`   | 5000 | `admin / admin` | Patator      |
| Hash files       | bind-mounted    | n/a  | (see below)     | John         |
| xrdp (opt-in)    | `lab_pwd_rdp`   | 3389 | `admin / admin` | Ncrack (RDP) |

All four core targets use `admin / admin` because that pair is in every
scanner's quick_probe default list — meaning **stage 3 HITS**, which gates
deep_scan + verify + privilege_check + chain_handoff to actually run.

## Spin it up

From the project root on the VPS:

```bash
docker compose up -d lab_pwd_ssh lab_pwd_smb lab_pwd_web
```

Wait ~15 seconds, then verify:

```bash
docker compose exec backend bash -c '
  echo "SSH banner:";   nc -w 3 lab_pwd_ssh 22 < /dev/null
  echo "SMB negotiate:"; nmap -p 445 --script smb-os-discovery lab_pwd_smb | head -20
  echo "HTTP login:";   curl -s -o /dev/null -w "%{http_code}\n" http://lab_pwd_web:5000/login
'
```

Expected: SSH-2.0-OpenSSH banner, SMB OS discovery output, HTTP 200.

## Per-scanner invocation (from VulnusLab UI)

In the Password Attacks tile, set **Target** + **Options** as below:

### 1. Hydra SSH spray  →  `lab_pwd_ssh`

```
Target:    lab_pwd_ssh
Options:
  port:         22
  userlist:     admin\nroot\nubuntu
  passlist:     admin\npassword\n123456
  always_deep:  true
```

Expected 7-stage trace:
- `pre_flight`     port 22 reachable (~12ms)
- `fingerprint`    `SSH-2.0-OpenSSH_X.Y` captured
- `quick_probe`    HIT on admin/admin (~3-5s)
- `deep_scan`      hydra re-confirms admin/admin (~10-20s)
- `verify`         paramiko `id` returns `uid=1000(admin)` → **CONFIRMED**
- `privilege`      classified as **user** (uid≥1000, sudo group → could escalate)
- `chain_handoff`  suggests `privesc_linpeas_remote_audit`
- Severity:        **MEDIUM** (CONFIRMED × user)

### 2. Medusa SMB spray  →  `lab_pwd_smb`

```
Target:    lab_pwd_smb
Options:
  port:         445
  userlist:     admin\nguest
  passlist:     admin\nempty
  always_deep:  true
```

Expected 7-stage trace:
- `pre_flight`     port 445 reachable
- `fingerprint`    SMB dialect + signing status (Samba allows no-signing → bonus finding)
- `quick_probe`    HIT on admin/admin
- `deep_scan`      medusa confirms (or skips if already confirmed)
- `verify`         second SMB session lists `\\lab_pwd_smb\public` → **CONFIRMED**
- `privilege`      C$/IPC$ access → classified as **user**
- `chain_handoff`  suggests `post_exploit_smb_share_dump`
- Severity:        **MEDIUM** (CONFIRMED × user)
- BONUS finding:   HIGH — SMB signing not required (CVE-2021-36942 PetitPotam class)

### 3. Patator HTTP form  →  `lab_pwd_web`

```
Target:    lab_pwd_web
Options:
  form_url:     http://lab_pwd_web:5000/login
  user_field:   username
  pass_field:   password
  fail_string:  Invalid credentials
  userlist:     admin\nroot
  passlist:     admin\npassword
  always_deep:  true
```

Expected 7-stage trace:
- `pre_flight`     HTTP 200 on /login
- `fingerprint`    Flask/Werkzeug headers detected; no CAPTCHA, no rate-limit
- `quick_probe`    HIT on admin/admin (302 + Set-Cookie)
- `deep_scan`      wordlist tested; only admin/admin succeeds
- `verify`         second request to /dashboard with session cookie → 200 → **CONFIRMED**
- `privilege`      /admin/users + /admin/settings both 200 → classified as **admin**
- `chain_handoff`  suggests `post_exploit_session_takeover`
- Severity:        **HIGH** (CONFIRMED × admin)

### 4. John hash audit  →  no network target

```
Target:    localhost              (ignored — John is offline)
Options:
  hashes:       (paste contents of labs/vl_password_range/hashes/test_md5.txt)
  hash_format:  raw-md5            (or leave blank — hashid auto-detects)
  always_deep:  true
```

Expected 7-stage trace:
- `pre_flight`     hashes input non-empty (no network probe)
- `fingerprint`    hashid identifies all 3 as MD5
- `quick_probe`    john --wordlist=top-100 cracks `password` (~5s)
- `deep_scan`      john --rules=Single cracks `123456` + `password123`
- `verify`         passlib re-hashes each plaintext → matches original → **CONFIRMED**
- `privilege`      raw-md5 → classified as **user** (no privilege context for generic hash)
- `chain_handoff`  none (offline scan)
- Severity:        **MEDIUM** × 3 findings (CONFIRMED × user)

Also try `test_bcrypt.txt` (bcrypt of `password`) and `test_ntlm.txt`
(NTLM of `password`) to exercise different fingerprint branches.

### 5. Ncrack RDP spray  →  `lab_pwd_rdp` (opt-in)

RDP requires xrdp container (~600MB). Uncomment `lab_pwd_rdp` in
docker-compose.yml then:

```bash
docker compose up -d lab_pwd_rdp
```

```
Target:    lab_pwd_rdp
Options:
  port:         3389
  userlist:     admin\nAdministrator
  passlist:     admin\nadmin123
  always_deep:  true
```

Expected: same 7-stage pattern. Note — xrdp on Linux doesn't expose WinRM,
so privilege_check will fall back to **unknown** (still all stages execute).

## Verifying the methodology trace

After any scan, open the PDF and confirm each finding shows:

- `confidence: CONFIRMED` (not SUSPECTED, not INFO)
- `verification_method: <description>` (e.g. "paramiko id command in second session")
- `privilege_level: <class>` (root / sudo / admin / user / service / guest)
- `chain_next: [...]` (list of suggested followup scanners)
- Stage timings visible: `pre_flight`, `fingerprint`, `quick_probe`,
  `deep_scan`, `verify`, `privilege_check`, `chain_handoff`

If any stage is missing from the timings dict, that scanner's VL-METHOD
implementation has a bug — file it as a regression.

## Tear down

```bash
docker compose stop lab_pwd_ssh lab_pwd_smb lab_pwd_web lab_pwd_rdp
docker compose rm -f lab_pwd_ssh lab_pwd_smb lab_pwd_web lab_pwd_rdp
```

Hash files persist in `labs/vl_password_range/hashes/` and don't need cleanup.
