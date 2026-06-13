# VulnusLab — Target / Lab Range (backup manifest)

The deliberately-vulnerable Docker targets for testing every module. Defined in
both `docker-compose.yml` (live stack) and `docker-compose.targets.yml`
(standalone backup). Build files live under `labs/`.

## Restore / run

```bash
# Whole range (attaches to the backend network):
docker compose -f docker-compose.targets.yml up -d
# Or via the main stack:
docker compose up -d lab_dvwa lab_juiceshop lab_bwapp lab_mutillidae lab_webgoat \
  lab_metasploitable lab_pwd_ssh lab_pwd_smb lab_pwd_web lab_mysql lab_postgres \
  lab_ftp lab_redis lab_mongo lab_modbus lab_k3s lab_pwd_ad lab_pwd_oauth lab_pwd_saml
# One-time post-boot:
sleep 90 && docker compose exec lab_pwd_ad bash /bootstrap.sh
sleep 25 && sed -i 's#https://127.0.0.1:6443#https://lab_k3s:6443#' labs/vl_k8s_range/kubeconfig.yaml
```

## Targets

| Target | Image | Port | Credentials | Tests module(s) |
|---|---|---|---|---|
| lab_dvwa | vulnerables/web-dvwa | 80 | admin / password | webapp, recon, vuln, exploit, client_side, auth_attacks |
| lab_juiceshop | bkimminich/juice-shop | 3000 | admin@juice-sh.op / admin123 | webapp, apisec, client_side, vuln, recon, auth_attacks |
| lab_bwapp | raesene/bwapp | 80 | bee / bug (run install.php once) | webapp |
| lab_mutillidae | citizenstig/nowasp | 80 | admin / admin | webapp |
| lab_webgoat | webgoat/webgoat | 8080 | guest / guest | webapp |
| lab_metasploitable | tleemcjr/metasploitable2 | many | msfadmin / msfadmin | network, exploit, system_exploit, metasploit, privesc, pivot, post_exploit, tunnel, password |
| lab_pwd_ssh | linuxserver/openssh-server | 2222 | admin / admin | password (hydra) |
| lab_pwd_smb | dperson/samba | 445 | admin / admin | password (medusa) |
| lab_pwd_web | (built: labs/vl_password_range/webform) | 5000 | admin / admin | password (patator HTTP form) |
| lab_mysql | mysql:5.7 | 3306 | root / root | password (mysql_brute), network, vuln |
| lab_postgres | postgres:15-alpine | 5432 | postgres / postgres | password (postgres_brute), network, vuln |
| lab_ftp | delfer/alpine-ftp-server | 21 | admin / admin | password (ftp_brute) |
| lab_redis | redis:7-alpine | 6379 | none (exposed) | network, vuln |
| lab_mongo | mongo:6 | 27017 | none (exposed) | network, vuln |
| lab_pwd_ad | nowsci/samba-domain | 389/445/88 | Administrator / VLrange_Admin_2026! (+ svc_mssql/Password123, svc_http/Spring2024, jbloggs/NoPreAuth!) | ad, password tier3 |
| lab_pwd_oauth | quay.io/keycloak/keycloak:24.0.5 | 8080 | admin / admin_VLrange_2026; realm vl-test-realm: alice/Password1!, bob/Password2! | auth_attacks (OAuth) |
| lab_pwd_saml | kristophjunge/test-saml-idp | 8080 | user1 / user1pass, user2 / user2pass | auth_attacks (SAML) |
| lab_modbus | (built: labs/vl_ics_range/modbus) | 502 | none (unauth Modbus) | iot_ot, vuln tier15 |
| lab_k3s | rancher/k3s:v1.29.6-k3s2 | 6443 | kubeconfig -> labs/vl_k8s_range/kubeconfig.yaml | container_k8s, vuln tier9/10 |

All targets are internal-only (no published host ports) — reachable by the
scanner backend over the `vulnuslab` Docker network by hostname.

## Source build files (do not delete)
- `labs/vl_ics_range/modbus/{Dockerfile,server.py}` — lab_modbus
- `labs/vl_password_range/webform/{Dockerfile,app.py}` — lab_pwd_web
- `labs/vl_password_range/keycloak/` — lab_pwd_oauth realm import
- `labs/vl_password_range/ad_bootstrap.sh` — lab_pwd_ad seeded users
- `labs/vl_k8s_range/` — k3s kubeconfig output dir (kubeconfig.yaml is git-ignored)
