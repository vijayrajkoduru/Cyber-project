"""Full Vuln-module dev-time asset generator.

Mirrors gen_recon_assets.py — writes generated payload files to
/tmp/vl_payloads/<kind>.py so you can review before copying into
tools/_payloads/. Driven by ANTHROPIC_API_KEY env var.

5 assets covering the Vuln-module scanners with thin hardcoded lists:
  default_cred_pairs, default_cred_paths, snmp_communities,
  smtp_vrfy_users, db_exposure_probes
"""
import json, os, re, sys
import anthropic

CONFIGS = {
    "default_cred_pairs": {
        "max_tokens": 28000, "var": "DEFAULT_CRED_PAIRS",
        "prompt": """Generate 800 default-credential pairs for a credential-brute scanner.
Priority-ordered (highest hit-rate first).

REQUIRED coverage:
- Generic admin (admin/admin, admin/password, root/root, etc.) — 50 pairs
- Router/CPE vendors (TP-Link, Tenda, Netgear, D-Link, Asus, Linksys, Cisco, Huawei, ZTE, Mikrotik) — 120 pairs
- ISP CPE (Airtel, JIO, BSNL, Reliance, Vodafone India, Comcast, AT&T) — 60 pairs
- IoT cameras (Hikvision, Dahua, Axis, Foscam, TP-Link Tapo, Ring, Nest) — 80 pairs
- Industrial / SCADA (Siemens, Schneider, Allen-Bradley, Mitsubishi) — 40 pairs
- Network gear (Cisco IOS, Juniper, Palo Alto, Fortinet, Ubiquiti, Aruba, HP ProCurve) — 80 pairs
- Database admin (MySQL, PostgreSQL, MongoDB, Redis, Elastic, Mssql) — 60 pairs
- Web admin panels (cPanel, WHM, Plesk, DirectAdmin, Webmin, phpMyAdmin) — 50 pairs
- CMS defaults (WordPress, Joomla, Drupal, Magento, OpenCart, PrestaShop) — 50 pairs
- DevOps / CI panels (Jenkins, GitLab, Bitbucket, Bamboo, Argo, Spinnaker, Grafana, Kibana) — 60 pairs
- App framework (Tomcat manager, JBoss admin console, GlassFish, WebLogic) — 40 pairs
- Storage / backup (Synology, QNAP, FreeNAS, TrueNAS, Veeam, Backblaze) — 40 pairs
- VoIP / PBX (FreePBX, Asterisk, 3CX, Cisco UCM, Yealink, Polycom) — 30 pairs
- Misc cloud / SaaS appliances (Splunk, Nagios, Zabbix, Cacti, Observium) — 40 pairs

Each item EXACTLY 5 keys:
  username (string), password (string),
  service (snake_case category — generic, router, iot, scada, network, database, web_admin, cms, devops, app, storage, voip, misc),
  vendor (string or null — specific product),
  priority (1-10, 10 = highest hit-rate)

OUTPUT: ONLY JSON array. Start [ end ]. No prose. Keep ALL strings concise."""
    },

    "default_cred_paths": {
        "max_tokens": 18000, "var": "DEFAULT_CRED_PATHS",
        "prompt": """Generate 250 admin / login / panel URL paths for a default-credential discovery scanner.
Priority-ordered (most-common first).

REQUIRED coverage:
- Generic admin (/admin, /administrator, /login, /signin, /panel, /dashboard) — 30 paths
- WordPress (/wp-admin, /wp-login.php, etc.) — 15 paths
- Joomla / Drupal / Magento — 20 paths
- Database admin tools (/phpmyadmin, /pma, /myadmin, /adminer, /sqlbuddy) — 25 paths
- Network gear admin paths (/router, /webconsole, /admin.html, /system.html, /config) — 25 paths
- Cloud / SaaS panels (/console, /control-panel, /manage) — 15 paths
- Hosting panels (/cpanel, /whm, /plesk, /directadmin, /webmin, /usermin) — 20 paths
- IoT camera/NVR (/doc/page/login.asp, /cgi-bin/login.cgi, /webadmin) — 20 paths
- Industrial / SCADA (/scada, /hmi, /ics-admin) — 15 paths
- DevOps panels (/jenkins, /gitlab, /grafana, /kibana, /prometheus, /argo, /spinnaker) — 25 paths
- Mail admin (/horde, /squirrelmail, /roundcube, /webmail/admin) — 15 paths
- Backup / storage (/syno, /qnap, /diskstation) — 15 paths
- VoIP / PBX (/freepbx, /asterisk, /admin/config.php) — 10 paths

Each item EXACTLY 4 keys:
  path (with leading /), category (snake_case),
  expected_indicators (array of 1-3 strings that suggest a panel page — "login", "Sign in", "username", "Welcome"),
  priority (1-10)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "snmp_communities": {
        "max_tokens": 8000, "var": "SNMP_COMMUNITIES",
        "prompt": """Generate 120 SNMP community strings for a community-brute scanner.
Priority-ordered.

REQUIRED coverage:
- Universal defaults (public, private, community, manager, admin) — 15 entries
- Cisco IOS / NX-OS defaults — 15 entries
- HP ProCurve / Aruba defaults — 10 entries
- Brocade / Foundry defaults — 8 entries
- Juniper defaults — 8 entries
- Dell PowerConnect / EMC — 8 entries
- IBM / Lenovo server — 8 entries
- HP iLO / Dell iDRAC management — 10 entries
- Camera/IoT defaults — 8 entries
- Printer defaults (HP, Lexmark, Xerox) — 10 entries
- UPS (APC, Eaton, Liebert) — 8 entries
- Industrial / SCADA — 6 entries
- Misc weak strings (test, monitor, snmpd, c0mmunity) — 6 entries

Each item EXACTLY 3 keys:
  community (string), category (snake_case), priority (1-10)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "smtp_vrfy_users": {
        "max_tokens": 10000, "var": "SMTP_VRFY_USERS",
        "prompt": """Generate 200 username candidates for SMTP VRFY user enumeration.
Priority-ordered (most-common in corporate environments first).

REQUIRED coverage:
- Generic admin (admin, administrator, postmaster, webmaster, hostmaster, root) — 25
- Operations roles (ops, devops, sysadmin, sre, dba, security, soc, helpdesk, support) — 30
- Business roles (info, contact, sales, marketing, hr, finance, accounting, legal, ceo, cfo) — 35
- Service accounts (noreply, no-reply, mail, mailer, mailman, listserv, daemon, cron) — 25
- Common first names (john, mike, david, sarah, lisa, mark, chris, alex) — 30
- Service / generic (test, demo, guest, dev, developer, qa, staging, prod) — 20
- Mail-related (abuse, security@, dmarc, dkim, spf, soc, fraud, phishing) — 15
- Misc / shell access (nobody, www-data, apache, nginx, mysql, postgres, oracle) — 20

Each item EXACTLY 3 keys:
  username (string, lowercase, no @domain), category (snake_case), priority (1-10)

OUTPUT: ONLY JSON array. Start [ end ]. No prose."""
    },

    "db_exposure_probes": {
        "max_tokens": 12000, "var": "DB_EXPOSURE_PROBES",
        "prompt": """Generate 60 database-exposure probe signatures for a service-fingerprint scanner.
Cover NoSQL, SQL, search, cache, message-queue.

REQUIRED coverage:
- MongoDB (default 27017, alternative 27018-27021) — 5
- Redis (6379, sentinels 26379, cluster 16379) — 5
- Elasticsearch (9200, 9300 transport) — 5
- CouchDB (5984) — 3
- Memcached (11211 + UDP) — 4
- MySQL / MariaDB (3306, Galera 4567) — 4
- PostgreSQL (5432) — 3
- MSSQL (1433, 1434/UDP) — 3
- Oracle (1521, 1526) — 3
- Cassandra (9042, 9160) — 3
- Kafka (9092, KRaft 9093) — 3
- RabbitMQ (5672, management 15672) — 3
- InfluxDB (8086) — 2
- Neo4j (7474, 7687) — 2
- ClickHouse (8123, 9000) — 2
- ArangoDB (8529) — 2
- Etcd (2379, 2380) — 2
- Riak (8087, 8098) — 2

Each item EXACTLY 8 keys:
  port (int), protocol ("tcp" or "udp"),
  service (string, snake_case like "mongodb"),
  probe_bytes (hex string OR text like "PING\\r\\n" OR empty string ""),
  expect_substring (hex string OR text the server must echo back — empty "" if any data on connect = positive),
  severity (CRITICAL | HIGH | MEDIUM),
  cvss (number as string),
  remediation (1 short sentence)

OUTPUT: ONLY JSON array. Start [ end ]. No prose. CWE-306 (no-auth) implied throughout."""
    },
}


def salvage(raw):
    """Multi-point salvage — walks backwards finding the longest valid JSON prefix."""
    raw = re.sub(r"^```(?:json)?\s*", "", raw.strip())
    raw = re.sub(r"\s*```$", "", raw)
    try:
        return json.loads(raw), False
    except json.JSONDecodeError:
        pass
    end_positions = [m.end() - 1 for m in re.finditer(r"\},", raw)]
    end_positions.reverse()
    for pos in end_positions:
        candidate = raw[:pos + 1] + "]"
        try:
            res = json.loads(candidate)
            if isinstance(res, list) and len(res) > 5:
                return res, True
        except json.JSONDecodeError:
            pass
    return None, False


def main():
    kind = sys.argv[1] if len(sys.argv) > 1 else ""
    if kind not in CONFIGS:
        sys.exit(f"Usage: gen_vuln_assets.py {list(CONFIGS.keys())}")
    cfg = CONFIGS[kind]
    print(f"=== {kind} (max_tokens={cfg['max_tokens']}, streaming) ===")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY missing")

    client = anthropic.Anthropic()
    chunks, last_dot = [], 0
    with client.messages.stream(
        model="claude-sonnet-4-6",
        max_tokens=cfg["max_tokens"],
        messages=[{"role": "user", "content": cfg["prompt"]}],
    ) as stream:
        for text in stream.text_stream:
            chunks.append(text)
            total = sum(len(c) for c in chunks)
            if total // 5000 > last_dot:
                print(".", end="", flush=True); last_dot = total // 5000
        final = stream.get_final_message()
        in_tok, out_tok = final.usage.input_tokens, final.usage.output_tokens
    print()

    raw = "".join(chunks)
    items, salvaged = salvage(raw)
    if items is None:
        open(f"/tmp/{kind}_raw.txt", "w").write(raw)
        sys.exit(f"Salvage failed. Saved /tmp/{kind}_raw.txt ({len(raw)} bytes)")
    if salvaged:
        print(f"  truncated, salvaged {len(items)} items")

    out = f"/tmp/vl_payloads/{kind}.py"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    import pprint
    with open(out, "w") as f:
        f.write(f'"""{kind} — generated dev-time by Claude. Vuln module asset.\n"""\n\n')
        f.write(f'{cfg["var"]} = ')
        f.write(pprint.pformat(items, width=120, sort_dicts=False))
        f.write("\n")
    cost = (in_tok * 3 + out_tok * 15) / 1_000_000
    print(f"  wrote {len(items)} items to {out}")
    print(f"  tokens: {in_tok} in, {out_tok} out  |  cost: ~${cost:.3f}")


if __name__ == "__main__":
    main()
