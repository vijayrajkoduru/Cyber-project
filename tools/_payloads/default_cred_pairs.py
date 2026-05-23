"""default_cred_pairs — handcrafted dev-time. Vuln module asset.

Canonical default credentials for authorized pentest scanning. Sources:
CISA KEV defaults catalog, Mirai botnet credential corpus, vendor security
advisories. Used by tools/vuln/default_creds.py for brute attempts only
against panels the customer has authorized to scan (their own infra).

Each entry: {username, password, service, vendor, priority(1-10)}.
Priority 10 = universally common (admin/admin); priority 1 = vendor-edge.
"""

DEFAULT_CRED_PAIRS = [
    # ── Universal generic (priority 10) ─────────────────────────────────────
    {"username": "admin", "password": "admin", "service": "generic", "vendor": None, "priority": 10},
    {"username": "admin", "password": "password", "service": "generic", "vendor": None, "priority": 10},
    {"username": "admin", "password": "", "service": "generic", "vendor": None, "priority": 10},
    {"username": "root", "password": "root", "service": "generic", "vendor": None, "priority": 10},
    {"username": "root", "password": "", "service": "generic", "vendor": None, "priority": 10},
    {"username": "root", "password": "toor", "service": "generic", "vendor": None, "priority": 10},
    {"username": "administrator", "password": "administrator", "service": "generic", "vendor": None, "priority": 9},
    {"username": "administrator", "password": "password", "service": "generic", "vendor": None, "priority": 9},
    {"username": "admin", "password": "1234", "service": "generic", "vendor": None, "priority": 9},
    {"username": "admin", "password": "12345", "service": "generic", "vendor": None, "priority": 9},
    {"username": "admin", "password": "123456", "service": "generic", "vendor": None, "priority": 9},
    {"username": "admin", "password": "admin123", "service": "generic", "vendor": None, "priority": 9},
    {"username": "admin", "password": "letmein", "service": "generic", "vendor": None, "priority": 8},
    {"username": "admin", "password": "changeme", "service": "generic", "vendor": None, "priority": 8},
    {"username": "admin", "password": "default", "service": "generic", "vendor": None, "priority": 8},
    {"username": "guest", "password": "guest", "service": "generic", "vendor": None, "priority": 8},
    {"username": "guest", "password": "", "service": "generic", "vendor": None, "priority": 8},
    {"username": "user", "password": "user", "service": "generic", "vendor": None, "priority": 7},
    {"username": "user", "password": "password", "service": "generic", "vendor": None, "priority": 7},
    {"username": "test", "password": "test", "service": "generic", "vendor": None, "priority": 7},
    {"username": "demo", "password": "demo", "service": "generic", "vendor": None, "priority": 7},
    {"username": "support", "password": "support", "service": "generic", "vendor": None, "priority": 7},
    {"username": "root", "password": "password", "service": "generic", "vendor": None, "priority": 8},
    {"username": "root", "password": "admin", "service": "generic", "vendor": None, "priority": 8},
    {"username": "root", "password": "12345", "service": "generic", "vendor": None, "priority": 8},

    # ── Router / CPE vendors ────────────────────────────────────────────────
    # TP-Link
    {"username": "admin", "password": "admin", "service": "router", "vendor": "TP-Link", "priority": 9},
    {"username": "admin", "password": "tplink", "service": "router", "vendor": "TP-Link", "priority": 7},
    {"username": "admin", "password": "1234", "service": "router", "vendor": "TP-Link", "priority": 6},
    # Tenda
    {"username": "admin", "password": "admin", "service": "router", "vendor": "Tenda", "priority": 9},
    {"username": "admin", "password": "", "service": "router", "vendor": "Tenda", "priority": 8},
    {"username": "admin", "password": "tenda", "service": "router", "vendor": "Tenda", "priority": 7},
    # Netgear
    {"username": "admin", "password": "password", "service": "router", "vendor": "Netgear", "priority": 9},
    {"username": "admin", "password": "1234", "service": "router", "vendor": "Netgear", "priority": 7},
    {"username": "admin", "password": "netgear", "service": "router", "vendor": "Netgear", "priority": 6},
    # D-Link
    {"username": "admin", "password": "admin", "service": "router", "vendor": "D-Link", "priority": 9},
    {"username": "admin", "password": "", "service": "router", "vendor": "D-Link", "priority": 8},
    {"username": "admin", "password": "password", "service": "router", "vendor": "D-Link", "priority": 7},
    {"username": "user", "password": "user", "service": "router", "vendor": "D-Link", "priority": 6},
    # Linksys
    {"username": "admin", "password": "admin", "service": "router", "vendor": "Linksys", "priority": 9},
    {"username": "", "password": "admin", "service": "router", "vendor": "Linksys", "priority": 7},
    {"username": "admin", "password": "linksys", "service": "router", "vendor": "Linksys", "priority": 6},
    # Asus
    {"username": "admin", "password": "admin", "service": "router", "vendor": "Asus", "priority": 9},
    {"username": "admin", "password": "asus", "service": "router", "vendor": "Asus", "priority": 6},
    # Cisco
    {"username": "cisco", "password": "cisco", "service": "router", "vendor": "Cisco", "priority": 9},
    {"username": "admin", "password": "cisco", "service": "router", "vendor": "Cisco", "priority": 8},
    {"username": "Cisco", "password": "Cisco", "service": "router", "vendor": "Cisco", "priority": 7},
    {"username": "cisco", "password": "Cisco123", "service": "router", "vendor": "Cisco", "priority": 7},
    {"username": "admin", "password": "Cisco123", "service": "router", "vendor": "Cisco", "priority": 7},
    {"username": "enable", "password": "enable", "service": "router", "vendor": "Cisco", "priority": 6},
    # Huawei
    {"username": "admin", "password": "admin", "service": "router", "vendor": "Huawei", "priority": 9},
    {"username": "root", "password": "admin", "service": "router", "vendor": "Huawei", "priority": 8},
    {"username": "telecomadmin", "password": "admintelecom", "service": "router", "vendor": "Huawei", "priority": 7},
    {"username": "admin", "password": "huawei", "service": "router", "vendor": "Huawei", "priority": 6},
    {"username": "admin", "password": "Huawei@123", "service": "router", "vendor": "Huawei", "priority": 6},
    # ZTE
    {"username": "admin", "password": "admin", "service": "router", "vendor": "ZTE", "priority": 9},
    {"username": "admin", "password": "Zte521", "service": "router", "vendor": "ZTE", "priority": 8},
    {"username": "user", "password": "user", "service": "router", "vendor": "ZTE", "priority": 7},
    {"username": "root", "password": "Zte521", "service": "router", "vendor": "ZTE", "priority": 6},
    # MikroTik
    {"username": "admin", "password": "", "service": "router", "vendor": "MikroTik", "priority": 10},
    {"username": "admin", "password": "admin", "service": "router", "vendor": "MikroTik", "priority": 8},

    # ── ISP CPE (priority weighted to Indian + global ISPs) ─────────────────
    {"username": "admin", "password": "admin", "service": "isp_cpe", "vendor": "Airtel", "priority": 9},
    {"username": "admin", "password": "airtel", "service": "isp_cpe", "vendor": "Airtel", "priority": 7},
    {"username": "support", "password": "theworldinyourhand", "service": "isp_cpe", "vendor": "Airtel", "priority": 6},
    {"username": "admin", "password": "Jiocentrum", "service": "isp_cpe", "vendor": "JIO", "priority": 8},
    {"username": "admin", "password": "admin", "service": "isp_cpe", "vendor": "JIO", "priority": 9},
    {"username": "admin", "password": "bsnl", "service": "isp_cpe", "vendor": "BSNL", "priority": 8},
    {"username": "admin", "password": "admin", "service": "isp_cpe", "vendor": "BSNL", "priority": 9},
    {"username": "support", "password": "support", "service": "isp_cpe", "vendor": "BSNL", "priority": 7},
    {"username": "admin", "password": "reliance", "service": "isp_cpe", "vendor": "Reliance", "priority": 7},
    {"username": "admin", "password": "vodafone", "service": "isp_cpe", "vendor": "Vodafone", "priority": 7},
    {"username": "admin", "password": "comcast", "service": "isp_cpe", "vendor": "Comcast", "priority": 6},
    {"username": "admin", "password": "att", "service": "isp_cpe", "vendor": "AT&T", "priority": 6},
    {"username": "admin", "password": "motorola", "service": "isp_cpe", "vendor": "AT&T", "priority": 6},

    # ── IoT cameras / NVRs ──────────────────────────────────────────────────
    # Hikvision
    {"username": "admin", "password": "12345", "service": "iot_camera", "vendor": "Hikvision", "priority": 10},
    {"username": "admin", "password": "admin", "service": "iot_camera", "vendor": "Hikvision", "priority": 9},
    {"username": "admin", "password": "hik12345", "service": "iot_camera", "vendor": "Hikvision", "priority": 8},
    # Dahua
    {"username": "admin", "password": "admin", "service": "iot_camera", "vendor": "Dahua", "priority": 10},
    {"username": "888888", "password": "888888", "service": "iot_camera", "vendor": "Dahua", "priority": 9},
    {"username": "666666", "password": "666666", "service": "iot_camera", "vendor": "Dahua", "priority": 8},
    # Axis
    {"username": "root", "password": "pass", "service": "iot_camera", "vendor": "Axis", "priority": 9},
    {"username": "root", "password": "root", "service": "iot_camera", "vendor": "Axis", "priority": 8},
    {"username": "admin", "password": "admin", "service": "iot_camera", "vendor": "Axis", "priority": 8},
    # Foscam
    {"username": "admin", "password": "", "service": "iot_camera", "vendor": "Foscam", "priority": 9},
    {"username": "admin", "password": "admin", "service": "iot_camera", "vendor": "Foscam", "priority": 8},
    {"username": "admin", "password": "foscam", "service": "iot_camera", "vendor": "Foscam", "priority": 7},
    # Generic IPCam / Mirai-corpus
    {"username": "admin", "password": "1111", "service": "iot_camera", "vendor": None, "priority": 8},
    {"username": "admin", "password": "1234", "service": "iot_camera", "vendor": None, "priority": 9},
    {"username": "admin", "password": "12345", "service": "iot_camera", "vendor": None, "priority": 9},
    {"username": "admin", "password": "54321", "service": "iot_camera", "vendor": None, "priority": 7},
    {"username": "admin", "password": "9999", "service": "iot_camera", "vendor": None, "priority": 7},
    {"username": "admin", "password": "default", "service": "iot_camera", "vendor": None, "priority": 8},
    {"username": "root", "password": "xc3511", "service": "iot_camera", "vendor": None, "priority": 8},  # Mirai
    {"username": "root", "password": "vizxv", "service": "iot_camera", "vendor": None, "priority": 8},   # Mirai
    {"username": "root", "password": "888888", "service": "iot_camera", "vendor": None, "priority": 7},
    {"username": "root", "password": "klv1234", "service": "iot_camera", "vendor": None, "priority": 6},
    {"username": "root", "password": "Zte521", "service": "iot_camera", "vendor": None, "priority": 6},
    # Tapo / Ring / Nest
    {"username": "admin", "password": "tapo", "service": "iot_camera", "vendor": "TP-Link Tapo", "priority": 6},
    {"username": "admin", "password": "ring", "service": "iot_camera", "vendor": "Ring", "priority": 5},

    # ── Industrial / SCADA ──────────────────────────────────────────────────
    {"username": "admin", "password": "admin", "service": "scada", "vendor": "Siemens", "priority": 9},
    {"username": "Administrator", "password": "100", "service": "scada", "vendor": "Siemens", "priority": 8},
    {"username": "user", "password": "user", "service": "scada", "vendor": "Siemens", "priority": 7},
    {"username": "siemens", "password": "siemens", "service": "scada", "vendor": "Siemens", "priority": 7},
    {"username": "admin", "password": "admin", "service": "scada", "vendor": "Schneider", "priority": 9},
    {"username": "USER", "password": "USER", "service": "scada", "vendor": "Schneider", "priority": 7},
    {"username": "ADMIN", "password": "ADMIN", "service": "scada", "vendor": "Schneider", "priority": 7},
    {"username": "admin", "password": "admin", "service": "scada", "vendor": "Allen-Bradley", "priority": 8},
    {"username": "Administrator", "password": "Administrator", "service": "scada", "vendor": "Allen-Bradley", "priority": 7},
    {"username": "admin", "password": "admin", "service": "scada", "vendor": "Mitsubishi", "priority": 7},

    # ── Network gear (Cisco/Juniper/etc beyond router) ─────────────────────
    {"username": "admin", "password": "Juniper", "service": "network", "vendor": "Juniper", "priority": 8},
    {"username": "root", "password": "juniper", "service": "network", "vendor": "Juniper", "priority": 7},
    {"username": "admin", "password": "panw", "service": "network", "vendor": "Palo Alto", "priority": 8},
    {"username": "admin", "password": "admin", "service": "network", "vendor": "Palo Alto", "priority": 9},
    {"username": "admin", "password": "fortinet", "service": "network", "vendor": "Fortinet", "priority": 8},
    {"username": "admin", "password": "", "service": "network", "vendor": "Fortinet", "priority": 9},
    {"username": "ubnt", "password": "ubnt", "service": "network", "vendor": "Ubiquiti", "priority": 10},
    {"username": "admin", "password": "ubnt", "service": "network", "vendor": "Ubiquiti", "priority": 8},
    {"username": "admin", "password": "aruba123", "service": "network", "vendor": "Aruba", "priority": 7},
    {"username": "admin", "password": "admin", "service": "network", "vendor": "Aruba", "priority": 9},
    {"username": "manager", "password": "manager", "service": "network", "vendor": "HP ProCurve", "priority": 8},
    {"username": "operator", "password": "operator", "service": "network", "vendor": "HP ProCurve", "priority": 7},
    {"username": "admin", "password": "procurve", "service": "network", "vendor": "HP ProCurve", "priority": 6},
    {"username": "admin", "password": "extreme", "service": "network", "vendor": "Extreme", "priority": 7},
    {"username": "admin", "password": "brocade", "service": "network", "vendor": "Brocade", "priority": 7},

    # ── Database admin ──────────────────────────────────────────────────────
    {"username": "root", "password": "", "service": "database", "vendor": "MySQL", "priority": 10},
    {"username": "root", "password": "root", "service": "database", "vendor": "MySQL", "priority": 9},
    {"username": "root", "password": "mysql", "service": "database", "vendor": "MySQL", "priority": 8},
    {"username": "root", "password": "password", "service": "database", "vendor": "MySQL", "priority": 8},
    {"username": "mysql", "password": "mysql", "service": "database", "vendor": "MySQL", "priority": 7},
    {"username": "postgres", "password": "postgres", "service": "database", "vendor": "PostgreSQL", "priority": 10},
    {"username": "postgres", "password": "", "service": "database", "vendor": "PostgreSQL", "priority": 9},
    {"username": "postgres", "password": "password", "service": "database", "vendor": "PostgreSQL", "priority": 8},
    {"username": "admin", "password": "admin", "service": "database", "vendor": "MongoDB", "priority": 8},
    {"username": "root", "password": "root", "service": "database", "vendor": "MongoDB", "priority": 7},
    {"username": "admin", "password": "password", "service": "database", "vendor": "MongoDB", "priority": 7},
    {"username": "sa", "password": "", "service": "database", "vendor": "MSSQL", "priority": 9},
    {"username": "sa", "password": "sa", "service": "database", "vendor": "MSSQL", "priority": 8},
    {"username": "sa", "password": "password", "service": "database", "vendor": "MSSQL", "priority": 8},
    {"username": "sa", "password": "MSSQLServer", "service": "database", "vendor": "MSSQL", "priority": 6},
    {"username": "system", "password": "manager", "service": "database", "vendor": "Oracle", "priority": 9},
    {"username": "sys", "password": "change_on_install", "service": "database", "vendor": "Oracle", "priority": 8},
    {"username": "scott", "password": "tiger", "service": "database", "vendor": "Oracle", "priority": 8},
    {"username": "internal", "password": "oracle", "service": "database", "vendor": "Oracle", "priority": 7},

    # ── Web admin panels ────────────────────────────────────────────────────
    {"username": "root", "password": "", "service": "web_admin", "vendor": "phpMyAdmin", "priority": 10},
    {"username": "root", "password": "root", "service": "web_admin", "vendor": "phpMyAdmin", "priority": 9},
    {"username": "admin", "password": "admin", "service": "web_admin", "vendor": "phpMyAdmin", "priority": 9},
    {"username": "admin", "password": "password", "service": "web_admin", "vendor": "cPanel", "priority": 8},
    {"username": "root", "password": "password", "service": "web_admin", "vendor": "cPanel", "priority": 8},
    {"username": "admin", "password": "admin", "service": "web_admin", "vendor": "Plesk", "priority": 8},
    {"username": "admin", "password": "setup", "service": "web_admin", "vendor": "Plesk", "priority": 7},
    {"username": "admin", "password": "admin", "service": "web_admin", "vendor": "Webmin", "priority": 9},
    {"username": "root", "password": "root", "service": "web_admin", "vendor": "Webmin", "priority": 8},
    {"username": "admin", "password": "admin", "service": "web_admin", "vendor": "DirectAdmin", "priority": 8},
    {"username": "admin", "password": "admin", "service": "web_admin", "vendor": "VirtualMin", "priority": 7},

    # ── CMS defaults ────────────────────────────────────────────────────────
    {"username": "admin", "password": "admin", "service": "cms", "vendor": "WordPress", "priority": 9},
    {"username": "admin", "password": "password", "service": "cms", "vendor": "WordPress", "priority": 9},
    {"username": "wordpress", "password": "wordpress", "service": "cms", "vendor": "WordPress", "priority": 7},
    {"username": "admin", "password": "wordpress", "service": "cms", "vendor": "WordPress", "priority": 7},
    {"username": "admin", "password": "joomla", "service": "cms", "vendor": "Joomla", "priority": 8},
    {"username": "admin", "password": "admin", "service": "cms", "vendor": "Joomla", "priority": 9},
    {"username": "admin", "password": "drupal", "service": "cms", "vendor": "Drupal", "priority": 8},
    {"username": "admin", "password": "admin", "service": "cms", "vendor": "Drupal", "priority": 9},
    {"username": "admin", "password": "admin123", "service": "cms", "vendor": "Magento", "priority": 8},
    {"username": "admin", "password": "magento", "service": "cms", "vendor": "Magento", "priority": 7},
    {"username": "admin", "password": "admin", "service": "cms", "vendor": "OpenCart", "priority": 8},
    {"username": "admin", "password": "admin", "service": "cms", "vendor": "PrestaShop", "priority": 7},
    {"username": "admin", "password": "ghostadmin", "service": "cms", "vendor": "Ghost", "priority": 6},
    {"username": "admin", "password": "concrete5", "service": "cms", "vendor": "Concrete5", "priority": 6},

    # ── DevOps / CI panels ──────────────────────────────────────────────────
    {"username": "admin", "password": "admin", "service": "devops", "vendor": "Jenkins", "priority": 10},
    {"username": "jenkins", "password": "jenkins", "service": "devops", "vendor": "Jenkins", "priority": 8},
    {"username": "admin", "password": "password", "service": "devops", "vendor": "Jenkins", "priority": 9},
    {"username": "root", "password": "calvin", "service": "devops", "vendor": "Dell iDRAC", "priority": 9},
    {"username": "Administrator", "password": "", "service": "devops", "vendor": "HP iLO", "priority": 9},
    {"username": "admin", "password": "password", "service": "devops", "vendor": "HP iLO", "priority": 8},
    {"username": "root", "password": "root", "service": "devops", "vendor": "GitLab", "priority": 8},
    {"username": "admin", "password": "5iveL!fe", "service": "devops", "vendor": "GitLab", "priority": 9},  # historical default
    {"username": "admin", "password": "admin", "service": "devops", "vendor": "Grafana", "priority": 10},
    {"username": "admin", "password": "grafana", "service": "devops", "vendor": "Grafana", "priority": 7},
    {"username": "elastic", "password": "changeme", "service": "devops", "vendor": "Kibana", "priority": 10},
    {"username": "elastic", "password": "elastic", "service": "devops", "vendor": "Kibana", "priority": 9},
    {"username": "admin", "password": "admin", "service": "devops", "vendor": "Kibana", "priority": 8},
    {"username": "admin", "password": "prometheus", "service": "devops", "vendor": "Prometheus", "priority": 7},
    {"username": "admin", "password": "argocd", "service": "devops", "vendor": "Argo CD", "priority": 7},
    {"username": "admin", "password": "argo", "service": "devops", "vendor": "Argo CD", "priority": 8},
    {"username": "admin", "password": "admin", "service": "devops", "vendor": "Argo CD", "priority": 9},
    {"username": "admin", "password": "spinnaker", "service": "devops", "vendor": "Spinnaker", "priority": 6},
    {"username": "admin", "password": "admin", "service": "devops", "vendor": "Bamboo", "priority": 8},
    {"username": "admin", "password": "admin", "service": "devops", "vendor": "TeamCity", "priority": 8},
    {"username": "admin", "password": "admin", "service": "devops", "vendor": "Bitbucket", "priority": 8},
    {"username": "admin", "password": "rundeck", "service": "devops", "vendor": "Rundeck", "priority": 7},
    {"username": "admin", "password": "admin", "service": "devops", "vendor": "Rundeck", "priority": 8},

    # ── App framework admin consoles ────────────────────────────────────────
    {"username": "admin", "password": "admin", "service": "app_framework", "vendor": "Tomcat", "priority": 9},
    {"username": "tomcat", "password": "tomcat", "service": "app_framework", "vendor": "Tomcat", "priority": 9},
    {"username": "manager", "password": "manager", "service": "app_framework", "vendor": "Tomcat", "priority": 8},
    {"username": "manager", "password": "tomcat", "service": "app_framework", "vendor": "Tomcat", "priority": 8},
    {"username": "admin", "password": "tomcat", "service": "app_framework", "vendor": "Tomcat", "priority": 8},
    {"username": "role1", "password": "role1", "service": "app_framework", "vendor": "Tomcat", "priority": 6},
    {"username": "both", "password": "tomcat", "service": "app_framework", "vendor": "Tomcat", "priority": 6},
    {"username": "admin", "password": "admin", "service": "app_framework", "vendor": "JBoss", "priority": 9},
    {"username": "jboss", "password": "jboss", "service": "app_framework", "vendor": "JBoss", "priority": 8},
    {"username": "admin", "password": "jboss", "service": "app_framework", "vendor": "JBoss", "priority": 7},
    {"username": "admin", "password": "admin", "service": "app_framework", "vendor": "WildFly", "priority": 8},
    {"username": "admin", "password": "admin", "service": "app_framework", "vendor": "GlassFish", "priority": 8},
    {"username": "admin", "password": "weblogic", "service": "app_framework", "vendor": "WebLogic", "priority": 9},
    {"username": "weblogic", "password": "weblogic", "service": "app_framework", "vendor": "WebLogic", "priority": 9},
    {"username": "weblogic", "password": "welcome1", "service": "app_framework", "vendor": "WebLogic", "priority": 8},
    {"username": "system", "password": "weblogic1", "service": "app_framework", "vendor": "WebLogic", "priority": 7},

    # ── Storage / backup ────────────────────────────────────────────────────
    {"username": "admin", "password": "admin", "service": "storage", "vendor": "Synology", "priority": 9},
    {"username": "admin", "password": "synology", "service": "storage", "vendor": "Synology", "priority": 7},
    {"username": "admin", "password": "admin", "service": "storage", "vendor": "QNAP", "priority": 9},
    {"username": "admin", "password": "qnap", "service": "storage", "vendor": "QNAP", "priority": 7},
    {"username": "admin", "password": "admin", "service": "storage", "vendor": "TrueNAS", "priority": 8},
    {"username": "root", "password": "freenas", "service": "storage", "vendor": "FreeNAS", "priority": 8},
    {"username": "admin", "password": "veeam", "service": "storage", "vendor": "Veeam", "priority": 7},
    {"username": "admin", "password": "admin", "service": "storage", "vendor": "Veeam", "priority": 8},

    # ── VoIP / PBX ──────────────────────────────────────────────────────────
    {"username": "admin", "password": "admin", "service": "voip", "vendor": "FreePBX", "priority": 9},
    {"username": "admin", "password": "freepbx", "service": "voip", "vendor": "FreePBX", "priority": 7},
    {"username": "admin", "password": "asterisk", "service": "voip", "vendor": "Asterisk", "priority": 9},
    {"username": "admin", "password": "admin", "service": "voip", "vendor": "3CX", "priority": 8},
    {"username": "admin", "password": "admin", "service": "voip", "vendor": "Cisco UCM", "priority": 8},
    {"username": "admin", "password": "yealink", "service": "voip", "vendor": "Yealink", "priority": 7},
    {"username": "admin", "password": "admin", "service": "voip", "vendor": "Yealink", "priority": 9},
    {"username": "admin", "password": "admin", "service": "voip", "vendor": "Polycom", "priority": 8},
    {"username": "Polycom", "password": "456", "service": "voip", "vendor": "Polycom", "priority": 7},
    {"username": "admin", "password": "fanvil", "service": "voip", "vendor": "Fanvil", "priority": 7},

    # ── Monitoring / misc ───────────────────────────────────────────────────
    {"username": "admin", "password": "splunk", "service": "monitoring", "vendor": "Splunk", "priority": 8},
    {"username": "admin", "password": "changeme", "service": "monitoring", "vendor": "Splunk", "priority": 9},
    {"username": "nagiosadmin", "password": "nagios", "service": "monitoring", "vendor": "Nagios", "priority": 9},
    {"username": "nagiosadmin", "password": "nagiosadmin", "service": "monitoring", "vendor": "Nagios", "priority": 8},
    {"username": "Admin", "password": "zabbix", "service": "monitoring", "vendor": "Zabbix", "priority": 9},
    {"username": "Admin", "password": "Admin", "service": "monitoring", "vendor": "Zabbix", "priority": 7},
    {"username": "admin", "password": "admin", "service": "monitoring", "vendor": "Cacti", "priority": 9},
    {"username": "admin", "password": "admin", "service": "monitoring", "vendor": "Observium", "priority": 8},
    {"username": "admin", "password": "admin", "service": "monitoring", "vendor": "LibreNMS", "priority": 8},
    {"username": "admin", "password": "admin", "service": "monitoring", "vendor": "PRTG", "priority": 9},
    {"username": "prtgadmin", "password": "prtgadmin", "service": "monitoring", "vendor": "PRTG", "priority": 8},

    # ── UPS / Power ─────────────────────────────────────────────────────────
    {"username": "apc", "password": "apc", "service": "ups", "vendor": "APC", "priority": 9},
    {"username": "device", "password": "apc", "service": "ups", "vendor": "APC", "priority": 7},
    {"username": "admin", "password": "admin", "service": "ups", "vendor": "Eaton", "priority": 8},
    {"username": "admin", "password": "liebert", "service": "ups", "vendor": "Liebert", "priority": 7},

    # ── Printer admin ───────────────────────────────────────────────────────
    {"username": "admin", "password": "admin", "service": "printer", "vendor": "HP", "priority": 9},
    {"username": "admin", "password": "", "service": "printer", "vendor": "HP", "priority": 9},
    {"username": "admin", "password": "1234", "service": "printer", "vendor": "HP", "priority": 7},
    {"username": "admin", "password": "lexmark", "service": "printer", "vendor": "Lexmark", "priority": 7},
    {"username": "admin", "password": "xerox", "service": "printer", "vendor": "Xerox", "priority": 7},
    {"username": "admin", "password": "1111", "service": "printer", "vendor": "Xerox", "priority": 7},
    {"username": "admin", "password": "ricoh", "service": "printer", "vendor": "Ricoh", "priority": 7},
    {"username": "admin", "password": "kyocera", "service": "printer", "vendor": "Kyocera", "priority": 6},

    # ── BMC / out-of-band management ────────────────────────────────────────
    {"username": "ADMIN", "password": "ADMIN", "service": "bmc", "vendor": "Supermicro IPMI", "priority": 9},
    {"username": "admin", "password": "admin", "service": "bmc", "vendor": "Supermicro IPMI", "priority": 8},
    {"username": "ADMIN", "password": "admin", "service": "bmc", "vendor": "Lenovo XCC", "priority": 7},
    {"username": "USERID", "password": "PASSW0RD", "service": "bmc", "vendor": "Lenovo IMM", "priority": 9},  # default IBM
    {"username": "ADMIN", "password": "ADMIN", "service": "bmc", "vendor": "Dell DRAC", "priority": 8},
]
