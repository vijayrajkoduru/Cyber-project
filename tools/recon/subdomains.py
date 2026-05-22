"""recon_subdomains -- isolated tool (Kali-style architecture).

Route: /api/recon/subdomains
Split from recon_module.py monolith by scripts/split_recon_module.py.
Failure here is quarantined by the healing autoloader -- other tools unaffected.
"""

import asyncio
import base64
import datetime
import hashlib
import re
import socket
from typing import Optional
import requests
import dns.resolver
import dns.asyncresolver
import whois as whois_lib
from fastapi import APIRouter, Depends
from tools._shared import (
    ScanRequest, verify_scan_quota, recon_host, safe_get, web_url,
)

# SUBDOMAINS-AI-WORDLIST-V1
import pathlib as _pl, json as _json
def _load_ai_subs():
    try:
        f = _pl.Path(__file__).parent.parent / "_payloads" / "recon" / "subdomain_wordlist.json"
        if f.exists(): return _json.loads(f.read_text())
    except Exception: pass
    return None
_AI_SUBS = _load_ai_subs()
import aiohttp as _aiohttp_crawl
import ssl as _ssl_mod

from fastapi import APIRouter, Depends

router = APIRouter()

_SUB_BRUTE_WORDLIST = [
    "www","mail","ftp","smtp","pop","imap","webmail","remote","ns1","ns2","ns3","ns4","ns5",
    "mx","mx1","mx2","mx3","dns","dns1","dns2","ldap",
    "dev","test","staging","stage","stg","beta","alpha","preview","demo","sandbox","qa","uat",
    "lab","labs","internal","intranet","preprod","pre-prod","production","prod",
    "admin","administrator","panel","cpanel","phpmyadmin","pma","auth","sso","login",
    "account","accounts","signup","register","oauth","saml","openid",
    "app","apps","application","api","api-v1","api-v2","api-v3","api1","api2","api3",
    "api-dev","api-staging","api-prod","api-internal","api-public","api-gateway",
    "cdn","static","assets","media","img","images","files","downloads","upload","uploads","videos","video",
    "m","mobile","wap","iphone","android",
    "us","uk","eu","asia","na","sa","africa","au","us-east","us-west","eu-west","eu-east","ap-south",
    "blog","shop","store","forum","wiki","kb","support","help","docs","documentation","portal",
    "dashboard","console","status","stats","metrics","monitor","monitoring",
    "git","gitlab","github","bitbucket","jenkins","ci","cd","build","deploy","registry","docker",
    "k8s","kubernetes","grafana","kibana","prometheus","alertmanager","sentry","datadog","splunk",
    "db","database","mysql","postgres","postgresql","mongo","mongodb","redis","memcache",
    "memcached","elasticsearch","es","cassandra",
    "vpn","secure","ssl","tls","ssh","rdp",
    "intra","ext","external","partners","partner","vendor","vendors","ticket","tickets","helpdesk",
    "news","ads","tracker","tracking","analytics","marketing","campaign","campaigns","newsletter",
    "checkout","payment","payments","billing","invoice","invoices","subscription","subscriptions",
    "hr","careers","jobs","recruiting","talent","ops","devops","sre","noc","soc",
    "email","mailing","outbound","smtp1","smtp2","mail2","webmail2","outlook",
    "old","new","legacy","v1","v2","v3","next","deprecated","archive","archives",
    "drupal","joomla","wordpress","wp",
    "auth-internal","auth-service","user-service","user-api","account-service","billing-service",
    "payment-service","order-service","search-service","notification-service","metrics-service",
    "server","server1","server2","host","host1","host2","node1","node2","node3","node4",
    "aws","gcp","azure","cloud","compute",
    "crm","sales","erp","salesforce","hubspot",
    "client","clients","customer","customers","user","users","guest","anonymous","public","private","vip",
    "security","audit","compliance","vault","keyvault",
    "it","tech","engineering","eng","dev-team",
    "feed","feeds","rss","atom",
    "proxy","gateway","router","firewall","fw","switch","ap","wifi",
    "loadbalancer","lb","haproxy","nginx","apache","iis",
    "elk","logstash","fluentd","rabbitmq","kafka","zookeeper","nats","consul","etcd","minio",
    "pci","stripe","paypal","square",
]

async def _resolve_sub_brute(host, prefix):
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        ans = await resolver.resolve(f"{prefix}.{host}", "A")
        return (f"{prefix}.{host}", str(ans[0]))
    except Exception:
        return None

@router.post("/api/recon/subdomains")
async def recon_subdomains(req: ScanRequest, _=Depends(verify_scan_quota)):
    host = recon_host(req.target)
    # Batch parallel to avoid DNS server flooding
    BATCH = 50
    found = []
    for i in range(0, len(_SUB_BRUTE_WORDLIST), BATCH):
        batch = _SUB_BRUTE_WORDLIST[i:i+BATCH]
        results = await asyncio.gather(*[_resolve_sub_brute(host, p) for p in batch])
        for r in results:
            if r is not None:
                found.append({"subdomain": r[0], "ip": r[1]})
    return {
        "ok": True,
        "subdomains": [f["subdomain"] for f in found],
        "details": found,
        "total": len(found),
        "wordlist_size": len(_SUB_BRUTE_WORDLIST),
        "engine": f"pure-Python active DNS brute force ({len(_SUB_BRUTE_WORDLIST)} prefixes, parallel async)",
    }


def register(app):
    app.include_router(router)
