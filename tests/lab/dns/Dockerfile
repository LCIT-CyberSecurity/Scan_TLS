# Authoritative DNS lab (BIND) with controlled zones: AXFR accepted, AXFR refused, wildcard, reverse. NEVER for real use.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends bind9 iproute2 && rm -rf /var/lib/apt/lists/* && mkdir -p /etc/bind/zones /run/named && chown bind:bind /run/named
COPY tests/lab/dns/named.conf /etc/bind/named.conf
COPY tests/lab/dns/zones /zones.in
COPY tests/lab/dns/entrypoint.sh /entrypoint.sh
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
