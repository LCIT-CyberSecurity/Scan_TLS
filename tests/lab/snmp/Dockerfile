FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends snmpd snmp python3 && rm -rf /var/lib/apt/lists/*
COPY tests/lab/snmp/snmpd.conf /etc/snmp/snmpd.conf
COPY tests/lab/snmp/lldp-pass-persist.py /usr/local/bin/lldp-pass-persist.py
RUN chmod 755 /usr/local/bin/lldp-pass-persist.py
EXPOSE 161/udp
CMD ["snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf", "udp:161"]
