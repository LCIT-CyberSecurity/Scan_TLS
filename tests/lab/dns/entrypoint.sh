#!/bin/sh
set -e
LAB_IP="$(hostname -i | awk '{print $1}')"
for f in /zones.in/*; do sed "s/@LAB_IP@/$LAB_IP/g" "$f" > "/etc/bind/zones/$(basename "$f")"; done
{ printf '$TTL 300\n@ IN SOA ns1.bulk.test. hostmaster.bulk.test. 1 7200 3600 1209600 300\n@ IN NS ns1.bulk.test.\nns1 IN A %s\n' "$LAB_IP"; i=1; while [ $i -le 120 ]; do printf 'host%03d IN A 10.20.0.%d\n' $i $i; i=$((i+1)); done; } > /etc/bind/zones/bulk.test.zone
chown -R bind:bind /etc/bind/zones
named-checkconf /etc/bind/named.conf
exec named -g -u bind -c /etc/bind/named.conf
