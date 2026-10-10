#!/bin/sh
# Lab TLS endpoints for tests: throw-away certificates and deliberately weak configurations. NEVER for real use.
set -e
mkdir -p /certs /ca && cd /certs
mk() { # mk name days
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.crt" -days "$2" -subj "/CN=lab-tls" -addext "subjectAltName=DNS:lab-tls" 2>/dev/null
}
mk ok 365
mk soon 10          # expires within the default 30-day warning window
mk exp 1
# Already-expired certificate, signed through a minimal CA database (openssl req cannot back-date).
cat > /ca/ca.cnf <<CNF
[ca]
default_ca = CA_default
[CA_default]
dir = /ca
database = /ca/index.txt
new_certs_dir = /ca
serial = /ca/serial
default_md = sha256
policy = pol
unique_subject = no
[pol]
commonName = supplied
CNF
: > /ca/index.txt; echo 01 > /ca/serial
openssl req -newkey rsa:2048 -nodes -keyout expired.key -out expired.csr -subj "/CN=lab-tls" 2>/dev/null
openssl ca -batch -selfsign -config /ca/ca.cnf -keyfile expired.key -in expired.csr -out expired.crt \
  -startdate 20200101000000Z -enddate 20200102000000Z -notext 2>/dev/null
exec nginx -g 'daemon off;'
