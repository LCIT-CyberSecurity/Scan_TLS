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

# --- complementary TLS checks (lot 1): identity, stapled OCSP, Diffie-Hellman parameters ---
# SAN that does not cover the requested name (and no IP SAN): the identity check must fail while the chain stays a separate matter.
openssl req -x509 -newkey rsa:2048 -nodes -keyout mismatch.key -out mismatch.crt -days 365 -subj "/CN=other.example" -addext "subjectAltName=DNS:other.example,DNS:*.wild.example" 2>/dev/null
# Wildcard certificate covering exactly one label under lab.example (a.lab.example) but not lab.example itself.
openssl req -x509 -newkey rsa:2048 -nodes -keyout wild.key -out wild.crt -days 365 -subj "/CN=*.lab.example" -addext "subjectAltName=DNS:*.lab.example" 2>/dev/null
# A tiny CA, a leaf with an OCSP URL, and static OCSP responses (good / revoked) that nginx staples from files.
openssl req -x509 -newkey rsa:2048 -nodes -keyout labca.key -out labca.crt -days 365 -subj "/CN=Lab OCSP CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout stap.key -out stap.csr -subj "/CN=lab-tls" 2>/dev/null
printf 'subjectAltName=DNS:lab-tls\nauthorityInfoAccess=OCSP;URI:http://lab-tls:9/ocsp\n' > stap.ext
openssl x509 -req -in stap.csr -CA labca.crt -CAkey labca.key -set_serial 0x1001 -days 365 -extfile stap.ext -out stap.leaf.crt 2>/dev/null
cat stap.leaf.crt labca.crt > stap.crt
printf 'V\t491231235959Z\t\t1001\tunknown\t/CN=lab-tls\n' > ocsp-good.idx
printf 'R\t491231235959Z\t250101000000Z\t1001\tunknown\t/CN=lab-tls\n' > ocsp-revoked.idx
openssl ocsp -issuer labca.crt -cert stap.leaf.crt -reqout ocsp.req 2>/dev/null
for kind in good revoked; do
  openssl ocsp -index ocsp-$kind.idx -CA labca.crt -rsigner labca.crt -rkey labca.key -reqin ocsp.req -respout $kind.ocsp -ndays 30 >/dev/null 2>&1
done
# Diffie-Hellman parameters: 1024 bits (weak) and the named ffdhe2048 group.
openssl dhparam -dsaparam -out dh1024.pem 1024 2>/dev/null
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out dh2048.pem 2>/dev/null

# --- private PKI scenarios (administered trust stores) ---
# ACME: Root CA -> Issuing CA (intermediate) -> leaves; Globex: an unrelated customer PKI. Only public certificates are exposed under /pki.
mkdir -p /pki /pkica && cd /pkica
mkca() { # mkca name subject [issuer-name]
  if [ -z "$3" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.crt" -days 3650 -subj "/O=$2/CN=$1" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  else
    openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/O=$2/CN=$1" 2>/dev/null
    printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$3.crt" -CAkey "$3.key" -CAcreateserial -days 3650 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  fi
}
mkca ACME-Root-CA ACME
mkca ACME-Issuing-CA ACME ACME-Root-CA
mkca Globex-Root-CA Globex
mkca Globex-Issuing-CA Globex Globex-Root-CA
cat > acme-ca.cnf <<CNF
[ca]
default_ca = CA_default
[CA_default]
dir = /pkica
database = /pkica/index.txt
new_certs_dir = /pkica
serial = /pkica/serial
default_md = sha256
default_days = 365
default_crl_days = 30
policy = pol
unique_subject = no
copy_extensions = none
[pol]
commonName = supplied
CNF
: > index.txt; echo 1000 > serial
leaf() { # leaf name cn san [extra openssl ca args...]
  n="$1"; cn="$2"; san="$3"; shift 3
  openssl req -newkey rsa:2048 -nodes -keyout "$n.key" -out "$n.csr" -subj "/CN=$cn" 2>/dev/null
  printf '[leaf]\nsubjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\ncrlDistributionPoints=URI:http://lab-tls/pki/acme.crl\n' "$san" > "$n.ext"
  openssl ca -batch -config acme-ca.cnf -cert ACME-Issuing-CA.crt -keyfile ACME-Issuing-CA.key -in "$n.csr" -out "$n.crt" \
    -extfile "$n.ext" -extensions leaf -notext "$@" 2>/dev/null
}
leaf intranet intranet.acme.local "DNS:intranet.acme.local"
cat intranet.crt ACME-Issuing-CA.crt > intranet.chain.crt
leaf wrongsan intranet.acme.local "DNS:other.acme.local"
cat wrongsan.crt ACME-Issuing-CA.crt > wrongsan.chain.crt
leaf expiredleaf intranet.acme.local "DNS:intranet.acme.local" -startdate 20200101000000Z -enddate 20200102000000Z
cat expiredleaf.crt ACME-Issuing-CA.crt > expiredleaf.chain.crt
leaf revoked intranet.acme.local "DNS:intranet.acme.local"
cat revoked.crt ACME-Issuing-CA.crt > revoked.chain.crt
openssl ca -config acme-ca.cnf -cert ACME-Issuing-CA.crt -keyfile ACME-Issuing-CA.key -revoke revoked.crt 2>/dev/null
openssl ca -config acme-ca.cnf -cert ACME-Issuing-CA.crt -keyfile ACME-Issuing-CA.key -gencrl -out acme.crl 2>/dev/null
# Globex leaf signed by the other customer's issuing CA
openssl req -newkey rsa:2048 -nodes -keyout globex-leaf.key -out globex-leaf.csr -subj "/CN=intranet.globex.local" 2>/dev/null
printf 'subjectAltName=DNS:intranet.globex.local\nbasicConstraints=CA:FALSE\n' > globex-leaf.ext
openssl x509 -req -in globex-leaf.csr -CA Globex-Issuing-CA.crt -CAkey Globex-Issuing-CA.key -CAcreateserial -days 365 -extfile globex-leaf.ext -out globex-leaf.crt 2>/dev/null
cat globex-leaf.crt Globex-Issuing-CA.crt > globex-leaf.chain.crt
cp ACME-Root-CA.crt ACME-Issuing-CA.crt Globex-Root-CA.crt Globex-Issuing-CA.crt acme.crl /pki/
# a private key and a PKCS#12 bundle, to check that the import refuses them
cp ACME-Root-CA.key /pki/private-key-sample.pem
openssl pkcs12 -export -inkey ACME-Root-CA.key -in ACME-Root-CA.crt -passout pass:x -out /pki/bundle.p12 2>/dev/null
chmod 644 /pki/*
cd /certs
# --- lot 2: STARTTLS services (real TLS behind scripted application dialogues)
python3 -u /starttls_server.py &
exec nginx -g 'daemon off;'
