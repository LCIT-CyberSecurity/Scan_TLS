#!/bin/sh
# Lab TLS endpoints for tests: self-signed certificates, never for real use.
set -e
mkdir -p /certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout /certs/ok.key -out /certs/ok.crt -days 365 -subj "/CN=lab-tls" -addext "subjectAltName=DNS:lab-tls" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout /certs/exp.key -out /certs/exp.crt -days 1 -subj "/CN=lab-tls" 2>/dev/null
exec nginx -g 'daemon off;'
