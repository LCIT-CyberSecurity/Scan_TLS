#!/bin/sh
# Starts the real daemons of the lab (see real-services.Dockerfile). Throw-away certificate, no real accounts, NEVER for real use.
set -u
mkdir -p /certs && cd /certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout real.key -out real.crt -days 30 -subj "/CN=lab-real" \
  -addext "subjectAltName=DNS:lab-real,DNS:localhost" 2>/dev/null
chmod 644 real.crt real.key
log() { echo "[real-services] $*"; }

# --- Postfix (SMTP, STARTTLS on 25 and 587) ---
postconf -e "myhostname=lab-real" "inet_interfaces=all" "inet_protocols=ipv4" "smtpd_tls_cert_file=/certs/real.crt" "smtpd_tls_key_file=/certs/real.key" \
  "smtpd_tls_security_level=may" "mydestination=lab-real" >/dev/null 2>&1
postconf -M "submission/inet=submission inet n - n - - smtpd" >/dev/null 2>&1
postfix start >/dev/null 2>&1 && log "postfix started"

# --- Dovecot (IMAP 143, POP3 110) ---
DOVECOT_VERSION="$(dovecot --version | cut -d. -f1-2)"
case "$DOVECOT_VERSION" in
  2.4*)
    cat > /etc/dovecot/dovecot.conf <<CONF
dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0
protocols = imap pop3
ssl = yes
ssl_server_cert_file = /certs/real.crt
ssl_server_key_file = /certs/real.key
auth_allow_cleartext = no
mail_driver = maildir
mail_path = /tmp/mail
passdb static {
  password = lab
}
userdb static {
  fields {
    uid = 1000
    gid = 1000
    home = /tmp
  }
}
CONF
    ;;
  *)
    cat > /etc/dovecot/dovecot.conf <<CONF
protocols = imap pop3
ssl = yes
ssl_cert = </certs/real.crt
ssl_key = </certs/real.key
disable_plaintext_auth = yes
mail_location = maildir:/tmp/mail
passdb { driver = static
  args = password=lab }
userdb { driver = static
  args = uid=1000 gid=1000 home=/tmp }
CONF
    ;;
esac
dovecot && log "dovecot started ($DOVECOT_VERSION)"

# --- vsftpd (FTP 21, AUTH TLS) ---
mkdir -p /var/run/vsftpd/empty
cat > /etc/vsftpd.conf <<CONF
listen=YES
listen_ipv6=NO
anonymous_enable=NO
local_enable=YES
seccomp_sandbox=NO
ssl_enable=YES
force_local_logins_ssl=NO
rsa_cert_file=/certs/real.crt
rsa_private_key_file=/certs/real.key
secure_chroot_dir=/var/run/vsftpd/empty
CONF
vsftpd /etc/vsftpd.conf &
log "vsftpd started"

# --- OpenLDAP (389, StartTLS) ---
mkdir -p /var/lib/ldap-lab /run/slapd
cat > /etc/ldap/slapd-lab.conf <<CONF
include /etc/ldap/schema/core.schema
pidfile /run/slapd/slapd-lab.pid
TLSCertificateFile /certs/real.crt
TLSCertificateKeyFile /certs/real.key
moduleload back_mdb
database mdb
maxsize 1073741824
suffix "dc=lab,dc=example"
directory /var/lib/ldap-lab
CONF
chown -R openldap:openldap /var/lib/ldap-lab /run/slapd
# slapd sizes tables from the open-files limit, which is huge in containers
(ulimit -n 1024; slapd -f /etc/ldap/slapd-lab.conf -h "ldap://0.0.0.0:389/" -u openldap -g openldap) && log "slapd started"

# --- PostgreSQL (5432, SSLRequest) ---
PGVER="$(ls /usr/lib/postgresql | head -1)"
PGDATA=/var/lib/postgresql/lab
mkdir -p $PGDATA && chown postgres:postgres $PGDATA && chmod 700 $PGDATA
cp /certs/real.crt /var/lib/postgresql/server.crt; cp /certs/real.key /var/lib/postgresql/server.key
chown postgres:postgres /var/lib/postgresql/server.*; chmod 600 /var/lib/postgresql/server.key
su postgres -c "/usr/lib/postgresql/$PGVER/bin/initdb -D $PGDATA --auth=trust >/dev/null 2>&1"
su postgres -c "/usr/lib/postgresql/$PGVER/bin/pg_ctl -D $PGDATA -o \"-c listen_addresses=* -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt -c ssl_key_file=/var/lib/postgresql/server.key -c unix_socket_directories=/tmp\" -l /tmp/pg.log start >/dev/null 2>&1" && log "postgresql started ($PGVER)"
echo "host all all 0.0.0.0/0 trust" >> $PGDATA/pg_hba.conf

# --- Prosody (XMPP 5222 client, 5269 server) ---
cat > /etc/prosody/prosody.cfg.lua <<CONF
daemonize = false
pidfile = "/tmp/prosody.pid"
modules_enabled = { "roster"; "saslauth"; "tls"; "disco"; "s2s" }
allow_registration = false
c2s_require_encryption = true
s2s_require_encryption = true
s2s_secure_auth = false
ssl = { key = "/certs/real.key"; certificate = "/certs/real.crt"; }
VirtualHost "lab-real"
CONF
chown -R prosody:prosody /etc/prosody 2>/dev/null; chmod 644 /certs/real.key
su prosody -s /bin/sh -c "prosody" &
log "prosody started"
log "ready"
wait
