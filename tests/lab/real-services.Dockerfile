# Real STARTTLS daemons (Dovecot, vsftpd, OpenLDAP, PostgreSQL, Prosody, Postfix) with a throw-away certificate, on their
# standard ports. Used by tests/regression/real-servers.sh to validate the STARTTLS adapters against genuine implementations.
# NEVER for real use.
FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssl ca-certificates dovecot-core dovecot-imapd dovecot-pop3d vsftpd slapd postgresql prosody postfix procps \
    && rm -rf /var/lib/apt/lists/*
COPY tests/lab/real-services.sh /real-services.sh
ENTRYPOINT ["/bin/sh", "/real-services.sh"]
