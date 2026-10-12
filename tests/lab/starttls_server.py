"""Lab STARTTLS services for the TLS Scan tests. NEVER for real use.

Each port speaks just enough of its protocol (greeting, capabilities, the STARTTLS request) and then performs a
REAL TLS handshake with the OpenSSL of the `ssl` module, so the checks run against a genuine negotiated channel.
Variants deliberately misbehave (no STARTTLS offered, refusal, a service that is not the protocol, silence).
Every command received is logged to stdout so that tests can verify that nothing but the TLS upgrade is ever sent.
"""

import socket
import socketserver
import ssl
import sys
import threading
import time

CERT, KEY = "/certs/ok.crt", "/certs/ok.key"
SERVICES = {
    8470: ("smtp", "ok"), 8471: ("imap", "ok"), 8472: ("pop3", "ok"), 8473: ("ftp", "ok"), 8474: ("ldap", "ok"),
    8475: ("postgres", "ok"), 8476: ("xmpp", "ok"),
    8477: ("imap", "no_starttls"), 8478: ("pop3", "no_stls"), 8479: ("ftp", "no_auth_tls"), 8480: ("postgres", "no_ssl"),
    8481: ("ldap", "refused"), 8482: ("xmpp", "no_starttls"), 8483: ("http", "not_the_protocol"), 8484: ("silent", "silent"),
    8485: ("imap", "refused"),
    # standard ports (the container runs as root): the whole scan pipeline, Nmap included, sees them as the real services
    25: ("smtp", "ok"), 587: ("smtp", "ok"), 143: ("imap", "ok"), 110: ("pop3", "ok"), 21: ("ftp", "ok"),
    389: ("ldap", "ok"), 5432: ("postgres", "ok"), 5222: ("xmpp", "ok"), 5269: ("xmpp", "server"), 8486: ("xmpp", "server"),
}


def log(port, text):
    print(f"[{port}] {text}", flush=True)


_CONTEXT = None


def tls_context():
    """One context for all connections, so that session tickets and the session cache survive between them."""
    global _CONTEXT
    if _CONTEXT is None:
        _CONTEXT = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        _CONTEXT.load_cert_chain(CERT, KEY)
    return _CONTEXT


class Session:
    def __init__(self, conn, port):
        self.conn, self.port, self.buffer = conn, port, b""
        conn.settimeout(8)

    def line(self):
        while b"\n" not in self.buffer:
            chunk = self.conn.recv(1024)
            if not chunk:
                raise ConnectionError
            self.buffer += chunk
        raw, _, self.buffer = self.buffer.partition(b"\n")
        text = raw.decode("latin-1").rstrip("\r")
        log(self.port, f"<- {text}")
        return text

    def read(self, count):
        while len(self.buffer) < count:
            chunk = self.conn.recv(1024)
            if not chunk:
                raise ConnectionError
            self.buffer += chunk
        data, self.buffer = self.buffer[:count], self.buffer[count:]
        return data

    def send(self, text):
        data = text if isinstance(text, bytes) else text.encode()
        log(self.port, f"-> {data[:60]!r}")
        self.conn.sendall(data)

    def upgrade(self):
        tls = tls_context().wrap_socket(self.conn, server_side=True)
        log(self.port, "TLS established " + tls.version())
        tls.settimeout(4)
        try:
            while tls.recv(1024):
                pass
        except (OSError, ssl.SSLError):
            pass


def smtp(s, variant):
    s.send("220 lab ESMTP\r\n")
    while True:
        command = s.line().upper()
        if command.startswith("EHLO"):
            s.send("250-lab\r\n250 STARTTLS\r\n")
        elif command == "STARTTLS":
            s.send("220 go ahead\r\n")
            return s.upgrade()
        else:
            s.send("502 not implemented\r\n")


def imap(s, variant):
    s.send("* OK [CAPABILITY IMAP4rev1] ready\r\n")
    while True:
        tag, _, command = s.line().partition(" ")
        if command.upper() == "CAPABILITY":
            s.send("* CAPABILITY IMAP4rev1" + ("" if variant == "no_starttls" else " STARTTLS") + f"\r\n{tag} OK done\r\n")
        elif command.upper() == "STARTTLS":
            if variant == "refused":
                s.send(f"{tag} NO TLS not available now\r\n")
                continue
            s.send(f"{tag} OK Begin TLS negotiation now\r\n")
            return s.upgrade()
        else:
            s.send(f"{tag} BAD unknown command\r\n")


def pop3(s, variant):
    s.send("+OK POP3 ready\r\n")
    while True:
        command = s.line().upper()
        if command == "CAPA":
            s.send("+OK\r\nUSER\r\n" + ("" if variant == "no_stls" else "STLS\r\n") + ".\r\n")
        elif command == "STLS":
            s.send("+OK Begin TLS\r\n")
            return s.upgrade()
        else:
            s.send("-ERR unknown\r\n")


def ftp(s, variant):
    s.send("220 lab FTP\r\n")
    while True:
        command = s.line().upper()
        if command == "AUTH TLS":
            if variant == "no_auth_tls":
                s.send("502 AUTH not implemented\r\n")
                continue
            s.send("234 AUTH TLS successful\r\n")
            return s.upgrade()
        s.send("530 Please login\r\n")


def ldap(s, variant):
    request = s.read(2)
    request += s.read(request[1])
    log(s.port, f"<- LDAP message {len(request)} bytes")
    code = 0 if variant == "ok" else 53
    s.send(bytes([0x30, 0x0C, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0A, 0x01, code, 0x04, 0x00, 0x04, 0x00]))
    if code == 0:
        s.upgrade()


def postgres(s, variant):
    request = s.read(8)
    log(s.port, f"<- SSLRequest {request.hex()}")
    if variant == "no_ssl":
        return s.send(b"N")
    s.send(b"S")
    s.upgrade()


def xmpp(s, variant):
    server_to_server = variant == "server"
    while b">" not in s.buffer:
        chunk = s.conn.recv(1024)
        if not chunk:
            return
        s.buffer += chunk
    expected = b"jabber:server" if server_to_server else b"jabber:client"
    if expected not in s.buffer:
        return s.send("<stream:error><invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>")
    log(s.port, "<- stream header")
    feature = "" if variant == "no_starttls" else "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"
    s.send(f"<?xml version='1.0'?><stream:stream from='lab' id='1' version='1.0' xmlns='{'jabber:server' if server_to_server else 'jabber:client'}' xmlns:stream='http://etherx.jabber.org/streams'><stream:features>{feature}</stream:features>")
    s.buffer = b""
    while b"/>" not in s.buffer:
        chunk = s.conn.recv(1024)
        if not chunk:
            return
        s.buffer += chunk
    log(s.port, "<- starttls request")
    s.send("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
    s.upgrade()


def http(s, variant):
    s.send("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")


def silent(s, variant):
    time.sleep(30)


HANDLERS = {"smtp": smtp, "imap": imap, "pop3": pop3, "ftp": ftp, "ldap": ldap, "postgres": postgres, "xmpp": xmpp, "http": http, "silent": silent}


def serve(port, kind, variant):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                HANDLERS[kind](Session(self.request, port), variant)
            except (OSError, ssl.SSLError, ConnectionError):
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    Server(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    for port, (kind, variant) in SERVICES.items():
        threading.Thread(target=serve, args=(port, kind, variant), daemon=True).start()
    log(0, f"{len(SERVICES)} STARTTLS services ready")
    threading.Event().wait()
