"""
Technical helpers shared by the complementary TLS checks.

- `run_s_client`: one bounded `openssl s_client` connection (argument list, no shell).
- `send_client_hello`: one bounded raw TLS (<= 1.2) ClientHello whose server answer is parsed and
  then dropped. Nothing is ever negotiated beyond the ServerHello flight, so no application data
  and no dangerous client-side feature (compression, legacy renegotiation) is ever enabled.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field

from ..pki import safe_sni_name
from .contracts import CheckContext

S_CLIENT_MAX_OUTPUT_BYTES = 262144
RAW_MAX_BYTES = 262144

TLS_VERSION_CODES = {"TLSv1.0": 0x0301, "TLSv1.1": 0x0302, "TLSv1.2": 0x0303}
TLS_VERSION_NAMES = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}

HANDSHAKE_SERVER_HELLO = 2
HANDSHAKE_CERTIFICATE = 11
HANDSHAKE_CERTIFICATE_STATUS = 22
HANDSHAKE_SERVER_HELLO_DONE = 14

EXT_SERVER_NAME = 0x0000
EXT_STATUS_REQUEST = 0x0005
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_EXTENDED_MASTER_SECRET = 0x0017
EXT_RENEGOTIATION_INFO = 0xFF01

SCSV_FALLBACK = 0x5600
SCSV_EMPTY_RENEGOTIATION = 0x00FF

ALERT_INAPPROPRIATE_FALLBACK = 86
ALERT_PROTOCOL_VERSION = 70
ALERT_HANDSHAKE_FAILURE = 40

# A broad TLS <= 1.2 offer so that a server has something to select.
DEFAULT_CIPHER_SUITES = (
    0xC02B, 0xC02C, 0xC02F, 0xC030, 0xCCA8, 0xCCA9, 0x009E, 0x009F, 0x009C, 0x009D,
    0xC009, 0xC00A, 0xC013, 0xC014, 0xC023, 0xC024, 0xC027, 0xC028,
    0x0033, 0x0039, 0x0067, 0x006B, 0x002F, 0x0035, 0x003C, 0x003D, 0x000A,
)
DEFAULT_GROUPS = (0x001D, 0x0017, 0x0018, 0x0019)  # x25519, secp256r1, secp384r1, secp521r1
DEFAULT_SIGNATURE_ALGORITHMS = (
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0807, 0x0203, 0x0201, 0x0402, 0x0202,
)


# ---------------------------------------------------------------------------------------------
# openssl s_client
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SClientOutput:
    text: str
    returncode: int | None
    timed_out: bool = False
    error: str = ""

    @property
    def connected(self) -> bool:
        """True when a cipher was actually negotiated."""
        return bool(re.search(r"Cipher is (?!\(NONE\))\S", self.text)) or bool(re.search(r"^\s*Cipher\s*:\s*(?!0000|\(NONE\))\S", self.text, re.MULTILINE))


def format_endpoint(host: str, port: int) -> str:
    return f"[{host}]:{int(port)}" if ":" in host else f"{host}:{int(port)}"


def run_s_client(context: CheckContext, extra_args: list[str], server_name: str | None = None, stdin: bytes = b"", timeout: float | None = None) -> SClientOutput:
    """Run one `openssl s_client`. `extra_args` must only contain fixed, whitelisted option strings."""
    if shutil.which("openssl") is None:
        return SClientOutput("", None, error="openssl is not available")
    command = ["openssl", "s_client", "-connect", format_endpoint(context.host, context.port)]
    if context.starttls:
        command.extend(["-starttls", context.starttls])
    name = safe_sni_name(server_name if server_name is not None else (context.sni or ""))
    if name:
        command.extend(["-servername", name])
    command.extend(extra_args)
    wait = timeout if timeout is not None else context.probe_timeout()
    try:
        completed = subprocess.run(command, input=stdin, capture_output=True, timeout=wait, check=False)
    except subprocess.TimeoutExpired:
        return SClientOutput("", None, timed_out=True, error="timeout")
    except OSError as error:
        return SClientOutput("", None, error=str(error))
    raw = (completed.stdout + completed.stderr)[:S_CLIENT_MAX_OUTPUT_BYTES]
    return SClientOutput(raw.decode("utf-8", errors="replace"), completed.returncode)


def classify_s_client_failure(output: SClientOutput) -> str:
    """'refused' = the server answered with a protocol-level refusal; 'unreachable' = no answer at all."""
    if output.timed_out:
        return "unreachable"
    text = output.text.lower()
    if re.search(r"connection refused|connect:errno|no route to host|network is unreachable|name or service not known|nodename nor servname|timed out", text):
        return "unreachable"
    if re.search(r"alert|handshake failure|no shared cipher|no ciphers available|wrong version number|unsupported protocol|protocol version|no protocols available|unexpected eof|internal error|bad key share|illegal parameter|dh key too small", text):
        return "refused"
    return "unreachable"


# ---------------------------------------------------------------------------------------------
# Raw ClientHello
# ---------------------------------------------------------------------------------------------


@dataclass
class ServerReply:
    kind: str = "error"  # server_hello | alert | closed | error
    version: str = ""
    cipher_suite: int | None = None
    compression: int | None = None
    extensions: dict[int, bytes] = field(default_factory=dict)
    alert: int | None = None
    error: str = ""
    messages: dict[int, bytes] = field(default_factory=dict)  # handshake type -> first body

    def has_extension(self, code: int) -> bool:
        return code in self.extensions


def _u16(value: int) -> bytes:
    return struct.pack("!H", value)


def _extension(code: int, body: bytes) -> bytes:
    return _u16(code) + _u16(len(body)) + body


def build_client_hello(
    max_version: int = 0x0303,
    server_name: str = "",
    cipher_suites: tuple[int, ...] = DEFAULT_CIPHER_SUITES,
    compression_methods: tuple[int, ...] = (0,),
    extended_master_secret: bool = False,
    renegotiation_info: bool = False,
    status_request: bool = False,
    extra_extensions: bytes = b"",
) -> bytes:
    suites = b"".join(_u16(value) for value in cipher_suites)
    extensions = b""
    if server_name:
        encoded = server_name.encode("ascii")
        extensions += _extension(EXT_SERVER_NAME, _u16(len(encoded) + 3) + b"\x00" + _u16(len(encoded)) + encoded)
    extensions += _extension(EXT_SUPPORTED_GROUPS, _u16(len(DEFAULT_GROUPS) * 2) + b"".join(_u16(g) for g in DEFAULT_GROUPS))
    extensions += _extension(EXT_EC_POINT_FORMATS, b"\x01\x00")
    extensions += _extension(EXT_SIGNATURE_ALGORITHMS, _u16(len(DEFAULT_SIGNATURE_ALGORITHMS) * 2) + b"".join(_u16(s) for s in DEFAULT_SIGNATURE_ALGORITHMS))
    if extended_master_secret:
        extensions += _extension(EXT_EXTENDED_MASTER_SECRET, b"")
    if renegotiation_info:
        extensions += _extension(EXT_RENEGOTIATION_INFO, b"\x00")
    if status_request:
        extensions += _extension(EXT_STATUS_REQUEST, b"\x01\x00\x00\x00\x00")  # ocsp, empty responder ids, empty extensions
    extensions += extra_extensions
    body = (
        _u16(max_version)
        + os.urandom(32)
        + b"\x00"  # empty session id: no resumption
        + _u16(len(suites)) + suites
        + bytes([len(compression_methods)]) + bytes(compression_methods)
        + _u16(len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record_version = 0x0301 if max_version >= 0x0301 else max_version
    return b"\x16" + _u16(record_version) + _u16(len(handshake)) + handshake


def _read_exact(sock: socket.socket, count: int, deadline: float) -> bytes:
    data = b""
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timeout")
        sock.settimeout(remaining)
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def _smtp_starttls(sock: socket.socket, deadline: float) -> None:
    """Minimal SMTP STARTTLS prelude (the only STARTTLS protocol supported by the engine)."""

    def read_reply() -> str:
        text = b""
        while len(text) < 8192:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timeout")
            sock.settimeout(remaining)
            chunk = sock.recv(1024)
            if not chunk:
                raise ConnectionError("closed")
            text += chunk
            lines = text.decode("latin-1").splitlines()
            if lines and re.match(r"^\d{3} ", lines[-1]) and text.endswith(b"\n"):
                return text.decode("latin-1")
        raise ConnectionError("SMTP reply too long")

    read_reply()
    sock.sendall(b"EHLO tls-scan.invalid\r\n")
    read_reply()
    sock.sendall(b"STARTTLS\r\n")
    if not read_reply().startswith("220"):
        raise ConnectionError("STARTTLS refused")


def parse_server_flight(sock: socket.socket, deadline: float) -> ServerReply:
    """Read TLS records until the ServerHello flight is complete, an alert arrives, or the limit is hit."""
    reply = ServerReply()
    buffer = b""
    consumed = 0
    try:
        while consumed < RAW_MAX_BYTES:
            header = _read_exact(sock, 5, deadline)
            record_type, _version, length = header[0], header[1:3], struct.unpack("!H", header[3:5])[0]
            if length > 18432:
                reply.error = "oversized record"
                return reply
            payload = _read_exact(sock, length, deadline)
            consumed += 5 + length
            if record_type == 21:
                if reply.kind != "server_hello" and len(payload) >= 2:
                    reply.kind, reply.alert = "alert", payload[1]
                return reply
            if record_type != 22:
                return reply  # ChangeCipherSpec / data: the flight is over
            buffer += payload
            while len(buffer) >= 4:
                message_type = buffer[0]
                message_length = int.from_bytes(buffer[1:4], "big")
                if len(buffer) < 4 + message_length:
                    break
                body = buffer[4:4 + message_length]
                buffer = buffer[4 + message_length:]
                reply.messages.setdefault(message_type, body)
                if message_type == HANDSHAKE_SERVER_HELLO:
                    _parse_server_hello(body, reply)
                if message_type == HANDSHAKE_SERVER_HELLO_DONE:
                    return reply
    except (TimeoutError, socket.timeout):
        if reply.kind != "server_hello":
            reply.kind, reply.error = "error", "timeout"
    except (ConnectionError, OSError) as error:
        if reply.kind != "server_hello":
            reply.kind, reply.error = ("closed", "connection closed") if isinstance(error, ConnectionError) else ("error", str(error))
    return reply


def _parse_server_hello(body: bytes, reply: ServerReply) -> None:
    try:
        version = struct.unpack("!H", body[0:2])[0]
        position = 2 + 32
        session_length = body[position]
        position += 1 + session_length
        reply.cipher_suite = struct.unpack("!H", body[position:position + 2])[0]
        reply.compression = body[position + 2]
        position += 3
        extensions = {}
        if len(body) >= position + 2:
            total = struct.unpack("!H", body[position:position + 2])[0]
            position += 2
            end = min(len(body), position + total)
            while position + 4 <= end:
                code, length = struct.unpack("!HH", body[position:position + 4])
                extensions[code] = body[position + 4:position + 4 + length]
                position += 4 + length
        reply.extensions = extensions
        reply.version = TLS_VERSION_NAMES.get(version, f"0x{version:04x}")
        reply.kind = "server_hello"
    except (struct.error, IndexError):
        reply.kind, reply.error = "error", "malformed ServerHello"


def send_client_hello(context: CheckContext, **hello_options) -> ServerReply:
    """Open one connection, send one ClientHello, parse the server flight, close. Never raises."""
    if not context.can_probe():
        return ServerReply(kind="error", error="no time left or scan cancelled")
    if context.starttls not in ("", "smtp"):
        return ServerReply(kind="error", error=f"STARTTLS {context.starttls} not supported by raw probes")
    deadline = time.monotonic() + context.probe_timeout()
    hello_options.setdefault("server_name", safe_sni_name(context.sni) if context.sni and not _is_ip(context.sni) else "")
    try:
        with socket.create_connection((context.host, context.port), timeout=context.probe_timeout()) as sock:
            if context.starttls == "smtp":
                _smtp_starttls(sock, deadline)
            sock.sendall(build_client_hello(**hello_options))
            return parse_server_flight(sock, deadline)
    except (TimeoutError, socket.timeout):
        return ServerReply(kind="error", error="timeout")
    except (OSError, ConnectionError) as error:
        return ServerReply(kind="error", error=str(error)[:120])


def _is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def max_observed_version(observed_versions) -> str:
    order = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    known = [v for v in order if v in set(observed_versions)]
    return known[-1] if known else ""
