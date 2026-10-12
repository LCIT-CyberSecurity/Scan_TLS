"""
Common ground of the STARTTLS adapters.

An adapter speaks the *minimum* of an application protocol to ask the server to switch to TLS, on a
socket that is already connected: it never authenticates, never runs a business command and never
transfers data. It first checks that the service really answers like the protocol (banner or first
reply), so a port number alone never proves a protocol.

Adding a protocol = one module with `upgrade(wire, server_name) -> Upgrade` and one line in `ADAPTERS`.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Callable

MAX_LINE_BYTES = 4096
MAX_EXCHANGE_BYTES = 65536
MAX_REPLY_LINES = 64

UPGRADED = "upgraded"  # the server agreed: the next bytes are a TLS handshake
NOT_OFFERED = "not_offered"  # protocol confirmed, STARTTLS not advertised / not available
REFUSED = "refused"  # protocol confirmed, the server answered the STARTTLS request negatively
NOT_PROTOCOL = "not_protocol"  # the service does not answer like this protocol
ERROR = "error"  # timeout, closed connection, malformed or oversized answer


class WireError(Exception):
    """Raised by `Wire` for a timeout, a closed connection, a cancellation or an oversized answer."""


@dataclass(frozen=True)
class Upgrade:
    status: str
    protocol: str
    detail: str = ""
    confirmed: bool = False  # the protocol itself was recognised in the server's answers
    advertised: bool | None = None  # STARTTLS announced by the server (None = not observable)

    @property
    def upgraded(self) -> bool:
        return self.status == UPGRADED


class Wire:
    """Bounded, deadline-driven reads and writes on a connected socket."""

    def __init__(self, sock: socket.socket, deadline: float, cancelled: Callable[[], bool] = lambda: False):
        self.sock = sock
        self.deadline = deadline
        self.cancelled = cancelled
        self.received = 0
        self._buffer = b""

    def _fill(self) -> None:
        if self.cancelled():
            raise WireError("cancelled")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise WireError("timeout")
        if self.received >= MAX_EXCHANGE_BYTES:
            raise WireError("answer too large")
        self.sock.settimeout(remaining)
        try:
            chunk = self.sock.recv(2048)
        except (TimeoutError, socket.timeout) as error:
            raise WireError("timeout") from error
        except OSError as error:
            raise WireError(f"connection error: {error.__class__.__name__}") from error
        if not chunk:
            raise WireError("connection closed")
        self.received += len(chunk)
        self._buffer += chunk

    def send(self, data: bytes) -> None:
        try:
            self.sock.settimeout(max(0.5, self.deadline - time.monotonic()))
            self.sock.sendall(data)
        except OSError as error:
            raise WireError(f"connection error: {error.__class__.__name__}") from error

    def read_line(self) -> str:
        while b"\n" not in self._buffer:
            if len(self._buffer) > MAX_LINE_BYTES:
                raise WireError("line too long")
            self._fill()
        line, _, self._buffer = self._buffer.partition(b"\n")
        if len(line) > MAX_LINE_BYTES:
            raise WireError("line too long")
        return line.decode("latin-1").rstrip("\r")

    def read_exact(self, count: int) -> bytes:
        while len(self._buffer) < count:
            self._fill()
        data, self._buffer = self._buffer[:count], self._buffer[count:]
        return data

    def read_until(self, markers: tuple[bytes, ...]) -> bytes:
        """Everything received up to and including the first marker (bounded)."""
        while True:
            for marker in markers:
                position = self._buffer.find(marker)
                if position >= 0:
                    end = position + len(marker)
                    data, self._buffer = self._buffer[:end], self._buffer[end:]
                    return data
            self._fill()

    def leftover(self) -> int:
        return len(self._buffer)


def numbered_reply(wire: Wire) -> tuple[str, list[str]]:
    """One SMTP/FTP style reply (`250-...` lines then `250 ...`): (code, lines)."""
    lines: list[str] = []
    while len(lines) < MAX_REPLY_LINES:
        line = wire.read_line()
        lines.append(line)
        if len(line) >= 3 and line[:3].isdigit() and (len(line) == 3 or line[3] == " "):
            return line[:3], lines
        if not (len(line) >= 4 and line[:3].isdigit() and line[3] == "-"):
            raise WireError("not a numbered reply")
    raise WireError("reply too long")
