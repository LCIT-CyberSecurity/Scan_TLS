"""
TLS session resumption and session tickets.

Both checks read the same probes, collected once per endpoint (`context.shared`): for each of TLS 1.3 and
TLS 1.2 a first connection obtains a session (and, in TLS 1.3, waits a short, bounded time for the
post-handshake ticket), then up to `attempts` further connections offer it back with the same server name.
The Python `ssl` module reports whether the session was really reused, so the conclusion comes from the
handshake and not from a banner.

Nothing but the TLS handshake is exchanged: no application data is sent, tickets are never stored or logged
(only their presence and the lifetime hint), and the sessions live in memory for the duration of the probe.

What an external probe cannot show: how often the server rotates its ticket keys, whether tickets are
stateless or stateful in TLS 1.3, and whether other back-ends behind a load balancer share their session
cache. A refusal is therefore reported as "refused after N attempts", never as proof that the server cannot resume.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import asdict, dataclass

from ..pki import safe_sni_name
from .contracts import INCONCLUSIVE, NOT_APPLICABLE, PASS, CheckContext, CheckResult, result
from .protocols import open_channel
from .transport import _extension, send_client_hello

RESUMPTION_ID = "session_resumption"
TICKETS_ID = "session_tickets"
EXT_SESSION_TICKET = 35

DEFAULT_ATTEMPTS = 2
DEFAULT_TICKET_WAIT_SECONDS = 2
TLS12, TLS13 = "TLSv1.2", "TLSv1.3"


@dataclass
class MechanismProbe:
    version: str
    mechanism: str  # "ticket" (TLS 1.2 ticket / TLS 1.3 PSK ticket) or "session_id" (TLS 1.2 only)
    handshake: bool = False  # the first full handshake completed
    ticket_issued: bool | None = None
    session_id_issued: bool | None = None
    lifetime_hint_seconds: int | None = None
    attempts: int = 0  # resumption attempts actually made
    resumed: bool | None = None  # None = nothing could be offered
    detail: str = ""


def client_context(version: str, no_ticket: bool) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # observation of the server's behaviour, not a trust decision
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3 if version == TLS13 else ssl.TLSVersion.TLSv1_2
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")  # client side only: lets the probe talk to weak servers
    except ssl.SSLError:
        pass
    if no_ticket:
        context.options |= ssl.OP_NO_TICKET
    return context


def _handshake(check: CheckContext, client: ssl.SSLContext, session) -> tuple[ssl.SSLSocket | None, str]:
    """One bounded connection (after the STARTTLS upgrade when needed) and its TLS handshake."""
    sock, upgrade, error = open_channel(check)
    if sock is None:
        return None, error
    name = safe_sni_name(check.sni or "") or None
    try:
        sock.settimeout(check.probe_timeout())
        return client.wrap_socket(sock, server_hostname=name, session=session), ""
    except (ssl.SSLError, OSError, ValueError) as failure:
        sock.close()
        return None, f"handshake failed: {failure.__class__.__name__}"


def _await_ticket(tls: ssl.SSLSocket, wait_seconds: float) -> None:
    """TLS 1.3 tickets arrive after the handshake: read (never write) for a short time until one is there."""
    end = time.monotonic() + wait_seconds
    while time.monotonic() < end and not tls.session.has_ticket:
        tls.settimeout(max(0.05, min(0.25, end - time.monotonic())))
        try:
            tls.recv(1)
        except (TimeoutError, socket.timeout, ssl.SSLWantReadError):
            continue
        except (ssl.SSLError, OSError):
            return
        return  # data or end of stream: nothing more to wait for


def probe_mechanism(check: CheckContext, version: str, mechanism: str, attempts: int, wait_seconds: float) -> MechanismProbe:
    probe = MechanismProbe(version, mechanism)
    client = client_context(version, no_ticket=mechanism == "session_id")
    session = None
    for index in range(attempts + 1):
        if not check.can_probe():
            probe.detail = "time budget exhausted or scan cancelled"
            break
        tls, error = _handshake(check, client, session)
        if tls is None:
            probe.detail = error
            break
        try:
            if index > 0:
                probe.attempts += 1
                if tls.session_reused:
                    probe.resumed = True
                    break
            else:
                probe.handshake = True
            if version == TLS13:
                _await_ticket(tls, wait_seconds)
            current = tls.session
            if index == 0:
                probe.ticket_issued = bool(current.has_ticket)
                probe.session_id_issued = bool(current.id)
                probe.lifetime_hint_seconds = int(current.ticket_lifetime_hint) if current.has_ticket else None
            session = current
        finally:
            tls.close()
        offerable = session.has_ticket if mechanism == "ticket" else bool(session.id)
        if not offerable:
            break
    if probe.handshake and probe.resumed is None and probe.attempts:
        probe.resumed = False
    return probe


def observe_sessions(context: CheckContext) -> dict:
    """Collected once per endpoint and shared by the checks that need it."""
    cached = context.shared.get("sessions")
    if cached is not None:
        return cached
    attempts = int(context.option("attempts", DEFAULT_ATTEMPTS))
    wait = float(context.option("ticket_wait_seconds", DEFAULT_TICKET_WAIT_SECONDS))
    versions = [v for v in (TLS13, TLS12) if not context.observed_versions or v in context.observed_versions]
    observation: dict = {"versions": versions, "probes": [], "connections_limit": len(versions) * 2 * (attempts + 1)}
    for version in versions:
        for mechanism in (("ticket",) if version == TLS13 else ("ticket", "session_id")):
            if context.can_probe():
                observation["probes"].append(probe_mechanism(context, version, mechanism, attempts, wait))
    context.shared["sessions"] = observation
    return observation


def _not_applicable(check_id: str, observation: dict) -> CheckResult | None:
    if not observation["versions"]:
        return result(check_id, NOT_APPLICABLE, "The endpoint supports neither TLS 1.2 nor TLS 1.3; sessions are only probed on those versions.")
    return None


def _probe_view(probe: MechanismProbe) -> dict:
    view = asdict(probe)
    view["outcome"] = _outcome(probe)
    return view


def _outcome(probe: MechanismProbe) -> str:
    if not probe.handshake:
        return "undetermined"
    if probe.resumed:
        return "resumed"
    if probe.resumed is False:
        return "refused"
    offered = probe.ticket_issued if probe.mechanism == "ticket" else probe.session_id_issued
    return "not_issued" if offered is False else "undetermined"


def check_session_resumption(context: CheckContext) -> CheckResult:
    observation = observe_sessions(context)
    unavailable = _not_applicable(RESUMPTION_ID, observation)
    if unavailable:
        return unavailable
    probes: list[MechanismProbe] = observation["probes"]
    views = [_probe_view(probe) for probe in probes]
    attempts = sum(probe.attempts for probe in probes)
    resumed = [f"{p.version} {p.mechanism}" for p in probes if p.resumed]
    observations = {
        "outcome": "undetermined", "mechanisms_resumed": resumed, "attempts_made": attempts, "probes": views,
        "limit": "refusal after a few attempts does not prove that no back-end can resume; ticket-key rotation is not observable from outside",
    }
    evidence = [f"{v['version']} {v['mechanism']}: {v['outcome']} ({v['attempts']} attempt(s))" for v in views]
    if resumed:
        observations["outcome"] = "resumed"
        return result(RESUMPTION_ID, PASS, f"Session resumption was demonstrated ({', '.join(resumed)}). This is a normal capability, not a defect by itself.", observations, evidence)
    if any(_outcome(p) == "refused" for p in probes):
        observations["outcome"] = "refused"
        return result(RESUMPTION_ID, PASS, f"A session was offered back {attempts} time(s) and the server did not resume it (full handshake each time); other back-ends may behave differently.", observations, evidence)
    if probes and all(_outcome(p) == "not_issued" for p in probes if p.handshake) and any(p.handshake for p in probes):
        observations["outcome"] = "not_offered"
        return result(RESUMPTION_ID, PASS, "The server issued neither a session ticket nor a session identifier that could be resumed.", observations, evidence)
    details = "; ".join(sorted({p.detail for p in probes if p.detail})) or "no probe completed"
    return result(RESUMPTION_ID, INCONCLUSIVE, f"Session resumption could not be determined ({details}).", observations, evidence)


def _advertised_tls12(context: CheckContext) -> bool | None:
    """Is the session_ticket extension echoed in a TLS 1.2 ServerHello? (one raw connection)"""
    if context.observed_versions and TLS12 not in context.observed_versions:
        return None
    reply = send_client_hello(context, extra_extensions=_extension(EXT_SESSION_TICKET, b""))
    if reply.kind != "server_hello" or reply.version == TLS13:
        return None
    return reply.has_extension(EXT_SESSION_TICKET)


def check_session_tickets(context: CheckContext) -> CheckResult:
    observation = observe_sessions(context)
    unavailable = _not_applicable(TICKETS_ID, observation)
    if unavailable:
        return unavailable
    probes = [p for p in observation["probes"] if p.mechanism == "ticket"]
    per_version = {}
    for probe in probes:
        per_version[probe.version] = {
            "issued": probe.ticket_issued if probe.handshake else None,
            "resumption_demonstrated": bool(probe.resumed) if probe.resumed is not None else None,
            "lifetime_hint_seconds": probe.lifetime_hint_seconds,
            "attempts": probe.attempts,
            "detail": probe.detail,
        }
    if TLS12 in per_version:
        per_version[TLS12]["advertised"] = _advertised_tls12(context)
    issued = [v for v, item in per_version.items() if item["issued"]]
    demonstrated = [v for v, item in per_version.items() if item["resumption_demonstrated"]]
    hints = {v: item["lifetime_hint_seconds"] for v, item in per_version.items() if item["lifetime_hint_seconds"] is not None}
    observations = {
        "outcome": "undetermined", "issued_versions": issued, "resumption_demonstrated_versions": demonstrated,
        "lifetime_hint_seconds": hints, "by_version": per_version,
        "limit": "only presence and lifetime hint are read; ticket content is dropped, key rotation and ticket-key strength are not observable from outside",
    }
    evidence = [f"{v}: ticket issued={item['issued']}, resumption={item['resumption_demonstrated']}, hint={item['lifetime_hint_seconds']}" for v, item in per_version.items()]
    if demonstrated:
        observations["outcome"] = "issued_and_resumed"
        return result(TICKETS_ID, PASS, f"The server issues session tickets and resumption with a ticket was demonstrated ({', '.join(demonstrated)}).", observations, evidence)
    if issued:
        observations["outcome"] = "issued_not_resumed"
        return result(TICKETS_ID, PASS, f"Session tickets are issued ({', '.join(issued)}) but resumption with them was not demonstrated.", observations, evidence)
    handshakes = [v for v, item in per_version.items() if item["issued"] is False]
    if handshakes and TLS13 not in handshakes:
        observations["outcome"] = "not_issued"
        return result(TICKETS_ID, PASS, "The server did not issue a session ticket in TLS 1.2.", observations, evidence)
    if handshakes:
        return result(TICKETS_ID, INCONCLUSIVE, f"No TLS 1.3 ticket was received within {context.option('ticket_wait_seconds', DEFAULT_TICKET_WAIT_SECONDS)} s; a later ticket cannot be excluded.", observations, evidence)
    return result(TICKETS_ID, INCONCLUSIVE, "Session tickets could not be determined (no probe completed).", observations, evidence)
