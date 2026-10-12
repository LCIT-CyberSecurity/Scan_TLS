"""
TLS 1.3 Early Data (0-RTT).

What can be established without sending application data: whether the server *announces* early-data
support in the session tickets it issues (`max_early_data_size` > 0), read from `openssl s_client` after a
bounded wait for the post-handshake ticket.

Acceptance can only be demonstrated by really sending early data. That deep probe is OFF by default
(`probe: true` in the profile) and sends nothing but an empty line (CRLF): HTTP servers ignore it, and it
carries no request, no method and no command, so it cannot change any state. It is skipped on STARTTLS channels.
Without it the result says "announced, acceptance not tested".

0-RTT data can be replayed by an attacker, so an accepting server needs replay protection in the application;
this is a property to know about, not a vulnerability by itself, and it is never graded.
"""

from __future__ import annotations

import os
import re
import tempfile

from .contracts import INCONCLUSIVE, NOT_APPLICABLE, PASS, CheckContext, CheckResult, result
from .transport import run_s_client

CHECK_ID = "early_data"
DEFAULT_TICKET_WAIT_SECONDS = 3
MAX_EARLY_RE = re.compile(r"Max Early Data:\s*(\d+)")
SAFE_EARLY_PAYLOAD = b"\r\n"  # an empty line: ignored by HTTP, no application-level effect


def _ticket_and_limit(context: CheckContext, session_file: str, wait: float):
    """Returns (connected, got_ticket, max_early_data|None, detail)."""
    output = run_s_client(context, ["-tls1_3", "-sess_out", session_file], stdin=b"", timeout=context.probe_timeout() + wait, hold=wait)
    if not output.connected:
        return False, False, None, output.error or "TLS 1.3 handshake failed"
    got_ticket = os.path.exists(session_file) and os.path.getsize(session_file) > 0
    limit = MAX_EARLY_RE.search(output.text)
    return True, got_ticket, int(limit.group(1)) if limit else None, ""


def _early_data_accepted(context: CheckContext, session_file: str, payload_file: str) -> bool | None:
    output = run_s_client(context, ["-tls1_3", "-sess_in", session_file, "-early_data", payload_file], stdin=b"", hold=0.5)
    if re.search(r"Early data was accepted", output.text):
        return True
    if re.search(r"Early data was rejected", output.text):
        return False
    return None


def check_early_data(context: CheckContext) -> CheckResult:
    if context.observed_versions and "TLSv1.3" not in context.observed_versions:
        return result(CHECK_ID, NOT_APPLICABLE, "The endpoint does not support TLS 1.3, where Early Data exists.", {"observed_versions": list(context.observed_versions)})
    wait = float(context.option("ticket_wait_seconds", DEFAULT_TICKET_WAIT_SECONDS))
    deep = bool(context.option("probe", False)) and not context.starttls
    with tempfile.TemporaryDirectory(prefix="tlsscan-0rtt-") as directory:  # private (0700) and removed at once
        session_file = os.path.join(directory, "session")
        connected, got_ticket, limit, detail = _ticket_and_limit(context, session_file, wait)
        observations = {"tls_version": "TLSv1.3", "ticket_received": got_ticket, "max_early_data_size": limit, "acceptance": "not_tested", "deep_probe": deep}
        if not connected:
            return result(CHECK_ID, INCONCLUSIVE, f"Early Data could not be examined ({detail}).", observations)
        if not got_ticket:
            return result(CHECK_ID, INCONCLUSIVE, f"No TLS 1.3 ticket was received within {wait:g} s, so the Early Data announcement cannot be read.", observations)
        if not limit:
            observations["outcome"] = "not_advertised"
            return result(CHECK_ID, PASS, "The server's tickets do not announce Early Data (0-RTT).", observations, ["ticket without max_early_data_size"])
        observations["outcome"] = "advertised"
        evidence = [f"ticket announces max_early_data_size={limit}"]
        if not deep:
            return result(CHECK_ID, PASS, f"The server announces 0-RTT (max {limit} bytes). Acceptance was not tested (deep probe off): replay protection is the application's responsibility.", observations, evidence)
        payload_file = os.path.join(directory, "early")
        with open(payload_file, "wb") as handle:
            handle.write(SAFE_EARLY_PAYLOAD)
        accepted = _early_data_accepted(context, session_file, payload_file)
        if accepted is None:
            return result(CHECK_ID, INCONCLUSIVE, f"The server announces 0-RTT (max {limit} bytes) but the acceptance probe gave no clear answer.", observations, evidence)
        observations["acceptance"] = "accepted" if accepted else "rejected"
        observations["outcome"] = "accepted" if accepted else "rejected"
        if accepted:
            return result(CHECK_ID, PASS, "The server accepted early data (0-RTT demonstrated with an empty line). Early data can be replayed: the application must be idempotent or reject it.", observations, evidence + ["early data accepted"])
        return result(CHECK_ID, PASS, "The server announces 0-RTT but rejected the early data that was sent.", observations, evidence + ["early data rejected"])
