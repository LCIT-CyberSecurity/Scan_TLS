"""Lot 2 checks (sessions, 0-RTT, client authentication, STARTTLS protocols) against real TLS endpoints:
nginx on OpenSSL 3.5 and the Python STARTTLS lab services (real TLS behind scripted application dialogues)."""
from __future__ import annotations

import json
import socket

import pytest
from conftest import LAB
from test_tls_checks_lab import s_server
from tls_scanner.checks import client_auth, early_data, sessions
from tls_scanner.checks.catalog import run_complementary_checks
from tls_scanner.checks.contracts import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, CheckContext

LAB_IP = socket.gethostbyname(LAB)
BOTH = ("TLSv1.2", "TLSv1.3")


def lab(port: int, **kwargs) -> CheckContext:
    return CheckContext(host=LAB_IP, port=port, timeout_seconds=8, **kwargs)


def run(check_id: str, port: int, options=None, **kwargs):
    (outcome,) = run_complementary_checks((check_id,), LAB_IP, port, observed_versions=kwargs.pop("observed_versions", BOTH),
                                          timeout_seconds=kwargs.pop("timeout_seconds", 8), options={check_id: options or {}}, **kwargs)
    return outcome


# --- sessions -----------------------------------------------------------------------------------

def test_tickets_and_psk_resumption_are_demonstrated_on_tls12_and_tls13():
    outcome = sessions.check_session_resumption(lab(8460, observed_versions=BOTH))
    assert outcome.status == PASS and outcome.observations["outcome"] == "resumed", outcome
    assert set(outcome.observations["mechanisms_resumed"]) >= {"TLSv1.3 ticket", "TLSv1.2 ticket"}


def test_ticket_metadata_is_reported_without_the_ticket():
    outcome = sessions.check_session_tickets(lab(8460, observed_versions=BOTH))
    assert outcome.status == PASS and outcome.observations["outcome"] == "issued_and_resumed", outcome
    assert outcome.observations["lifetime_hint_seconds"]["TLSv1.3"] > 0 and outcome.observations["lifetime_hint_seconds"]["TLSv1.2"] > 0
    assert outcome.observations["by_version"]["TLSv1.2"]["advertised"] is True
    json.dumps(outcome.to_dict())  # no bytes anywhere: nothing like a ticket can have been kept


def test_session_identifier_resumption_without_tickets():
    context = lab(8461, observed_versions=("TLSv1.2",))
    resumption = sessions.check_session_resumption(context)
    assert resumption.observations["outcome"] == "resumed" and resumption.observations["mechanisms_resumed"] == ["TLSv1.2 session_id"]
    tickets = sessions.check_session_tickets(context)
    assert tickets.observations["outcome"] == "not_issued" and tickets.observations["by_version"]["TLSv1.2"]["advertised"] is False


def test_tickets_that_the_server_does_not_honour_are_reported_as_refused():
    # nginx with ticket keys off and no cache still issues TLS 1.3 tickets it cannot resume: "refused", not "unsupported"
    outcome = sessions.check_session_resumption(lab(8462, observed_versions=BOTH, options={"ticket_wait_seconds": 1}))
    assert outcome.status == PASS and outcome.observations["outcome"] == "refused", outcome
    tls12 = [p for p in outcome.observations["probes"] if p["version"] == "TLSv1.2"]
    assert tls12 and all(p["outcome"] == "not_issued" for p in tls12)


def test_both_session_checks_share_one_set_of_probes():
    context = lab(8460, observed_versions=BOTH)
    sessions.check_session_resumption(context)
    shared = context.shared["sessions"]
    sessions.check_session_tickets(context)
    assert context.shared["sessions"] is shared


def test_old_versions_only_is_not_applicable():
    assert sessions.check_session_resumption(lab(8446, observed_versions=("TLSv1.0", "TLSv1.1"))).status == NOT_APPLICABLE


# --- early data ---------------------------------------------------------------------------------

def test_early_data_announced_but_acceptance_not_tested_by_default():
    outcome = early_data.check_early_data(lab(8460, observed_versions=BOTH))
    assert outcome.status == PASS and outcome.observations["outcome"] == "advertised", outcome
    assert outcome.observations["max_early_data_size"] > 0 and outcome.observations["acceptance"] == "not_tested"


def test_early_data_acceptance_is_demonstrated_only_with_the_deep_probe():
    outcome = early_data.check_early_data(lab(8460, observed_versions=BOTH, options={"probe": True}))
    assert outcome.observations["outcome"] == "accepted" and outcome.observations["deep_probe"] is True, outcome


def test_early_data_not_announced_by_a_server_that_does_not_issue_tickets():
    outcome = early_data.check_early_data(lab(8462, observed_versions=BOTH, options={"ticket_wait_seconds": 1}))
    assert outcome.status in (INCONCLUSIVE, PASS) and outcome.observations.get("outcome") != "advertised"


def test_early_data_does_not_apply_to_tls12_only():
    assert early_data.check_early_data(lab(8461, observed_versions=("TLSv1.2",))).status == NOT_APPLICABLE


# --- client authentication ----------------------------------------------------------------------

def test_optional_client_certificate_request_is_observed_with_its_accepted_cas():
    outcome = client_auth.check_client_auth(lab(8463, observed_versions=BOTH))
    assert outcome.status == PASS and outcome.observations["outcome"] == "requested_optional_or_probable", outcome
    assert any("Lab OCSP CA" in name for name in outcome.observations["acceptable_ca_names"])


def test_no_request_is_reported_as_not_observed_not_as_proof_of_absence():
    outcome = client_auth.check_client_auth(lab(443, observed_versions=BOTH))
    assert outcome.observations["outcome"] == "none_observed" and "application" in outcome.observations["limit"]


@pytest.mark.parametrize("version_flag, versions", [("-tls1_2", ("TLSv1.2",)), ("-tls1_3", ("TLSv1.3",))])
def test_required_client_certificate_is_demonstrated(version_flag, versions):
    with s_server(version_flag, "-Verify", "1") as port:
        outcome = client_auth.check_client_auth(CheckContext(host="127.0.0.1", port=port, timeout_seconds=8, observed_versions=versions))
    assert outcome.observations["outcome"] == "required_demonstrated", outcome


# --- STARTTLS protocols -------------------------------------------------------------------------

UPGRADES = {8471: "imap", 8472: "pop3", 8473: "ftp", 8474: "ldap", 8475: "postgres", 8476: "xmpp"}


@pytest.mark.parametrize("port, protocol", UPGRADES.items())
def test_protocol_is_confirmed_and_switched_to_tls(port, protocol):
    outcome = run(f"starttls_{protocol}", port, {"ports": [port]})
    assert outcome.status == PASS, outcome
    assert outcome.observations["confirmed"] is True and outcome.observations["upgraded"] is True
    assert outcome.observations["tls_version"] in BOTH and outcome.observations["assumed_by"] == "configured ports"


@pytest.mark.parametrize("port, protocol, status", [
    (8477, "imap", FAIL), (8485, "imap", FAIL), (8478, "pop3", FAIL), (8479, "ftp", FAIL), (8480, "postgres", FAIL),
    (8481, "ldap", FAIL), (8482, "xmpp", FAIL), (8483, "imap", NOT_APPLICABLE), (8483, "ldap", NOT_APPLICABLE), (8484, "pop3", INCONCLUSIVE),
])
def test_misbehaving_services_are_qualified_not_guessed(port, protocol, status):
    outcome = run(f"starttls_{protocol}", port, {"ports": [port]}, timeout_seconds=2)
    assert outcome.status == status, outcome
    if status == FAIL:
        assert outcome.observations["confirmed"] is True and outcome.observations["upgraded"] is False


def test_a_protocol_check_only_exists_on_its_own_ports():
    assert run_complementary_checks(("starttls_imap", "starttls_pop3"), LAB_IP, 443) == ()
    assert run_complementary_checks(("starttls_imap",), LAB_IP, 8471) == ()  # port not configured: skipped, not guessed


def test_other_checks_run_through_the_negotiated_channel():
    options = {"starttls_imap": {"ports": [8471]}}
    selected = ("starttls_imap", "tls_compression", "extended_master_secret", "session_resumption")
    outcomes = {o.check_id: o for o in run_complementary_checks(selected, LAB_IP, 8471, observed_versions=BOTH, timeout_seconds=8, options=options)}
    assert outcomes["starttls_imap"].status == PASS
    assert outcomes["tls_compression"].status == PASS and outcomes["extended_master_secret"].status == PASS
    assert outcomes["session_resumption"].observations["outcome"] == "resumed"


def test_smtp_keeps_working_on_its_historical_handling():
    outcome = run_complementary_checks(("tls_compression",), LAB_IP, 8470, observed_versions=BOTH, timeout_seconds=8, options={})
    assert outcome[0].status == INCONCLUSIVE  # port 8470 is not 25/587: no SMTP assumption without configuration
    context = CheckContext(host=LAB_IP, port=8470, timeout_seconds=8, observed_versions=BOTH, starttls_protocol="smtp")
    from tls_scanner.checks import handshake
    assert handshake.check_tls_compression(context).status == PASS
