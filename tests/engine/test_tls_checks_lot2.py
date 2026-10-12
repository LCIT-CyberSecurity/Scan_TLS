"""Lot 2: STARTTLS adapters, option parsing, protocol resolution, session/0-RTT/mTLS decision logic.
Network-free except for loopback scripted servers; real TLS negotiations are in tests/backend/test_tls_checks_lab2.py."""

import socket
import threading
import time
import unittest
from unittest.mock import patch

from tls_scanner.checks import catalog, client_auth, early_data, sessions
from tls_scanner.checks.contracts import FAIL, INCONCLUSIVE, NOT_APPLICABLE, PASS, CheckContext
from tls_scanner.checks.protocols import ADAPTERS, OPT_IN_PROTOCOLS, STANDARD_PORTS, negotiate, open_channel, resolve_protocol
from tls_scanner.checks.protocols import checks as protocol_checks
from tls_scanner.checks.protocols import ldap as ldap_adapter
from tls_scanner.checks.protocols.starttls import ERROR, NOT_OFFERED, NOT_PROTOCOL, REFUSED, UPGRADED
from tls_scanner.config import ConfigError, parse_tls_checks_config


class Script:
    """One loopback server that plays a script and records every byte it receives."""

    def __init__(self, play):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.port = self.listener.getsockname()[1]
        self.received = b""
        self.play = play
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            self.listener.settimeout(5)
            conn, _ = self.listener.accept()
        except OSError:
            return
        conn.settimeout(2)
        try:
            self.play(conn, self)
        except OSError:
            pass
        finally:
            conn.close()

    def recv_until(self, conn, marker=b"\n"):
        data = b""
        while marker not in data:
            chunk = conn.recv(1024)
            if not chunk:
                break
            data += chunk
        self.received += data
        return data

    def close(self):
        self.listener.close()


def upgrade(protocol, play, timeout=2.0, name="mail.example"):
    server = Script(play)
    try:
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=2)
        try:
            outcome = negotiate(protocol, sock, time.monotonic() + timeout, name)
        finally:
            sock.close()
        time.sleep(0.05)
        return outcome, server.received
    finally:
        server.close()


class ImapTests(unittest.TestCase):
    def script(self, greeting=b"* OK ready\r\n", capability=b"* CAPABILITY IMAP4rev1 STARTTLS\r\n", starttls=b"a002 OK go\r\n"):
        def play(conn, server):
            conn.sendall(greeting)
            server.recv_until(conn)
            conn.sendall(capability + b"a001 OK done\r\n")
            if b"STARTTLS" in capability:
                server.recv_until(conn)
                conn.sendall(starttls)
        return play

    def test_upgrade_sends_only_capability_and_starttls(self):
        outcome, received = upgrade("imap", self.script())
        self.assertEqual((outcome.status, outcome.confirmed, outcome.advertised), (UPGRADED, True, True))
        self.assertEqual(received, b"a001 CAPABILITY\r\na002 STARTTLS\r\n")
        self.assertNotIn(b"LOGIN", received)

    def test_starttls_not_advertised_is_never_requested(self):
        outcome, received = upgrade("imap", self.script(capability=b"* CAPABILITY IMAP4rev1\r\n"))
        self.assertEqual((outcome.status, outcome.advertised), (NOT_OFFERED, False))
        self.assertEqual(received, b"a001 CAPABILITY\r\n")

    def test_negative_answer_is_a_refusal(self):
        self.assertEqual(upgrade("imap", self.script(starttls=b"a002 NO later\r\n"))[0].status, REFUSED)

    def test_other_services_and_odd_greetings(self):
        self.assertEqual(upgrade("imap", self.script(greeting=b"220 smtp ready\r\n"))[0].status, NOT_PROTOCOL)
        self.assertEqual(upgrade("imap", self.script(greeting=b"* BYE no\r\n"))[0].status, REFUSED)
        self.assertEqual(upgrade("imap", self.script(greeting=b"* PREAUTH hi\r\n"))[0].status, NOT_OFFERED)


class Pop3Tests(unittest.TestCase):
    def script(self, capa=b"+OK\r\nUSER\r\nSTLS\r\n.\r\n", stls=b"+OK go\r\n"):
        def play(conn, server):
            conn.sendall(b"+OK POP3 ready\r\n")
            server.recv_until(conn)
            conn.sendall(capa)
            if b"STLS" in capa or capa.startswith(b"-ERR"):
                server.recv_until(conn)
                conn.sendall(stls)
        return play

    def test_upgrade(self):
        outcome, received = upgrade("pop3", self.script())
        self.assertEqual(outcome.status, UPGRADED)
        self.assertEqual(received, b"CAPA\r\nSTLS\r\n")

    def test_missing_stls_is_not_requested(self):
        outcome, received = upgrade("pop3", self.script(capa=b"+OK\r\nUSER\r\n.\r\n"))
        self.assertEqual((outcome.status, received), (NOT_OFFERED, b"CAPA\r\n"))

    def test_server_without_capa_is_tried_anyway(self):
        self.assertEqual(upgrade("pop3", self.script(capa=b"-ERR unknown\r\n"))[0].status, UPGRADED)
        self.assertEqual(upgrade("pop3", self.script(capa=b"-ERR unknown\r\n", stls=b"-ERR no\r\n"))[0].status, NOT_OFFERED)

    def test_not_pop3(self):
        def play(conn, server):
            conn.sendall(b"* OK IMAP\r\n")
        self.assertEqual(upgrade("pop3", play)[0].status, NOT_PROTOCOL)


class FtpTests(unittest.TestCase):
    def test_multiline_banner_then_auth_tls(self):
        def play(conn, server):
            conn.sendall(b"220-Welcome\r\n220 ready\r\n")
            server.recv_until(conn)
            conn.sendall(b"234 AUTH TLS ok\r\n")
        outcome, received = upgrade("ftp", play)
        self.assertEqual((outcome.status, received), (UPGRADED, b"AUTH TLS\r\n"))
        self.assertNotIn(b"USER", received)

    def test_auth_not_implemented_and_refused(self):
        def play(code):
            def run(conn, server):
                conn.sendall(b"220 ready\r\n")
                server.recv_until(conn)
                conn.sendall(code)
            return run
        self.assertEqual(upgrade("ftp", play(b"502 no\r\n"))[0].status, NOT_OFFERED)
        self.assertEqual(upgrade("ftp", play(b"534 policy\r\n"))[0].status, REFUSED)

    def test_not_ftp(self):
        def play(conn, server):
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        self.assertEqual(upgrade("ftp", play)[0].status, NOT_PROTOCOL)


class SmtpTests(unittest.TestCase):
    def test_historical_dialogue_is_unchanged(self):
        def play(conn, server):
            conn.sendall(b"220 ESMTP\r\n")
            server.recv_until(conn)
            conn.sendall(b"250-host\r\n250 STARTTLS\r\n")
            server.recv_until(conn)
            conn.sendall(b"220 go\r\n")
        outcome, received = upgrade("smtp", play)
        self.assertEqual((outcome.status, received), (UPGRADED, b"EHLO tls-scan.invalid\r\nSTARTTLS\r\n"))

    def test_starttls_is_requested_even_if_ehlo_does_not_list_it_as_before(self):
        def play(conn, server):
            conn.sendall(b"220 ESMTP\r\n")
            server.recv_until(conn)
            conn.sendall(b"250 host\r\n")
            server.recv_until(conn)
            conn.sendall(b"502 no\r\n")
        outcome, received = upgrade("smtp", play)
        self.assertEqual((outcome.status, outcome.advertised, received), (NOT_OFFERED, False, b"EHLO tls-scan.invalid\r\nSTARTTLS\r\n"))


class PostgresTests(unittest.TestCase):
    def play(self, answer):
        def run(conn, server):
            data = b""
            while len(data) < 8:
                data += conn.recv(8 - len(data))
            server.received = data
            conn.sendall(answer)
        return run

    def test_ssl_request_bytes_and_answers(self):
        outcome, received = upgrade("postgres", self.play(b"S"))
        self.assertEqual((outcome.status, received), (UPGRADED, bytes([0, 0, 0, 8, 4, 0xD2, 0x16, 0x2F])))
        self.assertEqual(upgrade("postgres", self.play(b"N"))[0].status, NOT_OFFERED)
        self.assertEqual(upgrade("postgres", self.play(b"E"))[0].status, REFUSED)
        self.assertEqual(upgrade("postgres", self.play(b"H"))[0].status, NOT_PROTOCOL)


class LdapTests(unittest.TestCase):
    def play(self, answer):
        def run(conn, server):
            conn.settimeout(2)
            server.received = conn.recv(100)
            conn.sendall(answer)
        return run

    def response(self, code):
        return bytes([0x30, 0x0C, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0A, 0x01, code, 0x04, 0x00, 0x04, 0x00])

    def test_request_is_the_starttls_extended_operation(self):
        outcome, received = upgrade("ldap", self.play(self.response(0)))
        self.assertEqual(outcome.status, UPGRADED)
        self.assertEqual(received[:5], b"\x30\x1d\x02\x01\x01")
        self.assertIn(b"1.3.6.1.4.1.1466.20037", received)
        self.assertNotIn(b"\x60", received[:8])  # no bind request

    def test_refusals_and_garbage(self):
        self.assertEqual(upgrade("ldap", self.play(self.response(53)))[0].status, REFUSED)
        self.assertEqual(upgrade("ldap", self.play(b"HTTP/1.1 400 Bad\r\n\r\n"))[0].status, NOT_PROTOCOL)
        self.assertEqual(upgrade("ldap", self.play(b"\x30\x84\xff\xff\xff\xff"))[0].status, NOT_PROTOCOL)  # implausible length
        self.assertEqual(upgrade("ldap", self.play(b"\x30\x03\x04\x01\x00"))[0].status, NOT_PROTOCOL)  # no message id

    def test_start_tls_request_constant_is_well_formed(self):
        request = ldap_adapter.START_TLS_REQUEST
        self.assertEqual(request[1], len(request) - 2)  # outer length


class XmppTests(unittest.TestCase):
    STREAM = b"<?xml version='1.0'?><stream:stream from='x' id='1' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"

    def play(self, features, answer=b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"):
        def run(conn, server):
            server.recv_until(conn, b">")
            conn.sendall(self.STREAM + b"<stream:features>" + features + b"</stream:features>")
            if features:
                server.recv_until(conn, b"/>")
                conn.sendall(answer)
        return run

    def test_upgrade_and_stream_header(self):
        outcome, received = upgrade("xmpp", self.play(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"))
        self.assertEqual(outcome.status, UPGRADED)
        self.assertIn(b'to="mail.example"', received)
        self.assertIn(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", received)
        self.assertNotIn(b"<auth", received)

    def test_domain_is_quoted_so_that_it_cannot_inject_markup(self):
        outcome, received = upgrade("xmpp", self.play(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"), name="a'b\"><x/>")
        self.assertEqual(outcome.status, UPGRADED)
        self.assertNotIn(b"<x/>", received.split(b"xmlns='jabber:client'")[0])

    def test_server_to_server_stream_uses_its_own_namespace(self):
        outcome, received = upgrade("xmpp_server", self.play(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
        self.assertEqual((outcome.status, outcome.protocol), (UPGRADED, "xmpp_server"))
        self.assertIn(b"xmlns='jabber:server'", received)
        self.assertNotIn(b"jabber:client", received)
        self.assertNotIn(b"dialback", received)

    def test_no_starttls_feature_failure_and_not_xmpp(self):
        self.assertEqual(upgrade("xmpp", self.play(b""))[0].status, NOT_OFFERED)
        failing = self.play(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", b"<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        self.assertEqual(upgrade("xmpp", failing)[0].status, REFUSED)

        def other(conn, server):
            server.recv_until(conn, b">")
            conn.sendall(b"SSH-2.0-OpenSSH\r\n</stream:features>")
        self.assertEqual(upgrade("xmpp", other)[0].status, NOT_PROTOCOL)


class RobustnessTests(unittest.TestCase):
    def test_silence_times_out_into_an_error(self):
        started = time.monotonic()
        outcome, _ = upgrade("imap", lambda conn, server: time.sleep(1.5), timeout=0.5)
        self.assertEqual(outcome.status, ERROR)
        self.assertLess(time.monotonic() - started, 2.5)

    def test_closed_connection_and_oversized_answers_are_errors(self):
        self.assertEqual(upgrade("pop3", lambda conn, server: None)[0].status, ERROR)

        def flood(conn, server):
            conn.sendall(b"x" * 20000)
        outcome, _ = upgrade("imap", flood)
        self.assertEqual(outcome.status, ERROR)
        self.assertIn("long", outcome.detail)

        def endless_reply(conn, server):
            conn.sendall(b"220 ok\r\n")
            server.recv_until(conn)
            for _ in range(200):
                conn.sendall(b"250-more\r\n")
        self.assertEqual(upgrade("smtp", endless_reply)[0].status, ERROR)

    def test_cancellation_stops_a_waiting_adapter(self):
        server = Script(lambda conn, s: time.sleep(1.5))
        self.addCleanup(server.close)
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=2)
        self.addCleanup(sock.close)
        flag = threading.Event()
        threading.Timer(0.2, flag.set).start()
        started = time.monotonic()
        outcome = negotiate("imap", sock, time.monotonic() + 5, "x", flag.is_set)
        self.assertEqual(outcome.status, ERROR)
        self.assertLess(time.monotonic() - started, 4.5)

    def test_unknown_protocol_is_an_error_not_a_crash(self):
        server = Script(lambda conn, s: None)
        self.addCleanup(server.close)
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=2)
        self.addCleanup(sock.close)
        self.assertEqual(negotiate("irc", sock, time.monotonic() + 1).status, ERROR)

    def test_open_channel_refused_connection_is_reported(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        sock, upgrade_result, error = open_channel(CheckContext(host="127.0.0.1", port=port, starttls_protocol="imap"))
        self.assertEqual((sock, upgrade_result), (None, None))
        self.assertIn("connection failed", error)

    def test_every_adapter_is_registered(self):
        self.assertEqual(set(ADAPTERS), {"smtp", *OPT_IN_PROTOCOLS})
        self.assertEqual(set(STANDARD_PORTS), set(ADAPTERS))


class ResolutionAndConfigurationTests(unittest.TestCase):
    def test_smtp_ports_stay_historical_and_others_are_opt_in(self):
        for port in (25, 587):
            self.assertEqual(resolve_protocol(port, (), {}), "smtp")
        self.assertEqual(resolve_protocol(143, (), {}), "")  # nothing selected: no assumption, no new behaviour
        self.assertEqual(resolve_protocol(143, ("starttls_imap",), {}), "imap")
        self.assertEqual(resolve_protocol(143, ("starttls_pop3",), {}), "")
        self.assertEqual(resolve_protocol(1143, ("starttls_imap",), {"starttls_imap": {"ports": [1143]}}), "imap")
        self.assertEqual(resolve_protocol(143, ("starttls_imap",), {"starttls_imap": {"ports": [1143]}}), "")

    def test_protocol_check_is_skipped_on_other_ports_and_run_without_guessing(self):
        self.assertEqual(catalog.run_complementary_checks(("starttls_imap", "starttls_ldap"), "127.0.0.1", 9, options={}), ())

    def test_options_are_validated_by_the_common_parser(self):
        selected, _, _, options = parse_tls_checks_config({"tls": {
            "session_resumption": {"enabled": True, "attempts": 3, "ticket_wait_seconds": 4},
            "early_data": {"probe": True}, "starttls_imap": {"ports": [143, 1143]}, "client_auth": True}})
        self.assertEqual(selected, ("session_resumption", "early_data", "client_auth", "starttls_imap"))
        self.assertEqual(options, {"session_resumption": {"attempts": 3, "ticket_wait_seconds": 4}, "early_data": {"probe": True}, "starttls_imap": {"ports": [143, 1143]}})

    def test_invalid_options_are_rejected(self):
        for bad in ({"session_resumption": {"attempts": 0}}, {"session_resumption": {"attempts": True}}, {"session_resumption": {"ticket_wait_seconds": 11}},
                    {"early_data": {"probe": "yes"}}, {"starttls_imap": {"ports": []}}, {"starttls_imap": {"ports": [0]}}, {"starttls_imap": {"ports": [143, 143]}},
                    {"starttls_imap": {"ports": "143"}}, {"starttls_imap": {"ports": list(range(1, 18))}}, {"client_auth": {"certificate": "/x"}},
                    {"tls_compression": {"attempts": 1}}, {"starttls_imap": {"command": "x"}}):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                parse_tls_checks_config({"tls": bad})

    def test_catalogue_describes_options_for_the_profile_form(self):
        entries = {entry["id"]: entry for entry in catalog.catalog_as_dicts()}
        self.assertEqual([o["name"] for o in entries["session_resumption"]["options"]], ["attempts", "ticket_wait_seconds"])
        self.assertEqual(entries["early_data"]["options"][0], {"name": "probe", "kind": "bool", "default": False, "min": None, "max": None})
        self.assertEqual(entries["starttls_imap"]["options"][0]["kind"], "ports")
        self.assertEqual({entries[c]["family"] for c in ("session_resumption", "client_auth", "starttls_pop3")}, {"sessions", "authentication", "protocols"})
        self.assertEqual({e["id"] for e in entries.values()} - set(catalog.CHECK_LABELS), set())


class DecisionLogicTests(unittest.TestCase):
    def ctx(self, **kwargs):
        return CheckContext(host="127.0.0.1", port=1, **kwargs)

    def observation(self, *probes, versions=("TLSv1.3", "TLSv1.2")):
        return {"versions": list(versions), "probes": list(probes), "connections_limit": 0}

    def probe(self, version="TLSv1.3", mechanism="ticket", **kwargs):
        defaults = dict(handshake=True, ticket_issued=True, session_id_issued=False, attempts=0, resumed=None)
        return sessions.MechanismProbe(version, mechanism, **{**defaults, **kwargs})

    def run_resumption(self, *probes):
        context = self.ctx()
        context.shared["sessions"] = self.observation(*probes)
        return sessions.check_session_resumption(context)

    def test_outcomes_resumed_refused_not_offered_undetermined(self):
        self.assertEqual(self.run_resumption(self.probe(attempts=1, resumed=True)).observations["outcome"], "resumed")
        refused = self.run_resumption(self.probe(attempts=2, resumed=False))
        self.assertEqual((refused.status, refused.observations["outcome"]), (PASS, "refused"))
        self.assertIn("other back-ends", refused.message)
        self.assertEqual(self.run_resumption(self.probe(ticket_issued=False)).observations["outcome"], "not_offered")
        undetermined = self.run_resumption(self.probe(handshake=False, detail="handshake failed: SSLError"))
        self.assertEqual(undetermined.status, INCONCLUSIVE)

    def test_resumption_is_never_called_a_failure(self):
        for probe in (self.probe(attempts=1, resumed=True), self.probe(attempts=2, resumed=False), self.probe(ticket_issued=False)):
            self.assertNotEqual(self.run_resumption(probe).status, FAIL)

    def test_tls13_ticket_not_seen_in_time_is_inconclusive_but_tls12_absence_is_definite(self):
        context = self.ctx()
        context.shared["sessions"] = self.observation(self.probe(ticket_issued=False))
        with patch.object(sessions, "_advertised_tls12", return_value=None):
            self.assertEqual(sessions.check_session_tickets(context).status, INCONCLUSIVE)
            context.shared["sessions"] = self.observation(self.probe(version="TLSv1.2", ticket_issued=False), versions=("TLSv1.2",))
            self.assertEqual(sessions.check_session_tickets(context).observations["outcome"], "not_issued")

    def test_tickets_distinguish_issuance_from_demonstrated_resumption(self):
        context = self.ctx()
        with patch.object(sessions, "_advertised_tls12", return_value=True):
            context.shared["sessions"] = self.observation(self.probe(attempts=1, resumed=False, lifetime_hint_seconds=300))
            outcome = sessions.check_session_tickets(context)
            self.assertEqual(outcome.observations["outcome"], "issued_not_resumed")
            self.assertEqual(outcome.observations["lifetime_hint_seconds"], {"TLSv1.3": 300})

    def test_not_applicable_without_tls12_or_tls13(self):
        self.assertEqual(sessions.check_session_resumption(self.ctx(observed_versions=("TLSv1.0",))).status, NOT_APPLICABLE)

    def test_cancelled_session_probe_makes_no_connection(self):
        event = threading.Event()
        event.set()
        probe = sessions.probe_mechanism(self.ctx(cancel_event=event), "TLSv1.3", "ticket", 2, 1)
        self.assertFalse(probe.handshake)
        self.assertIn("cancelled", probe.detail)

    def test_client_auth_classification(self):
        classify = client_auth._classify
        self.assertEqual(classify(True, "rejected"), "required_demonstrated")
        self.assertEqual(classify(True, "completed"), "requested_optional_or_probable")
        self.assertEqual(classify(False, "completed"), "none_observed")
        self.assertEqual(classify(False, "rejected"), "undetermined")  # a rejection without a request is not attributable
        self.assertEqual(classify(True, "closed"), "undetermined")
        self.assertEqual(classify(None, "completed"), "undetermined")

    def test_client_auth_reads_the_request_and_the_ca_names(self):
        text = "<<< TLS 1.2, Handshake [length 0010], CertificateRequest\n---\nAcceptable client certificate CA names\nCN=Lab CA\nO=Other\n---\nSSL handshake"
        self.assertEqual(client_auth.parse_request(text), (True, ["CN=Lab CA", "O=Other"]))
        self.assertEqual(client_auth.parse_request("<<< ServerHello\nNo client certificate CA names sent\n"), (False, []))

    def test_early_data_outcomes_with_a_stubbed_openssl(self):
        context = self.ctx(observed_versions=("TLSv1.3",))
        with patch.object(early_data, "_ticket_and_limit", return_value=(True, True, 16384, "")):
            advertised = early_data.check_early_data(context)
        self.assertEqual((advertised.status, advertised.observations["outcome"], advertised.observations["acceptance"]), (PASS, "advertised", "not_tested"))
        with patch.object(early_data, "_ticket_and_limit", return_value=(True, True, None, "")):
            self.assertEqual(early_data.check_early_data(context).observations["outcome"], "not_advertised")
        with patch.object(early_data, "_ticket_and_limit", return_value=(True, False, None, "")):
            self.assertEqual(early_data.check_early_data(context).status, INCONCLUSIVE)
        with patch.object(early_data, "_ticket_and_limit", return_value=(False, False, None, "boom")):
            self.assertEqual(early_data.check_early_data(context).status, INCONCLUSIVE)
        self.assertEqual(early_data.check_early_data(self.ctx(observed_versions=("TLSv1.2",))).status, NOT_APPLICABLE)

    def test_deep_probe_is_off_by_default_and_never_used_on_starttls(self):
        with patch.object(early_data, "_ticket_and_limit", return_value=(True, True, 16384, "")), patch.object(early_data, "_early_data_accepted") as accepted:
            early_data.check_early_data(self.ctx(observed_versions=("TLSv1.3",)))
            early_data.check_early_data(self.ctx(observed_versions=("TLSv1.3",), options={"probe": True}, starttls_protocol="imap"))
            accepted.assert_not_called()
            accepted.return_value = True
            result = early_data.check_early_data(self.ctx(observed_versions=("TLSv1.3",), options={"probe": True}))
        self.assertEqual(result.observations["acceptance"], "accepted")
        self.assertEqual(early_data.SAFE_EARLY_PAYLOAD, b"\r\n")  # an empty line: no method, no command, no body

    def test_protocol_check_statuses(self):
        outcome = protocol_checks.make_check("imap")(self.ctx(starttls_protocol="imap"))
        self.assertEqual(outcome.status, INCONCLUSIVE)  # nothing listens on port 1
        self.assertEqual(outcome.observations["assumed_by"], "standard port")


if __name__ == "__main__":
    unittest.main()
