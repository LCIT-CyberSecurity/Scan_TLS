"""Test SMTP sink: accepts any mail on :1025 and lists them as JSON on http://:8025/messages (tests only)."""
import json
import threading
from email import message_from_bytes
from http.server import BaseHTTPRequestHandler, HTTPServer

from aiosmtpd.controller import Controller

MESSAGES: list[dict] = []


class Handler:
    async def handle_DATA(self, server, session, envelope):
        msg = message_from_bytes(envelope.content)
        MESSAGES.append({"to": envelope.rcpt_tos, "from": envelope.mail_from, "subject": msg["Subject"], "body": msg.get_payload()})
        return "250 OK"


class Http(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(MESSAGES).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


Controller(Handler(), hostname="0.0.0.0", port=1025).start()
HTTPServer(("0.0.0.0", 8025), Http).serve_forever()
