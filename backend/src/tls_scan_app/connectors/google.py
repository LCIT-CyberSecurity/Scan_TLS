"""Google Workspace directory connector: read-only Admin SDK lookup, to pre-provision people. Not needed to sign in with Google.

Uses a service account with domain-wide delegation limited to `admin.directory.user.readonly`: the key file is read from the
server (TLS_SCAN_GOOGLE_DIRECTORY_KEY_FILE), never stored in the database. The signed assertion is built with authlib (already a
dependency); nothing is added.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import httpx
from authlib.jose import jwt

from tls_scan_app.connectors.base import ConnectorError, DirectoryPerson, Step

SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"
DEFAULT_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105
DEFAULT_API = "https://admin.googleapis.com/admin/directory/v1"


class GoogleConnector:
    kind = "google"

    def __init__(self, cfg: dict[str, Any], key_file: str, token_url: str = "", api_url: str = "") -> None:
        self.cfg, self.key_file = cfg, key_file
        self.token_url, self.api_url = token_url or DEFAULT_TOKEN_URL, (api_url or DEFAULT_API).rstrip("/")

    def _key(self) -> dict[str, Any]:
        if not self.key_file:
            raise ConnectorError("TLS_SCAN_GOOGLE_DIRECTORY_KEY_FILE is not set (path of the service-account JSON key).")
        try:
            key = json.loads(Path(self.key_file).read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ConnectorError(f"The service-account key file cannot be read ({type(error).__name__}).") from error
        if not key.get("private_key") or not key.get("client_email"):
            raise ConnectorError("The key file is not a service-account key (private_key / client_email missing).")
        return key

    def _token(self) -> str:
        key, now = self._key(), int(time.time())
        assertion = jwt.encode({"alg": "RS256", "typ": "JWT"}, {
            "iss": key["client_email"], "sub": self.cfg["admin_email"], "scope": SCOPE, "aud": self.token_url, "iat": now, "exp": now + 300,
        }, key["private_key"]).decode()
        r = httpx.post(self.token_url, timeout=15, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion})
        if r.status_code != 200:
            body = r.json() if "json" in r.headers.get("content-type", "") else {}
            raise ConnectorError(f"token refused ({body.get('error', r.status_code)}): {str(body.get('error_description', ''))[:200]}")
        return r.json()["access_token"]

    def _get(self, path: str, token: str, params: dict[str, Any]) -> dict:
        r = httpx.get(f"{self.api_url}{path}", timeout=20, params=params, headers={"Authorization": f"Bearer {token}"})
        if r.status_code in (401, 403):
            raise ConnectorError("Google denied access: enable the Admin SDK API, delegate the scope admin.directory.user.readonly to the service account "
                                 "(Admin console → Security → API controls → Domain-wide delegation), and use a real administrator as the delegated user.")
        if r.status_code != 200:
            raise ConnectorError(f"Admin SDK error {r.status_code}: {r.text[:160]}")
        return r.json()

    def diagnose(self) -> list[Step]:
        if not (self.cfg.get("domain") and self.cfg.get("admin_email")):
            return [Step("configuration", "fail", "The Workspace domain and the delegated administrator e-mail are required.")]
        try:
            self._key()
            steps = [Step("key file", "ok")]
        except ConnectorError as error:
            return [Step("key file", "fail", str(error))]
        try:
            token = self._token()
            steps.append(Step("token", "ok"))
        except httpx.HTTPError as error:
            return [*steps, Step("token", "fail", f"Cannot reach Google: {type(error).__name__}")]
        except ConnectorError as error:
            return [*steps, Step("token", "fail", f"{error}. Check the delegation and the administrator e-mail.")]
        try:
            self._get("/users", token, {"domain": self.cfg["domain"], "maxResults": 1, "fields": "users(id)"})
            steps.append(Step("read-users", "ok"))
        except ConnectorError as error:
            steps.append(Step("read-users", "fail", str(error)))
        except httpx.HTTPError as error:
            steps.append(Step("read-users", "fail", f"Admin SDK unreachable: {type(error).__name__}"))
        return steps

    def search(self, query: str, limit: int = 25) -> list[DirectoryPerson]:
        token = self._token()
        q = query.replace("'", "").replace('"', "").strip()
        data = self._get("/users", token, {"domain": self.cfg["domain"], "maxResults": min(limit, 100), "query": f"name:'{q}*' OR email:'{q}*'",
                                           "fields": "users(id,primaryEmail,name(fullName))"})
        return [DirectoryPerson(u["id"], u.get("primaryEmail", ""), (u.get("name") or {}).get("fullName", "")) for u in data.get("users", []) if u.get("primaryEmail")]
