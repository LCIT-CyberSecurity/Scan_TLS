"""Microsoft Entra ID directory connector through Microsoft Graph (application permission User.Read.All)."""
from __future__ import annotations

from typing import Any

import httpx

from tls_scan_app.connectors.base import ConnectorError, DirectoryPerson, Step


class EntraConnector:
    kind = "entra"

    def __init__(self, cfg: dict[str, Any], secret: str, login_url: str, base_url: str) -> None:
        self.cfg, self.secret = cfg, secret
        self.login_url, self.base_url = login_url.rstrip("/"), base_url.rstrip("/")

    def _token(self) -> str:
        r = httpx.post(f"{self.login_url}/{self.cfg['tenant_id']}/oauth2/v2.0/token", timeout=15, data={
            "grant_type": "client_credentials", "client_id": self.cfg["client_id"], "client_secret": self.secret,
            "scope": "https://graph.microsoft.com/.default"})
        if r.status_code != 200:
            body = r.json() if "json" in r.headers.get("content-type", "") else {}
            raise ConnectorError(f"token refused ({body.get('error', r.status_code)}): {str(body.get('error_description', ''))[:200]}")
        return r.json()["access_token"]

    def diagnose(self) -> list[Step]:
        if not self.secret:
            return [Step("secret", "fail", "TLS_SCAN_DIRECTORY_CLIENT_SECRET is not set.")]
        try:
            token = self._token()
        except httpx.HTTPError as error:
            return [Step("token", "fail", f"Cannot reach the login endpoint: {type(error).__name__}")]
        except ConnectorError as error:
            return [Step("token", "fail", f"{error}. Check tenant id, client id and secret.")]
        steps = [Step("token", "ok")]
        try:
            self._get("/users?$top=1&$select=id", token)
            steps.append(Step("read-users", "ok"))
        except ConnectorError as error:
            steps.append(Step("read-users", "fail", str(error)))
        except httpx.HTTPError as error:
            steps.append(Step("read-users", "fail", f"Graph unreachable: {type(error).__name__}"))
        return steps

    def _get(self, path: str, token: str) -> dict:
        r = httpx.get(f"{self.base_url}{path}", timeout=20, headers={"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"})
        if r.status_code == 403:
            raise ConnectorError("Graph denied access (403): grant the application permission User.Read.All with admin consent.")
        if r.status_code != 200:
            raise ConnectorError(f"Graph error {r.status_code}: {r.text[:160]}")
        return r.json()

    def search(self, query: str, limit: int = 25) -> list[DirectoryPerson]:
        token = self._token()
        q = query.replace('"', "")
        data = self._get(f'/users?$search="displayName:{q}" OR "mail:{q}"&$top={limit}&$select=id,displayName,mail,userPrincipalName', token)
        return [DirectoryPerson(u["id"], u.get("mail") or u.get("userPrincipalName") or "", u.get("displayName") or "") for u in data.get("value", [])
                if (u.get("mail") or u.get("userPrincipalName"))]
