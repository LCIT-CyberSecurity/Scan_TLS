"""Throwaway OIDC provider for CrashTests only (accepts any client, auto-signs-in the requested fictional user).

Never deploy outside a test environment. Pick the identity with ?login_hint=<email> on /authorize
(default: alice@sso.example.com).
"""
from __future__ import annotations

import os
import time
import uuid
from urllib.parse import urlencode

from authlib.jose import JsonWebKey, jwt
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse

ISSUER = os.environ.get("MOCK_OIDC_ISSUER", "http://mock-oidc:8080")
KEY = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "mock-1"})
CODES: dict[str, dict] = {}
app = FastAPI()


@app.get("/.well-known/openid-configuration")
def discovery():
    return {"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/authorize", "token_endpoint": f"{ISSUER}/token", "jwks_uri": f"{ISSUER}/jwks.json"}


@app.get("/jwks.json")
def jwks():
    return {"keys": [KEY.as_dict(is_private=False)]}


@app.get("/authorize")
def authorize(redirect_uri: str, state: str, nonce: str, code_challenge: str, login_hint: str = "alice@sso.example.com",
              response_type: str = "", client_id: str = "", scope: str = "", code_challenge_method: str = ""):
    code = uuid.uuid4().hex
    CODES[code] = {"email": login_hint, "nonce": nonce, "challenge": code_challenge}
    return RedirectResponse(redirect_uri + "?" + urlencode({"code": code, "state": state}), status_code=302)


@app.post("/token")
def token(code: str = Form(), code_verifier: str = Form(), client_id: str = Form(), client_secret: str = Form(""),
          grant_type: str = Form(""), redirect_uri: str = Form("")):
    entry = CODES.pop(code, None)
    if not entry or create_s256_code_challenge(code_verifier) != entry["challenge"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "bad code or PKCE verifier"}, status_code=400)
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "sub-" + entry["email"], "aud": client_id, "exp": now + 300, "iat": now, "nonce": entry["nonce"],
              "email": entry["email"], "name": entry["email"].split("@")[0].title()}
    return {"access_token": "x", "token_type": "Bearer", "id_token": jwt.encode({"alg": "RS256", "kid": "mock-1"}, claims, KEY).decode()}


@app.get("/healthz")
def healthz():
    return {"ok": True}
