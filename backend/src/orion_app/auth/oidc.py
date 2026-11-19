from __future__ import annotations
# Adapted from LCIT-Sign (GPL-3.0).

import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

import httpx
from authlib.common.security import generate_token
from authlib.jose import JsonWebKey
from authlib.jose import jwt as jose_jwt
from authlib.jose.errors import JoseError
from authlib.oauth2.rfc7636 import create_s256_code_challenge


class OidcError(Exception):
    """Raised on any discovery, exchange or ID-token validation failure.

    Deliberately generic to the caller: the HTTP layer turns every instance
    into the same 400 response, never echoing provider internals back to
    the browser.
    """


@dataclass(frozen=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


@dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    state: str
    nonce: str
    code_verifier: str


@dataclass(frozen=True)
class IdentityClaims:
    subject: str
    issuer: str
    email: str
    given_name: str
    family_name: str
    name: str
    extra: dict[str, object] = field(default_factory=dict)   # tid / hd / email_verified: what provider-specific rules check


_metadata_cache: dict[str, tuple[float, ProviderMetadata]] = {}
_METADATA_TTL_SECONDS = 3600


async def discover_provider(issuer: str) -> ProviderMetadata:
    cached = _metadata_cache.get(issuer)
    if cached and cached[0] > time.monotonic():
        return cached[1]

    issuer_parts = urlsplit(issuer)
    local_http_issuer = issuer_parts.scheme == "http" and issuer_parts.hostname in {
        "localhost", "127.0.0.1", "::1", "mock-oidc",
    }
    if (not issuer_parts.hostname or issuer_parts.username or issuer_parts.password or issuer_parts.query or issuer_parts.fragment
            or (issuer_parts.scheme != "https" and not local_http_issuer)):
        raise OidcError("The configured issuer URL is invalid or insecure")
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(url)
    if response.status_code != 200:
        raise OidcError(f"OIDC discovery failed for issuer {issuer!r}")
    data = response.json()
    try:
        metadata = ProviderMetadata(
            issuer=data["issuer"],
            authorization_endpoint=data["authorization_endpoint"],
            token_endpoint=data["token_endpoint"],
            jwks_uri=data["jwks_uri"],
        )
    except KeyError as exc:
        raise OidcError("OIDC discovery document is missing a required field") from exc

    # OIDC requires the ID token issuer to match the issuer identifier in the
    # discovery document. Do not silently let the document replace the issuer
    # the administrator configured.
    if metadata.issuer != issuer:
        raise OidcError("OIDC discovery issuer does not match the configured issuer")
    for endpoint in (metadata.authorization_endpoint, metadata.token_endpoint, metadata.jwks_uri):
        endpoint_parts = urlsplit(endpoint)
        if (not endpoint_parts.hostname or endpoint_parts.username or endpoint_parts.password
                or endpoint_parts.scheme != ("http" if local_http_issuer else "https")):
            raise OidcError("OIDC discovery contains an invalid or insecure endpoint")

    _metadata_cache[issuer] = (time.monotonic() + _METADATA_TTL_SECONDS, metadata)
    return metadata


def build_authorization_request(
    metadata: ProviderMetadata, *, client_id: str, redirect_uri: str, extra_params: dict[str, str] | None = None
) -> AuthorizationRequest:
    state = generate_token(32)
    nonce = generate_token(32)
    code_verifier = generate_token(64)
    code_challenge = create_s256_code_challenge(code_verifier)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        **(extra_params or {}),
    }
    url = metadata.authorization_endpoint + "?" + urlencode(params)
    return AuthorizationRequest(url=url, state=state, nonce=nonce, code_verifier=code_verifier)


async def exchange_code(
    metadata: ProviderMetadata,
    *,
    code: str,
    redirect_uri: str,
    client_id: str,
    client_secret: str,
    code_verifier: str,
    expected_nonce: str,
) -> IdentityClaims:
    async with httpx.AsyncClient(timeout=10) as client:
        token_response = await client.post(
            metadata.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
                "code_verifier": code_verifier,
            },
        )
        if token_response.status_code != 200:
            raise OidcError(f"Token exchange failed: {_provider_error(token_response)}")
        token_data = token_response.json()
        id_token = token_data.get("id_token")
        if not id_token:
            raise OidcError("Token response is missing id_token")

        jwks_response = await client.get(metadata.jwks_uri)
        if jwks_response.status_code != 200:
            raise OidcError("Failed to fetch provider JWKS")
        key_set = JsonWebKey.import_key_set(jwks_response.json())

    try:
        claims = jose_jwt.decode(
            id_token,
            key_set,
            claims_options={
                "iss": {"values": [metadata.issuer]},
                "aud": {"values": [client_id]},
            },
        )
        claims.validate()
    except JoseError as exc:
        raise OidcError(f"Invalid ID token: {exc}") from exc

    if claims.get("nonce") != expected_nonce:
        raise OidcError("ID token nonce does not match the login attempt")

    return identity_from_claims(dict(claims), default_issuer=metadata.issuer)


def _provider_error(response: httpx.Response) -> str:
    """The provider's own error (code and description, never a secret), for logs and audit."""
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    description = " ".join(str(body.get("error_description", "")).split())[:300]
    return f"HTTP {response.status_code} {body.get('error', '')}: {description}"


def _looks_like_email(value: object) -> bool:
    return isinstance(value, str) and "@" in value and " " not in value.strip()


def identity_from_claims(claims: dict[str, object], *, default_issuer: str) -> IdentityClaims:
    """Read who the person is from validated ID-token claims.

    Providers differ. Keycloak and the mock send `email`, `given_name` and
    `family_name`. Microsoft Entra ID's v2.0 tokens carry `name` and
    `preferred_username` (the sign-in name, normally the mailbox) but `email`
    only when configured as an optional claim and never `given_name` /
    `family_name` by default. So: take `email` when present, otherwise the
    sign-in name when it is an address; split a full name when the parts are
    missing. A login with no usable address is refused rather than creating an
    account the directory could never reconcile.
    """
    subject = str(claims.get("sub") or "")
    if not subject:
        raise OidcError("ID token is missing a subject")

    email = ""
    for candidate in (claims.get("email"), claims.get("preferred_username"), claims.get("upn")):
        if _looks_like_email(candidate):
            email = str(candidate).strip()
            break
    if not email:
        raise OidcError("ID token carries no e-mail address (add the 'email' claim)")

    name = str(claims.get("name") or "").strip()
    given = str(claims.get("given_name") or "").strip()
    family = str(claims.get("family_name") or "").strip()
    if name and not (given or family):
        given, _, family = name.partition(" ")

    return IdentityClaims(
        subject=subject,
        issuer=str(claims.get("iss") or default_issuer),
        email=email,
        given_name=given,
        family_name=family,
        name=name,
        extra={k: claims[k] for k in ("tid", "hd", "email_verified") if k in claims},
    )
