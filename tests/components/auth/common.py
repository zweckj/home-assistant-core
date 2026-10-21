"""Helpers for testing identity provider integrations.

Usage guide:

1. Create a fake provider with the test ``aioclient_mock`` fixture.
2. Return an ``IdentityProvider`` spec from the integration platform.
3. Add and load a ``MockConfigEntry`` for the integration.
4. Call ``async_link`` to link an existing Home Assistant user.
5. Call ``async_sign_in`` to drive the real browser sign-in flow.

The helpers exercise the actual Home Assistant auth HTTP endpoints and the
audited OIDC/OAuth2 engine; integrations only need to provide their spec.
"""

from collections.abc import Mapping
from dataclasses import dataclass
import json
import time
from typing import Any
from unittest.mock import patch

from aiohttp.test_utils import TestClient
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from jwt.algorithms import RSAAlgorithm
from pytest_homeassistant.common import CLIENT_ID, CLIENT_REDIRECT_URI
from pytest_homeassistant.test_util.aiohttp import (
    AiohttpClientMocker,
    AiohttpClientMockResponse,
)
from yarl import URL

from homeassistant.auth.const import LOGIN_CALLBACK_PATH
from homeassistant.auth.providers.oidc import IdentityProvider, ProtocolSpec
from homeassistant.auth.providers.oidc.client import (
    OAuth2IdentityClient,
    async_bearer_get,
)
from homeassistant.core import HomeAssistant

_KEY_ID = "test-key"
_SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks() -> dict[str, Any]:
    """Return the fake provider key set."""
    key = json.loads(RSAAlgorithm.to_jwk(_SIGNING_KEY.public_key()))
    key |= {"kid": _KEY_ID, "alg": "RS256", "use": "sig"}
    return {"keys": [key]}


@dataclass
class _NextToken:
    nonce: str | None
    claims: dict[str, Any]


class FakeOpenIDProvider:
    """Fake OpenID Provider that serves discovery, JWKS and token responses."""

    def __init__(
        self,
        aioclient_mock: AiohttpClientMocker,
        issuer: str,
        *,
        client_id: str = CLIENT_ID,
        discovery_url: str | None = None,
        authorization_endpoint: str | None = None,
        token_endpoint: str | None = None,
        jwks_uri: str | None = None,
        userinfo_endpoint: str | None = None,
    ) -> None:
        """Initialize the provider and register HTTP mocks."""
        self.issuer = issuer
        self.client_id = client_id
        self.discovery_url = (
            discovery_url or f"{issuer}/.well-known/openid-configuration"
        )
        self.authorization_endpoint = authorization_endpoint or f"{issuer}/authorize"
        self.token_endpoint = token_endpoint or f"{issuer}/token"
        self.jwks_uri = jwks_uri or f"{issuer}/jwks"
        self.userinfo_endpoint = userinfo_endpoint or f"{issuer}/userinfo"
        self._next_token: _NextToken | None = None
        aioclient_mock.get(self.discovery_url, json=self.discovery_document())
        aioclient_mock.get(self.jwks_uri, json=_jwks())
        aioclient_mock.post(self.token_endpoint, side_effect=self._async_token)

    def discovery_document(self) -> dict[str, Any]:
        """Return the discovery document."""
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "jwks_uri": self.jwks_uri,
            "userinfo_endpoint": self.userinfo_endpoint,
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def set_next_token(self, *, nonce: str, **claims: Any) -> None:
        """Set the ID token claims returned by the next token request."""
        self._next_token = _NextToken(nonce, claims)

    def make_id_token(
        self,
        *,
        nonce: str | None = None,
        iss: str | None = None,
        **claims: Any,
    ) -> str:
        """Return a signed ID token."""
        now = int(time.time())
        token_claims: dict[str, Any] = {
            "iss": iss or self.issuer,
            "sub": "user-1234",
            "aud": self.client_id,
            "exp": now + 3600,
            "iat": now,
            "nonce": nonce,
            "preferred_username": "alice",
            "name": "Alice",
        } | claims
        return jwt.encode(
            {key: value for key, value in token_claims.items() if value is not None},
            _SIGNING_KEY,
            algorithm="RS256",
            headers={"kid": _KEY_ID},
        )

    async def _async_token(
        self, method: str, url: URL, data: Any
    ) -> AiohttpClientMockResponse:
        """Return the queued token response."""
        token = self._next_token or _NextToken(None, {})
        self._next_token = None
        return AiohttpClientMockResponse(
            method=method,
            url=url,
            json={
                "access_token": "idp-access-token",
                "id_token": self.make_id_token(nonce=token.nonce, **token.claims),
                "refresh_token": "idp-refresh-token",
                "token_type": "Bearer",
            },
        )


PROFILE_ISSUER = "https://api.profile.example.com"
PROFILE_AUTHORIZE_URL = "https://profile.example.com/authorize"
PROFILE_TOKEN_URL = "https://profile.example.com/token"
PROFILE_URL = "https://api.profile.example.com/user"


class ProfileClient(OAuth2IdentityClient):
    """OAuth2 client that reads the account from a profile endpoint."""

    async def async_fetch_identity(self, access_token: str) -> tuple[str, str | None]:
        """Return the subject and account name from the profile."""
        body = await async_bearer_get(
            self.hass,
            PROFILE_URL,
            access_token,
            endpoint="profile",
            fetching="the profile",
            headers={"X-Api-Version": "1"},
        )
        return str(body["id"]), body.get("login")


@dataclass(frozen=True, slots=True, kw_only=True)
class ProfileProtocol(ProtocolSpec):
    """Protocol of an identity provider without OpenID Connect."""

    scopes: tuple[str, ...] = ()

    def create_client(
        self, hass: HomeAssistant, spec: IdentityProvider
    ) -> ProfileClient:
        """Return the profile client."""
        return ProfileClient(
            hass,
            issuer=PROFILE_ISSUER,
            authorize_url=PROFILE_AUTHORIZE_URL,
            token_url=PROFILE_TOKEN_URL,
            client_id=spec.client_id,
            client_secret=spec.client_secret,
            scopes=self.scopes,
            token_auth_method="client_secret_post",
            allow_insecure_transport=spec.allow_insecure_transport,
        )


class FakeOAuth2ProfileProvider:
    """Fake OAuth2 provider that serves token and profile endpoint responses."""

    def __init__(
        self,
        aioclient_mock: AiohttpClientMocker,
        *,
        authorize_url: str,
        token_url: str,
        profile_url: str,
        profile: Mapping[str, Any] | None = None,
    ) -> None:
        """Initialize the provider and register HTTP mocks."""
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.profile_url = profile_url
        self.profile = dict(profile or {"id": "user-1234", "login": "alice"})
        aioclient_mock.post(
            self.token_url,
            json={"access_token": "profile-access-token", "token_type": "Bearer"},
        )
        aioclient_mock.get(self.profile_url, side_effect=self._async_profile)

    def set_profile(self, **profile: Any) -> None:
        """Set the profile endpoint response."""
        self.profile = profile

    async def _async_profile(
        self, method: str, url: URL, data: Any
    ) -> AiohttpClientMockResponse:
        """Return the current profile response."""
        return AiohttpClientMockResponse(method=method, url=url, json=self.profile)


def _state_and_nonce(url: str) -> tuple[str, str | None]:
    """Return the state and optional nonce from an external step URL."""
    parsed = URL(url)
    return parsed.query["state"], parsed.query.get("nonce")


async def _start_flow(
    client: TestClient, idp_id: str, *, access_token: str | None
) -> tuple[str, str | None]:
    """Start a login or link flow and return state and nonce."""
    payload = {
        "client_id": CLIENT_ID,
        "handler": ["oidc", idp_id],
        "redirect_uri": CLIENT_REDIRECT_URI,
    }
    headers = None
    if access_token is not None:
        payload["type"] = "link_user"
        headers = {"authorization": "Bearer " + access_token}
    with patch(
        "homeassistant.auth.providers.oidc.get_url",
        return_value="https://ha.example.com",
    ):
        resp = await client.post("/auth/login_flow", json=payload, headers=headers)
    assert resp.status == 200
    step = await resp.json()
    assert step["type"] == "external"
    return _state_and_nonce(step["url"])


async def _finish_flow(client: TestClient, state: str) -> dict[str, Any]:
    """Complete the browser callback and finish the flow."""
    resp = await client.get(
        f"{LOGIN_CALLBACK_PATH}?code=the-code&state={state}",
        allow_redirects=False,
    )
    assert resp.status == 302
    flow_id = URL(resp.headers["location"]).query["flow_id"]
    resp = await client.post(
        f"/auth/login_flow/{flow_id}", json={"client_id": CLIENT_ID}
    )
    assert resp.status == 200
    return await resp.json()


async def async_sign_in(
    client: TestClient,
    idp_id: str,
    fake: FakeOpenIDProvider | FakeOAuth2ProfileProvider,
    **claims: Any,
) -> dict[str, Any]:
    """Drive a real identity provider sign-in flow and return the final flow JSON."""
    state, nonce = await _start_flow(client, idp_id, access_token=None)
    if isinstance(fake, FakeOpenIDProvider):
        assert nonce is not None
        fake.set_next_token(nonce=nonce, **claims)
    elif claims:
        fake.set_profile(**claims)
    return await _finish_flow(client, state)


async def async_link(
    client: TestClient,
    idp_id: str,
    fake: FakeOpenIDProvider | FakeOAuth2ProfileProvider,
    access_token: str,
    **claims: Any,
) -> dict[str, Any]:
    """Drive a real identity provider link flow and return the link response JSON."""
    state, nonce = await _start_flow(client, idp_id, access_token=access_token)
    if isinstance(fake, FakeOpenIDProvider):
        assert nonce is not None
        fake.set_next_token(nonce=nonce, **claims)
    elif claims:
        fake.set_profile(**claims)
    step = await _finish_flow(client, state)
    resp = await client.post(
        "/auth/link_user",
        json={"client_id": CLIENT_ID, "code": step["result"]},
        headers={"authorization": "Bearer " + access_token},
    )
    assert resp.status == 200
    return await resp.json()
