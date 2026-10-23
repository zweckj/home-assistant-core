"""Test the OIDC protocol clients."""

from typing import Any

import pytest
from pytest_homeassistant.test_util.aiohttp import AiohttpClientMocker

from homeassistant.auth.providers.oidc.client import (
    OidcClient,
    OidcDiscoveryError,
    async_discover,
)
from homeassistant.core import HomeAssistant

ISSUER = "https://idp.example.com"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
CLIENT_ID = "home-assistant"


def discovery_document(**overrides: Any) -> dict[str, Any]:
    """Return a discovery document."""
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
    } | overrides


async def test_async_discover_does_not_compare_issuer(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test standalone discovery validates metadata without issuer binding."""
    aioclient_mock.get(
        DISCOVERY_URL, json=discovery_document(issuer="https://other.example.com")
    )

    metadata = await async_discover(hass, DISCOVERY_URL)

    assert metadata.issuer == "https://other.example.com"


async def test_oidc_metadata_refuses_redirects(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test OIDC discovery redirects are refused."""
    aioclient_mock.get(
        DISCOVERY_URL, status=302, headers={"Location": "https://evil.example.com"}
    )
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="redirects"):
        await client.async_metadata()


def test_oidc_client_requires_an_https_issuer(hass: HomeAssistant) -> None:
    """Test the client refuses an issuer reached over plain HTTP."""
    with pytest.raises(OidcDiscoveryError, match="must be an https URL"):
        OidcClient(hass, issuer="http://idp.example.com", client_id=CLIENT_ID)


