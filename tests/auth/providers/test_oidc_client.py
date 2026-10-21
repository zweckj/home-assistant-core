"""Test the OIDC protocol clients."""

from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from pytest_homeassistant.test_util.aiohttp import AiohttpClientMocker

from homeassistant.auth.providers.oidc.client import (
    OAuth2IdentityClient,
    OidcClient,
    OidcDiscoveryError,
    OidcError,
    OidcInvalidGrantError,
    OidcTokenError,
    OidcTransientError,
    async_bearer_get,
    async_discover,
)
from homeassistant.core import HomeAssistant

ISSUER = "https://idp.example.com"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
CLIENT_ID = "home-assistant"
OAUTH2_ISSUER = "https://api.example.com"
AUTHORIZE_URL = f"{ISSUER}/authorize"
TOKEN_URL = f"{ISSUER}/token"
PROFILE_URL = "https://api.example.com/user"
CODE_VERIFIER = "v" * 43


class _OAuth2Client(OAuth2IdentityClient):
    """OAuth2 client with a fixed identity."""

    async def async_fetch_identity(self, access_token: str) -> tuple[str, str | None]:
        """Return a fixed identity."""
        return "subject", None


def _oauth2_client(hass: HomeAssistant, **kwargs: Any) -> _OAuth2Client:
    """Return an OAuth2 client with test endpoints."""
    return _OAuth2Client(
        hass,
        **{
            "issuer": OAUTH2_ISSUER,
            "authorize_url": AUTHORIZE_URL,
            "token_url": TOKEN_URL,
            "client_id": CLIENT_ID,
            "client_secret": "secret",
        }
        | kwargs,
    )


def discovery_document(**overrides: Any) -> dict[str, Any]:
    """Return a discovery document."""
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
    } | overrides


def test_accepts_issuer(hass: HomeAssistant) -> None:
    """Test stored credential issuer matching."""
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    assert client.accepts_issuer(ISSUER)
    assert not client.accepts_issuer("idp.example.com")


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


def test_oauth2_authorize_url(hass: HomeAssistant) -> None:
    """Test the OAuth2 client builds a PKCE authorization URL."""
    client = _oauth2_client(
        hass,
        authorize_url=f"{AUTHORIZE_URL}?prompt=login",
        scopes=("read:user", "user:email"),
    )

    url = client.async_authorize_url(
        redirect_uri="https://ha.example.com/auth/callback",
        state="state",
        code_verifier=CODE_VERIFIER,
    )
    query = parse_qs(urlparse(url).query)

    assert query["prompt"] == ["login"]
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["scope"] == ["read:user user:email"]
    assert query["code_challenge_method"] == ["S256"]


@pytest.mark.parametrize(
    ("client_secret", "token_auth_method", "expected_body", "has_auth"),
    [
        pytest.param("secret", "client_secret_basic", {}, True, id="basic"),
        pytest.param(
            "secret",
            "client_secret_post",
            {"client_id": CLIENT_ID, "client_secret": "secret"},
            False,
            id="post",
        ),
        pytest.param(
            None, "client_secret_basic", {"client_id": CLIENT_ID}, False, id="public"
        ),
    ],
)
async def test_oauth2_exchange_auth_methods(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    client_secret: str | None,
    token_auth_method: str,
    expected_body: dict[str, str],
    has_auth: bool,
) -> None:
    """Test supported token endpoint client authentication methods."""
    aioclient_mock.post(TOKEN_URL, json={"access_token": "at", "token_type": "Bearer"})
    client = _oauth2_client(
        hass, client_secret=client_secret, token_auth_method=token_auth_method
    )

    tokens = await client.async_exchange_code(
        code="code",
        redirect_uri="https://ha.example.com/cb",
        code_verifier=CODE_VERIFIER,
    )

    assert tokens.access_token == "at"
    assert expected_body.items() <= aioclient_mock.mock_calls[-1][2].items()
    assert ("Authorization" in aioclient_mock.mock_calls[-1][3]) is has_auth
    assert aioclient_mock.mock_calls[-1][3]["Accept"] == "application/json"


@pytest.mark.parametrize(
    ("status", "body", "error"),
    [
        pytest.param(
            200, {"error": "bad_verification_code"}, OidcTokenError, id="ok-error"
        ),
        pytest.param(
            400, {"error": "invalid_grant"}, OidcInvalidGrantError, id="invalid-grant"
        ),
        pytest.param(
            200, {"access_token": "at", "token_type": "mac"}, OidcTokenError, id="mac"
        ),
        pytest.param(503, {}, OidcTransientError, id="transient"),
    ],
)
async def test_oauth2_exchange_errors(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    status: int,
    body: dict[str, str],
    error: type[OidcError],
) -> None:
    """Test token endpoint failures are mapped to OIDC errors."""
    aioclient_mock.post(TOKEN_URL, status=status, json=body)
    client = _oauth2_client(hass)

    with pytest.raises(error):
        await client.async_exchange_code(
            code="code",
            redirect_uri="https://ha.example.com/cb",
            code_verifier=CODE_VERIFIER,
        )


async def test_oauth2_exchange_refuses_redirects(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test token endpoint redirects are refused."""
    aioclient_mock.post(
        TOKEN_URL, status=307, headers={"Location": "https://evil.example.com"}
    )
    client = _oauth2_client(hass)

    with pytest.raises(OidcTokenError, match="307"):
        await client.async_exchange_code(
            code="code",
            redirect_uri="https://ha.example.com/cb",
            code_verifier=CODE_VERIFIER,
        )


@pytest.mark.parametrize("url_field", ["issuer", "authorize_url", "token_url"])
def test_oauth2_rejects_insecure_urls(hass: HomeAssistant, url_field: str) -> None:
    """Test OAuth2 endpoint URLs have to be HTTPS."""
    with pytest.raises(OidcDiscoveryError, match="https"):
        _oauth2_client(hass, **{url_field: "http://api.example.com/plain"})


def test_oauth2_allows_insecure_transport(hass: HomeAssistant) -> None:
    """Test an administrator can allow plain HTTP endpoints."""
    client = _oauth2_client(
        hass,
        issuer="http://api.example.com",
        authorize_url="http://idp.example.com/authorize",
        token_url="http://idp.example.com/token",
        allow_insecure_transport=True,
    )

    assert client.accepts_issuer("http://api.example.com")
    assert not client.accepts_issuer(OAUTH2_ISSUER)


async def test_bearer_get_sends_the_token_and_headers(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test bearer requests carry the access token and the caller's headers."""
    aioclient_mock.get(PROFILE_URL, json={"id": 1})

    body = await async_bearer_get(
        hass,
        PROFILE_URL,
        "token",
        endpoint="profile",
        fetching="the profile",
        headers={"X-Api-Version": "1"},
    )

    assert body == {"id": 1}
    assert aioclient_mock.mock_calls[-1][3]["Authorization"] == "Bearer token"
    assert aioclient_mock.mock_calls[-1][3]["X-Api-Version"] == "1"


async def test_bearer_get_refuses_redirects(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test bearer requests do not follow redirects."""
    aioclient_mock.get(
        PROFILE_URL, status=302, headers={"Location": "https://evil.example.com"}
    )

    with pytest.raises(OidcError, match="redirects"):
        await async_bearer_get(
            hass, PROFILE_URL, "token", endpoint="profile", fetching="the profile"
        )


def test_oidc_client_uses_a_given_discovery_url(hass: HomeAssistant) -> None:
    """Test a client may fetch discovery from elsewhere than its issuer."""
    client = OidcClient(
        hass,
        issuer=ISSUER,
        client_id=CLIENT_ID,
        discovery_url="https://discovery.example.com/openid-configuration",
    )

    assert client.discovery_url == "https://discovery.example.com/openid-configuration"

    with pytest.raises(OidcDiscoveryError, match="must be an https URL"):
        OidcClient(
            hass,
            issuer=ISSUER,
            client_id=CLIENT_ID,
            discovery_url="http://discovery.example.com/openid-configuration",
        )
