"""Test the OpenID Connect auth provider configuration API."""

from typing import Any

import pytest

from homeassistant.auth import models as auth_models
from homeassistant.auth.models import Credentials
from homeassistant.auth.providers.oidc import OidcAuthProvider
from homeassistant.auth.providers.oidc.client import TokenResponse
from homeassistant.auth.providers.oidc.store import OidcConfig
from homeassistant.components.config import auth_provider_oidc
from homeassistant.core import HomeAssistant

from tests.common import CLIENT_ID as TEST_CLIENT_ID, MockUser
from tests.test_util.aiohttp import AiohttpClientMocker
from tests.typing import WebSocketGenerator

ISSUER = "https://idp.example.com"
CLIENT_ID = "home-assistant"
SUBJECT = "user-1234"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"

DISCOVERY_DOCUMENT = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "jwks_uri": f"{ISSUER}/jwks",
    "userinfo_endpoint": f"{ISSUER}/userinfo",
    "scopes_supported": ["openid", "profile", "email"],
    "id_token_signing_alg_values_supported": ["RS256"],
}

MINIMAL_UPDATE = {
    "type": "config/auth_provider/oidc/update",
    "issuer": ISSUER,
    "client_id": CLIENT_ID,
}


@pytest.fixture
async def oidc_provider(hass: HomeAssistant) -> OidcAuthProvider:
    """Load the OpenID Connect auth provider."""
    prv = OidcAuthProvider(hass, hass.auth._store, {"type": "oidc"})
    await prv.async_initialize()
    hass.auth._providers[(prv.type, prv.id)] = prv
    return prv


@pytest.fixture(autouse=True)
def setup_config(hass: HomeAssistant, oidc_provider: OidcAuthProvider) -> None:
    """Set up the configuration API."""
    auth_provider_oidc.async_setup(hass)


async def test_get_without_configuration(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator
) -> None:
    """Test an unconfigured provider reports no configuration."""
    client = await hass_ws_client(hass)
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/get"})

    result = await client.receive_json()

    assert result["success"]
    assert result["result"]["config"] is None


async def test_get_returns_redirect_uris(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator
) -> None:
    """Test the redirect URIs to register are reported."""
    hass.config.internal_url = "http://homeassistant.local:8123"
    hass.config.external_url = "https://ha.example.com"

    client = await hass_ws_client(hass)
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/get"})

    result = await client.receive_json()

    assert result["success"]
    assert result["result"]["redirect_uris"] == [
        "https://ha.example.com/auth/oidc/callback",
        "http://homeassistant.local:8123/auth/oidc/callback",
    ]


async def test_update(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
) -> None:
    """Test storing a configuration."""
    client = await hass_ws_client(hass)
    await client.send_json_auto_id(
        MINIMAL_UPDATE
        | {
            "client_secret": "s3cret",
            "name": "  Contoso ID  ",
            "admin_group": "ha-admins",
            "allow_auto_create": True,
        }
    )

    result = await client.receive_json()

    assert result["success"]
    # The secret is write only, the UI only learns that one is set.
    assert "client_secret" not in result["result"]["config"]
    assert result["result"]["config"]["client_secret_set"] is True
    assert result["result"]["config"]["name"] == "Contoso ID"

    config = oidc_provider.oidc_config
    assert config.client_secret == "s3cret"
    assert config.name == "Contoso ID"
    assert config.admin_group == "ha-admins"
    assert config.allow_auto_create is True
    assert oidc_provider.name == "Contoso ID"


async def test_update_rejects_a_blank_name(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
) -> None:
    """Test a name made of whitespace is refused rather than stored."""
    client = await hass_ws_client(hass)
    await client.send_json_auto_id(MINIMAL_UPDATE | {"name": "   "})

    result = await client.receive_json()

    assert not result["success"]


async def test_update_keeps_secret_when_omitted(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
) -> None:
    """Test saving an unrelated change does not drop the client secret."""
    await oidc_provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, client_secret="s3cret")
    )

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(MINIMAL_UPDATE | {"allow_auto_create": True})

    result = await client.receive_json()

    assert result["success"]
    assert oidc_provider.oidc_config.client_secret == "s3cret"


@pytest.mark.parametrize(
    "overrides",
    [
        {"issuer": "https://other-idp.example.com"},
        {"client_id": "other-client"},
    ],
    ids=["issuer", "client-id"],
)
async def test_update_does_not_reuse_secret_for_another_client(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    overrides: dict[str, str],
) -> None:
    """Test changing client identity cannot disclose the old client secret."""
    await oidc_provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, client_secret="s3cret")
    )

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(MINIMAL_UPDATE | overrides)

    result = await client.receive_json()

    assert result["success"]
    assert oidc_provider.oidc_config.client_secret is None


async def test_update_clears_secret_when_null(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
) -> None:
    """Test a public client can drop a previously stored secret."""
    await oidc_provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, client_secret="s3cret")
    )

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(MINIMAL_UPDATE | {"client_secret": None})

    result = await client.receive_json()

    assert result["success"]
    assert oidc_provider.oidc_config.client_secret is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"issuer": "http://idp.example.com"},
        {"issuer": "idp.example.com"},
        {"issuer": "https://"},
        {"issuer": "https://user:password@idp.example.com"},
        {"subject_claim": "email"},
        {"scopes": ["profile"]},
        {"revalidate_interval": 10},
    ],
    ids=[
        "plain-http",
        "not-a-url",
        "missing-host",
        "embedded-credentials",
        "custom-subject",
        "without-openid-scope",
        "interval-too-short",
    ],
)
async def test_update_rejects_invalid_configuration(
    hass: HomeAssistant, hass_ws_client: WebSocketGenerator, overrides: dict[str, Any]
) -> None:
    """Test unusable configurations are refused."""
    client = await hass_ws_client(hass)
    await client.send_json_auto_id(MINIMAL_UPDATE | overrides)

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "invalid_format"


async def test_delete(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
) -> None:
    """Test removing the configuration."""
    await oidc_provider.async_set_config(OidcConfig(issuer=ISSUER, client_id=CLIENT_ID))

    client = await hass_ws_client(hass)
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/delete"})

    result = await client.receive_json()

    assert result["success"]
    assert not oidc_provider.is_configured


async def test_test_reports_discovery(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test probing an identity provider before saving."""
    aioclient_mock.get(DISCOVERY_URL, json=DISCOVERY_DOCUMENT)

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(
        {
            "type": "config/auth_provider/oidc/test",
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
        }
    )

    result = await client.receive_json()

    assert result["success"]
    assert result["result"]["token_endpoint"] == f"{ISSUER}/token"
    assert result["result"]["scopes_supported"] == ["openid", "profile", "email"]


async def test_test_reports_failure(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test a broken identity provider is reported back to the UI."""
    aioclient_mock.get(DISCOVERY_URL, status=404)

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(
        {
            "type": "config/auth_provider/oidc/test",
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
        }
    )

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "discovery_failed"


@pytest.mark.parametrize(
    "command",
    [
        {"type": "config/auth_provider/oidc/get"},
        {"type": "config/auth_provider/oidc/delete"},
        MINIMAL_UPDATE,
        {
            "type": "config/auth_provider/oidc/test",
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
        },
    ],
    ids=["get", "delete", "update", "test"],
)
async def test_requires_admin(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    hass_read_only_access_token: str,
    command: dict[str, Any],
) -> None:
    """Test configuring the provider is reserved for administrators."""
    client = await hass_ws_client(hass, hass_read_only_access_token)
    await client.send_json_auto_id(command)

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "unauthorized"


async def _link(
    hass: HomeAssistant, oidc_provider: OidcAuthProvider, user: auth_models.User
) -> Credentials:
    """Attach an identity provider login to a user."""
    credentials = oidc_provider.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await hass.auth.async_link_user(user, credentials)
    return credentials


async def _give_password(hass: HomeAssistant, user: auth_models.User) -> None:
    """Attach a password login to a user."""
    await hass.auth.async_link_user(
        user,
        Credentials(
            auth_provider_type="homeassistant",
            auth_provider_id=None,
            data={"username": "hello"},
            is_new=False,
        ),
    )


async def test_unlink(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_admin_user: MockUser,
) -> None:
    """Test a user can detach their own identity provider login."""
    await oidc_provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=False)
    )
    credentials = await _link(hass, oidc_provider, hass_admin_user)
    await _give_password(hass, hass_admin_user)

    client = await hass_ws_client(hass)
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/unlink"})

    result = await client.receive_json()

    assert result["success"]
    assert credentials not in hass_admin_user.credentials
    assert await hass.auth.async_get_user_by_credentials(credentials) is None


async def test_unlink_needs_another_way_in(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
) -> None:
    """Test a user cannot remove the only login they have."""
    await oidc_provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=False)
    )
    user = await hass.auth.async_create_user("Alice")
    credentials = await _link(hass, oidc_provider, user)
    await oidc_provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=TokenResponse(access_token="at"),
    )
    refresh_token = await hass.auth.async_create_refresh_token(
        user, TEST_CLIENT_ID, credential=credentials
    )

    client = await hass_ws_client(
        hass, hass.auth.async_create_access_token(refresh_token)
    )
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/unlink"})

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "no_other_login"
    assert credentials in user.credentials


async def test_unlink_refused_while_auto_create_is_on(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_admin_user: MockUser,
) -> None:
    """Test unlinking is pointless while the next login would link again."""
    await oidc_provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=True)
    )
    await _link(hass, oidc_provider, hass_admin_user)
    await _give_password(hass, hass_admin_user)

    client = await hass_ws_client(hass)
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/unlink"})

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "auto_create_enabled"


async def test_unlink_without_a_linked_account(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_admin_user: MockUser,
) -> None:
    """Test a user with nothing linked is told so."""
    await oidc_provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=False)
    )
    await _give_password(hass, hass_admin_user)

    client = await hass_ws_client(hass)
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/unlink"})

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "not_linked"


async def test_unlink_is_allowed_for_non_admins(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_read_only_user: MockUser,
    hass_read_only_access_token: str,
) -> None:
    """Test detaching your own login does not need administrator rights."""
    await oidc_provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=False)
    )
    # The access token fixture already gives this user a password login.
    credentials = await _link(hass, oidc_provider, hass_read_only_user)

    client = await hass_ws_client(hass, hass_read_only_access_token)
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/unlink"})

    result = await client.receive_json()

    assert result["success"]
    assert credentials not in hass_read_only_user.credentials
