"""Tests for the Google Sign-In config flow."""

from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.auth.providers.oidc.spec import (
    AccountPolicy,
    IdentityProviderError,
    OpenIDConnect,
)
from homeassistant.components.google_sign_in.const import DOMAIN
from homeassistant.components.google_sign_in.identity_provider import _identity_provider
from homeassistant.config_entries import (
    SOURCE_RECONFIGURE,
    SOURCE_USER,
    ConfigFlowResult,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from tests.common import MockConfigEntry, get_schema_suggested_value

USER_INPUT = {CONF_CLIENT_ID: "client-id", CONF_CLIENT_SECRET: "client-secret"}
UPDATED_INPUT = {
    CONF_CLIENT_ID: "updated-client-id",
    CONF_CLIENT_SECRET: "updated-client-secret",
}


@pytest.fixture
def mock_validate() -> Generator[AsyncMock]:
    """Mock identity provider validation."""
    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_validate_identity_provider",
        new_callable=AsyncMock,
    ) as mock:
        yield mock


async def _start_user_flow(hass: HomeAssistant) -> ConfigFlowResult:
    """Start a user config flow."""
    return await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )


@pytest.mark.usefixtures("oidc_auth", "redirect_url", "mock_setup_entry")
async def test_user_flow_success(hass: HomeAssistant, mock_validate: AsyncMock) -> None:
    """Test a successful user flow."""
    result = await _start_user_flow(hass)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["description_placeholders"] == {
        "console_url": "https://console.cloud.google.com/apis/credentials",
        "redirect_uris": "- `https://example.com/auth/login_callback`\n"
        "- `http://10.10.10.10:8123/auth/login_callback`",
    }

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Google"
    assert result["data"] == USER_INPUT
    mock_validate.assert_awaited_once_with(hass, _identity_provider(USER_INPUT, {}))


@pytest.mark.parametrize(
    ("reason", "error"),
    [
        pytest.param("cannot_connect", "cannot_connect", id="cannot-connect"),
        pytest.param("invalid_discovery", "invalid_discovery", id="invalid-discovery"),
        pytest.param("invalid_client_id", "invalid_config", id="invalid-config"),
    ],
)
@pytest.mark.usefixtures("oidc_auth", "redirect_url", "mock_setup_entry")
async def test_user_flow_identity_provider_errors_recover(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
    reason: str,
    error: str,
) -> None:
    """Test identity provider validation errors and recovery."""
    result = await _start_user_flow(hass)

    mock_validate.side_effect = [
        IdentityProviderError(reason),
        _identity_provider(USER_INPUT, {}),
    ]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Google"
    assert result["data"] == USER_INPUT


@pytest.mark.usefixtures("oidc_auth", "redirect_url", "mock_setup_entry")
async def test_user_flow_unknown_error_recovers(
    hass: HomeAssistant, mock_validate: AsyncMock
) -> None:
    """Test unexpected validation errors and recovery."""
    result = await _start_user_flow(hass)

    mock_validate.side_effect = [Exception("Boom"), _identity_provider(USER_INPUT, {})]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "unknown"}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Google"
    assert result["data"] == USER_INPUT


@pytest.mark.usefixtures("oidc_auth", "redirect_url")
async def test_user_flow_single_instance_allowed(hass: HomeAssistant) -> None:
    """Test user flow aborts when an entry already exists."""
    MockConfigEntry(domain=DOMAIN, data=USER_INPUT).add_to_hass(hass)

    result = await _start_user_flow(hass)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "single_instance_allowed"


@pytest.mark.usefixtures("redirect_url")
async def test_user_flow_identity_providers_disabled(hass: HomeAssistant) -> None:
    """Test user flow aborts when identity providers are disabled."""
    result = await _start_user_flow(hass)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "identity_providers_disabled"


@pytest.mark.usefixtures("oidc_auth")
async def test_user_flow_no_url_available(hass: HomeAssistant) -> None:
    """Test user flow aborts when no redirect URL is available."""
    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_get_redirect_uris",
        return_value=[],
    ):
        result = await _start_user_flow(hass)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_url_available"


@pytest.mark.usefixtures("oidc_auth", "redirect_url", "mock_setup_entry")
async def test_reconfigure_success(
    hass: HomeAssistant, mock_validate: AsyncMock
) -> None:
    """Test reconfigure success."""
    entry = MockConfigEntry(domain=DOMAIN, title="Google", data=USER_INPUT)
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    schema = result["data_schema"].schema
    assert get_schema_suggested_value(schema, CONF_CLIENT_ID) == "client-id"
    assert get_schema_suggested_value(schema, CONF_CLIENT_SECRET) is None

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], UPDATED_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert entry.data == UPDATED_INPUT
    mock_validate.assert_awaited_once_with(hass, _identity_provider(UPDATED_INPUT, {}))


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        pytest.param(
            IdentityProviderError("cannot_connect"),
            "cannot_connect",
            id="cannot-connect",
        ),
        pytest.param(
            IdentityProviderError("invalid_discovery"),
            "invalid_discovery",
            id="invalid-discovery",
        ),
        pytest.param(
            IdentityProviderError("invalid_client_id"),
            "invalid_config",
            id="invalid-config",
        ),
        pytest.param(Exception("Boom"), "unknown", id="unknown"),
    ],
)
@pytest.mark.usefixtures("oidc_auth", "redirect_url", "mock_setup_entry")
async def test_reconfigure_error_recovers(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
    side_effect: Exception,
    error: str,
) -> None:
    """Test reconfigure errors and recovery."""
    entry = MockConfigEntry(domain=DOMAIN, title="Google", data=USER_INPUT)
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
    )

    mock_validate.side_effect = [side_effect, _identity_provider(UPDATED_INPUT, {})]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], UPDATED_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], UPDATED_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert entry.data == UPDATED_INPUT


def test_identity_provider_uses_link_only() -> None:
    """Test Google Sign-In uses link-only OpenID Connect settings."""
    spec = _identity_provider(USER_INPUT, {})

    assert spec.accounts is AccountPolicy.LINK
    assert isinstance(spec.protocol, OpenIDConnect)
    assert spec.protocol.issuer == "https://accounts.google.com"
    assert spec.protocol.issuer_aliases == frozenset({"accounts.google.com"})
    assert spec.protocol.scopes == ("openid", "email")
    assert spec.protocol.account_name_claim == "email"
