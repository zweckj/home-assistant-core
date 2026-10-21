"""Tests for the OpenID Connect config flow."""

from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant.common import MockConfigEntry

from homeassistant.components.auth import IdentityProviderError, ProviderMetadata
from homeassistant.components.openid_connect.const import (
    CONF_ACCOUNTS,
    CONF_ADMIN_GROUP,
    CONF_ALLOW_INSECURE_TRANSPORT,
    CONF_DISPLAY_NAME_CLAIM,
    CONF_ISSUER,
    CONF_REVALIDATE_INTERVAL,
    CONF_SCOPES,
    DOMAIN,
)
from homeassistant.components.openid_connect.identity_provider import (
    get_identity_provider,
)
from homeassistant.config_entries import (
    SOURCE_RECONFIGURE,
    SOURCE_USER,
    ConfigFlowResult,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from .conftest import CLIENT_ID, CLIENT_SECRET, ISSUER

USER_INPUT = {
    CONF_ISSUER: ISSUER,
    CONF_CLIENT_ID: CLIENT_ID,
    CONF_CLIENT_SECRET: CLIENT_SECRET,
}
USER_INPUT_TRAILING_SLASH = {
    CONF_ISSUER: f"{ISSUER}/",
    CONF_CLIENT_ID: CLIENT_ID,
    CONF_CLIENT_SECRET: CLIENT_SECRET,
}
PUBLIC_CLIENT_INPUT = {CONF_ISSUER: ISSUER, CONF_CLIENT_ID: CLIENT_ID}
ADVANCED_INPUT = {
    CONF_ISSUER: "http://idp.example.com",
    CONF_CLIENT_ID: CLIENT_ID,
    CONF_ALLOW_INSECURE_TRANSPORT: True,
}
UPDATED_INPUT = {
    CONF_CLIENT_ID: "updated-client-id",
    CONF_CLIENT_SECRET: "updated-client-secret",
}
UPDATED_DATA = {
    CONF_ISSUER: ISSUER,
    CONF_CLIENT_ID: "updated-client-id",
    CONF_CLIENT_SECRET: "updated-client-secret",
    CONF_ALLOW_INSECURE_TRANSPORT: False,
}
OPTIONS_INPUT = {
    CONF_ACCOUNTS: "link",
    CONF_SCOPES: "openid profile email",
    "account_name_claim": "email",
    "username_claim": "preferred_username",
    CONF_DISPLAY_NAME_CLAIM: "name",
    CONF_REVALIDATE_INTERVAL: 1440,
}
PROVISION_OPTIONS = {
    **OPTIONS_INPUT,
    CONF_ACCOUNTS: "provision",
    CONF_ADMIN_GROUP: "home-assistant-admins",
    CONF_REVALIDATE_INTERVAL: 60,
}


def _metadata(issuer: str = ISSUER) -> ProviderMetadata:
    """Return provider metadata."""
    return ProviderMetadata(
        issuer=issuer,
        authorization_endpoint=f"{issuer}/authorize",
        token_endpoint=f"{issuer}/token",
        jwks_uri=f"{issuer}/jwks",
    )


def _field_default_is_set(data_schema: Any, field: str) -> bool:
    """Return whether a schema field has a default."""
    key = next(schema_key for schema_key in data_schema.schema if schema_key == field)
    return callable(key.default)


@pytest.fixture(autouse=True)
def mock_discover() -> Generator[AsyncMock]:
    """Mock OIDC discovery."""
    with patch(
        "homeassistant.components.openid_connect.config_flow.async_discover_identity_provider",
        new_callable=AsyncMock,
        return_value=_metadata(),
    ) as mock:
        yield mock


@pytest.fixture(autouse=True)
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


@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
@pytest.mark.parametrize(
    ("user_input", "discovery_url"),
    [
        pytest.param(
            USER_INPUT,
            "https://idp.example.com/.well-known/openid-configuration",
            id="without-trailing-slash",
        ),
        pytest.param(
            USER_INPUT_TRAILING_SLASH,
            "https://idp.example.com/.well-known/openid-configuration",
            id="with-trailing-slash",
        ),
    ],
)
async def test_user_flow_success(
    hass: HomeAssistant,
    mock_discover: AsyncMock,
    mock_validate: AsyncMock,
    user_input: dict[str, str],
    discovery_url: str,
) -> None:
    """Test successful user flows."""
    result = await _start_user_flow(hass)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["description_placeholders"] == {
        "redirect_uris": "- `https://example.com/auth/login_callback`\n"
        "- `http://10.10.10.10:8123/auth/login_callback`"
    }

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], user_input
    )

    data = {
        CONF_ISSUER: ISSUER,
        CONF_CLIENT_ID: CLIENT_ID,
        CONF_CLIENT_SECRET: CLIENT_SECRET,
        CONF_ALLOW_INSECURE_TRANSPORT: False,
    }
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "idp.example.com"
    assert result["data"] == data
    mock_discover.assert_awaited_once_with(
        hass, discovery_url, allow_insecure_transport=False
    )
    mock_validate.assert_awaited_once_with(hass, get_identity_provider(data, {}))


@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_user_flow_public_client(
    hass: HomeAssistant, mock_validate: AsyncMock
) -> None:
    """Test user flow without a client secret."""
    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], PUBLIC_CLIENT_INPUT
    )

    data = {
        CONF_ISSUER: ISSUER,
        CONF_CLIENT_ID: CLIENT_ID,
        CONF_ALLOW_INSECURE_TRANSPORT: False,
    }
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == data
    mock_validate.assert_awaited_once_with(hass, get_identity_provider(data, {}))


@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_user_flow_advanced_insecure_transport(
    hass: HomeAssistant, mock_discover: AsyncMock, mock_validate: AsyncMock
) -> None:
    """Test advanced mode exposes and stores insecure transport."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER, "show_advanced_options": True},
    )

    key = next(
        key
        for key in result["data_schema"].schema
        if key == CONF_ALLOW_INSECURE_TRANSPORT
    )
    assert key == CONF_ALLOW_INSECURE_TRANSPORT

    mock_discover.return_value = _metadata("http://idp.example.com")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], ADVANCED_INPUT
    )

    data = ADVANCED_INPUT.copy()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == data
    mock_validate.assert_awaited_once_with(hass, get_identity_provider(data, {}))


@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_user_flow_issuer_mismatch_recovers(
    hass: HomeAssistant, mock_discover: AsyncMock
) -> None:
    """Test issuer mismatch is reported with the returned issuer, and recovery."""
    result = await _start_user_flow(hass)

    mock_discover.return_value = _metadata("https://other.example.com")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "issuer_mismatch"}
    assert (
        result["description_placeholders"]["reported_issuer"]
        == "https://other.example.com"
    )

    mock_discover.return_value = _metadata()
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.parametrize(
    ("reason", "error"),
    [
        pytest.param("cannot_connect", "cannot_connect", id="cannot-connect"),
        pytest.param("invalid_discovery", "invalid_discovery", id="invalid-discovery"),
        pytest.param("invalid_spec", "invalid_config", id="invalid-config"),
    ],
)
@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_user_flow_discovery_errors_recover(
    hass: HomeAssistant,
    mock_discover: AsyncMock,
    reason: str,
    error: str,
) -> None:
    """Test discovery errors and recovery."""
    result = await _start_user_flow(hass)

    mock_discover.side_effect = [IdentityProviderError(reason), _metadata()]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_user_flow_discovery_unknown_recovers(
    hass: HomeAssistant, mock_discover: AsyncMock
) -> None:
    """Test unexpected discovery errors and recovery."""
    result = await _start_user_flow(hass)

    mock_discover.side_effect = [Exception("Boom"), _metadata()]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "unknown"}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.parametrize(
    ("reason", "error"),
    [
        pytest.param("cannot_connect", "cannot_connect", id="cannot-connect"),
        pytest.param("invalid_discovery", "invalid_discovery", id="invalid-discovery"),
        pytest.param("invalid_client_id", "invalid_config", id="invalid-config"),
    ],
)
@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_user_flow_validation_errors_recover(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
    reason: str,
    error: str,
) -> None:
    """Test validation errors and recovery."""
    result = await _start_user_flow(hass)

    mock_validate.side_effect = [IdentityProviderError(reason), None]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_user_flow_validation_unknown_recovers(
    hass: HomeAssistant, mock_validate: AsyncMock
) -> None:
    """Test unexpected validation errors and recovery."""
    result = await _start_user_flow(hass)

    mock_validate.side_effect = [Exception("Boom"), None]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "unknown"}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_user_flow_already_configured(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test user flow aborts when the issuer is already configured."""
    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    assert mock_config_entry.unique_id == ISSUER


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


@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_reconfigure_success(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_validate: AsyncMock
) -> None:
    """Test reconfigure success."""
    result = await mock_config_entry.start_reconfigure_flow(hass)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    assert result["description_placeholders"] == {CONF_ISSUER: ISSUER}
    assert not _field_default_is_set(result["data_schema"], CONF_CLIENT_SECRET)

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], UPDATED_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert mock_config_entry.data == UPDATED_DATA
    mock_validate.assert_awaited_once_with(
        hass, get_identity_provider(UPDATED_DATA, mock_config_entry.options)
    )


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
@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_reconfigure_error_recovers(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_validate: AsyncMock,
    side_effect: Exception,
    error: str,
) -> None:
    """Test reconfigure errors and recovery."""
    result = await mock_config_entry.start_reconfigure_flow(hass)

    mock_validate.side_effect = [side_effect, None]
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


@pytest.mark.usefixtures("oidc_auth")
async def test_options_success(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_validate: AsyncMock
) -> None:
    """Test options success."""
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], OPTIONS_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == OPTIONS_INPUT
    mock_validate.assert_awaited_once_with(
        hass, get_identity_provider(mock_config_entry.data, OPTIONS_INPUT)
    )


@pytest.mark.usefixtures("oidc_auth")
async def test_options_invalid_scopes_recovers(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_validate: AsyncMock
) -> None:
    """Test options map invalid scopes and recover."""
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)

    mock_validate.side_effect = [IdentityProviderError("invalid_scopes"), None]
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {**OPTIONS_INPUT, CONF_SCOPES: "profile email"}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_scopes"}

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], OPTIONS_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.usefixtures("oidc_auth")
async def test_options_provision_stores_interval(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_validate: AsyncMock
) -> None:
    """Test provision options store the revalidation interval."""
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], PROVISION_OPTIONS
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == PROVISION_OPTIONS
    mock_validate.assert_awaited_once_with(
        hass, get_identity_provider(mock_config_entry.data, PROVISION_OPTIONS)
    )


@pytest.mark.usefixtures("oidc_auth", "mock_setup_entry")
async def test_reconfigure_advanced_public_client(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_validate: AsyncMock
) -> None:
    """Test advanced reconfigure can switch to a public insecure client."""
    # The helper can't start the flow with advanced options.
    # pylint: disable-next=home-assistant-test-flow-start-helper
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={
            "source": SOURCE_RECONFIGURE,
            "entry_id": mock_config_entry.entry_id,
            "show_advanced_options": True,
        },
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_CLIENT_ID: "public-client",
            CONF_CLIENT_SECRET: "",
            CONF_ALLOW_INSECURE_TRANSPORT: True,
        },
    )

    data = {
        CONF_ISSUER: ISSUER,
        CONF_CLIENT_ID: "public-client",
        CONF_ALLOW_INSECURE_TRANSPORT: True,
    }
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert dict(mock_config_entry.data) == data
    mock_validate.assert_awaited_once_with(
        hass, get_identity_provider(data, mock_config_entry.options)
    )


@pytest.mark.usefixtures("oidc_auth")
async def test_options_unknown_recovers(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_validate: AsyncMock
) -> None:
    """Test unexpected options errors and recovery."""
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)

    mock_validate.side_effect = [Exception("Boom"), None]
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], OPTIONS_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "unknown"}

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], OPTIONS_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
