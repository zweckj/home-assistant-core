"""Tests for the identity provider config flow base."""

from collections.abc import Generator, Mapping
from typing import Any
from unittest.mock import AsyncMock, patch

import probatio
import pytest

from homeassistant import data_entry_flow
from homeassistant.components.auth import (
    IdentityProvider,
    IdentityProviderConfigFlow,
    IdentityProviderError,
    IdentityProviderFlowError,
    IdentityProviderSetup,
    OpenIDConnect,
)
from homeassistant.config_entries import SOURCE_USER, ConfigFlowResult
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from tests.common import (
    MockConfigEntry,
    MockModule,
    get_schema_suggested_value,
    mock_config_flow,
    mock_integration,
    mock_platform,
)

DOMAIN = "test_idp_flow"
ISSUER = "https://idp.example.com"
CONF_SCOPES = "scopes"
USER_INPUT = {CONF_CLIENT_ID: "client-id", CONF_CLIENT_SECRET: "client-secret"}
PUBLIC_INPUT = {CONF_CLIENT_ID: "client-id", CONF_CLIENT_SECRET: ""}
UPDATED_INPUT = {CONF_CLIENT_ID: "new-client-id", CONF_CLIENT_SECRET: "new-secret"}
OPTIONS_INPUT = {CONF_SCOPES: "openid profile"}
REDIRECT_URIS = "- `https://example.com/auth/login_callback`"

DATA_SCHEMA = probatio.Schema(
    {
        probatio.Required(CONF_CLIENT_ID): str,
        probatio.Optional(CONF_CLIENT_SECRET): str,
    }
)
OPTIONS_SCHEMA = probatio.Schema(
    {probatio.Required(CONF_SCOPES, default="openid"): str}
)


def _identity_provider(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> IdentityProvider:
    """Return the spec of the test integration."""
    return IdentityProvider(
        client_id=data[CONF_CLIENT_ID],
        client_secret=data.get(CONF_CLIENT_SECRET),
        protocol=OpenIDConnect(
            issuer=ISSUER, scopes=tuple(options.get(CONF_SCOPES, "openid").split())
        ),
    )


class _Flow(IdentityProviderConfigFlow):
    """Flow storing the form input as entry data."""

    TITLE = "Test IdP"
    DATA_SCHEMA = DATA_SCHEMA
    USER_PLACEHOLDERS = {"console_url": "https://console.example.com"}
    RECONFIGURE_PLACEHOLDERS = (CONF_CLIENT_ID,)
    TRANSLATED_ERRORS = frozenset({"invalid_scopes"})
    identity_provider = staticmethod(_identity_provider)


class _OptionsFlow(_Flow):
    """Flow with options."""

    OPTIONS_SCHEMA = OPTIONS_SCHEMA


class _ResolvingFlow(_Flow):
    """Flow deriving the entry from the form input."""

    async def async_resolve_setup(
        self, user_input: Mapping[str, Any]
    ) -> IdentityProviderSetup:
        """Resolve the entry."""
        return IdentityProviderSetup(
            title="Resolved", unique_id=ISSUER, data={**user_input, "issuer": ISSUER}
        )


@pytest.fixture
def ignore_translations_for_mock_domains() -> list[str]:
    """Skip translation checks for the mock integration."""
    return [DOMAIN]


@pytest.fixture
def flow_class() -> type[IdentityProviderConfigFlow]:
    """Return the flow under test."""
    return _Flow


@pytest.fixture(autouse=True)
def mock_flow(
    hass: HomeAssistant, flow_class: type[IdentityProviderConfigFlow]
) -> Generator[None]:
    """Register the mock integration and its flow."""
    hass.config.external_url = "https://example.com"
    mock_integration(hass, MockModule(DOMAIN, partial_manifest={"config_flow": True}))
    mock_platform(hass, f"{DOMAIN}.config_flow")
    with mock_config_flow(DOMAIN, flow_class):
        yield


@pytest.fixture
def mock_validate() -> Generator[AsyncMock]:
    """Mock identity provider validation."""
    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_validate_identity_provider",
        new_callable=AsyncMock,
    ) as mock:
        yield mock


@pytest.fixture
def mock_config_entry(hass: HomeAssistant) -> MockConfigEntry:
    """Return a config entry of the mock integration."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Test IdP",
        data=USER_INPUT,
        options={CONF_SCOPES: "openid"},
    )
    entry.add_to_hass(hass)
    return entry


async def _start_user_flow(hass: HomeAssistant) -> ConfigFlowResult:
    """Start a user flow."""
    return await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )


@pytest.mark.usefixtures("oidc_auth")
async def test_user_flow_creates_entry(
    hass: HomeAssistant, mock_validate: AsyncMock
) -> None:
    """Test the user step validates the spec and stores the input."""
    result = await _start_user_flow(hass)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["description_placeholders"] == {
        "console_url": "https://console.example.com",
        "redirect_uris": REDIRECT_URIS,
    }

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Test IdP"
    assert result["data"] == USER_INPUT
    mock_validate.assert_awaited_once_with(hass, _identity_provider(USER_INPUT, {}))


@pytest.mark.usefixtures("oidc_auth", "mock_validate")
async def test_user_flow_empty_secret_is_public_client(hass: HomeAssistant) -> None:
    """Test an empty client secret is not stored."""
    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], PUBLIC_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {CONF_CLIENT_ID: "client-id"}


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        pytest.param(
            IdentityProviderError("cannot_connect"), "cannot_connect", id="connect"
        ),
        pytest.param(
            IdentityProviderError("invalid_discovery"),
            "invalid_discovery",
            id="discovery",
        ),
        pytest.param(
            IdentityProviderError("invalid_scopes"), "invalid_scopes", id="translated"
        ),
        pytest.param(
            IdentityProviderError("invalid_client_id"), "invalid_config", id="other"
        ),
        pytest.param(RuntimeError("boom"), "unknown", id="unknown"),
    ],
)
@pytest.mark.usefixtures("oidc_auth")
async def test_user_flow_validation_errors_recover(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
    side_effect: Exception,
    error: str,
) -> None:
    """Test validation failures map to form errors and the flow recovers."""
    result = await _start_user_flow(hass)

    mock_validate.side_effect = [side_effect, None]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}
    assert (
        get_schema_suggested_value(result["data_schema"].schema, CONF_CLIENT_ID)
        == "client-id"
    )

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_user_flow_identity_providers_disabled(hass: HomeAssistant) -> None:
    """Test the user step aborts without the engine."""
    result = await _start_user_flow(hass)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "identity_providers_disabled"


@pytest.mark.usefixtures("oidc_auth")
async def test_user_flow_no_url_available(hass: HomeAssistant) -> None:
    """Test the user step aborts without a redirect URI."""
    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_get_redirect_uris",
        return_value=[],
    ):
        result = await _start_user_flow(hass)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_url_available"


@pytest.mark.parametrize("flow_class", [_ResolvingFlow])
@pytest.mark.usefixtures("oidc_auth")
async def test_user_flow_resolved_setup(
    hass: HomeAssistant, mock_validate: AsyncMock
) -> None:
    """Test a resolved setup provides title, unique ID and data."""
    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    data = {**USER_INPUT, "issuer": ISSUER}
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Resolved"
    assert result["data"] == data
    assert result["result"].unique_id == ISSUER
    mock_validate.assert_awaited_once_with(hass, _identity_provider(data, {}))

    result = await _start_user_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


@pytest.mark.parametrize(
    ("side_effect", "errors", "placeholders"),
    [
        pytest.param(
            IdentityProviderFlowError(
                "issuer_mismatch",
                field=CONF_CLIENT_ID,
                placeholders={"reported_issuer": "https://other.example.com"},
            ),
            {CONF_CLIENT_ID: "issuer_mismatch"},
            {"reported_issuer": "https://other.example.com"},
            id="flow-error",
        ),
        pytest.param(
            IdentityProviderError("cannot_connect"),
            {"base": "cannot_connect"},
            {},
            id="discovery-error",
        ),
        pytest.param(
            IdentityProviderError("invalid_spec"),
            {"base": "invalid_config"},
            {},
            id="other-error",
        ),
        pytest.param(RuntimeError("boom"), {"base": "unknown"}, {}, id="unknown"),
    ],
)
@pytest.mark.parametrize("flow_class", [_ResolvingFlow])
@pytest.mark.usefixtures("oidc_auth", "mock_validate")
async def test_user_flow_resolve_errors_recover(
    hass: HomeAssistant,
    side_effect: Exception,
    errors: dict[str, str],
    placeholders: dict[str, str],
) -> None:
    """Test resolution failures map to form errors and the flow recovers."""
    result = await _start_user_flow(hass)

    with patch.object(_ResolvingFlow, "async_resolve_setup", side_effect=side_effect):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], USER_INPUT
        )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == errors
    assert result["description_placeholders"] == {
        "console_url": "https://console.example.com",
        "redirect_uris": REDIRECT_URIS,
        **placeholders,
    }

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.usefixtures("oidc_auth")
async def test_reconfigure(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_validate: AsyncMock
) -> None:
    """Test reconfiguring asks for the secret again and validates the result."""
    result = await mock_config_entry.start_reconfigure_flow(hass)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    assert result["description_placeholders"] == {CONF_CLIENT_ID: "client-id"}
    schema = result["data_schema"].schema
    assert get_schema_suggested_value(schema, CONF_CLIENT_ID) == "client-id"
    assert get_schema_suggested_value(schema, CONF_CLIENT_SECRET) is None

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], UPDATED_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert mock_config_entry.data == UPDATED_INPUT
    mock_validate.assert_awaited_once_with(
        hass, _identity_provider(UPDATED_INPUT, mock_config_entry.options)
    )


@pytest.mark.usefixtures("oidc_auth", "mock_validate")
async def test_reconfigure_empty_secret_drops_stored_secret(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test an empty client secret removes the stored one."""
    result = await mock_config_entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], PUBLIC_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert mock_config_entry.data == {CONF_CLIENT_ID: "client-id"}


@pytest.mark.usefixtures("oidc_auth")
async def test_reconfigure_error_recovers(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_validate: AsyncMock
) -> None:
    """Test a reconfigure validation error keeps the input and recovers."""
    result = await mock_config_entry.start_reconfigure_flow(hass)

    mock_validate.side_effect = [IdentityProviderError("invalid_client_id"), None]
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], UPDATED_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_config"}
    schema = result["data_schema"].schema
    assert get_schema_suggested_value(schema, CONF_CLIENT_ID) == "new-client-id"
    assert get_schema_suggested_value(schema, CONF_CLIENT_SECRET) is None
    assert mock_config_entry.data == USER_INPUT

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], UPDATED_INPUT
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"


async def test_options_flow_requires_schema(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Test a flow without an options schema has no options flow."""
    assert not _Flow.async_supports_options_flow(mock_config_entry)
    assert _OptionsFlow.async_supports_options_flow(mock_config_entry)

    with pytest.raises(data_entry_flow.UnknownHandler):
        await hass.config_entries.options.async_init(mock_config_entry.entry_id)


@pytest.mark.parametrize("flow_class", [_OptionsFlow])
async def test_options_flow(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_validate: AsyncMock
) -> None:
    """Test the options flow validates the spec built from the new options."""
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"
    assert (
        get_schema_suggested_value(result["data_schema"].schema, CONF_SCOPES)
        == "openid"
    )

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], OPTIONS_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_config_entry.options == OPTIONS_INPUT
    mock_validate.assert_awaited_once_with(
        hass, _identity_provider(mock_config_entry.data, OPTIONS_INPUT)
    )


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        pytest.param(
            IdentityProviderError("invalid_scopes"), "invalid_scopes", id="translated"
        ),
        pytest.param(
            IdentityProviderError("invalid_claim_rule"), "invalid_config", id="other"
        ),
        pytest.param(RuntimeError("boom"), "unknown", id="unknown"),
    ],
)
@pytest.mark.parametrize("flow_class", [_OptionsFlow])
async def test_options_flow_errors_recover(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_validate: AsyncMock,
    side_effect: Exception,
    error: str,
) -> None:
    """Test options validation failures keep the input and recover."""
    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)

    mock_validate.side_effect = [side_effect, None]
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], OPTIONS_INPUT
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}
    assert (
        get_schema_suggested_value(result["data_schema"].schema, CONF_SCOPES)
        == "openid profile"
    )
    assert mock_config_entry.options == {CONF_SCOPES: "openid"}

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], OPTIONS_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
