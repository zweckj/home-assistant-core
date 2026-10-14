"""Tests for the GitHub Sign-In config flow."""

from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.components.auth import IdentityProviderError
from homeassistant.components.github_sign_in.const import DOMAIN
from homeassistant.components.github_sign_in.identity_provider import (
    get_identity_provider,
)
from homeassistant.config_entries import SOURCE_USER
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from .conftest import NEW_USER_INPUT, TITLE, USER_INPUT

from tests.common import MockConfigEntry, get_schema_suggested_value


@pytest.mark.usefixtures("oidc_auth", "external_url")
async def test_user_flow_success(
    hass: HomeAssistant,
    mock_setup_entry: AsyncMock,
) -> None:
    """Test the user flow success path."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["description_placeholders"] == {
        "developer_settings_url": "https://github.com/settings/developers",
        "redirect_uris": "- `https://example.com/auth/login_callback`\n- `http://10.10.10.10:8123/auth/login_callback`",
    }

    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_validate_identity_provider",
        return_value=None,
    ) as mock_validate:
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input=USER_INPUT
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == TITLE
    assert result["data"] == USER_INPUT
    assert mock_validate.await_args.args[1] == get_identity_provider(USER_INPUT, {})
    assert len(mock_setup_entry.mock_calls) == 1


@pytest.mark.parametrize(
    ("side_effect", "expected_error"),
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
        pytest.param(Exception("boom"), "unknown", id="unknown"),
    ],
)
@pytest.mark.usefixtures("oidc_auth", "external_url")
async def test_user_flow_errors_recover(
    hass: HomeAssistant,
    side_effect: Exception,
    expected_error: str,
) -> None:
    """Test user flow errors and recovery."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )

    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_validate_identity_provider",
        side_effect=[side_effect, None],
    ) as mock_validate:
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input=USER_INPUT
        )
        assert result["type"] is FlowResultType.FORM
        assert result["errors"] == {"base": expected_error}

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input=USER_INPUT
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_validate.await_count == 2


@pytest.mark.usefixtures("oidc_auth", "external_url")
async def test_user_flow_single_instance_allowed(
    hass: HomeAssistant,
    github_sign_in_entry: MockConfigEntry,
) -> None:
    """Test the user flow allows only one config entry."""
    github_sign_in_entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "single_instance_allowed"


async def test_user_flow_identity_providers_disabled(hass: HomeAssistant) -> None:
    """Test the user flow aborts when identity providers are disabled."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "identity_providers_disabled"


@pytest.mark.usefixtures("oidc_auth")
async def test_user_flow_no_url_available(hass: HomeAssistant) -> None:
    """Test the user flow aborts when no URL is available."""
    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_get_redirect_uris",
        return_value=[],
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_url_available"


@pytest.mark.usefixtures("oidc_auth")
async def test_reconfigure_success(
    hass: HomeAssistant,
    github_sign_in_entry: MockConfigEntry,
) -> None:
    """Test reconfiguration success."""
    github_sign_in_entry.add_to_hass(hass)

    result = await github_sign_in_entry.start_reconfigure_flow(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    assert (
        get_schema_suggested_value(result["data_schema"].schema, CONF_CLIENT_ID)
        == USER_INPUT[CONF_CLIENT_ID]
    )
    assert (
        get_schema_suggested_value(result["data_schema"].schema, CONF_CLIENT_SECRET)
        is None
    )

    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_validate_identity_provider",
        return_value=None,
    ) as mock_validate:
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input=NEW_USER_INPUT
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert github_sign_in_entry.data == NEW_USER_INPUT
    assert mock_validate.await_args.args[1] == get_identity_provider(NEW_USER_INPUT, {})


@pytest.mark.usefixtures("oidc_auth")
async def test_reconfigure_error_recover(
    hass: HomeAssistant,
    github_sign_in_entry: MockConfigEntry,
) -> None:
    """Test reconfiguration errors and recovery."""
    github_sign_in_entry.add_to_hass(hass)

    result = await github_sign_in_entry.start_reconfigure_flow(hass)

    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_validate_identity_provider",
        side_effect=[IdentityProviderError("invalid_client_secret"), None],
    ) as mock_validate:
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input=NEW_USER_INPUT
        )
        assert result["type"] is FlowResultType.FORM
        assert result["errors"] == {"base": "invalid_config"}
        assert (
            get_schema_suggested_value(result["data_schema"].schema, CONF_CLIENT_ID)
            == NEW_USER_INPUT[CONF_CLIENT_ID]
        )
        assert (
            get_schema_suggested_value(result["data_schema"].schema, CONF_CLIENT_SECRET)
            is None
        )

        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input=NEW_USER_INPUT
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert github_sign_in_entry.data[CONF_CLIENT_ID] == NEW_USER_INPUT[CONF_CLIENT_ID]
    assert (
        github_sign_in_entry.data[CONF_CLIENT_SECRET]
        == NEW_USER_INPUT[CONF_CLIENT_SECRET]
    )
    assert mock_validate.await_count == 2
