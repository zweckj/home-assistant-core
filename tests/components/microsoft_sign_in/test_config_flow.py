"""Test the Microsoft Sign-In config flow."""

from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest

from homeassistant.components.auth import IdentityProviderError, ProviderMetadata
from homeassistant.components.microsoft_sign_in.config_flow import (
    MicrosoftSignInConfigFlow,
)
from homeassistant.components.microsoft_sign_in.const import (
    CONF_ACCOUNTS,
    CONF_ADMIN_GROUP,
    CONF_REVALIDATE_INTERVAL,
    CONF_TENANT,
    CONSUMERS_TENANT_ID,
    DOMAIN,
)
from homeassistant.config_entries import (
    SOURCE_RECONFIGURE,
    SOURCE_USER,
    ConfigFlowResult,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from tests.common import MockConfigEntry

CLIENT_ID = "client-id"
CLIENT_SECRET = "client-secret"
NEW_CLIENT_SECRET = "new-client-secret"
TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
TENANT_ID_UPPER = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"
ADMIN_GROUP = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
USER_INPUT = {
    CONF_TENANT: "common",
    CONF_CLIENT_ID: CLIENT_ID,
    CONF_CLIENT_SECRET: CLIENT_SECRET,
}


def _metadata(issuer: str) -> ProviderMetadata:
    """Return provider metadata."""
    return ProviderMetadata(
        issuer=issuer,
        authorization_endpoint="https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize",
        token_endpoint="https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
        jwks_uri="https://login.microsoftonline.com/tenant/discovery/v2.0/keys",
    )


@pytest.fixture
def mock_validate() -> Generator[AsyncMock]:
    """Mock identity provider validation."""
    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_validate_identity_provider",
        AsyncMock(),
    ) as validate:
        yield validate


async def _async_configure_user(
    hass: HomeAssistant, user_input: dict[str, str]
) -> ConfigFlowResult:
    """Start and configure the user flow."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    return await hass.config_entries.flow.async_configure(result["flow_id"], user_input)


@pytest.mark.parametrize(
    ("tenant", "title"),
    [
        pytest.param("common", "Microsoft", id="common"),
        pytest.param("organizations", "Microsoft", id="organizations"),
        pytest.param("consumers", "Microsoft", id="consumers"),
    ],
)
@pytest.mark.usefixtures("ha_url", "mock_setup_entry", "oidc_auth")
async def test_user_flow_tenant_keyword(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
    tenant: str,
    title: str,
) -> None:
    """Test the user flow with a tenant keyword."""
    result = await _async_configure_user(hass, USER_INPUT | {CONF_TENANT: tenant})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == title
    assert result["data"] == USER_INPUT | {CONF_TENANT: tenant}
    mock_validate.assert_awaited_once()


@pytest.mark.usefixtures("ha_url", "mock_setup_entry", "oidc_auth")
async def test_user_flow_guid_normalized(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
) -> None:
    """Test the user flow normalizes a GUID tenant."""
    result = await _async_configure_user(
        hass, USER_INPUT | {CONF_TENANT: TENANT_ID_UPPER}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == f"Microsoft ({TENANT_ID.lower()})"
    assert result["data"] == USER_INPUT | {CONF_TENANT: TENANT_ID}
    mock_validate.assert_awaited_once()


@pytest.mark.usefixtures("ha_url", "mock_setup_entry", "oidc_auth")
async def test_user_flow_domain_resolved(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
) -> None:
    """Test the user flow resolves a domain to a tenant GUID."""
    with patch(
        "homeassistant.components.microsoft_sign_in.config_flow.async_discover_identity_provider",
        return_value=_metadata(f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"),
    ) as discover:
        result = await _async_configure_user(
            hass, USER_INPUT | {CONF_TENANT: "Example.COM"}
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == "Microsoft (example.com)"
    assert result["data"] == USER_INPUT | {CONF_TENANT: TENANT_ID}
    discover.assert_awaited_once_with(
        hass,
        "https://login.microsoftonline.com/example.com/v2.0/.well-known/openid-configuration",
    )
    mock_validate.assert_awaited_once()


@pytest.mark.usefixtures("ha_url", "mock_setup_entry", "oidc_auth")
async def test_user_flow_domain_issuer_mismatch_recovers(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
) -> None:
    """Test domain discovery with a mismatched issuer recovers."""
    with patch(
        "homeassistant.components.microsoft_sign_in.config_flow.async_discover_identity_provider",
        side_effect=[
            _metadata("https://example.com/not-a-tenant"),
            _metadata(f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"),
        ],
    ):
        result = await _async_configure_user(
            hass, USER_INPUT | {CONF_TENANT: "example.com"}
        )
        assert result["type"] is FlowResultType.FORM
        assert result["errors"] == {CONF_TENANT: "invalid_tenant"}
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], USER_INPUT | {CONF_TENANT: "example.com"}
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == USER_INPUT | {CONF_TENANT: TENANT_ID}
    mock_validate.assert_awaited_once()


@pytest.mark.usefixtures("ha_url", "mock_setup_entry", "oidc_auth")
async def test_user_flow_invalid_domain_syntax_recovers(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
) -> None:
    """Test invalid domain syntax recovers."""
    result = await _async_configure_user(hass, USER_INPUT | {CONF_TENANT: "bad_domain"})
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {CONF_TENANT: "invalid_tenant"}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == USER_INPUT
    mock_validate.assert_awaited_once()


@pytest.mark.usefixtures("ha_url", "mock_setup_entry", "oidc_auth")
async def test_user_flow_discovery_cannot_connect_recovers(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
) -> None:
    """Test discovery cannot connect recovers."""
    with patch(
        "homeassistant.components.microsoft_sign_in.config_flow.async_discover_identity_provider",
        side_effect=[
            IdentityProviderError("cannot_connect"),
            _metadata(f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"),
        ],
    ):
        result = await _async_configure_user(
            hass, USER_INPUT | {CONF_TENANT: "example.com"}
        )
        assert result["type"] is FlowResultType.FORM
        assert result["errors"] == {"base": "cannot_connect"}
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], USER_INPUT | {CONF_TENANT: "example.com"}
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == USER_INPUT | {CONF_TENANT: TENANT_ID}
    mock_validate.assert_awaited_once()


@pytest.mark.parametrize(
    ("side_effect", "errors"),
    [
        pytest.param(
            IdentityProviderError("invalid_discovery"),
            {CONF_TENANT: "invalid_tenant"},
            id="invalid-discovery",
        ),
        pytest.param(
            IdentityProviderError("invalid_spec"),
            {"base": "invalid_config"},
            id="invalid-config",
        ),
        pytest.param(RuntimeError("boom"), {"base": "unknown"}, id="unknown"),
    ],
)
@pytest.mark.usefixtures("ha_url", "mock_setup_entry", "oidc_auth")
async def test_user_flow_discovery_errors_recover(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
    side_effect: Exception,
    errors: dict[str, str],
) -> None:
    """Test discovery errors recover."""
    with patch(
        "homeassistant.components.microsoft_sign_in.config_flow.async_discover_identity_provider",
        side_effect=[
            side_effect,
            _metadata(f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"),
        ],
    ):
        result = await _async_configure_user(
            hass, USER_INPUT | {CONF_TENANT: "example.com"}
        )
        assert result["type"] is FlowResultType.FORM
        assert result["errors"] == errors
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], USER_INPUT | {CONF_TENANT: "example.com"}
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == USER_INPUT | {CONF_TENANT: TENANT_ID}
    mock_validate.assert_awaited_once()


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        pytest.param(
            IdentityProviderError("cannot_connect"),
            "cannot_connect",
            id="cannot-connect",
        ),
        pytest.param(
            IdentityProviderError("invalid_scopes"),
            "invalid_config",
            id="invalid-config",
        ),
        pytest.param(RuntimeError("boom"), "unknown", id="unknown"),
    ],
)
@pytest.mark.usefixtures("ha_url", "mock_setup_entry", "oidc_auth")
async def test_user_flow_validation_errors_recover(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
    side_effect: Exception,
    error: str,
) -> None:
    """Test validation errors recover."""
    mock_validate.side_effect = [side_effect, None]

    result = await _async_configure_user(hass, USER_INPUT)
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], USER_INPUT
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == USER_INPUT
    assert mock_validate.await_count == 2


@pytest.mark.usefixtures("ha_url", "oidc_auth")
async def test_user_flow_already_configured(hass: HomeAssistant) -> None:
    """Test already configured abort."""
    entry = MockConfigEntry(domain=DOMAIN, unique_id="common", data=USER_INPUT)
    entry.add_to_hass(hass)

    result = await _async_configure_user(hass, USER_INPUT)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


@pytest.mark.usefixtures("ha_url")
async def test_user_flow_identity_providers_disabled(hass: HomeAssistant) -> None:
    """Test identity providers disabled abort."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "identity_providers_disabled"


@pytest.mark.usefixtures("oidc_auth")
async def test_user_flow_no_url_available(hass: HomeAssistant) -> None:
    """Test no URL available abort."""
    with patch(
        "homeassistant.components.auth.identity_provider_flow.async_get_redirect_uris",
        return_value=[],
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "no_url_available"


@pytest.mark.usefixtures("mock_setup_entry", "oidc_auth")
async def test_reconfigure_success(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
) -> None:
    """Test reconfigure success."""
    entry = MockConfigEntry(domain=DOMAIN, data=USER_INPUT, unique_id="common")
    entry.add_to_hass(hass)

    result = await entry.start_reconfigure_flow(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_CLIENT_SECRET: NEW_CLIENT_SECRET},
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert entry.data == USER_INPUT | {CONF_CLIENT_SECRET: NEW_CLIENT_SECRET}
    mock_validate.assert_awaited_once()


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        pytest.param(
            IdentityProviderError("invalid_discovery"),
            "invalid_discovery",
            id="invalid-discovery",
        ),
        pytest.param(RuntimeError("boom"), "unknown", id="unknown"),
    ],
)
@pytest.mark.usefixtures("mock_setup_entry", "oidc_auth")
async def test_reconfigure_error_recovers(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
    side_effect: Exception,
    error: str,
) -> None:
    """Test reconfigure validation error recovers."""
    mock_validate.side_effect = [side_effect, None]
    entry = MockConfigEntry(domain=DOMAIN, data=USER_INPUT, unique_id="common")
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_CLIENT_SECRET: NEW_CLIENT_SECRET},
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_CLIENT_SECRET: NEW_CLIENT_SECRET},
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert mock_validate.await_count == 2


@pytest.mark.usefixtures("mock_setup_entry", "oidc_auth")
async def test_options_success(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
) -> None:
    """Test options success."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=USER_INPUT | {CONF_TENANT: TENANT_ID},
        unique_id=TENANT_ID,
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            CONF_ACCOUNTS: "provision",
            CONF_ADMIN_GROUP: ADMIN_GROUP,
            CONF_REVALIDATE_INTERVAL: 60,
        },
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        CONF_ACCOUNTS: "provision",
        CONF_ADMIN_GROUP: ADMIN_GROUP,
        CONF_REVALIDATE_INTERVAL: 60,
    }
    mock_validate.assert_awaited_once()


@pytest.mark.parametrize(
    ("side_effect", "error"),
    [
        pytest.param(
            IdentityProviderError("invalid_scopes"),
            "invalid_config",
            id="invalid-config",
        ),
        pytest.param(RuntimeError("boom"), "unknown", id="unknown"),
    ],
)
@pytest.mark.usefixtures("mock_setup_entry", "oidc_auth")
async def test_options_errors_recover(
    hass: HomeAssistant,
    mock_validate: AsyncMock,
    side_effect: Exception,
    error: str,
) -> None:
    """Test options errors recover."""
    mock_validate.side_effect = [side_effect, None]
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=USER_INPUT | {CONF_TENANT: TENANT_ID},
        unique_id=TENANT_ID,
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            CONF_ACCOUNTS: "provision",
            CONF_ADMIN_GROUP: "",
            CONF_REVALIDATE_INTERVAL: 60,
        },
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            CONF_ACCOUNTS: "provision",
            CONF_ADMIN_GROUP: "",
            CONF_REVALIDATE_INTERVAL: 60,
        },
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        CONF_ACCOUNTS: "provision",
        CONF_ADMIN_GROUP: "",
        CONF_REVALIDATE_INTERVAL: 60,
    }
    assert mock_validate.await_count == 2


def test_options_not_offered_for_non_guid_tenant() -> None:
    """Test options are not offered for non-GUID tenants."""
    entry = MockConfigEntry(domain=DOMAIN, data=USER_INPUT, unique_id="common")

    assert not MicrosoftSignInConfigFlow.async_supports_options_flow(entry)


def test_options_offered_for_guid_tenant() -> None:
    """Test options are offered for GUID tenants."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=USER_INPUT | {CONF_TENANT: CONSUMERS_TENANT_ID},
        unique_id=CONSUMERS_TENANT_ID,
    )

    assert MicrosoftSignInConfigFlow.async_supports_options_flow(entry)
