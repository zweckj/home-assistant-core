"""Config flow for Microsoft Sign-In."""

from collections.abc import Mapping
import re
from typing import Any, override
import uuid

import probatio

from homeassistant.components.auth import (
    AccountPolicy,
    IdentityProviderConfigFlow,
    IdentityProviderError,
    IdentityProviderFlowError,
    IdentityProviderSetup,
    async_discover_identity_provider,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import (
    BASE_URL,
    CONF_ACCOUNTS,
    CONF_ADMIN_GROUP,
    CONF_REVALIDATE_INTERVAL,
    CONF_TENANT,
    DEFAULT_REVALIDATE_INTERVAL,
    DOMAIN,
    TENANT_KEYWORDS,
)
from .identity_provider import _is_guid, get_identity_provider

_DEFAULT_TENANT = "common"
_PORTAL_URL = "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"
_DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_ISSUER_RE = re.compile(r"https://login\.microsoftonline\.com/([0-9a-f-]{36})/v2\.0\Z")

_TEXT_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.TEXT))
_PASSWORD_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
_ACCOUNTS_SELECTOR = SelectSelector(
    SelectSelectorConfig(
        options=[policy.value for policy in AccountPolicy],
        translation_key=CONF_ACCOUNTS,
        mode=SelectSelectorMode.DROPDOWN,
    )
)
_REVALIDATE_SELECTOR = probatio.All(
    NumberSelector(NumberSelectorConfig(min=5, max=43200, mode=NumberSelectorMode.BOX)),
    probatio.Coerce(int),
)

DATA_SCHEMA = probatio.Schema(
    {
        probatio.Required(CONF_TENANT, default=_DEFAULT_TENANT): _TEXT_SELECTOR,
        probatio.Required(CONF_CLIENT_ID): _TEXT_SELECTOR,
        probatio.Required(CONF_CLIENT_SECRET): _PASSWORD_SELECTOR,
    }
)
RECONFIGURE_SCHEMA = probatio.Schema(
    {probatio.Required(CONF_CLIENT_SECRET): _PASSWORD_SELECTOR}
)
OPTIONS_SCHEMA = probatio.Schema(
    {
        probatio.Required(
            CONF_ACCOUNTS, default=AccountPolicy.LINK.value
        ): _ACCOUNTS_SELECTOR,
        probatio.Optional(CONF_ADMIN_GROUP, default=""): _TEXT_SELECTOR,
        probatio.Required(
            CONF_REVALIDATE_INTERVAL, default=DEFAULT_REVALIDATE_INTERVAL
        ): _REVALIDATE_SELECTOR,
    }
)


def _normalize_guid(tenant: str) -> str | None:
    """Return a normalized GUID tenant, if the tenant is a GUID."""
    try:
        return str(uuid.UUID(tenant))
    except ValueError:
        return None


def _invalid_tenant() -> IdentityProviderFlowError:
    """Return the form error for a tenant that cannot be resolved."""
    return IdentityProviderFlowError("invalid_tenant", field=CONF_TENANT)


async def _async_resolve_tenant(hass: HomeAssistant, tenant: str) -> str:
    """Resolve a tenant input to a Microsoft tenant keyword or GUID."""
    if tenant in TENANT_KEYWORDS:
        return tenant
    if guid := _normalize_guid(tenant):
        return guid
    if _DOMAIN_RE.fullmatch(tenant) is None:
        raise _invalid_tenant()
    try:
        metadata = await async_discover_identity_provider(
            hass, f"{BASE_URL}/{tenant}/v2.0/.well-known/openid-configuration"
        )
    except IdentityProviderError as err:
        if err.reason == "invalid_discovery":
            raise _invalid_tenant() from err
        raise
    if (match := _ISSUER_RE.fullmatch(metadata.issuer)) is None:
        raise _invalid_tenant()
    return match.group(1)


def _title(tenant_input: str) -> str:
    """Return the config entry title."""
    if tenant_input in TENANT_KEYWORDS:
        return "Microsoft"
    return f"Microsoft ({tenant_input})"


class MicrosoftSignInConfigFlow(IdentityProviderConfigFlow, domain=DOMAIN):
    """Handle a config flow for Microsoft Sign-In."""

    DATA_SCHEMA = DATA_SCHEMA
    RECONFIGURE_SCHEMA = RECONFIGURE_SCHEMA
    OPTIONS_SCHEMA = OPTIONS_SCHEMA
    USER_PLACEHOLDERS = {"portal_url": _PORTAL_URL}
    RECONFIGURE_PLACEHOLDERS = (CONF_CLIENT_ID, CONF_TENANT)
    identity_provider = staticmethod(get_identity_provider)

    @classmethod
    @callback
    @override
    def async_supports_options_flow(cls, config_entry: ConfigEntry) -> bool:
        """Offer options only for tenants that not everyone can join."""
        return _is_guid(config_entry.data[CONF_TENANT])

    @override
    async def async_resolve_setup(
        self, user_input: Mapping[str, Any]
    ) -> IdentityProviderSetup:
        """Resolve the tenant input to the entry to create."""
        tenant_input = user_input[CONF_TENANT].strip().lower()
        tenant = await _async_resolve_tenant(self.hass, tenant_input)
        return IdentityProviderSetup(
            title=_title(tenant_input),
            unique_id=tenant,
            data={
                CONF_TENANT: tenant,
                CONF_CLIENT_ID: user_input[CONF_CLIENT_ID],
                CONF_CLIENT_SECRET: user_input[CONF_CLIENT_SECRET],
            },
        )
