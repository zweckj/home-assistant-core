"""Config flow for the OpenID Connect integration."""

from collections.abc import Mapping
from typing import Any, override
from urllib.parse import urlsplit

import probatio

from homeassistant.components.auth import (
    IdentityProviderConfigFlow,
    IdentityProviderFlowError,
    IdentityProviderSetup,
    async_discover_identity_provider,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import callback
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
    CONF_ACCOUNT_NAME_CLAIM,
    CONF_ACCOUNTS,
    CONF_ADMIN_GROUP,
    CONF_ALLOW_INSECURE_TRANSPORT,
    CONF_DISPLAY_NAME_CLAIM,
    CONF_ISSUER,
    CONF_REVALIDATE_INTERVAL,
    CONF_SCOPES,
    CONF_USERNAME_CLAIM,
    DEFAULT_ACCOUNT_NAME_CLAIM,
    DEFAULT_ACCOUNTS,
    DEFAULT_DISPLAY_NAME_CLAIM,
    DEFAULT_REVALIDATE_INTERVAL,
    DEFAULT_SCOPES,
    DEFAULT_USERNAME_CLAIM,
    DOMAIN,
)
from .identity_provider import _identity_provider

_CLIENT_SECRET_SELECTOR = TextSelector(
    TextSelectorConfig(type=TextSelectorType.PASSWORD)
)

OPTIONS_SCHEMA = probatio.Schema(
    {
        probatio.Required(CONF_ACCOUNTS, default=DEFAULT_ACCOUNTS): SelectSelector(
            SelectSelectorConfig(
                options=["link", "provision"],
                mode=SelectSelectorMode.DROPDOWN,
                translation_key="accounts",
            )
        ),
        probatio.Required(CONF_SCOPES, default=DEFAULT_SCOPES): str,
        probatio.Required(
            CONF_ACCOUNT_NAME_CLAIM, default=DEFAULT_ACCOUNT_NAME_CLAIM
        ): str,
        probatio.Required(CONF_USERNAME_CLAIM, default=DEFAULT_USERNAME_CLAIM): str,
        probatio.Required(
            CONF_DISPLAY_NAME_CLAIM, default=DEFAULT_DISPLAY_NAME_CLAIM
        ): str,
        probatio.Optional(CONF_ADMIN_GROUP): str,
        probatio.Required(
            CONF_REVALIDATE_INTERVAL, default=DEFAULT_REVALIDATE_INTERVAL
        ): NumberSelector(
            NumberSelectorConfig(
                min=5,
                max=43200,
                mode=NumberSelectorMode.BOX,
                unit_of_measurement="min",
            )
        ),
    }
)


def _discovery_url(issuer: str) -> str:
    """Return the OpenID Connect discovery URL for an issuer."""
    return f"{issuer.rstrip('/')}/.well-known/openid-configuration"


def _issuer_matches(user_issuer: str, reported_issuer: str) -> bool:
    """Return whether two issuer strings match ignoring one trailing slash."""
    return user_issuer.rstrip("/") == reported_issuer.rstrip("/")


def _host_title(issuer: str) -> str:
    """Return the entry title for an issuer."""
    hostname = urlsplit(issuer).hostname
    return hostname or issuer


def _data_schema(*, advanced: bool) -> probatio.Schema:
    """Return the user step data schema."""
    schema: dict[Any, Any] = {
        probatio.Required(CONF_ISSUER): TextSelector(
            TextSelectorConfig(type=TextSelectorType.URL)
        ),
        probatio.Required(CONF_CLIENT_ID): str,
        probatio.Optional(CONF_CLIENT_SECRET): _CLIENT_SECRET_SELECTOR,
    }
    if advanced:
        schema[probatio.Optional(CONF_ALLOW_INSECURE_TRANSPORT, default=False)] = bool
    return probatio.Schema(schema)


def _reconfigure_schema(*, advanced: bool) -> probatio.Schema:
    """Return the reconfigure data schema."""
    schema: dict[Any, Any] = {
        probatio.Required(CONF_CLIENT_ID): str,
        probatio.Optional(CONF_CLIENT_SECRET): _CLIENT_SECRET_SELECTOR,
    }
    if advanced:
        schema[probatio.Optional(CONF_ALLOW_INSECURE_TRANSPORT, default=False)] = bool
    return probatio.Schema(schema)


class OpenIDConnectConfigFlow(IdentityProviderConfigFlow, domain=DOMAIN):
    """Handle a config flow for OpenID Connect."""

    DATA_SCHEMA = _data_schema(advanced=False)
    OPTIONS_SCHEMA = OPTIONS_SCHEMA
    RECONFIGURE_PLACEHOLDERS = (CONF_ISSUER,)
    TRANSLATED_ERRORS = frozenset({"invalid_scopes"})
    identity_provider = staticmethod(_identity_provider)

    @callback
    @override
    def user_schema(self) -> probatio.Schema:
        """Return the user step form."""
        return _data_schema(advanced=self.show_advanced_options)

    @callback
    @override
    def reconfigure_schema(self) -> probatio.Schema:
        """Return the reconfigure step form."""
        return _reconfigure_schema(advanced=self.show_advanced_options)

    @override
    async def async_resolve_setup(
        self, user_input: Mapping[str, Any]
    ) -> IdentityProviderSetup:
        """Resolve the issuer through discovery."""
        issuer = user_input[CONF_ISSUER]
        allow_insecure_transport = user_input.get(CONF_ALLOW_INSECURE_TRANSPORT, False)
        metadata = await async_discover_identity_provider(
            self.hass,
            _discovery_url(issuer),
            allow_insecure_transport=allow_insecure_transport,
        )
        if not _issuer_matches(issuer, metadata.issuer):
            raise IdentityProviderFlowError(
                "issuer_mismatch", placeholders={"reported_issuer": metadata.issuer}
            )
        return IdentityProviderSetup(
            title=_host_title(metadata.issuer),
            unique_id=metadata.issuer,
            data={
                CONF_ISSUER: metadata.issuer,
                CONF_CLIENT_ID: user_input[CONF_CLIENT_ID],
                CONF_CLIENT_SECRET: user_input.get(CONF_CLIENT_SECRET),
                CONF_ALLOW_INSECURE_TRANSPORT: allow_insecure_transport,
            },
        )
