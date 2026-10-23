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
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import CONF_ISSUER, DOMAIN
from .identity_provider import get_identity_provider

_CLIENT_SECRET_SELECTOR = TextSelector(
    TextSelectorConfig(type=TextSelectorType.PASSWORD)
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


def _data_schema(*, issuer: bool) -> probatio.Schema:
    """Return the user or reconfigure step form."""
    schema: dict[Any, Any] = {}
    if issuer:
        schema[probatio.Required(CONF_ISSUER)] = TextSelector(
            TextSelectorConfig(type=TextSelectorType.URL)
        )
    schema[probatio.Required(CONF_CLIENT_ID)] = str
    schema[probatio.Optional(CONF_CLIENT_SECRET)] = _CLIENT_SECRET_SELECTOR
    return probatio.Schema(schema)


class OpenIDConnectConfigFlow(IdentityProviderConfigFlow, domain=DOMAIN):
    """Handle a config flow for OpenID Connect."""

    RECONFIGURE_PLACEHOLDERS = (CONF_ISSUER,)
    identity_provider = staticmethod(get_identity_provider)

    @callback
    @override
    def user_schema(self) -> probatio.Schema:
        """Return the user step form."""
        return _data_schema(issuer=True)

    @callback
    @override
    def reconfigure_schema(self) -> probatio.Schema:
        """Return the reconfigure step form."""
        return _data_schema(issuer=False)

    @override
    async def async_resolve_setup(
        self, user_input: Mapping[str, Any]
    ) -> IdentityProviderSetup:
        """Resolve the issuer through discovery."""
        issuer = user_input[CONF_ISSUER]
        metadata = await async_discover_identity_provider(
            self.hass, _discovery_url(issuer)
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
            },
        )
