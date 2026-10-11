"""Identity provider platform for Google Sign-In."""

from collections.abc import Mapping
from typing import Any

from homeassistant.components.auth import AccountPolicy, IdentityProvider, OpenIDConnect
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET


def get_identity_provider(entry: ConfigEntry) -> IdentityProvider:
    """Return the identity provider spec for a config entry."""
    return _identity_provider(entry.data, entry.options)


def _identity_provider(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> IdentityProvider:
    """Return the Google Sign-In identity provider spec."""
    return IdentityProvider(
        client_id=data[CONF_CLIENT_ID],
        client_secret=data[CONF_CLIENT_SECRET],
        protocol=OpenIDConnect(
            issuer="https://accounts.google.com",
            issuer_aliases=frozenset({"accounts.google.com"}),
            scopes=("openid", "email"),
            account_name_claim="email",
        ),
        accounts=AccountPolicy.LINK,
    )
