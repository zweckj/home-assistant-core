"""Identity provider platform for OpenID Connect."""

from collections.abc import Mapping
from typing import Any

from homeassistant.components.auth import IdentityProvider, OpenIDConnect
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET

from .const import ACCOUNT_NAME_CLAIM, CONF_ISSUER


def get_identity_provider(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> IdentityProvider:
    """Return the identity provider spec for config entry data and options."""
    return IdentityProvider(
        client_id=data[CONF_CLIENT_ID],
        client_secret=data.get(CONF_CLIENT_SECRET),
        protocol=OpenIDConnect(
            issuer=data[CONF_ISSUER], account_name_claim=ACCOUNT_NAME_CLAIM
        ),
    )
