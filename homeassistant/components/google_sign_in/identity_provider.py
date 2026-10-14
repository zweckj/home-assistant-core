"""Identity provider platform for Google Sign-In."""

from collections.abc import Mapping
from typing import Any

from homeassistant.components.auth import AccountPolicy, IdentityProvider
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET

from .client import ISSUER, GoogleOpenIDConnect


def get_identity_provider(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> IdentityProvider:
    """Return the Google Sign-In identity provider spec."""
    return IdentityProvider(
        client_id=data[CONF_CLIENT_ID],
        client_secret=data[CONF_CLIENT_SECRET],
        protocol=GoogleOpenIDConnect(
            issuer=ISSUER,
            scopes=("openid", "email"),
            account_name_claim="email",
        ),
        accounts=AccountPolicy.LINK,
    )
