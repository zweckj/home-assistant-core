"""Identity provider platform for GitHub Sign-In."""

from collections.abc import Mapping
from typing import Any

from homeassistant.components.auth import AccountPolicy, IdentityProvider
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET

from .client import GitHubOAuth2


def get_identity_provider(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> IdentityProvider:
    """Return the GitHub identity provider specification."""
    return IdentityProvider(
        client_id=data[CONF_CLIENT_ID],
        client_secret=data[CONF_CLIENT_SECRET],
        protocol=GitHubOAuth2(),
        accounts=AccountPolicy.LINK,
    )
