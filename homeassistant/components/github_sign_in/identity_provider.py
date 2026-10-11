"""Identity provider platform for GitHub Sign-In."""

from collections.abc import Mapping
from typing import Any

from homeassistant.components.auth import AccountPolicy, IdentityProvider, OAuth2Profile
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET

_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


def get_identity_provider(entry: ConfigEntry) -> IdentityProvider:
    """Return the identity provider specification for this config entry."""
    return _identity_provider(entry.data, entry.options)


def _identity_provider(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> IdentityProvider:
    """Return the GitHub identity provider specification."""
    return IdentityProvider(
        client_id=data[CONF_CLIENT_ID],
        client_secret=data[CONF_CLIENT_SECRET],
        protocol=OAuth2Profile(
            authorize_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            profile_url="https://api.github.com/user",
            subject_field="id",
            account_name_field="login",
            scopes=(),
            headers=_HEADERS,
            token_auth_method="client_secret_post",
        ),
        accounts=AccountPolicy.LINK,
    )
