"""Identity provider platform for OpenID Connect."""

from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from homeassistant.components.auth import AccountPolicy, IdentityProvider, OpenIDConnect
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET

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
)


def get_identity_provider(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> IdentityProvider:
    """Return the identity provider spec for config entry data and options."""
    accounts = AccountPolicy(options.get(CONF_ACCOUNTS, DEFAULT_ACCOUNTS))
    scopes = options.get(CONF_SCOPES, DEFAULT_SCOPES)
    return IdentityProvider(
        client_id=data[CONF_CLIENT_ID],
        client_secret=data.get(CONF_CLIENT_SECRET),
        protocol=OpenIDConnect(
            issuer=data[CONF_ISSUER],
            scopes=tuple(scopes.split()),
            account_name_claim=options.get(
                CONF_ACCOUNT_NAME_CLAIM, DEFAULT_ACCOUNT_NAME_CLAIM
            ),
            username_claim=options.get(CONF_USERNAME_CLAIM, DEFAULT_USERNAME_CLAIM),
            display_name_claim=options.get(
                CONF_DISPLAY_NAME_CLAIM, DEFAULT_DISPLAY_NAME_CLAIM
            ),
            admin_group=options.get(CONF_ADMIN_GROUP) or None,
        ),
        accounts=accounts,
        revalidate_interval=timedelta(
            minutes=options.get(CONF_REVALIDATE_INTERVAL, DEFAULT_REVALIDATE_INTERVAL)
        )
        if accounts is AccountPolicy.PROVISION
        else None,
        allow_insecure_transport=data[CONF_ALLOW_INSECURE_TRANSPORT],
    )
