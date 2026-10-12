"""Identity provider specification for Microsoft Sign-In."""

from collections.abc import Mapping
from datetime import timedelta
from typing import Any
import uuid

from homeassistant.components.auth import (
    AccountPolicy,
    Equals,
    IdentityProvider,
    NotEquals,
    OpenIDConnect,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET

from .const import (
    BASE_URL,
    CONF_ACCOUNTS,
    CONF_ADMIN_GROUP,
    CONF_REVALIDATE_INTERVAL,
    CONF_TENANT,
    CONSUMERS_TENANT_ID,
    DEFAULT_REVALIDATE_INTERVAL,
    MULTI_TENANT_KEYWORDS,
    TENANT_KEYWORDS,
)

_SCOPES = ("openid", "profile")


def get_identity_provider(
    data: Mapping[str, Any], options: Mapping[str, Any]
) -> IdentityProvider:
    """Return the Microsoft identity provider specification."""
    tenant = data[CONF_TENANT]
    accounts = AccountPolicy.LINK
    # Tenants anyone can join must never create users.
    if _is_guid(tenant):
        accounts = AccountPolicy(options.get(CONF_ACCOUNTS, AccountPolicy.LINK))

    admin_group: str | None = None
    revalidate_interval: timedelta | None = None
    if accounts is AccountPolicy.PROVISION:
        admin_group = options.get(CONF_ADMIN_GROUP) or None
        revalidate_interval = timedelta(
            minutes=options.get(CONF_REVALIDATE_INTERVAL, DEFAULT_REVALIDATE_INTERVAL)
        )

    return IdentityProvider(
        client_id=data[CONF_CLIENT_ID],
        client_secret=data[CONF_CLIENT_SECRET],
        protocol=OpenIDConnect(
            issuer=_issuer(tenant),
            discovery_url=_discovery_url(tenant),
            issuer_claim="tid" if tenant in MULTI_TENANT_KEYWORDS else None,
            required_claims=_required_claims(tenant),
            scopes=_SCOPES,
            account_name_claim="preferred_username",
            username_claim="preferred_username",
            display_name_claim="name",
            admin_group=admin_group,
        ),
        accounts=accounts,
        revalidate_interval=revalidate_interval,
    )


def _is_guid(tenant: str) -> bool:
    """Return whether the tenant is a canonical GUID."""
    try:
        return str(uuid.UUID(tenant)) == tenant
    except ValueError:
        return False


def _issuer(tenant: str) -> str:
    """Return the issuer for the tenant."""
    if tenant == "consumers":
        return f"{BASE_URL}/{CONSUMERS_TENANT_ID}/v2.0"
    if tenant in MULTI_TENANT_KEYWORDS:
        return f"{BASE_URL}/{{tenantid}}/v2.0"
    return f"{BASE_URL}/{tenant}/v2.0"


def _discovery_url(tenant: str) -> str | None:
    """Return the discovery URL for the tenant."""
    if tenant in TENANT_KEYWORDS:
        return f"{BASE_URL}/{tenant}/v2.0/.well-known/openid-configuration"
    return None


def _required_claims(tenant: str) -> Mapping[str, Equals | NotEquals]:
    """Return required claims for the tenant."""
    if tenant == "common":
        return {}
    if tenant == "organizations":
        return {"tid": NotEquals(value=CONSUMERS_TENANT_ID)}
    if tenant == "consumers":
        return {"tid": Equals(value=CONSUMERS_TENANT_ID)}
    return {"tid": Equals(value=tenant)}
