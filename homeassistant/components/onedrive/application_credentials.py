"""Application credentials platform for the OneDrive integration."""

from homeassistant.components.application_credentials import (
    AuthImplementation,
    AuthorizationServer,
    ClientCredential,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_entry_oauth2_flow

from .const import (
    AUTH_DOMAIN_BUSINESS_PREFIX,
    ENTRA_URL,
    OAUTH2_AUTHORIZE,
    OAUTH2_TOKEN,
    REDIRECT_URL,
)


async def async_get_auth_implementation(
    hass: HomeAssistant, auth_domain: str, credential: ClientCredential
) -> config_entry_oauth2_flow.AbstractOAuth2Implementation:
    """Return auth implementation.

    For business accounts (identified by having a tenant_id in auth_domain),
    use tenant-specific OAuth URLs. For personal accounts, use the default
    consumer endpoints.
    """
    # Check if this is a business credential by checking if auth_domain contains tenant info
    # Business credentials are stored with auth_domain format: "onedrive_business_{tenant_id}"
    if auth_domain.startswith(AUTH_DOMAIN_BUSINESS_PREFIX):
        tenant_id = auth_domain.replace(AUTH_DOMAIN_BUSINESS_PREFIX, "")
        authorize_url = (
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        )
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    else:
        authorize_url = OAUTH2_AUTHORIZE
        token_url = OAUTH2_TOKEN

    return AuthImplementation(
        hass,
        auth_domain,
        credential,
        AuthorizationServer(
            authorize_url=authorize_url,
            token_url=token_url,
        ),
    )


async def async_get_description_placeholders(hass: HomeAssistant) -> dict[str, str]:
    """Return description placeholders for the credentials dialog."""
    return {
        "entra_url": ENTRA_URL,
        "redirect_url": REDIRECT_URL,
    }
