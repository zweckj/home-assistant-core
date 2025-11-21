"""Application credentials platform for the OneDrive integration."""

from homeassistant.components.application_credentials import AuthorizationServer
from homeassistant.core import HomeAssistant

from .const import OAUTH2_AUTHORIZE_PERSONAL, OAUTH2_TOKEN_PERSONAL


async def async_get_authorization_server(hass: HomeAssistant) -> AuthorizationServer:
    """Return authorization server."""
    return AuthorizationServer(
        authorize_url=OAUTH2_AUTHORIZE_PERSONAL,
        token_url=OAUTH2_TOKEN_PERSONAL,
    )
