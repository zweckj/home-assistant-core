"""Config flow for Google Sign-In."""

import probatio

from homeassistant.components.auth import IdentityProviderConfigFlow
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import DOMAIN
from .identity_provider import _identity_provider

CONSOLE_URL = "https://console.cloud.google.com/apis/credentials"


class GoogleSignInConfigFlow(IdentityProviderConfigFlow, domain=DOMAIN):
    """Handle a Google Sign-In config flow."""

    TITLE = "Google"
    DATA_SCHEMA = probatio.Schema(
        {
            probatio.Required(CONF_CLIENT_ID): TextSelector(TextSelectorConfig()),
            probatio.Required(CONF_CLIENT_SECRET): TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            ),
        }
    )
    USER_PLACEHOLDERS = {"console_url": CONSOLE_URL}
    identity_provider = staticmethod(_identity_provider)
