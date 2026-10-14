"""Config flow for GitHub Sign-In."""

import probatio

from homeassistant.components.auth import IdentityProviderConfigFlow
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import DOMAIN
from .identity_provider import get_identity_provider

DEVELOPER_SETTINGS_URL = "https://github.com/settings/developers"


class GitHubSignInConfigFlow(IdentityProviderConfigFlow, domain=DOMAIN):
    """Handle a GitHub Sign-In config flow."""

    TITLE = "GitHub"
    DATA_SCHEMA = probatio.Schema(
        {
            probatio.Required(CONF_CLIENT_ID): TextSelector(
                TextSelectorConfig(autocomplete="off")
            ),
            probatio.Required(CONF_CLIENT_SECRET): TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            ),
        }
    )
    USER_PLACEHOLDERS = {"developer_settings_url": DEVELOPER_SETTINGS_URL}
    identity_provider = staticmethod(get_identity_provider)
