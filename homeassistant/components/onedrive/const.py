"""Constants for the OneDrive integration."""

from collections.abc import Callable
from typing import Final

from homeassistant.util.hass_dict import HassKey

DOMAIN: Final = "onedrive"
CONF_FOLDER_NAME: Final = "folder_name"
CONF_FOLDER_ID: Final = "folder_id"
CONF_BUSINESS: Final = "business"

CONF_DELETE_PERMANENTLY: Final = "delete_permanently"

# OAuth URLs for personal accounts
OAUTH2_AUTHORIZE_PERSONAL: Final = (
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
)
OAUTH2_TOKEN_PERSONAL: Final = (
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
)

# OAuth URLs for business accounts
OAUTH2_AUTHORIZE_BUSINESS: Final = (
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
)
OAUTH2_TOKEN_BUSINESS: Final = (
    "https://login.microsoftonline.com/common/oauth2/v2.0/token"
)

# OAuth scopes for personal accounts
OAUTH_SCOPES_PERSONAL: Final = [
    "Files.ReadWrite.AppFolder",
    "offline_access",
    "openid",
]

# OAuth scopes for business accounts
OAUTH_SCOPES_BUSINESS: Final = [
    "Files.ReadWrite.All",
    "offline_access",
    "openid",
]

# Backwards compatibility
OAUTH2_AUTHORIZE: Final = OAUTH2_AUTHORIZE_PERSONAL
OAUTH2_TOKEN: Final = OAUTH2_TOKEN_PERSONAL
OAUTH_SCOPES: Final = OAUTH_SCOPES_PERSONAL

DATA_BACKUP_AGENT_LISTENERS: HassKey[list[Callable[[], None]]] = HassKey(
    f"{DOMAIN}.backup_agent_listeners"
)
