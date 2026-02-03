"""Constants for the OneDrive integration."""

from collections.abc import Callable
from enum import StrEnum
from typing import Final

from homeassistant.util.hass_dict import HassKey

DOMAIN: Final = "onedrive"
CONF_FOLDER_NAME: Final = "folder_name"
CONF_FOLDER_ID: Final = "folder_id"
CONF_ACCOUNT_TYPE: Final = "account_type"
CONF_TENANT_ID: Final = "tenant_id"

CONF_DELETE_PERMANENTLY: Final = "delete_permanently"


class AccountType(StrEnum):
    """Account types for OneDrive."""

    PERSONAL = "personal"
    BUSINESS = "business"


# Personal account OAuth URLs (using "consumers" endpoint)
OAUTH2_AUTHORIZE: Final = (
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
)
OAUTH2_TOKEN: Final = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"

OAUTH_SCOPES_PERSONAL: Final = [
    "Files.ReadWrite.AppFolder",
    "offline_access",
    "openid",
]

OAUTH_SCOPES_BUSINESS: Final = [
    "Files.ReadWrite.All",
    "offline_access",
    "openid",
]

DATA_BACKUP_AGENT_LISTENERS: HassKey[list[Callable[[], None]]] = HassKey(
    f"{DOMAIN}.backup_agent_listeners"
)
