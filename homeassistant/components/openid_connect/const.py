"""Constants for the OpenID Connect integration."""

from homeassistant.components.auth import AccountPolicy

DOMAIN = "openid_connect"

CONF_ACCOUNT_NAME_CLAIM = "account_name_claim"
CONF_ACCOUNTS = "accounts"
CONF_ADMIN_GROUP = "admin_group"
CONF_ALLOW_INSECURE_TRANSPORT = "allow_insecure_transport"
CONF_DISPLAY_NAME_CLAIM = "display_name_claim"
CONF_ISSUER = "issuer"
CONF_REVALIDATE_INTERVAL = "revalidate_interval"
CONF_SCOPES = "scopes"
CONF_USERNAME_CLAIM = "username_claim"

DEFAULT_ACCOUNT_NAME_CLAIM = "email"
DEFAULT_ACCOUNTS = AccountPolicy.LINK.value
DEFAULT_DISPLAY_NAME_CLAIM = "name"
DEFAULT_REVALIDATE_INTERVAL = 1440
DEFAULT_SCOPES = "openid profile email"
DEFAULT_USERNAME_CLAIM = "preferred_username"
