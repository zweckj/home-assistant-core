"""Constants for the Microsoft Sign-In integration."""

DOMAIN = "microsoft_sign_in"

CONF_ACCOUNTS = "accounts"
CONF_ADMIN_GROUP = "admin_group"
CONF_REVALIDATE_INTERVAL = "revalidate_interval"
CONF_TENANT = "tenant"

BASE_URL = "https://login.microsoftonline.com"
CONSUMERS_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad"
DEFAULT_REVALIDATE_INTERVAL = 1440
# Tenants anyone with a Microsoft account can sign in to.
MULTI_TENANT_KEYWORDS = frozenset({"common", "organizations"})
TENANT_KEYWORDS = MULTI_TENANT_KEYWORDS | {"consumers"}
