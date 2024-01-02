"""Constants for the Tedee integration."""
from datetime import timedelta

DOMAIN = "tedee"
NAME = "Tedee"

SCAN_INTERVAL = timedelta(seconds=10)

CONF_LOCAL_ACCESS_TOKEN = "local_access_token"
CONF_USE_LOCAL_API = "use_local_api"
CONF_USE_CLOUD_API = "use_cloud_api"
CONF_CLOUD_BRIDGE_ID = "cloud_bridge_id"
