"""Constants for the auth module."""

from datetime import timedelta

ACCESS_TOKEN_EXPIRATION = timedelta(minutes=30)
MFA_SESSION_EXPIRATION = timedelta(minutes=5)
REFRESH_TOKEN_EXPIRATION = timedelta(days=90).total_seconds()

GROUP_ID_ADMIN = "system-admin"
GROUP_ID_USER = "system-users"
GROUP_ID_READ_ONLY = "system-read-only"

# Where a login flow that sent the browser away comes back to. Lives here so a
# provider can build a redirect URI without reaching into the auth component.
LOGIN_CALLBACK_PATH = "/auth/login_callback"
# Matches how long a login may stay parked at an external party.
LOGIN_STATE_EXPIRATION = 300
