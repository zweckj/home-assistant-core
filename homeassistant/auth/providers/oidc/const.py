"""Constants for the OpenID Connect auth provider."""

from datetime import timedelta
from typing import Final

PROVIDER_TYPE: Final = "oidc"

STORAGE_VERSION: Final = 1
STORAGE_KEY: Final = "auth_provider.oidc"

# Keys of the credential data that identify a user at the identity provider.
# A subject is only unique within an issuer, so both are needed.
CONF_ISSUER: Final = "issuer"
CONF_SUBJECT: Final = "subject"

DEFAULT_SCOPES: Final = ["openid", "profile", "email"]
DEFAULT_USERNAME_CLAIM: Final = "preferred_username"
DEFAULT_DISPLAY_NAME_CLAIM: Final = "name"

GROUPS_CLAIM: Final = "groups"
DEFAULT_ADMIN_GROUP: Final = "home_assistant_admin"

DISCOVERY_PATH: Final = "/.well-known/openid-configuration"

AUTH_CALLBACK_PATH: Final = "/auth/oidc/callback"

HTTP_TIMEOUT: Final = 30

DISCOVERY_CACHE_TTL: Final = 3600
JWKS_CACHE_TTL: Final = 3600
# An unknown key id triggers a JWKS refetch, so rate limit it to keep an
# attacker from using bogus tokens to hammer the identity provider.
JWKS_REFETCH_COOLDOWN: Final = 60

# Tolerance for clock drift between Home Assistant and the identity provider.
CLOCK_SKEW_LEEWAY: Final = 30

# How long the user has to complete the redirect to the identity provider.
LOGIN_STATE_EXPIRATION: Final = 300

# Only asymmetric signatures are acceptable for ID tokens. HMAC would let anyone
# holding the client secret mint tokens, and "none" is unsigned entirely.
ALLOWED_ID_TOKEN_ALGORITHMS: Final = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)
# Mandatory to implement per OpenID Connect Core, assumed when discovery is silent.
DEFAULT_ID_TOKEN_ALGORITHM: Final = "RS256"

# The only PKCE challenge method worth having; "plain" offers no protection.
PKCE_CHALLENGE_METHOD: Final = "S256"

# How long a Home Assistant session may live before the identity provider has to
# confirm that the user is still allowed to sign in.
DEFAULT_REVALIDATE_INTERVAL: Final = 86400
MIN_REVALIDATE_INTERVAL: Final = 300
MAX_REVALIDATE_INTERVAL: Final = 30 * 86400

# Try the silent refresh once this fraction of the interval has elapsed, leaving
# room to retry before the session is hard expired.
REVALIDATE_REFRESH_RATIO: Final = 0.5
REVALIDATE_CHECK_INTERVAL: Final = timedelta(minutes=1)
