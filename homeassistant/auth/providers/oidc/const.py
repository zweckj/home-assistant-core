"""Constants for the OpenID Connect auth provider."""

from typing import Final

PROVIDER_TYPE: Final = "oidc"

STORAGE_VERSION: Final = 1
STORAGE_KEY: Final = "auth_provider.oidc"

# Keys of the credential data that identify a user at the identity provider.
# A subject is only unique within an issuer, so both are needed.
CONF_ISSUER: Final = "issuer"
CONF_SUBJECT: Final = "subject"

DEFAULT_SCOPES: Final = ("openid", "profile", "email")
DISCOVERY_PATH: Final = "/.well-known/openid-configuration"

HTTP_TIMEOUT: Final = 30

DISCOVERY_CACHE_TTL: Final = 3600
JWKS_CACHE_TTL: Final = 3600
# An unknown key id triggers a JWKS refetch, so rate limit it to keep an
# attacker from using bogus tokens to hammer the identity provider.
JWKS_REFETCH_COOLDOWN: Final = 60

# Tolerance for clock drift between Home Assistant and the identity provider.
CLOCK_SKEW_LEEWAY: Final = 30

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
