"""GitHub protocol for GitHub Sign-In.

GitHub OAuth apps have no OpenID Connect, so the account comes from the user
API, read with the access token of the same exchange.
"""

from dataclasses import dataclass
from typing import override

from homeassistant.components.auth import (
    IdentityProvider,
    OAuth2IdentityClient,
    OidcError,
    ProtocolSpec,
    async_bearer_get,
)
from homeassistant.core import HomeAssistant

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
PROFILE_URL = "https://api.github.com/user"
# Credentials are keyed by the API that answers who the user is.
ISSUER = "https://api.github.com"

_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


class GitHubClient(OAuth2IdentityClient):
    """Sign users in with a GitHub OAuth app."""

    @override
    async def async_fetch_identity(self, access_token: str) -> tuple[str, str | None]:
        """Return the GitHub user ID and login."""
        body = await async_bearer_get(
            self.hass,
            PROFILE_URL,
            access_token,
            endpoint="profile",
            fetching="the profile",
            headers=_HEADERS,
        )
        if not isinstance(body, dict):
            raise OidcError("Profile endpoint did not return a JSON object")

        # The login can be renamed and reused, so only the numeric ID identifies.
        user_id = body.get("id")
        if isinstance(user_id, bool) or not isinstance(user_id, int):
            raise OidcError("Profile has no usable user ID")

        login = body.get("login")
        return str(user_id), login if isinstance(login, str) and login else None


@dataclass(frozen=True, slots=True, kw_only=True)
class GitHubOAuth2(ProtocolSpec):
    """GitHub OAuth app sign-in."""

    @override
    def create_client(
        self, hass: HomeAssistant, spec: IdentityProvider
    ) -> GitHubClient:
        """Return the GitHub client."""
        return GitHubClient(
            hass,
            issuer=ISSUER,
            authorize_url=AUTHORIZE_URL,
            token_url=TOKEN_URL,
            client_id=spec.client_id,
            client_secret=spec.client_secret,
            token_auth_method="client_secret_post",
        )
