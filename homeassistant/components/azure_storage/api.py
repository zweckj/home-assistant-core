"""Token authentication."""

from typing import Any

from azure.core.credentials import AccessToken
from azure.core.credentials_async import AsyncTokenCredential

from homeassistant.helpers import config_entry_oauth2_flow


class AsyncConfigEntryAuth(AsyncTokenCredential):
    """Provide authentication tied to an OAuth2 based config entry."""

    def __init__(
        self,
        oauth_session: config_entry_oauth2_flow.OAuth2Session,
    ) -> None:
        """Initialize AsyncConfigEntryAuth."""
        super().__init__()
        self._oauth_session = oauth_session

    async def get_token(
        self,
        *scopes: str,
        claims: str | None = None,
        tenant_id: str | None = None,
        enable_cae: bool = False,
        **kwargs: Any,
    ) -> AccessToken:
        """Get the token from the config entry."""
        await self._oauth_session.async_ensure_token_valid()
        return AccessToken(
            token=self._oauth_session.token["access_token"],
            expires_on=self._oauth_session.token["expires_at"],
        )
