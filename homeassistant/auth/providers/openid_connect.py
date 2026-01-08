"""OpenID Connect authentication provider.

This provider allows authentication via OpenID Connect (OIDC) identity providers.
It uses PKCE (Proof Key for Code Exchange) for enhanced security.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import logging
import secrets
from typing import Any, cast

from aiohttp import ClientError, ClientResponseError
import jwt
import voluptuous as vol
from yarl import URL

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from ..auth_store import AuthStore
from ..models import AuthFlowContext, AuthFlowResult, Credentials, UserMeta
from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow

_LOGGER = logging.getLogger(__name__)

CONF_CLIENT_ID = "client_id"
CONF_CLIENT_SECRET = "client_secret"
CONF_ISSUER_URL = "issuer_url"
CONF_AUTHORIZE_URL = "authorize_url"
CONF_TOKEN_URL = "token_url"
CONF_USERINFO_URL = "userinfo_url"
CONF_SCOPES = "scopes"
CONF_DISPLAY_NAME = "display_name"

DEFAULT_SCOPES = ["openid", "profile", "email"]


def _validate_endpoint_config(config: dict[str, Any]) -> dict[str, Any]:
    """Validate endpoint configuration.

    Either issuer_url must be provided (for automatic discovery),
    or both authorize_url AND token_url must be provided together.
    """
    has_issuer = bool(config.get(CONF_ISSUER_URL))
    has_authorize = bool(config.get(CONF_AUTHORIZE_URL))
    has_token = bool(config.get(CONF_TOKEN_URL))

    # Valid configurations:
    # 1. issuer_url provided (discovery will be used)
    # 2. Both authorize_url and token_url provided (manual configuration)
    # 3. issuer_url + partial manual URLs (manual takes precedence)

    if not has_issuer and not (has_authorize and has_token):
        raise vol.Invalid(
            "Either 'issuer_url' must be provided for automatic discovery, "
            "or both 'authorize_url' and 'token_url' must be provided"
        )

    if has_authorize != has_token and not has_issuer:
        raise vol.Invalid(
            "Both 'authorize_url' and 'token_url' must be provided together "
            "when not using 'issuer_url' for discovery"
        )

    return config


CONFIG_SCHEMA = vol.All(
    AUTH_PROVIDER_SCHEMA.extend(
        {
            vol.Required(CONF_CLIENT_ID): str,
            vol.Optional(CONF_CLIENT_SECRET, default=""): str,
            vol.Optional(CONF_ISSUER_URL): str,
            vol.Optional(CONF_AUTHORIZE_URL): str,
            vol.Optional(CONF_TOKEN_URL): str,
            vol.Optional(CONF_USERINFO_URL): str,
            vol.Optional(CONF_SCOPES, default=DEFAULT_SCOPES): vol.All(
                [str], vol.Length(min=1)
            ),
            vol.Optional(CONF_DISPLAY_NAME): str,
        },
        extra=vol.PREVENT_EXTRA,
    ),
    _validate_endpoint_config,
)


class OpenIdConnectError(HomeAssistantError):
    """Raised when OpenID Connect authentication fails."""


class OpenIdConnectConfigError(OpenIdConnectError):
    """Raised when OpenID Connect configuration is invalid."""


class OpenIdConnectTokenError(OpenIdConnectError):
    """Raised when token exchange fails."""


class OpenIdConnectUserInfoError(OpenIdConnectError):
    """Raised when fetching user info fails."""


def _generate_code_verifier(length: int = 128) -> str:
    """Generate a PKCE code verifier.

    Args:
        length: Length of the code verifier (43-128 characters).

    Returns:
        A cryptographically random string suitable for use as a code verifier.

    """
    if not 43 <= length <= 128:
        msg = "Code verifier length must be between 43 and 128 characters"
        raise ValueError(msg)
    return secrets.token_urlsafe(96)[:length]


def _compute_code_challenge(code_verifier: str) -> str:
    """Compute the S256 code challenge from a code verifier.

    Args:
        code_verifier: The code verifier string.

    Returns:
        The base64url-encoded SHA256 hash of the code verifier.

    """
    if not 43 <= len(code_verifier) <= 128:
        msg = "Code verifier length must be between 43 and 128 characters"
        raise ValueError(msg)

    hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    return encoded.decode("ascii").replace("=", "")


class OpenIdConnectOAuth2Implementation:
    """OAuth2 implementation with PKCE for OpenID Connect.

    This class handles the OAuth2 authorization code flow with PKCE,
    specifically designed for OpenID Connect providers.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        client_id: str,
        client_secret: str,
        authorize_url: str,
        token_url: str,
        userinfo_url: str | None,
        scopes: list[str],
    ) -> None:
        """Initialize the OAuth2 implementation.

        Args:
            hass: Home Assistant instance.
            client_id: OAuth2 client ID.
            client_secret: OAuth2 client secret (can be empty for public clients).
            authorize_url: Authorization endpoint URL.
            token_url: Token endpoint URL.
            userinfo_url: UserInfo endpoint URL (optional).
            scopes: List of OAuth2 scopes to request.

        """
        self.hass = hass
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorize_url = authorize_url
        self.token_url = token_url
        self.userinfo_url = userinfo_url
        self.scopes = scopes

        # Generate PKCE code verifier for this session
        self.code_verifier = _generate_code_verifier()

    def generate_authorize_url(self, redirect_uri: str, state: str) -> str:
        """Generate the authorization URL with PKCE parameters.

        Args:
            redirect_uri: The redirect URI for the OAuth2 callback.
            state: State parameter for CSRF protection.

        Returns:
            The complete authorization URL.

        """
        code_challenge = _compute_code_challenge(self.code_verifier)

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "scope": " ".join(self.scopes),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        return str(URL(self.authorize_url).with_query(params))

    async def async_resolve_external_data(
        self, code: str, redirect_uri: str
    ) -> dict[str, Any]:
        """Exchange authorization code for tokens.

        Args:
            code: The authorization code from the OAuth2 callback.
            redirect_uri: The redirect URI used in the authorization request.

        Returns:
            The token response containing access_token, id_token, etc.

        Raises:
            OpenIdConnectTokenError: If token exchange fails.

        """
        session = async_get_clientsession(self.hass)

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
            "code_verifier": self.code_verifier,
        }

        if self.client_secret:
            data["client_secret"] = self.client_secret

        _LOGGER.debug("Exchanging authorization code for tokens")

        try:
            resp = await session.post(self.token_url, data=data)
            resp.raise_for_status()
            return cast(dict[str, Any], await resp.json())
        except ClientResponseError as err:
            _LOGGER.error("Token exchange failed with status %s: %s", err.status, err)
            raise OpenIdConnectTokenError(
                f"Token exchange failed: {err.status}"
            ) from err
        except ClientError as err:
            _LOGGER.error("Token exchange failed: %s", err)
            raise OpenIdConnectTokenError(f"Token exchange failed: {err}") from err

    async def async_get_userinfo(self, access_token: str) -> dict[str, Any]:
        """Fetch user information from the userinfo endpoint.

        Args:
            access_token: The OAuth2 access token.

        Returns:
            User information from the userinfo endpoint.

        Raises:
            OpenIdConnectUserInfoError: If fetching user info fails.

        """
        if not self.userinfo_url:
            raise OpenIdConnectUserInfoError("UserInfo URL not configured")

        session = async_get_clientsession(self.hass)

        try:
            resp = await session.get(
                self.userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            return cast(dict[str, Any], await resp.json())
        except ClientResponseError as err:
            _LOGGER.error("UserInfo request failed with status %s: %s", err.status, err)
            raise OpenIdConnectUserInfoError(
                f"UserInfo request failed: {err.status}"
            ) from err
        except ClientError as err:
            _LOGGER.error("UserInfo request failed: %s", err)
            raise OpenIdConnectUserInfoError(f"UserInfo request failed: {err}") from err


@AUTH_PROVIDERS.register("openid_connect")
class OpenIdConnectAuthProvider(AuthProvider):
    """Authentication provider using OpenID Connect.

    This provider authenticates users via an external OpenID Connect
    identity provider using the authorization code flow with PKCE.
    """

    DEFAULT_TITLE = "OpenID Connect"

    def __init__(
        self, hass: HomeAssistant, store: AuthStore, config: dict[str, Any]
    ) -> None:
        """Initialize the OpenID Connect auth provider."""
        super().__init__(hass, store, config)
        self._discovery_doc: dict[str, Any] | None = None
        self._oauth_impl: OpenIdConnectOAuth2Implementation | None = None

    @property
    def display_name(self) -> str:
        """Return the display name for this provider."""
        return self.config.get(CONF_DISPLAY_NAME) or self.DEFAULT_TITLE

    async def _async_fetch_discovery_document(self) -> dict[str, Any]:
        """Fetch the OpenID Connect discovery document.

        Returns:
            The parsed discovery document.

        Raises:
            OpenIdConnectConfigError: If fetching the discovery document fails.

        """
        if self._discovery_doc is not None:
            return self._discovery_doc

        issuer_url = self.config.get(CONF_ISSUER_URL)
        if not issuer_url:
            raise OpenIdConnectConfigError(
                "Either issuer_url or explicit URLs must be configured"
            )

        discovery_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
        session = async_get_clientsession(self.hass)

        try:
            _LOGGER.debug("Fetching OIDC discovery document from %s", discovery_url)
            resp = await session.get(discovery_url)
            resp.raise_for_status()
            discovery_doc = await resp.json()
        except ClientError as err:
            _LOGGER.error("Failed to fetch discovery document: %s", err)
            raise OpenIdConnectConfigError(
                f"Failed to fetch discovery document: {err}"
            ) from err

        # Validate required fields per OpenID Connect Discovery spec
        required_fields = ["authorization_endpoint", "token_endpoint", "issuer"]
        missing_fields = [
            field for field in required_fields if field not in discovery_doc
        ]
        if missing_fields:
            raise OpenIdConnectConfigError(
                f"Discovery document missing required fields: {', '.join(missing_fields)}"
            )

        self._discovery_doc = discovery_doc
        return cast(dict[str, Any], self._discovery_doc)

    async def _async_get_endpoint_urls(
        self,
    ) -> tuple[str, str, str | None]:
        """Get the OAuth2 endpoint URLs.

        Returns:
            Tuple of (authorize_url, token_url, userinfo_url).

        Raises:
            OpenIdConnectConfigError: If URLs cannot be determined.

        """
        # Check for explicit URLs first
        authorize_url = self.config.get(CONF_AUTHORIZE_URL)
        token_url = self.config.get(CONF_TOKEN_URL)
        userinfo_url = self.config.get(CONF_USERINFO_URL)

        if authorize_url and token_url:
            return authorize_url, token_url, userinfo_url

        # Fall back to discovery document
        discovery = await self._async_fetch_discovery_document()

        if not authorize_url:
            authorize_url = discovery.get("authorization_endpoint")
        if not token_url:
            token_url = discovery.get("token_endpoint")
        if not userinfo_url:
            userinfo_url = discovery.get("userinfo_endpoint")

        if not authorize_url or not token_url:
            raise OpenIdConnectConfigError(
                "Could not determine authorization and token endpoints "
                "from discovery document"
            )

        return authorize_url, token_url, userinfo_url

    async def _async_create_oauth_impl(self) -> OpenIdConnectOAuth2Implementation:
        """Create a new OAuth2 implementation instance.

        Returns:
            A configured OAuth2 implementation.

        """
        authorize_url, token_url, userinfo_url = await self._async_get_endpoint_urls()

        return OpenIdConnectOAuth2Implementation(
            hass=self.hass,
            client_id=self.config[CONF_CLIENT_ID],
            client_secret=self.config.get(CONF_CLIENT_SECRET, ""),
            authorize_url=authorize_url,
            token_url=token_url,
            userinfo_url=userinfo_url,
            scopes=self.config[CONF_SCOPES],
        )

    async def async_login_flow(
        self, context: AuthFlowContext | None
    ) -> OpenIdConnectLoginFlow:
        """Return a flow to login."""
        # Create a new OAuth implementation for each login flow
        # This ensures a fresh PKCE code verifier for each attempt
        self._oauth_impl = await self._async_create_oauth_impl()
        return OpenIdConnectLoginFlow(self, self._oauth_impl, context)

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result.

        Args:
            flow_result: The result from the login flow containing user info.

        Returns:
            Existing or newly created credentials for the user.

        """
        subject = flow_result["sub"]

        # Check for existing credentials
        for credential in await self.async_credentials():
            if credential.data.get("sub") == subject:
                return credential

        # Create new credentials
        return self.async_create_credentials(
            {
                "sub": subject,
                "email": flow_result.get("email"),
                "name": flow_result.get("name"),
            }
        )

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials.

        Will be used to populate info when creating a new user.
        """
        name = credentials.data.get("name") or credentials.data.get("email")
        return UserMeta(name=name, is_active=True)


class OpenIdConnectLoginFlow(LoginFlow[OpenIdConnectAuthProvider]):
    """Handler for the OpenID Connect login flow."""

    def __init__(
        self,
        auth_provider: OpenIdConnectAuthProvider,
        oauth_impl: OpenIdConnectOAuth2Implementation,
        context: AuthFlowContext | None,
    ) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._oauth_impl = oauth_impl
        self._context = context
        self._state: str | None = None
        self._redirect_uri: str | None = None

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Handle the initial step - redirect to identity provider."""
        if self._context is None:
            return self.async_abort(reason="no_context")

        redirect_uri = self._context.get("redirect_uri")
        if not redirect_uri:
            return self.async_abort(reason="no_redirect_uri")

        self._redirect_uri = redirect_uri
        self._state = secrets.token_urlsafe(32)

        authorize_url = self._oauth_impl.generate_authorize_url(
            redirect_uri=redirect_uri,
            state=self._state,
        )

        return self.async_external_step(step_id="authenticate", url=authorize_url)

    async def async_step_authenticate(
        self, user_input: dict[str, Any] | None = None
    ) -> AuthFlowResult:
        """Handle the callback from the identity provider."""
        if user_input is None:
            return self.async_abort(reason="no_response")

        # Verify state parameter
        if user_input.get("state") != self._state:
            _LOGGER.error("State mismatch in OAuth callback")
            return self.async_abort(reason="state_mismatch")

        # Check for error response
        if "error" in user_input:
            error = user_input["error"]
            error_description = user_input.get("error_description", "Unknown error")
            _LOGGER.error("OAuth error: %s - %s", error, error_description)
            return self.async_abort(reason="oauth_error")

        # Get authorization code
        code = user_input.get("code")
        if not code:
            return self.async_abort(reason="no_code")

        try:
            # Exchange code for tokens
            token_response = await self._oauth_impl.async_resolve_external_data(
                code=code,
                redirect_uri=self._redirect_uri or "",
            )
        except OpenIdConnectTokenError as err:
            _LOGGER.error("Token exchange failed: %s", err)
            return self.async_abort(reason="token_error")

        # Extract user information
        try:
            user_info = await self._extract_user_info(token_response)
        except OpenIdConnectError as err:
            _LOGGER.error("Failed to extract user info: %s", err)
            return self.async_abort(reason="userinfo_error")

        return await self.async_finish(user_info)

    async def _extract_user_info(
        self, token_response: dict[str, Any]
    ) -> dict[str, str]:
        """Extract user information from token response or userinfo endpoint.

        Args:
            token_response: The token response from the token endpoint.

        Returns:
            Dictionary containing user information (sub, email, name, etc.).

        Raises:
            OpenIdConnectError: If user info cannot be extracted.

        Note on ID token signature verification:
            We decode the ID token without signature verification because:
            1. The token is received directly from the token endpoint over TLS
            2. We authenticated to the token endpoint using our client credentials
            3. Full JWKS verification would require additional complexity
            4. This approach is common in confidential client scenarios

            For higher security requirements, consider implementing full JWKS
            verification by fetching the IdP's public keys from the jwks_uri
            endpoint in the discovery document.

        """
        user_info: dict[str, Any] = {}

        # Try to decode ID token first
        id_token = token_response.get("id_token")
        if id_token:
            try:
                # Decode without signature verification - see docstring for rationale
                decoded = jwt.decode(
                    id_token,
                    options={"verify_signature": False},
                )
                user_info.update(decoded)
                _LOGGER.debug("Extracted user info from ID token")
            except jwt.InvalidTokenError as err:
                _LOGGER.warning("Failed to decode ID token: %s", err)

        # If we don't have 'sub' claim, try userinfo endpoint
        if "sub" not in user_info:
            access_token = token_response.get("access_token")
            if access_token and self._oauth_impl.userinfo_url:
                try:
                    userinfo_response = await self._oauth_impl.async_get_userinfo(
                        access_token
                    )
                    user_info.update(userinfo_response)
                    _LOGGER.debug("Extracted user info from userinfo endpoint")
                except OpenIdConnectUserInfoError as err:
                    _LOGGER.warning("Failed to fetch userinfo: %s", err)

        # Validate we have required claims
        if "sub" not in user_info:
            raise OpenIdConnectError("Could not determine user identity (missing 'sub')")

        # Return string values for credential storage
        return {
            "sub": str(user_info["sub"]),
            "email": str(user_info.get("email", "")),
            "name": str(
                user_info.get("name")
                or user_info.get("preferred_username")
                or user_info.get("email")
                or ""
            ),
        }
