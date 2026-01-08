"""OpenID Connect authentication provider.

This provider allows authentication via OpenID Connect (OIDC) identity providers.
It uses the authorization code flow with proper JWKS signature verification.
"""

from __future__ import annotations

from collections.abc import Mapping
import logging
from secrets import token_hex
from typing import Any, cast

from aiohttp import ClientError
from jose import jwt
from jose.exceptions import JWTError
import voluptuous as vol
from yarl import URL

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.config_entry_oauth2_flow import LocalOAuth2Implementation

from ..models import AuthFlowContext, AuthFlowResult, Credentials, UserMeta
from . import AUTH_PROVIDER_SCHEMA, AUTH_PROVIDERS, AuthProvider, LoginFlow

_LOGGER = logging.getLogger(__name__)

CONF_CONFIGURATION = "configuration"
CONF_CLIENT_ID = "client_id"
CONF_CLIENT_SECRET = "client_secret"

DOMAIN = "openid_connect"
WANTED_SCOPES = {"openid", "email", "profile"}


CONFIG_SCHEMA = AUTH_PROVIDER_SCHEMA.extend(
    {
        vol.Required(CONF_CONFIGURATION): str,
        vol.Required(CONF_CLIENT_ID): str,
        vol.Required(CONF_CLIENT_SECRET): str,
    },
    extra=vol.PREVENT_EXTRA,
)

OPENID_CONFIGURATION_SCHEMA = vol.Schema(
    {
        vol.Required("issuer"): str,
        vol.Required("jwks_uri"): str,
        vol.Required("id_token_signing_alg_values_supported"): list,
        vol.Optional("scopes_supported"): vol.Contains("openid"),
        vol.Required("token_endpoint"): str,
        vol.Required("authorization_endpoint"): str,
        vol.Required("response_types_supported"): vol.Contains("code"),
        vol.Optional(
            "token_endpoint_auth_methods_supported", default=["client_secret_basic"]
        ): vol.Contains("client_secret_post"),
        vol.Optional(
            "grant_types_supported", default=["authorization_code", "implicit"]
        ): vol.Contains("authorization_code"),
    },
    extra=vol.ALLOW_EXTRA,
)


class InvalidAuthError(HomeAssistantError):
    """Raised when submitting invalid authentication."""


async def async_get_configuration(
    hass: HomeAssistant, configuration_url: str
) -> dict[str, Any]:
    """Get discovery document for OpenID."""
    session = async_get_clientsession(hass)
    try:
        resp = await session.get(configuration_url)
        resp.raise_for_status()
    except ClientError as err:
        raise InvalidAuthError(f"Failed to fetch configuration: {err}") from err
    data = await resp.json()
    return cast(dict[str, Any], OPENID_CONFIGURATION_SCHEMA(data))


class OpenIdConnectOAuth2Implementation(LocalOAuth2Implementation):
    """OAuth2 implementation for OpenID Connect."""

    _nonce: str | None = None
    _scope: str

    def __init__(
        self,
        hass: HomeAssistant,
        client_id: str,
        client_secret: str,
        configuration: dict[str, Any],
    ) -> None:
        """Initialize the OAuth2 implementation."""
        super().__init__(
            hass,
            DOMAIN,
            client_id,
            client_secret,
            configuration["authorization_endpoint"],
            configuration["token_endpoint"],
        )
        scopes_supported = configuration.get("scopes_supported", list(WANTED_SCOPES))
        self._scope = " ".join(sorted(WANTED_SCOPES.intersection(scopes_supported)))

    @property
    def extra_authorize_data(self) -> dict:
        """Extra data that needs to be appended to the authorize url."""
        return {"scope": self._scope, "nonce": self._nonce}

    def generate_authorize_url(
        self, redirect_uri: str, state: str, nonce: str
    ) -> str:
        """Generate the authorization URL."""
        self._nonce = nonce
        url = str(
            URL(self.authorize_url)
            .with_query(
                {
                    "response_type": "code",
                    "client_id": self.client_id,
                    "redirect_uri": redirect_uri,
                    "state": state,
                }
            )
            .update_query(self.extra_authorize_data)
        )
        self._nonce = None
        return url


@AUTH_PROVIDERS.register("openid_connect")
class OpenIdConnectAuthProvider(AuthProvider):
    """Authentication provider using OpenID Connect."""

    DEFAULT_TITLE = "OpenID Connect"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the auth provider."""
        super().__init__(*args, **kwargs)
        self._configuration: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None
        self._oauth2: OpenIdConnectOAuth2Implementation | None = None

    async def async_get_configuration(self) -> dict[str, Any]:
        """Get discovery document for OpenID."""
        return await async_get_configuration(
            self.hass, self.config[CONF_CONFIGURATION]
        )

    async def async_get_jwks(self) -> dict[str, Any]:
        """Get the keys for ID token verification."""
        if self._configuration is None:
            raise InvalidAuthError("Configuration not loaded")
        session = async_get_clientsession(self.hass)
        try:
            resp = await session.get(self._configuration["jwks_uri"])
            resp.raise_for_status()
        except ClientError as err:
            raise InvalidAuthError(f"Failed to fetch JWKS: {err}") from err
        return cast(dict[str, Any], await resp.json())

    async def async_login_flow(
        self, context: AuthFlowContext | None
    ) -> OpenIdConnectLoginFlow:
        """Return a flow to login."""
        if self._configuration is None:
            self._configuration = await self.async_get_configuration()

        if self._jwks is None:
            self._jwks = await self.async_get_jwks()

        self._oauth2 = OpenIdConnectOAuth2Implementation(
            self.hass,
            self.config[CONF_CLIENT_ID],
            self.config[CONF_CLIENT_SECRET],
            self._configuration,
        )
        return OpenIdConnectLoginFlow(self, context)

    def generate_authorize_url(
        self, redirect_uri: str, state: str, nonce: str
    ) -> str:
        """Generate the authorization URL."""
        if self._oauth2 is None:
            raise InvalidAuthError("OAuth2 implementation not initialized")
        return self._oauth2.generate_authorize_url(redirect_uri, state, nonce)

    async def async_resolve_external_data(
        self, external_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Resolve external data to tokens."""
        if self._oauth2 is None:
            raise InvalidAuthError("OAuth2 implementation not initialized")
        return cast(
            dict[str, Any],
            await self._oauth2.async_resolve_external_data(external_data),
        )

    def decode_id_token(self, token: dict[str, Any], nonce: str) -> dict[str, Any]:
        """Decode and verify the OpenID ID token."""
        if self._configuration is None or self._jwks is None:
            raise InvalidAuthError("Provider not properly initialized")

        algorithms = self._configuration["id_token_signing_alg_values_supported"]
        issuer = self._configuration["issuer"]

        try:
            id_token = jwt.decode(
                token["id_token"],
                algorithms=algorithms,
                issuer=issuer,
                key=self._jwks,
                audience=self.config[CONF_CLIENT_ID],
                access_token=token["access_token"],
            )
        except JWTError as err:
            raise InvalidAuthError(f"Invalid ID token: {err}") from err

        if id_token.get("nonce") != nonce:
            raise InvalidAuthError("Nonce mismatch in ID token")

        return cast(dict[str, Any], id_token)

    @property
    def support_mfa(self) -> bool:
        """Return whether multi-factor auth supported by the auth provider."""
        return False

    async def async_get_or_create_credentials(
        self, flow_result: Mapping[str, str]
    ) -> Credentials:
        """Get credentials based on the flow result."""
        subject = flow_result["sub"]

        for credential in await self.async_credentials():
            if credential.data.get("sub") == subject:
                return credential

        return self.async_create_credentials({**flow_result})

    async def async_user_meta_for_credentials(
        self, credentials: Credentials
    ) -> UserMeta:
        """Return extra user metadata for credentials."""
        if "preferred_username" in credentials.data:
            name = credentials.data["preferred_username"]
        elif "given_name" in credentials.data:
            name = credentials.data["given_name"]
        elif "name" in credentials.data:
            name = credentials.data["name"]
        elif "email" in credentials.data:
            name = cast(str, credentials.data["email"]).split("@", 1)[0]
        else:
            name = credentials.data["sub"]
        return UserMeta(name=name, is_active=True)


class OpenIdConnectLoginFlow(LoginFlow[OpenIdConnectAuthProvider]):
    """Handler for the OpenID Connect login flow."""

    _nonce: str
    _external_data: dict[str, Any]

    def __init__(
        self,
        auth_provider: OpenIdConnectAuthProvider,
        context: AuthFlowContext | None,
    ) -> None:
        """Initialize the login flow."""
        super().__init__(auth_provider)
        self._context = context

    async def async_step_init(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Handle the initial step."""
        return await self.async_step_authenticate()

    async def async_step_authenticate(
        self, user_input: dict[str, Any] | None = None
    ) -> AuthFlowResult:
        """Authenticate user using external step."""
        if user_input:
            self._external_data = user_input
            return self.async_external_step_done(next_step_id="authorize")

        if self._context is None:
            return self.async_abort(reason="no_context")

        redirect_uri = self._context.get("redirect_uri")
        if not redirect_uri:
            return self.async_abort(reason="no_redirect_uri")

        self._nonce = token_hex()
        url = self._auth_provider.generate_authorize_url(
            redirect_uri=redirect_uri,
            state=self.flow_id,
            nonce=self._nonce,
        )
        return self.async_external_step(step_id="authenticate", url=url)

    async def async_step_authorize(
        self, user_input: dict[str, str] | None = None
    ) -> AuthFlowResult:
        """Authorize user received from external step."""
        if "error" in self._external_data:
            _LOGGER.error("OAuth error: %s", self._external_data["error"])
            return self.async_abort(reason="oauth_error")

        if "code" not in self._external_data:
            return self.async_abort(reason="no_code")

        try:
            token = await self._auth_provider.async_resolve_external_data(
                self._external_data
            )
            id_token = self._auth_provider.decode_id_token(token, self._nonce)
        except InvalidAuthError as err:
            _LOGGER.error("Login failed: %s", err)
            return self.async_abort(reason="invalid_auth")

        return await self.async_finish(id_token)
