"""Offer API to configure the OpenID Connect auth provider."""

import logging
from typing import Any

import voluptuous as vol
from yarl import URL

from homeassistant.auth.providers.oidc import (
    OidcAuthProvider,
    OidcConfig,
    async_get_provider,
)
from homeassistant.auth.providers.oidc.client import OidcClient, OidcError
from homeassistant.auth.providers.oidc.const import (
    AUTH_CALLBACK_PATH,
    DEFAULT_ADMIN_GROUP,
    DEFAULT_DISPLAY_NAME_CLAIM,
    DEFAULT_REVALIDATE_INTERVAL,
    DEFAULT_SCOPES,
    DEFAULT_USERNAME_CLAIM,
    MAX_REVALIDATE_INTERVAL,
    MIN_REVALIDATE_INTERVAL,
    PROVIDER_TYPE,
)
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.network import NoURLAvailableError, get_url
from homeassistant.helpers.typing import VolDictType

_LOGGER = logging.getLogger(__name__)

# Matched on the credential rather than by importing the provider, so the two
# stay independent of one another.
PASSWORD_PROVIDER_TYPE = "homeassistant"


@callback
def async_setup(hass: HomeAssistant) -> bool:
    """Enable the OpenID Connect configuration commands."""
    websocket_api.async_register_command(hass, websocket_get)
    websocket_api.async_register_command(hass, websocket_update)
    websocket_api.async_register_command(hass, websocket_delete)
    websocket_api.async_register_command(hass, websocket_test)
    websocket_api.async_register_command(hass, websocket_unlink)
    return True


def _https_url(value: str) -> str:
    """Validate that a URL is https and has no query or fragment."""
    try:
        url = URL(value)
    except ValueError as err:
        raise vol.Invalid("must be an https URL") from err
    if url.scheme != "https" or not url.host:
        raise vol.Invalid("must be an https URL")
    if url.user is not None:
        raise vol.Invalid("must not contain credentials")
    if url.query_string or url.fragment:
        raise vol.Invalid("must not contain a query or fragment")
    return value


def _scopes(value: list[str]) -> list[str]:
    """Validate the requested scopes."""
    if "openid" not in value:
        raise vol.Invalid("the openid scope is required")
    return value


def _name(value: Any) -> str | None:
    """Validate the name the login screen offers the provider under."""
    if value is None:
        return None
    if not isinstance(value, str) or not (name := value.strip()):
        raise vol.Invalid("must be a name")
    return name


CONFIG_SCHEMA: VolDictType = {
    vol.Required("issuer"): vol.All(str, _https_url),
    vol.Required("client_id"): str,
    vol.Optional("client_secret"): vol.Any(str, None),
    vol.Optional("name", default=None): _name,
    vol.Optional("scopes", default=lambda: list(DEFAULT_SCOPES)): vol.All(
        [str], vol.Length(min=1), _scopes
    ),
    vol.Optional("username_claim", default=DEFAULT_USERNAME_CLAIM): str,
    vol.Optional("display_name_claim", default=DEFAULT_DISPLAY_NAME_CLAIM): str,
    vol.Optional("admin_group", default=DEFAULT_ADMIN_GROUP): vol.Any(str, None),
    vol.Optional("allow_auto_create", default=False): bool,
    vol.Optional("revalidate_interval"): vol.All(
        int, vol.Range(min=MIN_REVALIDATE_INTERVAL, max=MAX_REVALIDATE_INTERVAL)
    ),
}


@callback
def _async_provider(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> OidcAuthProvider | None:
    """Return the provider, reporting back when it is not enabled."""
    try:
        return async_get_provider(hass)
    except RuntimeError:
        connection.send_error(
            msg["id"], "not_enabled", "The OIDC auth provider is not enabled"
        )
        return None


@callback
def _async_redirect_uris(hass: HomeAssistant) -> list[str]:
    """Return the redirect URIs to register with the identity provider."""
    uris: list[str] = []
    for allow_internal, allow_external in ((False, True), (True, False)):
        try:
            base = get_url(
                hass,
                allow_internal=allow_internal,
                allow_external=allow_external,
                allow_cloud=False,
            )
        except NoURLAvailableError:
            continue
        if (uri := f"{base}{AUTH_CALLBACK_PATH}") not in uris:
            uris.append(uri)

    if not uris:
        _LOGGER.warning(
            "No URL is configured to build an OIDC redirect URI from, set an"
            " internal or external URL before registering the client"
        )
    return uris


@callback
def _config_to_dict(config: OidcConfig | None) -> dict[str, Any] | None:
    """Return the configuration without exposing the client secret."""
    if config is None:
        return None

    return {
        "issuer": config.issuer,
        "client_id": config.client_id,
        # The secret is write only, the UI only needs to know it is set.
        "client_secret_set": bool(config.client_secret),
        "name": config.name,
        "scopes": config.scopes,
        "username_claim": config.username_claim,
        "display_name_claim": config.display_name_claim,
        "admin_group": config.admin_group,
        "allow_auto_create": config.allow_auto_create,
        "revalidate_interval": config.revalidate_interval,
    }


@websocket_api.websocket_command(
    {vol.Required("type"): "config/auth_provider/oidc/get"}
)
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_get(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Return the current configuration."""
    if (provider := _async_provider(hass, connection, msg)) is None:
        return

    connection.send_result(
        msg["id"],
        {
            "config": _config_to_dict(
                provider.oidc_config if provider.is_configured else None
            ),
            # Tells the UI that settings were lost rather than never made.
            "config_discarded": provider.data is not None
            and provider.data.config_discarded,
            "redirect_uris": _async_redirect_uris(hass),
        },
    )


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth_provider/oidc/update",
        **CONFIG_SCHEMA,
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_update(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Store a new configuration."""
    if (provider := _async_provider(hass, connection, msg)) is None:
        return

    current = provider.oidc_config if provider.is_configured else None

    # Leaving these out of the message keeps the stored values, so the UI never
    # has to read the secret back to save an unrelated change.
    client_secret = (
        current.client_secret
        if current
        and current.issuer == msg["issuer"]
        and current.client_id == msg["client_id"]
        else None
    )
    if "client_secret" in msg:
        client_secret = msg["client_secret"] or None

    revalidate_interval = (
        current.revalidate_interval if current else DEFAULT_REVALIDATE_INTERVAL
    )
    if "revalidate_interval" in msg:
        revalidate_interval = msg["revalidate_interval"]

    config = OidcConfig(
        issuer=msg["issuer"],
        client_id=msg["client_id"],
        client_secret=client_secret,
        name=msg["name"],
        scopes=msg["scopes"],
        username_claim=msg["username_claim"],
        display_name_claim=msg["display_name_claim"],
        admin_group=msg["admin_group"],
        allow_auto_create=msg["allow_auto_create"],
        revalidate_interval=revalidate_interval,
    )

    await provider.async_set_config(config)
    connection.send_result(msg["id"], {"config": _config_to_dict(config)})


@websocket_api.websocket_command(
    {vol.Required("type"): "config/auth_provider/oidc/delete"}
)
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_delete(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Remove the configuration and every session that depends on it."""
    if (provider := _async_provider(hass, connection, msg)) is None:
        return

    await provider.async_set_config(None)
    connection.send_result(msg["id"])


@websocket_api.websocket_command(
    {vol.Required("type"): "config/auth_provider/oidc/unlink"}
)
@websocket_api.async_response
async def websocket_unlink(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Detach the caller's own identity from their Home Assistant account."""
    if (provider := _async_provider(hass, connection, msg)) is None:
        return

    # An unconfigured provider cannot sign anybody in, so nothing could relink.
    if provider.is_configured and provider.oidc_config.allow_auto_create:
        connection.send_error(
            msg["id"],
            "auto_create_enabled",
            "Signing in again would link the account straight back",
        )
        return

    user = connection.user
    linked = [
        credentials
        for credentials in user.credentials
        if credentials.auth_provider_type == PROVIDER_TYPE
    ]
    if not linked:
        connection.send_error(
            msg["id"], "not_linked", "This account has no identity provider login"
        )
        return

    if not any(
        credentials.auth_provider_type == PASSWORD_PROVIDER_TYPE
        for credentials in user.credentials
    ):
        connection.send_error(
            msg["id"],
            "no_other_login",
            "Set a password before removing the identity provider login",
        )
        return

    for credentials in linked:
        await hass.auth.async_remove_credentials(credentials)

    connection.send_result(msg["id"])


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth_provider/oidc/test",
        vol.Required("issuer"): vol.All(str, _https_url),
        vol.Required("client_id"): str,
        vol.Optional("client_secret"): vol.Any(str, None),
    }
)
@websocket_api.require_admin
@websocket_api.async_response
async def websocket_test(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Fetch the discovery document so the UI can report on it."""
    client = OidcClient(
        hass,
        issuer=msg["issuer"],
        client_id=msg["client_id"],
        client_secret=msg.get("client_secret"),
    )

    try:
        metadata = await client.async_metadata(force_refresh=True)
    except OidcError as err:
        connection.send_error(msg["id"], "discovery_failed", str(err))
        return

    connection.send_result(
        msg["id"],
        {
            "issuer": metadata.issuer,
            "authorization_endpoint": metadata.authorization_endpoint,
            "token_endpoint": metadata.token_endpoint,
            "userinfo_endpoint": metadata.userinfo_endpoint,
            "jwks_uri": metadata.jwks_uri,
            "scopes_supported": list(metadata.scopes_supported),
            "id_token_signing_alg_values_supported": list(
                metadata.id_token_signing_alg_values_supported
            ),
        },
    )
