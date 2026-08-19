"""Offer API to configure the Home Assistant auth provider."""

from dataclasses import asdict
from typing import Any

import voluptuous as vol
from webauthn.helpers.options_to_json_dict import options_to_json_dict
from webauthn.helpers.structs import PublicKeyCredentialCreationOptions

from homeassistant.auth.providers.webauthn import (
    CredentialNotFoundError,
    InvalidAuthError,
    WebAuthnCredentialMeta,
    async_get_provider,
)
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback


@callback
def async_setup(hass: HomeAssistant) -> bool:
    """Enable the Home Assistant views."""
    websocket_api.async_register_command(hass, websocket_list)
    websocket_api.async_register_command(hass, websocket_register)
    websocket_api.async_register_command(hass, websocket_delete)
    websocket_api.async_register_command(hass, websocket_register_verify)
    websocket_api.async_register_command(hass, websocket_rename)
    return True


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth_provider/webauthn/list",
    }
)
@websocket_api.async_response
async def websocket_list(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """List credentials for a user."""
    provider = async_get_provider(hass)
    credentials: list[
        WebAuthnCredentialMeta
    ] = await provider.async_list_credentials_meta(connection.user.id)

    connection.send_result(msg["id"], [asdict(cred) for cred in credentials])


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth_provider/webauthn/register",
    }
)
@websocket_api.async_response
async def websocket_register(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Start registration of new credentials."""
    if connection.user.system_generated:
        connection.send_error(
            msg["id"],
            "system_generated",
            "Cannot add credentials to a system generated user.",
        )
        return

    provider = async_get_provider(hass)
    try:
        options: PublicKeyCredentialCreationOptions = (
            await provider.async_start_registration(connection.user, connection.origin)
        )
    except InvalidAuthError as err:
        connection.send_error(msg["id"], "invalid_origin", str(err))
        return

    connection.send_result(msg["id"], options_to_json_dict(options))


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth_provider/webauthn/register_verify",
        vol.Required("credential"): object,
    },
)
@websocket_api.async_response
async def websocket_register_verify(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Verify registration of new credentials."""
    provider = async_get_provider(hass)
    try:
        await provider.async_verify_registration(connection.user, msg["credential"])
    except InvalidAuthError as err:
        connection.send_error(msg["id"], "invalid_auth", str(err))
        return
    connection.send_result(msg["id"])


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth_provider/webauthn/delete",
        vol.Required("credential_id"): str,
    },
)
@websocket_api.async_response
async def websocket_delete(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Delete a credential."""

    provider = async_get_provider(hass)
    try:
        await provider.async_delete_credential(connection.user.id, msg["credential_id"])
    except CredentialNotFoundError as err:
        connection.send_error(msg["id"], "credential_not_found", str(err))
        return
    connection.send_result(msg["id"])


@websocket_api.websocket_command(
    {
        vol.Required("type"): "config/auth_provider/webauthn/rename",
        vol.Required("credential_id"): str,
        vol.Required("name"): str,
    },
)
@websocket_api.async_response
async def websocket_rename(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Rename a credential."""
    provider = async_get_provider(hass)
    try:
        await provider.async_rename_credential(
            connection.user.id, msg["credential_id"], msg["name"]
        )
    except CredentialNotFoundError as err:
        connection.send_error(msg["id"], "credential_not_found", str(err))
        return
    connection.send_result(msg["id"])
