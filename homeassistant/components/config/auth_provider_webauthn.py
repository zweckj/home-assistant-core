"""Offer API to configure the Home Assistant auth provider."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

import voluptuous as vol
from webauthn.helpers.options_to_json_dict import options_to_json_dict
from webauthn.helpers.structs import PublicKeyCredentialCreationOptions

from homeassistant.auth.providers import AuthProvider
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


def _ensure_valid_user(
    provider: AuthProvider,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> str:
    """Ensure that the user is valid and return the username."""
    username = ""
    for credential in connection.user.credentials:
        if credential.auth_provider_type == provider.type:
            username = str(credential.data["username"])
            break
    if not username:
        connection.send_error(
            msg["id"], "credentials_not_found", "Credentials not found"
        )
    return username


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
    username = _ensure_valid_user(provider, connection, msg)
    credentials: list[
        WebAuthnCredentialMeta
    ] = await provider.async_list_credentials_meta(username)

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
    provider = async_get_provider(hass)
    username = _ensure_valid_user(provider, connection, msg)
    options: PublicKeyCredentialCreationOptions = (
        await provider.async_start_registration(username)
    )

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
    username = _ensure_valid_user(provider, connection, msg)
    try:
        await provider.async_verify_registration(username, msg["credential"])
    except InvalidAuthError as err:
        connection.send_error(msg["id"], "invalid_auth", str(err))
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
    username = _ensure_valid_user(provider, connection, msg)
    try:
        await provider.async_delete_credential(username, msg["credential_id"])
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
    username = _ensure_valid_user(provider, connection, msg)
    try:
        await provider.async_rename_credential(
            username, msg["credential_id"], msg["name"]
        )
    except CredentialNotFoundError as err:
        connection.send_error(msg["id"], "credential_not_found", str(err))
    connection.send_result(msg["id"])
