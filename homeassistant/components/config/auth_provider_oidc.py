"""Offer self-service OpenID Connect auth provider actions."""

from typing import Any, cast

import probatio

from homeassistant.auth.models import Credentials
from homeassistant.auth.providers.oidc import (
    OidcAuthProvider,
    OidcIdentityProvider,
    async_get_provider,
)
from homeassistant.auth.providers.oidc.const import PROVIDER_TYPE
from homeassistant.auth.providers.oidc.spec import AccountPolicy
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback


@callback
def async_setup(hass: HomeAssistant) -> bool:
    """Enable the OpenID Connect configuration commands."""
    websocket_api.async_register_command(hass, websocket_list)
    websocket_api.async_register_command(hass, websocket_unlink)
    return True


@callback
def _async_provider(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> OidcAuthProvider | None:
    """Return the provider, reporting back when it is not enabled."""
    if (provider := async_get_provider(hass)) is not None:
        return provider
    connection.send_error(
        msg["id"], "not_enabled", "The OIDC auth provider is not enabled"
    )
    return None


def _is_identity_provider_credential(credential: Credentials) -> bool:
    """Return if a credential belongs to an identity provider of the engine."""
    return (
        credential.auth_provider_type == PROVIDER_TYPE
        and credential.auth_provider_id is not None
    )


def _credential_for_user(
    credentials: list[Credentials], credential_id: str
) -> Credentials | None:
    """Return the caller-owned OIDC credential matching the id."""
    return next(
        (
            credential
            for credential in credentials
            if credential.id == credential_id
            and _is_identity_provider_credential(credential)
        ),
        None,
    )


def _child_name(hass: HomeAssistant, child: OidcIdentityProvider) -> str:
    """Return the config entry title or child provider name."""
    if (entry := hass.config_entries.async_get_entry(cast(str, child.id))) is not None:
        return entry.title
    return child.name


@websocket_api.websocket_command(
    {probatio.Required("type"): "config/auth_provider/oidc/list"}
)
@callback
def websocket_list(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """List identity provider options and the caller's linked credentials."""
    if (provider := _async_provider(hass, connection, msg)) is None:
        return

    active_children = [
        child
        for child in provider.child_providers
        if isinstance(child, OidcIdentityProvider) and child.active
    ]
    identity_providers = sorted(
        (
            {
                "id": cast(str, child.id),
                "name": _child_name(hass, child),
                "domain": cast(str, child.domain),
                "accounts": child.record.accounts.value,
            }
            for child in active_children
        ),
        key=lambda item: item["name"],
    )

    user = connection.user
    credentials = []
    for credential in user.credentials:
        if not _is_identity_provider_credential(credential):
            continue
        child = provider.async_get_child_provider(
            cast(str, credential.auth_provider_id)
        )
        if not isinstance(child, OidcIdentityProvider):
            continue
        credentials.append(
            {
                "credential_id": credential.id,
                "identity_provider_id": credential.auth_provider_id,
                "name": _child_name(hass, child),
                "domain": cast(str, child.domain),
                "account_name": credential.data.get("account_name"),
                "available": child.active,
                "can_unlink": child.record.accounts is AccountPolicy.LINK,
                "has_other_login": hass.auth.async_has_other_login_method(
                    user, credential
                ),
            }
        )

    connection.send_result(
        msg["id"],
        {"identity_providers": identity_providers, "credentials": credentials},
    )


@websocket_api.websocket_command(
    {
        probatio.Required("type"): "config/auth_provider/oidc/unlink",
        probatio.Required("credential_id"): str,
    }
)
@websocket_api.require_step_up
@websocket_api.async_response
async def websocket_unlink(
    hass: HomeAssistant,
    connection: websocket_api.ActiveConnection,
    msg: dict[str, Any],
) -> None:
    """Detach one of the caller's own identity provider credentials."""
    if (provider := _async_provider(hass, connection, msg)) is None:
        return

    user = connection.user
    credential = _credential_for_user(user.credentials, msg["credential_id"])
    if credential is None:
        connection.send_error(
            msg["id"],
            "not_linked",
            "This account has no matching identity provider login",
        )
        return

    child = provider.async_get_child_provider(cast(str, credential.auth_provider_id))
    if not isinstance(child, OidcIdentityProvider):
        connection.send_error(
            msg["id"], "not_linked", "The identity provider is not registered"
        )
        return
    if child.record.accounts is AccountPolicy.PROVISION:
        connection.send_error(
            msg["id"],
            "provisioning_provider",
            "Provisioning identity provider credentials cannot be unlinked",
        )
        return

    if not hass.auth.async_has_other_login_method(user, credential):
        connection.send_error(
            msg["id"],
            "no_other_login",
            "Add another login method before removing the identity provider login",
        )
        return

    with connection.async_defer_auth_close():
        await hass.auth.async_remove_credentials(credential)
        connection.send_result(msg["id"])
