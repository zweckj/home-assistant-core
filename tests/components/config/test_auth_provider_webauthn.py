"""Test the WebAuthn auth provider configuration API."""

from aiohttp import WSMsgType
import pytest
from webauthn.helpers.structs import CredentialDeviceType

from homeassistant.auth import auth_manager_from_config
from homeassistant.auth.providers.webauthn import WebAuthnCredential, WebAuthnProvider
from homeassistant.components.config import auth_provider_webauthn
from homeassistant.core import HomeAssistant

from tests.common import CLIENT_ID
from tests.typing import WebSocketGenerator


@pytest.mark.parametrize(
    ("credential_ids", "remaining_ids"),
    [
        pytest.param(
            ["credential-1", "credential-2"],
            ["credential-2"],
            id="one-of-two-passkeys",
        ),
        pytest.param(["credential-1"], [], id="last-passkey-with-password"),
    ],
)
async def test_delete_from_own_session_returns_result_before_disconnect(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    credential_ids: list[str],
    remaining_ids: list[str],
) -> None:
    """Test passkey deletion replies before closing the session that invoked it."""
    hass.auth = await auth_manager_from_config(
        hass, [{"type": "homeassistant"}, {"type": "webauthn"}], []
    )
    provider = hass.auth.get_auth_provider("webauthn", None)
    assert isinstance(provider, WebAuthnProvider)
    assert provider.data is not None
    auth_provider_webauthn.async_setup(hass)

    user = await hass.auth.async_create_user("Alice")
    password_provider = hass.auth.get_auth_provider("homeassistant", None)
    assert password_provider is not None
    await hass.auth.async_link_user(
        user, password_provider.async_create_credentials({"username": "alice"})
    )
    credentials = provider.async_create_credentials({"user_id": user.id})
    await hass.auth.async_link_user(user, credentials)
    for credential_id in credential_ids:
        await provider.data.async_add_credential(
            user.id,
            WebAuthnCredential(
                credential_id=credential_id,
                rp_id="ha.example.com",
                credential_public_key="public-key",
                sign_count=0,
                credential_device_type=CredentialDeviceType.MULTI_DEVICE,
                credential_backed_up=True,
            ),
        )

    refresh_token = await hass.auth.async_create_refresh_token(
        user, CLIENT_ID, credential=credentials
    )
    access_token = hass.auth.async_create_access_token(refresh_token)
    client = await hass_ws_client(hass, access_token)
    peer = await hass_ws_client(hass, access_token)
    unrelated = await hass.auth.async_create_refresh_token(
        user, "https://other-client.example.com"
    )
    command = {
        "type": "config/auth_provider/webauthn/delete",
        "credential_id": "credential-1",
    }

    await client.send_json_auto_id(command)

    result = await client.receive_json()
    assert result["id"] == command["id"]
    assert result["success"]
    assert hass.auth.async_get_refresh_token(refresh_token.id) is None
    assert hass.auth.async_get_refresh_token(unrelated.id) is unrelated
    assert (credentials in user.credentials) is bool(remaining_ids)
    assert [
        credential.credential_id
        for credential in await provider.async_list_credentials_meta(user)
    ] == remaining_ids
    assert (await peer.receive()).type is WSMsgType.CLOSE
    assert (await client.receive()).type is WSMsgType.CLOSE
