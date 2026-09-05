"""Test the WebAuthn auth provider."""

from ipaddress import ip_address

import pytest
from webauthn.helpers.structs import CredentialDeviceType

from homeassistant.auth.models import AuthFlowContext, Credentials, User
from homeassistant.auth.providers import homeassistant as hass_auth, webauthn
from homeassistant.core import HomeAssistant

from tests.common import CLIENT_ID

CONTEXT = AuthFlowContext(ip_address=ip_address("192.168.1.10"))


@pytest.fixture
async def provider(hass: HomeAssistant) -> webauthn.WebAuthnProvider:
    """Return an initialized WebAuthn provider registered with the auth manager."""
    prv = webauthn.WebAuthnProvider(hass, hass.auth._store, {"type": "webauthn"})
    await prv.async_initialize()
    hass.auth._providers[(prv.type, prv.id)] = prv
    return prv


async def _store_passkey(
    provider: webauthn.WebAuthnProvider, user_id: str, credential_id: str
) -> None:
    """Register a passkey without running a ceremony."""
    assert provider.data is not None
    await provider.data.async_add_credential(
        user_id,
        webauthn.WebAuthnCredential(
            credential_id=credential_id,
            rp_id="ha.example.com",
            credential_public_key="public-key",
            sign_count=0,
            credential_device_type=CredentialDeviceType.MULTI_DEVICE,
            credential_backed_up=True,
        ),
    )


async def _linked_user(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider, *credential_ids: str
) -> tuple[User, Credentials]:
    """Return a user with passkeys and the credentials backing them."""
    user = await hass.auth.async_create_user("Alice")
    credentials = provider.async_create_credentials({"user_id": user.id})
    await hass.auth.async_link_user(user, credentials)
    for credential_id in credential_ids:
        await _store_passkey(provider, user.id, credential_id)
    return user, credentials


async def test_provider_is_hidden_until_a_passkey_exists(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test the login screen does not offer a passkey nobody has."""
    assert provider.async_can_start_login(CONTEXT) is False

    await _store_passkey(provider, "user-1", "credential-1")

    assert provider.async_can_start_login(CONTEXT) is True


async def test_removing_credentials_revokes_only_passkey_sessions(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test unlinking takes the passkey sessions and the stored keys with it."""
    user, credentials = await _linked_user(hass, provider, "credential-1")
    passkey_token = await hass.auth.async_create_refresh_token(
        user, CLIENT_ID, credential=credentials
    )
    unrelated = await hass.auth.async_create_refresh_token(
        user, "https://other.example.com/"
    )

    await hass.auth.async_remove_credentials(credentials)

    assert hass.auth.async_get_refresh_token(passkey_token.id) is None
    assert hass.auth.async_get_refresh_token(unrelated.id) is unrelated
    assert provider.data is not None
    assert provider.data.list_credentials_meta(user.id) == []


async def test_deleting_one_of_several_passkeys_revokes_the_sessions(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test sessions go even though the account keeps a passkey.

    Every passkey shares one credential, so a session cannot be traced back to
    the key it was created with.
    """
    user, credentials = await _linked_user(
        hass, provider, "credential-1", "credential-2"
    )
    refresh_token = await hass.auth.async_create_refresh_token(
        user, CLIENT_ID, credential=credentials
    )

    await provider.async_delete_credential(user, "credential-1")

    assert hass.auth.async_get_refresh_token(refresh_token.id) is None
    assert credentials in user.credentials
    assert provider.data is not None
    assert len(provider.data.list_credentials_meta(user.id)) == 1


async def test_deleting_the_last_passkey_needs_another_login(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test an account cannot delete the only way it has to sign in."""
    user, credentials = await _linked_user(hass, provider, "credential-1")

    with pytest.raises(webauthn.LastLoginMethodError):
        await provider.async_delete_credential(user, "credential-1")

    assert credentials in user.credentials
    assert provider.data is not None
    assert len(provider.data.list_credentials_meta(user.id)) == 1


async def test_deleting_the_last_passkey_drops_the_credentials(
    hass: HomeAssistant,
    provider: webauthn.WebAuthnProvider,
    local_auth: hass_auth.HassAuthProvider,
) -> None:
    """Test the account keeps working through its password afterwards."""
    user, credentials = await _linked_user(hass, provider, "credential-1")
    await hass.auth.async_link_user(
        user, local_auth.async_create_credentials({"username": "alice"})
    )

    await provider.async_delete_credential(user, "credential-1")

    assert credentials not in user.credentials
    assert provider.data is not None
    assert provider.data.list_credentials_meta(user.id) == []
