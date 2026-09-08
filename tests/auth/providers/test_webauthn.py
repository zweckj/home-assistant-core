"""Test the WebAuthn auth provider."""

from ipaddress import ip_address
import time
from unittest.mock import ANY, patch

import pytest
from webauthn.helpers.structs import CredentialDeviceType

from homeassistant.auth.models import AuthFlowContext, Credentials, User
from homeassistant.auth.providers import webauthn
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType

from tests.common import CLIENT_ID

ORIGIN = "https://ha.example.com"
CONTEXT = AuthFlowContext(ip_address=ip_address("192.168.1.10"))
STEP_UP_CONTEXT = AuthFlowContext(ip_address=ip_address("192.168.1.10"), origin=ORIGIN)
RELYING_PARTY = webauthn._RelyingParty("ha.example.com", ORIGIN)


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


@pytest.mark.usefixtures("hass")
async def test_provider_is_hidden_until_a_passkey_exists(
    provider: webauthn.WebAuthnProvider,
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


@pytest.mark.parametrize("context", [None, CONTEXT])
async def test_start_step_up_needs_an_origin(
    hass: HomeAssistant,
    provider: webauthn.WebAuthnProvider,
    context: AuthFlowContext | None,
) -> None:
    """Test a passkey ceremony cannot start without an origin to run it for."""
    user, _ = await _linked_user(hass, provider, "credential-1")

    with pytest.raises(webauthn.InvalidAuthError):
        await provider.async_start_step_up(user, context)


async def test_start_step_up_offers_the_users_passkeys(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test starting a step up scopes the ceremony to the user's own passkeys."""
    user, _ = await _linked_user(hass, provider, "credential-1", "credential-2")

    with patch(f"{webauthn.__name__}._async_relying_party", return_value=RELYING_PARTY):
        options = await provider.async_start_step_up(user, STEP_UP_CONTEXT)

    assert len(options["allowCredentials"]) == 2
    assert user.id in provider._pending_step_up_challenges


@pytest.mark.parametrize("context", [None, CONTEXT])
async def test_verify_step_up_needs_an_origin(
    hass: HomeAssistant,
    provider: webauthn.WebAuthnProvider,
    context: AuthFlowContext | None,
) -> None:
    """Test a passkey proof is rejected when there is no origin to check it."""
    user, _ = await _linked_user(hass, provider, "credential-1")

    with pytest.raises(webauthn.InvalidStepUpError):
        await provider.async_verify_step_up(
            user, {webauthn.CONF_AUTHENTICATION_CREDENTIAL: "assertion"}, context
        )


async def test_verify_step_up_rejects_a_missing_challenge(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test a proof is rejected when the user never started a step up."""
    user, _ = await _linked_user(hass, provider, "credential-1")

    with pytest.raises(webauthn.InvalidStepUpError):
        await provider.async_verify_step_up(
            user,
            {webauthn.CONF_AUTHENTICATION_CREDENTIAL: "assertion"},
            STEP_UP_CONTEXT,
        )


async def test_verify_step_up_rejects_an_expired_challenge(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test a proof is rejected, and cleared, once the challenge has timed out."""
    user, _ = await _linked_user(hass, provider, "credential-1")
    provider._pending_step_up_challenges[user.id] = (b"challenge", time.time() - 1)

    with (
        patch.object(provider, "async_verify_authentication") as verify,
        pytest.raises(webauthn.InvalidStepUpError),
    ):
        await provider.async_verify_step_up(
            user,
            {webauthn.CONF_AUTHENTICATION_CREDENTIAL: "assertion"},
            STEP_UP_CONTEXT,
        )

    verify.assert_not_awaited()
    assert user.id not in provider._pending_step_up_challenges


async def test_step_up_succeeds_with_the_users_passkey(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test a valid passkey proof from the user clears the step up challenge."""
    user, _ = await _linked_user(hass, provider, "credential-1")
    provider._pending_step_up_challenges[user.id] = (b"challenge", time.time() + 60)

    with patch.object(
        provider, "async_verify_authentication", return_value=user.id
    ) as verify:
        await provider.async_verify_step_up(
            user,
            {webauthn.CONF_AUTHENTICATION_CREDENTIAL: "assertion"},
            STEP_UP_CONTEXT,
        )

    verify.assert_awaited_once_with("assertion", b"challenge", ORIGIN)
    assert user.id not in provider._pending_step_up_challenges


async def test_step_up_rejects_a_passkey_from_another_user(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test a proof made with someone else's passkey does not count."""
    user, _ = await _linked_user(hass, provider, "credential-1")
    provider._pending_step_up_challenges[user.id] = (b"challenge", time.time() + 60)

    with (
        patch.object(
            provider, "async_verify_authentication", return_value="another-user"
        ),
        pytest.raises(webauthn.InvalidStepUpError),
    ):
        await provider.async_verify_step_up(
            user,
            {webauthn.CONF_AUTHENTICATION_CREDENTIAL: "assertion"},
            STEP_UP_CONTEXT,
        )


async def test_verify_step_up_wraps_a_failed_assertion(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test a rejected passkey assertion surfaces as a step up failure."""
    user, _ = await _linked_user(hass, provider, "credential-1")
    provider._pending_step_up_challenges[user.id] = (b"challenge", time.time() + 60)

    with (
        patch.object(
            provider,
            "async_verify_authentication",
            side_effect=webauthn.InvalidAuthError("nope"),
        ),
        pytest.raises(webauthn.InvalidStepUpError),
    ):
        await provider.async_verify_step_up(
            user,
            {webauthn.CONF_AUTHENTICATION_CREDENTIAL: "assertion"},
            STEP_UP_CONTEXT,
        )


@pytest.mark.parametrize(
    ("context", "reason"),
    [
        (CONTEXT, "missing_origin"),
        (
            AuthFlowContext(ip_address=ip_address("192.168.1.10"), origin=None),
            "missing_origin",
        ),
        (
            AuthFlowContext(
                ip_address=ip_address("192.168.1.10"), origin="http://ha.example.com"
            ),
            "invalid_origin",
        ),
    ],
    ids=["absent", "empty", "not usable for webauthn"],
)
async def test_login_flow_needs_an_origin_to_run_a_ceremony_for(
    hass: HomeAssistant,
    provider: webauthn.WebAuthnProvider,
    context: AuthFlowContext,
    reason: str,
) -> None:
    """Test a passkey login is not offered without an origin to bind it to."""
    await _linked_user(hass, provider, "credential-1")

    result = await hass.auth.login_flow.async_init(
        (provider.type, provider.id), context=context
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == reason


async def test_login_flow_signs_in_against_the_browser_origin(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test the passkey login runs its ceremony for the origin of the browser."""
    user, credentials = await _linked_user(hass, provider, "credential-1")

    with patch(
        f"{webauthn.__name__}._async_relying_party", return_value=RELYING_PARTY
    ) as relying_party:
        result = await hass.auth.login_flow.async_init(
            (provider.type, provider.id), context=STEP_UP_CONTEXT
        )
        assert result["type"] is FlowResultType.FORM
        assert result["description_placeholders"]["webauthn_options"]

        with patch.object(
            provider, "async_verify_authentication", return_value=user.id
        ) as verify:
            result = await hass.auth.login_flow.async_configure(
                result["flow_id"],
                {webauthn.CONF_AUTHENTICATION_CREDENTIAL: "assertion"},
            )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"] is credentials
    verify.assert_awaited_once_with("assertion", ANY, ORIGIN)
    assert relying_party.call_args.args[1] == ORIGIN


async def test_login_flow_rejects_an_expired_challenge(
    hass: HomeAssistant, provider: webauthn.WebAuthnProvider
) -> None:
    """Test a passkey login is refused once its challenge has timed out."""
    user, _ = await _linked_user(hass, provider, "credential-1")

    with patch(f"{webauthn.__name__}._async_relying_party", return_value=RELYING_PARTY):
        result = await hass.auth.login_flow.async_init(
            (provider.type, provider.id), context=STEP_UP_CONTEXT
        )
        flow = hass.auth.login_flow._progress[result["flow_id"]]
        flow._challenge_expires_at = time.time() - 1

        with patch.object(
            provider, "async_verify_authentication", return_value=user.id
        ) as verify:
            result = await hass.auth.login_flow.async_configure(
                result["flow_id"],
                {webauthn.CONF_AUTHENTICATION_CREDENTIAL: "assertion"},
            )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
    verify.assert_not_awaited()
