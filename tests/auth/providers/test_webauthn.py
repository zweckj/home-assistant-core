"""Test the WebAuthn auth provider."""

from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
from webauthn.helpers.structs import (
    AuthenticationCredential,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
)

from homeassistant.auth.providers.webauthn import (
    InvalidAuthError,
    PendingOperation,
    WebAuthnProvider,
)
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util


@pytest.fixture
def provider(hass: HomeAssistant) -> WebAuthnProvider:
    """Create a WebAuthn provider."""
    store = Mock()
    config = {
        "type": "webauthn",
        "expected_origin": ["https://example.com"],
    }
    return WebAuthnProvider(hass, store, config)


def test_pending_operation_not_expired() -> None:
    """Test that a pending operation is not expired immediately."""
    options = Mock()
    created_at = dt_util.utcnow()
    pending = PendingOperation(options, created_at)

    # Should not be expired after 1 second
    assert not pending.is_expired(timedelta(seconds=60))


def test_pending_operation_expired() -> None:
    """Test that a pending operation expires after timeout."""
    options = Mock()
    # Create a timestamp 2 minutes in the past
    created_at = dt_util.utcnow() - timedelta(minutes=2)
    pending = PendingOperation(options, created_at)

    # Should be expired with 60 second timeout
    assert pending.is_expired(timedelta(seconds=60))


async def test_start_registration_stores_timestamp(provider: WebAuthnProvider) -> None:
    """Test that starting registration stores a timestamp."""
    username = "testuser"

    with patch("homeassistant.auth.providers.webauthn.generate_registration_options") as mock_gen:
        mock_options = Mock(spec=PublicKeyCredentialCreationOptions)
        mock_gen.return_value = mock_options

        result = await provider.async_start_registration(username)

        assert result == mock_options
        assert username in provider._pending_registrations
        pending = provider._pending_registrations[username]
        assert isinstance(pending, PendingOperation)
        assert pending.options == mock_options
        # Check timestamp is recent (within last 5 seconds)
        assert dt_util.utcnow() - pending.created_at < timedelta(seconds=5)


async def test_complete_registration_expired(provider: WebAuthnProvider) -> None:
    """Test that completing an expired registration fails."""
    username = "testuser"

    # Create an expired pending registration
    mock_options = Mock(spec=PublicKeyCredentialCreationOptions)
    mock_options.challenge = b"test_challenge"
    expired_time = dt_util.utcnow() - timedelta(minutes=2)
    provider._pending_registrations[username] = PendingOperation(
        mock_options, expired_time
    )

    mock_credential = Mock(spec=RegistrationCredential)

    with pytest.raises(InvalidAuthError, match="Registration has expired"):
        await provider.async_complete_registration(username, mock_credential)

    # Verify the pending registration was removed
    assert username not in provider._pending_registrations


async def test_complete_registration_not_expired(provider: WebAuthnProvider) -> None:
    """Test that completing a valid registration succeeds."""
    username = "testuser"

    # Initialize data store
    await provider.async_initialize()

    # Create a valid pending registration
    mock_options = Mock(spec=PublicKeyCredentialCreationOptions)
    mock_options.challenge = b"test_challenge"
    provider._pending_registrations[username] = PendingOperation(
        mock_options, dt_util.utcnow()
    )

    mock_credential = Mock(spec=RegistrationCredential)
    mock_verification = Mock()
    mock_verification.credential_id = b"credential_id"

    with (
        patch(
            "homeassistant.auth.providers.webauthn.verify_registration_response",
            return_value=mock_verification,
        ),
        patch.object(provider.data, "async_add") as mock_add,
    ):
        await provider.async_complete_registration(username, mock_credential)

        # Verify data was stored
        mock_add.assert_called_once_with(username, mock_verification)

    # Verify the pending registration was removed
    assert username not in provider._pending_registrations


async def test_complete_registration_no_pending(provider: WebAuthnProvider) -> None:
    """Test that completing registration without pending fails."""
    username = "testuser"
    mock_credential = Mock(spec=RegistrationCredential)

    with pytest.raises(InvalidAuthError, match="No pending registration found"):
        await provider.async_complete_registration(username, mock_credential)


async def test_start_authentication_stores_timestamp(provider: WebAuthnProvider) -> None:
    """Test that starting authentication stores a timestamp."""
    username = "testuser"

    # Initialize data store
    await provider.async_initialize()

    with (
        patch("homeassistant.auth.providers.webauthn.generate_authentication_options") as mock_gen,
        patch.object(
            provider.data,
            "async_get_user_registered_credentials",
            return_value=[],
        ),
    ):
        mock_options = Mock(spec=PublicKeyCredentialRequestOptions)
        mock_gen.return_value = mock_options

        result = await provider.async_start_authentication(username)

        assert result == mock_options
        assert username in provider._pending_signins
        pending = provider._pending_signins[username]
        assert isinstance(pending, PendingOperation)
        assert pending.options == mock_options
        # Check timestamp is recent (within last 5 seconds)
        assert dt_util.utcnow() - pending.created_at < timedelta(seconds=5)


async def test_complete_authentication_expired(provider: WebAuthnProvider) -> None:
    """Test that completing an expired authentication fails."""
    username = "testuser"

    # Create an expired pending signin
    mock_options = Mock(spec=PublicKeyCredentialRequestOptions)
    mock_options.challenge = b"test_challenge"
    expired_time = dt_util.utcnow() - timedelta(minutes=2)
    provider._pending_signins[username] = PendingOperation(mock_options, expired_time)

    mock_credential = Mock(spec=AuthenticationCredential)

    with pytest.raises(InvalidAuthError, match="Authentication has expired"):
        await provider.async_complete_authentication(username, mock_credential)

    # Verify the pending signin was removed
    assert username not in provider._pending_signins


async def test_complete_authentication_not_expired(provider: WebAuthnProvider) -> None:
    """Test that completing a valid authentication succeeds."""
    username = "testuser"

    # Initialize data store
    await provider.async_initialize()

    # Create a valid pending signin
    mock_options = Mock(spec=PublicKeyCredentialRequestOptions)
    mock_options.challenge = b"test_challenge"
    provider._pending_signins[username] = PendingOperation(
        mock_options, dt_util.utcnow()
    )

    mock_credential = Mock(spec=AuthenticationCredential)
    mock_credential.raw_id = b"credential_id"

    mock_registration = Mock()
    mock_registration.credential_public_key = b"public_key"
    mock_registration.sign_count = 0

    mock_response = Mock()
    mock_response.new_sign_count = 1

    with (
        patch.object(
            provider.data,
            "async_get_user_registration",
            return_value=mock_registration,
        ),
        patch(
            "homeassistant.auth.providers.webauthn.verify_authentication_response",
            return_value=mock_response,
        ),
        patch.object(provider.data, "async_update_user_registration") as mock_update,
    ):
        await provider.async_complete_authentication(username, mock_credential)

        # Verify registration was updated
        mock_update.assert_called_once_with(username, mock_response)

    # Verify the pending signin was removed
    assert username not in provider._pending_signins


async def test_complete_authentication_no_pending(provider: WebAuthnProvider) -> None:
    """Test that completing authentication without pending fails."""
    username = "testuser"
    mock_credential = Mock(spec=AuthenticationCredential)

    with pytest.raises(InvalidAuthError, match="No pending authentication found"):
        await provider.async_complete_authentication(username, mock_credential)
