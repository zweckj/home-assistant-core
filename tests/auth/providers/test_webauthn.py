"""Tests for the WebAuthn auth provider."""

import base64
from unittest.mock import AsyncMock
import uuid

import pytest

from homeassistant.auth import AuthManager, auth_store, models as auth_models
from homeassistant.auth.providers import webauthn
from homeassistant.core import HomeAssistant


@pytest.fixture
async def store(hass: HomeAssistant) -> auth_store.AuthStore:
    """Mock store."""
    store = auth_store.AuthStore(hass)
    await store.async_load()
    return store


@pytest.fixture
def provider(
    hass: HomeAssistant, store: auth_store.AuthStore
) -> webauthn.WebAuthnAuthProvider:
    """Mock provider."""
    return webauthn.WebAuthnAuthProvider(
        hass,
        store,
        {
            "type": "webauthn",
        },
    )


@pytest.fixture
def manager(
    hass: HomeAssistant,
    store: auth_store.AuthStore,
    provider: webauthn.WebAuthnAuthProvider,
) -> AuthManager:
    """Mock manager."""
    return AuthManager(hass, store, {(provider.type, provider.id): provider}, {})


async def test_create_new_credential(
    manager: AuthManager, provider: webauthn.WebAuthnAuthProvider
) -> None:
    """Test that we create a new credential."""
    await provider.async_initialize()
    assert provider.data is not None

    # Register a credential
    credential_id = "test_credential_id"
    public_key = base64.b64encode(b"test_public_key").decode()
    await provider.async_register_credential(
        "test-user", credential_id, public_key, sign_count=0
    )

    # Get or create credentials
    credentials = await provider.async_get_or_create_credentials(
        {"username": "test-user"}
    )
    assert credentials.is_new is True

    user = await manager.async_get_or_create_user(credentials)
    assert user.name == "test-user"
    assert user.is_active


async def test_match_existing_credentials(
    provider: webauthn.WebAuthnAuthProvider,
) -> None:
    """See if we match existing users."""
    await provider.async_initialize()

    # Register a credential
    credential_id = "test_credential_id"
    public_key = base64.b64encode(b"test_public_key").decode()
    await provider.async_register_credential(
        "test-user", credential_id, public_key, sign_count=0
    )

    existing = auth_models.Credentials(
        id=uuid.uuid4(),
        auth_provider_type="webauthn",
        auth_provider_id=None,
        data={"username": "test-user"},
        is_new=False,
    )
    provider.async_credentials = AsyncMock(return_value=[existing])
    credentials = await provider.async_get_or_create_credentials(
        {"username": "test-user"}
    )
    assert credentials is existing


async def test_verify_invalid_user(provider: webauthn.WebAuthnAuthProvider) -> None:
    """Test we raise if incorrect user specified."""
    await provider.async_initialize()

    with pytest.raises(webauthn.InvalidAuthError):
        await provider.async_validate_login(
            "non-existing-user",
            "credential_id",
            base64.b64encode(b"signature").decode(),
            base64.b64encode(b"auth_data").decode(),
        )


async def test_verify_invalid_credential(
    provider: webauthn.WebAuthnAuthProvider,
) -> None:
    """Test we raise if incorrect credential specified."""
    await provider.async_initialize()
    assert provider.data is not None

    # Register a user with a credential
    credential_id = "valid_credential_id"
    public_key = base64.b64encode(b"test_public_key").decode()
    await provider.async_register_credential(
        "test-user", credential_id, public_key, sign_count=0
    )

    # Generate a challenge
    provider.generate_challenge("test-user")

    # Try with wrong credential ID
    with pytest.raises(webauthn.InvalidAuthError):
        await provider.async_validate_login(
            "test-user",
            "wrong_credential_id",
            base64.b64encode(b"signature").decode(),
            base64.b64encode(b"auth_data").decode(),
        )


async def test_successful_authentication(
    provider: webauthn.WebAuthnAuthProvider,
) -> None:
    """Test successful authentication flow."""
    await provider.async_initialize()
    assert provider.data is not None

    # Register a user with a credential
    credential_id = "valid_credential_id"
    public_key = base64.b64encode(b"test_public_key").decode()
    await provider.async_register_credential(
        "test-user", credential_id, public_key, sign_count=0
    )

    # Generate a challenge
    challenge = provider.generate_challenge("test-user")
    assert challenge is not None
    assert len(challenge) == 32

    # Authenticate (this is a simplified version without actual signature verification)
    await provider.async_validate_login(
        "test-user",
        credential_id,
        base64.b64encode(b"signature").decode(),
        base64.b64encode(b"auth_data").decode(),
    )

    # Verify sign count was updated
    credentials = provider.data.get_user_credentials("test-user")
    assert len(credentials) == 1
    assert credentials[0]["sign_count"] == 1

    # Verify challenge was cleared
    assert provider.get_challenge("test-user") is None


async def test_register_multiple_credentials(
    provider: webauthn.WebAuthnAuthProvider,
) -> None:
    """Test registering multiple credentials for the same user."""
    await provider.async_initialize()
    assert provider.data is not None

    # Register first credential
    await provider.async_register_credential(
        "test-user",
        "credential_1",
        base64.b64encode(b"public_key_1").decode(),
        sign_count=0,
    )

    # Register second credential
    await provider.async_register_credential(
        "test-user",
        "credential_2",
        base64.b64encode(b"public_key_2").decode(),
        sign_count=0,
    )

    # Verify both credentials exist
    credentials = provider.data.get_user_credentials("test-user")
    assert len(credentials) == 2
    assert credentials[0]["credential_id"] == "credential_1"
    assert credentials[1]["credential_id"] == "credential_2"


async def test_challenge_management(provider: webauthn.WebAuthnAuthProvider) -> None:
    """Test challenge generation and management."""
    await provider.async_initialize()

    # Generate challenge
    challenge1 = provider.generate_challenge("user1")
    assert len(challenge1) == 32

    # Generate another challenge for different user
    challenge2 = provider.generate_challenge("user2")
    assert len(challenge2) == 32
    assert challenge1 != challenge2

    # Retrieve challenges
    assert provider.get_challenge("user1") == challenge1
    assert provider.get_challenge("user2") == challenge2

    # Clear challenge
    provider.clear_challenge("user1")
    assert provider.get_challenge("user1") is None
    assert provider.get_challenge("user2") == challenge2


async def test_remove_credentials(provider: webauthn.WebAuthnAuthProvider) -> None:
    """Test removing credentials."""
    await provider.async_initialize()
    assert provider.data is not None

    # Register a credential
    await provider.async_register_credential(
        "test-user",
        "credential_1",
        base64.b64encode(b"public_key_1").decode(),
        sign_count=0,
    )

    # Verify user exists
    assert len(provider.data.users) == 1

    # Remove credentials
    credentials = auth_models.Credentials(
        id=uuid.uuid4(),
        auth_provider_type="webauthn",
        auth_provider_id=None,
        data={"username": "test-user"},
        is_new=False,
    )
    await provider.async_will_remove_credentials(credentials)

    # Verify user was removed
    assert len(provider.data.users) == 0


async def test_no_challenge_error(provider: webauthn.WebAuthnAuthProvider) -> None:
    """Test authentication fails when no challenge exists."""
    await provider.async_initialize()
    assert provider.data is not None

    # Register a user with a credential
    credential_id = "valid_credential_id"
    public_key = base64.b64encode(b"test_public_key").decode()
    await provider.async_register_credential(
        "test-user", credential_id, public_key, sign_count=0
    )

    # Try to authenticate without generating a challenge first
    with pytest.raises(webauthn.InvalidAuthError, match="No challenge found"):
        await provider.async_validate_login(
            "test-user",
            credential_id,
            base64.b64encode(b"signature").decode(),
            base64.b64encode(b"auth_data").decode(),
        )


async def test_user_meta_for_credentials(
    provider: webauthn.WebAuthnAuthProvider,
) -> None:
    """Test getting user metadata."""
    await provider.async_initialize()
    assert provider.data is not None

    # Register a user with name
    provider.data.add_user("test-user", name="Test User")
    await provider.data.async_save()

    credentials = auth_models.Credentials(
        id=uuid.uuid4(),
        auth_provider_type="webauthn",
        auth_provider_id=None,
        data={"username": "test-user"},
        is_new=False,
    )

    meta = await provider.async_user_meta_for_credentials(credentials)
    assert meta.name == "Test User"
    assert meta.is_active is True


async def test_user_meta_no_name(provider: webauthn.WebAuthnAuthProvider) -> None:
    """Test getting user metadata when no name is set."""
    await provider.async_initialize()
    assert provider.data is not None

    # Register a user without name
    provider.data.add_user("test-user")
    await provider.data.async_save()

    credentials = auth_models.Credentials(
        id=uuid.uuid4(),
        auth_provider_type="webauthn",
        auth_provider_id=None,
        data={"username": "test-user"},
        is_new=False,
    )

    meta = await provider.async_user_meta_for_credentials(credentials)
    assert meta.name == "test-user"
    assert meta.is_active is True
