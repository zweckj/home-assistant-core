"""Test the WebAuthn auth provider configuration API."""

from dataclasses import replace
from datetime import timedelta
import json
from typing import Any
from unittest.mock import patch

from aiohttp import ClientWebSocketResponse, WSMsgType
import pytest
from syrupy.assertion import SnapshotAssertion
from syrupy.filters import props
from webauthn import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AttestationFormat,
    CredentialDeviceType,
    PublicKeyCredentialType,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

from homeassistant.auth import auth_manager_from_config
from homeassistant.auth.models import User
from homeassistant.auth.providers.webauthn import (
    STORAGE_KEY,
    WebAuthnCredential,
    WebAuthnProvider,
)
from homeassistant.components.config import auth_provider_webauthn
from homeassistant.const import EVENT_HOMEASSISTANT_FINAL_WRITE
from homeassistant.core import HomeAssistant
from homeassistant.core_config import async_process_ha_core_config
from homeassistant.setup import async_setup_component
from homeassistant.util import dt as dt_util

from tests.common import CLIENT_ID, async_fire_time_changed
from tests.typing import ClientSessionGenerator, WebSocketGenerator

pytestmark = pytest.mark.usefixtures("socket_enabled")

ORIGIN = "https://ha.example.com"
CREDENTIAL_ID = bytes_to_base64url(b"credential-1")


@pytest.fixture
async def webauthn_account(hass: HomeAssistant) -> tuple[WebAuthnProvider, User]:
    """Set up the provider and a user without any passkeys."""
    await async_process_ha_core_config(hass, {"external_url": ORIGIN})
    hass.auth = await auth_manager_from_config(
        hass, [{"type": "homeassistant"}, {"type": "webauthn"}], []
    )
    provider = hass.auth.get_auth_provider("webauthn", None)
    assert isinstance(provider, WebAuthnProvider)
    auth_provider_webauthn.async_setup(hass)
    return provider, await hass.auth.async_create_user("Alice")


@pytest.fixture
def registration_result() -> VerifiedRegistration:
    """Return the external library's result for a verified registration."""
    return VerifiedRegistration(
        credential_id=b"credential-1",
        credential_public_key=b"public-key",
        sign_count=3,
        aaguid="00000000-0000-0000-0000-000000000000",
        fmt=AttestationFormat.NONE,
        credential_type=PublicKeyCredentialType.PUBLIC_KEY,
        user_verified=True,
        attestation_object=b"attestation",
        credential_device_type=CredentialDeviceType.MULTI_DEVICE,
        credential_backed_up=True,
    )


async def _connect_user(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    user: User,
    headers: dict[str, str],
    *,
    client_id: str | None = CLIENT_ID,
) -> ClientWebSocketResponse:
    """Open an authenticated connection with the browser's origin."""
    assert await async_setup_component(hass, "websocket_api", {})
    token = await hass.auth.async_create_refresh_token(user, client_id)
    client = await aiohttp_client(hass.http.app)
    websocket = await client.ws_connect("/api/websocket", headers=headers)
    assert (await websocket.receive_json())["type"] == "auth_required"
    await websocket.send_json(
        {"type": "auth", "access_token": hass.auth.async_create_access_token(token)}
    )
    assert (await websocket.receive_json())["type"] == "auth_ok"
    return websocket


async def _register_passkey(
    client: ClientWebSocketResponse,
    registration_result: VerifiedRegistration,
    message_id: int,
) -> None:
    """Register a passkey through the API, substituting only library verification."""
    await client.send_json(
        {"id": message_id, "type": "config/auth_provider/webauthn/register"}
    )
    assert (await client.receive_json())["success"]
    with patch(
        "homeassistant.auth.providers.webauthn.verify_registration_response",
        return_value=registration_result,
    ):
        await client.send_json(
            {
                "id": message_id + 1,
                "type": "config/auth_provider/webauthn/register_verify",
                "credential": {
                    "id": bytes_to_base64url(registration_result.credential_id)
                },
            }
        )
        assert (await client.receive_json())["success"]


@pytest.mark.parametrize(
    ("name_input", "expected_name"),
    [
        pytest.param({}, "Passkey", id="default-name"),
        pytest.param({"name": "Laptop"}, "Laptop", id="named"),
    ],
)
async def test_register_and_list(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
    registration_result: VerifiedRegistration,
    name_input: dict[str, str],
    expected_name: str,
) -> None:
    """Test registration links credentials and lists the expected passkey name."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})
    await client.send_json({"id": 1, "type": "config/auth_provider/webauthn/list"})
    assert await client.receive_json() == {
        "id": 1,
        "type": "result",
        "success": True,
        "result": [],
    }

    await client.send_json({"id": 2, "type": "config/auth_provider/webauthn/register"})
    response = await client.receive_json()
    assert response["success"]
    options = response["result"]
    assert options["rp"] == {"id": "ha.example.com", "name": "Home Assistant"}
    assert base64url_to_bytes(options["user"]["id"]) == user.id.encode()
    assert options["user"]["name"] == user.name
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["authenticatorSelection"]["userVerification"] == "required"
    assert options["timeout"] == 60000
    assert options["excludeCredentials"] == []
    credential = {"id": CREDENTIAL_ID}

    with patch(
        "homeassistant.auth.providers.webauthn.verify_registration_response",
        return_value=registration_result,
    ) as verify:
        await client.send_json(
            {
                "id": 3,
                "type": "config/auth_provider/webauthn/register_verify",
                "credential": credential,
                **name_input,
            }
        )
        assert (await client.receive_json())["success"]

    verify.assert_called_once_with(
        credential=credential,
        expected_challenge=base64url_to_bytes(options["challenge"]),
        expected_rp_id="ha.example.com",
        expected_origin=ORIGIN,
        require_user_verification=True,
    )
    assert len(user.credentials) == 1
    assert user.credentials[0].auth_provider_type == "webauthn"
    assert user.credentials[0].auth_provider_id is None
    assert user.credentials[0].data == {"user_id": user.id}
    assert not user.credentials[0].is_new
    assert await hass.auth.async_get_user_by_credentials(user.credentials[0]) is user

    await client.send_json({"id": 4, "type": "config/auth_provider/webauthn/list"})
    response = await client.receive_json()
    assert response["id"] == 4
    assert response["success"]
    assert [credential["name"] for credential in response["result"]] == [expected_name]
    await client.send_json({"id": 5, "type": "config/auth_provider/webauthn/register"})
    response = await client.receive_json()
    assert response["success"]
    assert response["result"]["excludeCredentials"] == [
        {"id": CREDENTIAL_ID, "type": "public-key"}
    ]
    assert len(await provider.async_credentials()) == 1


async def test_registered_passkeys_survive_reload(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
    registration_result: VerifiedRegistration,
    snapshot: SnapshotAssertion,
) -> None:
    """Test registration, rename, and deletion persist without duplicating HA credentials."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})
    await _register_passkey(client, registration_result, 1)
    await _register_passkey(
        client, replace(registration_result, credential_id=b"credential-2"), 3
    )
    assert len(user.credentials) == 1
    credentials = user.credentials[0]

    await client.send_json(
        {
            "id": 5,
            "type": "config/auth_provider/webauthn/rename",
            "credential_id": CREDENTIAL_ID,
            "name": "Renamed passkey",
        }
    )
    assert (await client.receive_json())["success"]
    await client.send_json(
        {
            "id": 6,
            "type": "config/auth_provider/webauthn/delete",
            "credential_id": bytes_to_base64url(b"credential-2"),
        }
    )
    assert (await client.receive_json())["success"]
    await client.send_json({"id": 7, "type": "config/auth_provider/webauthn/list"})
    response = await client.receive_json()
    assert response == snapshot(exclude=props("created_at", "last_used_at"))
    before_reload = response["result"]
    assert isinstance(before_reload[0]["created_at"], float)
    assert isinstance(before_reload[0]["last_used_at"], float)
    await client.close()

    hass.bus.async_fire(EVENT_HOMEASSISTANT_FINAL_WRITE)
    await hass.async_block_till_done()
    hass_storage[STORAGE_KEY] = json.loads(json.dumps(hass_storage[STORAGE_KEY]))
    hass.auth = await auth_manager_from_config(
        hass, [{"type": "homeassistant"}, {"type": "webauthn"}], []
    )
    restored = hass.auth.get_auth_provider("webauthn", None)
    assert isinstance(restored, WebAuthnProvider)
    assert restored is not provider
    restored_user = await hass.auth.async_get_user(user.id)
    assert restored_user is not None
    assert restored_user is not user
    assert [credential.id for credential in restored_user.credentials] == [
        credentials.id
    ]
    assert (
        await hass.auth.async_get_user_by_credentials(restored_user.credentials[0])
        is restored_user
    )

    client = await _connect_user(
        hass, aiohttp_client, restored_user, {"Origin": ORIGIN}
    )
    await client.send_json({"id": 1, "type": "config/auth_provider/webauthn/list"})
    response = await client.receive_json()
    assert response["success"]
    assert response["result"] == before_reload
    assert restored.data is not None
    restored_key = restored.data.get_credential(user.id, CREDENTIAL_ID)
    assert restored_key is not None
    assert base64url_to_bytes(restored_key.credential_public_key) == b"public-key"
    assert restored_key.sign_count == registration_result.sign_count
    assert restored_key.credential_device_type is CredentialDeviceType.MULTI_DEVICE
    assert restored_key.credential_backed_up is True


async def test_registration_verification_failure(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
) -> None:
    """Test rejected registration neither stores a passkey nor links HA credentials."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})
    await client.send_json({"id": 1, "type": "config/auth_provider/webauthn/register"})
    assert (await client.receive_json())["success"]

    with patch(
        "homeassistant.auth.providers.webauthn.verify_registration_response",
        side_effect=InvalidRegistrationResponse("Invalid attestation"),
    ) as verify:
        await client.send_json(
            {
                "id": 2,
                "type": "config/auth_provider/webauthn/register_verify",
                "credential": {"id": CREDENTIAL_ID},
            }
        )
        response = await client.receive_json()

    verify.assert_called_once()
    assert response["id"] == 2
    assert not response["success"]
    assert response["error"]["code"] == "invalid_auth"
    assert user.credentials == []
    assert await provider.async_list_credentials_meta(user) == []


async def test_malformed_registration_response(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
) -> None:
    """Test a malformed response is rejected by the real verification library."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})
    await client.send_json({"id": 1, "type": "config/auth_provider/webauthn/register"})
    assert (await client.receive_json())["success"]

    await client.send_json(
        {
            "id": 2,
            "type": "config/auth_provider/webauthn/register_verify",
            "credential": {},
        }
    )
    response = await client.receive_json()

    assert not response["success"]
    assert response["error"]["code"] == "invalid_auth"
    assert user.credentials == []
    assert await provider.async_list_credentials_meta(user) == []


@pytest.mark.usefixtures("webauthn_account")
async def test_system_user_cannot_register(
    hass: HomeAssistant, aiohttp_client: ClientSessionGenerator
) -> None:
    """Test system accounts cannot start passkey enrollment."""
    user = await hass.auth.async_create_system_user("System")
    client = await _connect_user(
        hass, aiohttp_client, user, {"Origin": ORIGIN}, client_id=None
    )

    await client.send_json({"id": 1, "type": "config/auth_provider/webauthn/register"})
    response = await client.receive_json()

    assert not response["success"]
    assert response["error"]["code"] == "system_generated"
    assert user.credentials == []


async def test_registration_challenge_expires(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
) -> None:
    """Test an expired registration never reaches attestation verification."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})
    await client.send_json({"id": 1, "type": "config/auth_provider/webauthn/register"})
    assert (await client.receive_json())["success"]
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=61))
    await hass.async_block_till_done()

    with patch(
        "homeassistant.auth.providers.webauthn.verify_registration_response"
    ) as verify:
        await client.send_json(
            {
                "id": 2,
                "type": "config/auth_provider/webauthn/register_verify",
                "credential": {"id": CREDENTIAL_ID},
            }
        )
        response = await client.receive_json()

    verify.assert_not_called()
    assert not response["success"]
    assert response["error"]["code"] == "invalid_auth"
    assert user.credentials == []
    assert await provider.async_list_credentials_meta(user) == []


async def test_cannot_delete_last_login_method(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
    registration_result: VerifiedRegistration,
) -> None:
    """Test the API preserves the last passkey when no other login method exists."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})
    await _register_passkey(client, registration_result, 1)

    await client.send_json(
        {
            "id": 3,
            "type": "config/auth_provider/webauthn/delete",
            "credential_id": CREDENTIAL_ID,
        }
    )
    response = await client.receive_json()

    assert not response["success"]
    assert response["error"]["code"] == "last_login_method"
    assert len(user.credentials) == 1
    assert len(await provider.async_list_credentials_meta(user)) == 1
    await client.send_json({"id": 4, "type": "config/auth_provider/webauthn/list"})
    assert (await client.receive_json())["success"]


@pytest.mark.parametrize(
    "command",
    [
        pytest.param({"type": "config/auth_provider/webauthn/list"}, id="list"),
        pytest.param({"type": "config/auth_provider/webauthn/register"}, id="register"),
        pytest.param(
            {"type": "config/auth_provider/webauthn/register_verify", "credential": {}},
            id="verify",
        ),
        pytest.param(
            {
                "type": "config/auth_provider/webauthn/rename",
                "credential_id": CREDENTIAL_ID,
                "name": "Renamed",
            },
            id="rename",
        ),
        pytest.param(
            {
                "type": "config/auth_provider/webauthn/delete",
                "credential_id": CREDENTIAL_ID,
            },
            id="delete",
        ),
    ],
)
async def test_provider_not_enabled(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    command: dict[str, Any],
) -> None:
    """Test every management command reports an explicitly disabled provider."""
    hass.auth = await auth_manager_from_config(hass, [{"type": "homeassistant"}], [])
    auth_provider_webauthn.async_setup(hass)
    user = await hass.auth.async_create_user("Alice")
    client = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})

    await client.send_json({"id": 1, **command})
    response = await client.receive_json()

    assert response["id"] == 1
    assert not response["success"]
    assert response["error"]["code"] == "not_enabled"
    assert user.credentials == []


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="missing-origin"),
        pytest.param({"Origin": "http://ha.example.com"}, id="insecure-origin"),
        pytest.param({"Origin": "https://unknown.example.com"}, id="unknown-origin"),
        pytest.param({"Origin": "https://127.0.0.1"}, id="ip-address"),
        pytest.param({"Origin": "not-an-origin"}, id="malformed-origin"),
    ],
)
async def test_registration_rejects_unusable_origin(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
    headers: dict[str, str],
) -> None:
    """Test registration errors are returned without creating any credentials."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, headers)

    await client.send_json({"id": 1, "type": "config/auth_provider/webauthn/register"})
    response = await client.receive_json()

    assert not response["success"]
    assert response["error"]["code"] == "invalid_origin"
    assert user.credentials == []
    assert await provider.async_list_credentials_meta(user) == []


@pytest.mark.parametrize(
    ("headers", "error"),
    [
        pytest.param({}, "invalid_origin", id="missing-origin"),
        pytest.param({"Origin": ORIGIN}, "invalid_auth", id="no-pending-registration"),
    ],
)
async def test_verify_requires_a_registration(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
    headers: dict[str, str],
    error: str,
) -> None:
    """Test verification cannot start a registration or omit its origin."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, headers)

    with patch(
        "homeassistant.auth.providers.webauthn.verify_registration_response"
    ) as verify:
        await client.send_json(
            {
                "id": 1,
                "type": "config/auth_provider/webauthn/register_verify",
                "credential": {"id": CREDENTIAL_ID},
            }
        )
        response = await client.receive_json()

    verify.assert_not_called()
    assert not response["success"]
    assert response["error"]["code"] == error
    assert user.credentials == []
    assert await provider.async_list_credentials_meta(user) == []


async def test_registration_cannot_be_verified_twice(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
    registration_result: VerifiedRegistration,
) -> None:
    """Test completed registration consumes its challenge."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})
    await _register_passkey(client, registration_result, 1)

    with patch(
        "homeassistant.auth.providers.webauthn.verify_registration_response"
    ) as verify:
        await client.send_json(
            {
                "id": 3,
                "type": "config/auth_provider/webauthn/register_verify",
                "credential": {"id": CREDENTIAL_ID},
            }
        )
        response = await client.receive_json()

    verify.assert_not_called()
    assert not response["success"]
    assert response["error"]["code"] == "invalid_auth"
    assert len(user.credentials) == 1
    assert len(await provider.async_list_credentials_meta(user)) == 1


async def test_duplicate_registration_does_not_replace_passkey(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
    registration_result: VerifiedRegistration,
) -> None:
    """Test duplicate credential IDs return the public error without overwriting data."""
    provider, user = webauthn_account
    client = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})
    await _register_passkey(client, registration_result, 1)
    original = await provider.async_list_credentials_meta(user)
    await client.send_json({"id": 3, "type": "config/auth_provider/webauthn/register"})
    assert (await client.receive_json())["success"]

    with patch(
        "homeassistant.auth.providers.webauthn.verify_registration_response",
        return_value=replace(
            registration_result, credential_public_key=b"different-key"
        ),
    ):
        await client.send_json(
            {
                "id": 4,
                "type": "config/auth_provider/webauthn/register_verify",
                "credential": {"id": CREDENTIAL_ID},
                "name": "Replacement",
            }
        )
        response = await client.receive_json()

    assert not response["success"]
    assert response["error"]["code"] == "credential_already_registered"
    assert len(user.credentials) == 1
    assert await provider.async_list_credentials_meta(user) == original
    assert provider.data is not None
    stored = provider.data.get_credential(user.id, CREDENTIAL_ID)
    assert stored is not None
    assert base64url_to_bytes(stored.credential_public_key) == b"public-key"


@pytest.mark.parametrize(
    "command",
    [
        pytest.param(
            {
                "type": "config/auth_provider/webauthn/rename",
                "name": "Someone else's key",
            },
            id="rename",
        ),
        pytest.param({"type": "config/auth_provider/webauthn/delete"}, id="delete"),
    ],
)
@pytest.mark.parametrize(
    "credential_id",
    [
        pytest.param(CREDENTIAL_ID, id="another-users-key"),
        pytest.param("unknown", id="unknown-key"),
    ],
)
async def test_list_and_modify_only_own_passkeys(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    webauthn_account: tuple[WebAuthnProvider, User],
    registration_result: VerifiedRegistration,
    command: dict[str, str],
    credential_id: str,
) -> None:
    """Test another user's credentials are neither listed nor editable."""
    provider, user = webauthn_account
    owner = await _connect_user(hass, aiohttp_client, user, {"Origin": ORIGIN})
    await _register_passkey(owner, registration_result, 1)
    original = await provider.async_list_credentials_meta(user)
    other_user = await hass.auth.async_create_user("Bob")
    client = await _connect_user(hass, aiohttp_client, other_user, {"Origin": ORIGIN})

    await client.send_json({"id": 1, "type": "config/auth_provider/webauthn/list"})
    response = await client.receive_json()
    assert response["success"]
    assert response["result"] == []
    await client.send_json({"id": 2, "credential_id": credential_id, **command})
    response = await client.receive_json()

    assert not response["success"]
    assert response["error"]["code"] == "credential_not_found"
    assert await provider.async_list_credentials_meta(user) == original
    assert other_user.credentials == []


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
