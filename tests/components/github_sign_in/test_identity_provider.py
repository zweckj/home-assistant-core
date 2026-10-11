"""Tests for the GitHub Sign-In identity provider platform."""

from http import HTTPStatus
from typing import Any

import pytest
from syrupy.assertion import SnapshotAssertion

from homeassistant.auth.providers.oidc.spec import validate_identity_provider
from homeassistant.components.github_sign_in.const import DOMAIN
from homeassistant.components.github_sign_in.identity_provider import (
    get_identity_provider,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

from .conftest import CLIENT_ID, CLIENT_SECRET, TITLE, USER_INPUT

from tests.common import CLIENT_ID as HA_CLIENT_ID, MockConfigEntry
from tests.components.auth import async_setup_auth
from tests.components.auth.common import (
    FakeOAuth2ProfileProvider,
    async_link,
    async_sign_in,
)
from tests.test_util.aiohttp import AiohttpClientMocker
from tests.typing import ClientSessionGenerator

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
PROFILE_URL = "https://api.github.com/user"


def test_get_identity_provider(
    github_sign_in_entry: MockConfigEntry, snapshot: SnapshotAssertion
) -> None:
    """Test the identity provider specification."""
    spec = get_identity_provider(github_sign_in_entry)

    assert spec == snapshot
    assert validate_identity_provider(spec) == spec


def _fake_github(aioclient_mock: AiohttpClientMocker) -> FakeOAuth2ProfileProvider:
    """Return a fake GitHub OAuth2 profile provider."""
    return FakeOAuth2ProfileProvider(
        aioclient_mock,
        authorize_url=AUTHORIZE_URL,
        token_url=TOKEN_URL,
        profile_url=PROFILE_URL,
        profile={"id": 1234, "login": "octocat"},
    )


async def _async_setup_github_sign_in(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
) -> Any:
    """Set up auth and GitHub Sign-In."""
    client = await async_setup_auth(hass, aiohttp_client, [{"type": "oidc"}])
    entry = MockConfigEntry(domain=DOMAIN, title=TITLE, data=USER_INPUT)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return client, entry


def _request_body(call: tuple[Any, ...]) -> dict[str, Any]:
    """Return the request body from an aiohttp mock call."""
    return dict(call[2])


@pytest.mark.usefixtures("socket_enabled")
async def test_link_and_sign_in(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test linking and signing in through the real engine."""
    fake = _fake_github(aioclient_mock)
    client, entry = await _async_setup_github_sign_in(hass, aiohttp_client)
    unlinked = await async_sign_in(client, entry.entry_id, fake, id=5678)
    user = await hass.auth.async_create_user("Alice")
    refresh_token = await hass.auth.async_create_refresh_token(user, HA_CLIENT_ID)
    access_token = hass.auth.async_create_access_token(refresh_token)

    await async_link(
        client, entry.entry_id, fake, access_token, id=1234, login="octocat"
    )
    linked = await async_sign_in(client, entry.entry_id, fake, id=1234, login="octocat")
    resp = await client.post(
        "/auth/token",
        data={
            "client_id": HA_CLIENT_ID,
            "grant_type": "authorization_code",
            "code": linked["result"],
        },
    )
    credentials = [
        credential
        for credential in user.credentials
        if credential.auth_provider_type == "oidc"
    ][0]
    token_calls = [
        call for call in aioclient_mock.mock_calls if str(call[1]) == TOKEN_URL
    ]
    profile_calls = [
        call for call in aioclient_mock.mock_calls if str(call[1]) == PROFILE_URL
    ]

    assert unlinked["type"] == "abort"
    assert unlinked["reason"] == "user_not_allowed"
    assert linked["type"] == "create_entry"
    assert resp.status == HTTPStatus.OK
    assert credentials.data["subject"] == "1234"
    assert credentials.data["account_name"] == "octocat"
    assert token_calls
    for token_call in token_calls:
        assert _request_body(token_call)[CONF_CLIENT_ID] == CLIENT_ID
        assert _request_body(token_call)[CONF_CLIENT_SECRET] == CLIENT_SECRET
        assert "Authorization" not in token_call[3]
    assert profile_calls
    for profile_call in profile_calls:
        assert profile_call[3]["Accept"] == "application/vnd.github+json"
        assert profile_call[3]["X-GitHub-Api-Version"] == "2022-11-28"


@pytest.mark.usefixtures("socket_enabled")
async def test_token_error_aborts_sign_in(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test HTTP 200 token error responses abort the sign-in flow."""
    fake = _fake_github(aioclient_mock)
    client, entry = await _async_setup_github_sign_in(hass, aiohttp_client)
    aioclient_mock.clear_requests()
    aioclient_mock.post(TOKEN_URL, json={"error": "bad_verification_code"})

    result = await async_sign_in(client, entry.entry_id, fake)

    assert result["type"] == "abort"
    assert result["reason"] == "authorize_failed"
