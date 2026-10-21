"""Tests for the GitHub Sign-In client."""

from typing import Any

import pytest
from pytest_homeassistant.test_util.aiohttp import AiohttpClientMocker

from homeassistant.components.auth import IdentityProvider, OidcError
from homeassistant.components.github_sign_in.client import (
    ISSUER,
    PROFILE_URL,
    GitHubClient,
    GitHubOAuth2,
)
from homeassistant.core import HomeAssistant


@pytest.fixture
def client(hass: HomeAssistant) -> GitHubClient:
    """Return a GitHub client."""
    client = GitHubOAuth2().create_client(
        hass, IdentityProvider(client_id="client-id", protocol=GitHubOAuth2())
    )
    assert client.accepts_issuer(ISSUER)
    return client


@pytest.mark.parametrize(
    ("profile", "identity"),
    [
        pytest.param({"id": 123, "login": "octocat"}, ("123", "octocat"), id="login"),
        pytest.param({"id": 123}, ("123", None), id="no-login"),
        pytest.param({"id": 123, "login": ""}, ("123", None), id="empty-login"),
    ],
)
async def test_fetch_identity(
    client: GitHubClient,
    aioclient_mock: AiohttpClientMocker,
    profile: dict[str, Any],
    identity: tuple[str, str | None],
) -> None:
    """Test the user ID and login are read from the user API."""
    aioclient_mock.get(PROFILE_URL, json=profile)

    assert await client.async_fetch_identity("token") == identity
    assert aioclient_mock.mock_calls[-1][3]["Authorization"] == "Bearer token"
    assert aioclient_mock.mock_calls[-1][3]["X-GitHub-Api-Version"] == "2022-11-28"


@pytest.mark.parametrize(
    ("profile", "match"),
    [
        pytest.param([], "JSON object", id="not-an-object"),
        pytest.param({}, "user ID", id="missing"),
        pytest.param({"id": True}, "user ID", id="bool"),
        pytest.param({"id": "123"}, "user ID", id="string"),
    ],
)
async def test_fetch_identity_rejects_unusable_profiles(
    client: GitHubClient,
    aioclient_mock: AiohttpClientMocker,
    profile: Any,
    match: str,
) -> None:
    """Test profiles without a numeric user ID are refused."""
    aioclient_mock.get(PROFILE_URL, json=profile)

    with pytest.raises(OidcError, match=match):
        await client.async_fetch_identity("token")
