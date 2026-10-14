"""Test the Google Sign-In identity provider platform."""

from http import HTTPStatus

import pytest
from syrupy.assertion import SnapshotAssertion

from homeassistant.auth.providers.oidc.spec import validate_identity_provider
from homeassistant.components.google_sign_in.const import DOMAIN
from homeassistant.components.google_sign_in.identity_provider import (
    get_identity_provider,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

from tests.common import CLIENT_ID, MockConfigEntry
from tests.components.auth import async_setup_auth
from tests.components.auth.common import FakeOpenIDProvider, async_link, async_sign_in
from tests.test_util.aiohttp import AiohttpClientMocker
from tests.typing import ClientSessionGenerator

ISSUER = "https://accounts.google.com"
IDP_CLIENT_ID = "client-id"
CLIENT_SECRET = "client-secret"
EMAIL = "alice@example.com"


def test_get_identity_provider(snapshot: SnapshotAssertion) -> None:
    """Test the Google Sign-In identity provider spec."""
    entry = MockConfigEntry(
        data={CONF_CLIENT_ID: IDP_CLIENT_ID, CONF_CLIENT_SECRET: CLIENT_SECRET},
    )

    spec = get_identity_provider(entry.data, entry.options)

    assert spec == snapshot
    assert type(spec.protocol).__name__ == snapshot(name="protocol")
    assert validate_identity_provider(spec) == spec


@pytest.mark.usefixtures("socket_enabled")
async def test_link_and_sign_in(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test Google Sign-In can link and sign in through the real engine."""
    fake = FakeOpenIDProvider(aioclient_mock, ISSUER, client_id=IDP_CLIENT_ID)
    client = await async_setup_auth(hass, aiohttp_client, [{"type": "oidc"}])
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_CLIENT_ID: IDP_CLIENT_ID, CONF_CLIENT_SECRET: CLIENT_SECRET},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    user = await hass.auth.async_create_user("Alice")
    refresh_token = await hass.auth.async_create_refresh_token(user, CLIENT_ID)
    access_token = hass.auth.async_create_access_token(refresh_token)

    unlinked = await async_sign_in(client, entry.entry_id, fake, sub="unlinked")
    await async_link(client, entry.entry_id, fake, access_token, email=EMAIL)
    linked = await async_sign_in(client, entry.entry_id, fake, email=EMAIL)
    alias = await async_sign_in(
        client,
        entry.entry_id,
        fake,
        iss="accounts.google.com",
        email=EMAIL,
    )

    linked_resp = await client.post(
        "/auth/token",
        data={
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": linked["result"],
        },
    )
    alias_resp = await client.post(
        "/auth/token",
        data={
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": alias["result"],
        },
    )

    credential = user.credentials[0]
    assert credential.data["account_name"] == EMAIL
    assert credential.data["issuer"] == ISSUER
    assert credential.data["subject"] == "user-1234"
    assert unlinked["type"] == "abort"
    assert unlinked["reason"] == "user_not_allowed"
    assert linked["type"] == "create_entry"
    assert alias["type"] == "create_entry"
    assert linked_resp.status == HTTPStatus.OK
    assert alias_resp.status == HTTPStatus.OK

    linked_tokens = await linked_resp.json()
    alias_tokens = await alias_resp.json()
    linked_refresh_token = hass.auth.async_validate_access_token(
        linked_tokens["access_token"]
    )
    alias_refresh_token = hass.auth.async_validate_access_token(
        alias_tokens["access_token"]
    )
    assert linked_refresh_token is not None
    assert alias_refresh_token is not None
    assert linked_refresh_token.user == user
    assert alias_refresh_token.user == user
