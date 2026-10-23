"""Tests for the OpenID Connect identity provider platform."""

from http import HTTPStatus
from typing import Any

import pytest
from pytest_homeassistant.common import CLIENT_ID as HA_CLIENT_ID, MockConfigEntry
from pytest_homeassistant.test_util.aiohttp import AiohttpClientMocker
from pytest_homeassistant.typing import ClientSessionGenerator
from syrupy.assertion import SnapshotAssertion

from homeassistant.auth.providers.oidc.spec import validate_identity_provider
from homeassistant.components.openid_connect.const import CONF_ISSUER, DOMAIN
from homeassistant.components.openid_connect.identity_provider import (
    get_identity_provider,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

from tests.components.auth import async_setup_auth
from tests.components.auth.common import FakeOpenIDProvider, async_link, async_sign_in

ISSUER = "https://idp.example.com"
IDP_CLIENT_ID = "idp-client-id"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(
            {
                CONF_ISSUER: ISSUER,
                CONF_CLIENT_ID: "confidential-client",
                CONF_CLIENT_SECRET: "client-secret",
            },
            id="confidential-client",
        ),
        pytest.param(
            {CONF_ISSUER: ISSUER, CONF_CLIENT_ID: "public-client"},
            id="public-client",
        ),
    ],
)
def test_get_identity_provider(
    data: dict[str, Any], snapshot: SnapshotAssertion
) -> None:
    """Test building identity provider specs."""
    entry = MockConfigEntry(data=data)

    spec = get_identity_provider(entry.data, entry.options)

    assert validate_identity_provider(spec) == spec
    assert spec == snapshot


@pytest.mark.usefixtures("socket_enabled")
async def test_link_public_client_and_sign_in(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test a public client can link an account and sign in."""
    fake = FakeOpenIDProvider(aioclient_mock, ISSUER, client_id=IDP_CLIENT_ID)
    client = await async_setup_auth(hass, aiohttp_client, [{"type": "oidc"}])
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="idp.example.com",
        data={
            CONF_ISSUER: fake.issuer,
            CONF_CLIENT_ID: IDP_CLIENT_ID,
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    unlinked = await async_sign_in(
        client, entry.entry_id, fake, sub="unlinked", email="unlinked@example.com"
    )
    user = await hass.auth.async_create_user("Alice")
    refresh_token = await hass.auth.async_create_refresh_token(user, HA_CLIENT_ID)
    access_token = hass.auth.async_create_access_token(refresh_token)

    await async_link(
        client, entry.entry_id, fake, access_token, email="alice@example.com"
    )
    linked = await async_sign_in(
        client, entry.entry_id, fake, email="alice@example.com"
    )
    resp = await client.post(
        "/auth/token",
        data={
            "client_id": HA_CLIENT_ID,
            "grant_type": "authorization_code",
            "code": linked["result"],
        },
    )

    assert unlinked["type"] == "abort"
    assert unlinked["reason"] == "user_not_allowed"
    assert linked["type"] == "create_entry"
    assert resp.status == HTTPStatus.OK
    assert len(user.credentials) == 1
    assert user.credentials[0].data["subject"] == "user-1234"
    assert user.credentials[0].data["issuer"] == ISSUER
    assert user.credentials[0].data["account_name"] == "alice@example.com"
