"""Tests for the OpenID Connect identity provider platform."""

from http import HTTPStatus
from typing import Any

import pytest
from syrupy.assertion import SnapshotAssertion

from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.auth.providers.oidc.spec import validate_identity_provider
from homeassistant.components.openid_connect.const import (
    CONF_ACCOUNT_NAME_CLAIM,
    CONF_ACCOUNTS,
    CONF_ADMIN_GROUP,
    CONF_ALLOW_INSECURE_TRANSPORT,
    CONF_DISPLAY_NAME_CLAIM,
    CONF_ISSUER,
    CONF_REVALIDATE_INTERVAL,
    CONF_SCOPES,
    CONF_USERNAME_CLAIM,
    DOMAIN,
)
from homeassistant.components.openid_connect.identity_provider import (
    get_identity_provider,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

from tests.common import CLIENT_ID as HA_CLIENT_ID, MockConfigEntry
from tests.components.auth import async_setup_auth
from tests.components.auth.common import FakeOpenIDProvider, async_link, async_sign_in
from tests.test_util.aiohttp import AiohttpClientMocker
from tests.typing import ClientSessionGenerator

ISSUER = "https://idp.example.com"
IDP_CLIENT_ID = "idp-client-id"


@pytest.mark.parametrize(
    ("data", "options"),
    [
        pytest.param(
            {
                CONF_ISSUER: ISSUER,
                CONF_CLIENT_ID: "confidential-client",
                CONF_CLIENT_SECRET: "client-secret",
                CONF_ALLOW_INSECURE_TRANSPORT: False,
            },
            {},
            id="link-defaults-confidential",
        ),
        pytest.param(
            {
                CONF_ISSUER: ISSUER,
                CONF_CLIENT_ID: "public-client",
                CONF_ALLOW_INSECURE_TRANSPORT: False,
            },
            {},
            id="public-client",
        ),
        pytest.param(
            {
                CONF_ISSUER: ISSUER,
                CONF_CLIENT_ID: "client-id",
                CONF_CLIENT_SECRET: "client-secret",
                CONF_ALLOW_INSECURE_TRANSPORT: False,
            },
            {
                CONF_ACCOUNTS: "provision",
                CONF_ADMIN_GROUP: "home-assistant-admins",
                CONF_REVALIDATE_INTERVAL: 60,
            },
            id="provision-admin-group-interval",
        ),
        pytest.param(
            {
                CONF_ISSUER: "http://idp.example.com",
                CONF_CLIENT_ID: "client-id",
                CONF_ALLOW_INSECURE_TRANSPORT: True,
            },
            {},
            id="insecure-transport",
        ),
        pytest.param(
            {
                CONF_ISSUER: ISSUER,
                CONF_CLIENT_ID: "client-id",
                CONF_CLIENT_SECRET: "client-secret",
                CONF_ALLOW_INSECURE_TRANSPORT: False,
            },
            {
                CONF_SCOPES: "openid groups offline_access",
                CONF_ACCOUNT_NAME_CLAIM: "sub",
                CONF_USERNAME_CLAIM: "email",
                CONF_DISPLAY_NAME_CLAIM: "given_name",
            },
            id="custom-scopes-claims",
        ),
    ],
)
def test_get_identity_provider(
    data: dict[str, Any], options: dict[str, Any], snapshot: SnapshotAssertion
) -> None:
    """Test building identity provider specs."""
    entry = MockConfigEntry(data=data, options=options)

    spec = get_identity_provider(entry)

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
            CONF_ALLOW_INSECURE_TRANSPORT: False,
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


@pytest.mark.parametrize(
    ("claims", "expected_group"),
    [
        pytest.param(
            {
                "email": "admin@example.com",
                "full_name": "Admin User",
                "groups": ["ha-admins"],
            },
            GROUP_ID_ADMIN,
            id="admin-group",
        ),
        pytest.param(
            {
                "email": "user@example.com",
                "full_name": "Standard User",
            },
            GROUP_ID_USER,
            id="no-admin-group",
        ),
    ],
)
@pytest.mark.usefixtures("socket_enabled")
async def test_provision_creates_user(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
    claims: dict[str, Any],
    expected_group: str,
) -> None:
    """Test provisioning creates users with configured claims and groups."""
    fake = FakeOpenIDProvider(aioclient_mock, ISSUER, client_id=IDP_CLIENT_ID)
    client = await async_setup_auth(hass, aiohttp_client, [{"type": "oidc"}])
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="idp.example.com",
        data={
            CONF_ISSUER: fake.issuer,
            CONF_CLIENT_ID: IDP_CLIENT_ID,
            CONF_ALLOW_INSECURE_TRANSPORT: False,
        },
        options={
            CONF_ACCOUNTS: "provision",
            CONF_ADMIN_GROUP: "ha-admins",
            CONF_USERNAME_CLAIM: "email",
            CONF_DISPLAY_NAME_CLAIM: "full_name",
        },
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    step = await async_sign_in(client, entry.entry_id, fake, **claims)
    resp = await client.post(
        "/auth/token",
        data={
            "client_id": HA_CLIENT_ID,
            "grant_type": "authorization_code",
            "code": step["result"],
        },
    )

    assert step["type"] == "create_entry"
    assert resp.status == HTTPStatus.OK
    tokens = await resp.json()
    refresh_token = hass.auth.async_validate_access_token(tokens["access_token"])
    assert refresh_token is not None
    assert refresh_token.user.name == claims["full_name"]
    assert refresh_token.user.groups[0].id == expected_group
    assert refresh_token.user.is_owner is False
