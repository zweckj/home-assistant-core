"""Test Microsoft Sign-In identity provider specs."""

from http import HTTPStatus

import pytest
from syrupy.assertion import SnapshotAssertion

from homeassistant.auth.providers.oidc.spec import validate_identity_provider
from homeassistant.components.microsoft_sign_in.const import (
    CONF_ACCOUNTS,
    CONF_ADMIN_GROUP,
    CONF_REVALIDATE_INTERVAL,
    CONF_TENANT,
    DOMAIN,
)
from homeassistant.components.microsoft_sign_in.identity_provider import (
    CONSUMERS_TENANT_ID,
    get_identity_provider,
)
from homeassistant.const import CONF_CLIENT_ID, CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant

from tests.common import CLIENT_ID as HA_CLIENT_ID, MockConfigEntry
from tests.components.auth import async_setup_auth
from tests.components.auth.common import FakeOpenIDProvider, async_link, async_sign_in
from tests.test_util.aiohttp import AiohttpClientMocker
from tests.typing import ClientSessionGenerator

CLIENT_ID = "client-id"
CLIENT_SECRET = "client-secret"
TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
ADMIN_GROUP = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"


@pytest.mark.parametrize(
    ("tenant", "options"),
    [
        pytest.param("common", {}, id="common"),
        pytest.param("organizations", {}, id="organizations"),
        pytest.param("consumers", {}, id="consumers"),
        pytest.param(TENANT_ID, {}, id="guid-link"),
        pytest.param(
            TENANT_ID,
            {
                CONF_ACCOUNTS: "provision",
                CONF_ADMIN_GROUP: ADMIN_GROUP,
                CONF_REVALIDATE_INTERVAL: 60,
            },
            id="guid-provision-admin-group",
        ),
    ],
)
def test_get_identity_provider(
    snapshot: SnapshotAssertion,
    tenant: str,
    options: dict[str, object],
) -> None:
    """Test Microsoft identity provider specs."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_TENANT: tenant,
            CONF_CLIENT_ID: CLIENT_ID,
            CONF_CLIENT_SECRET: CLIENT_SECRET,
        },
        options=options,
    )

    spec = get_identity_provider(entry)

    assert spec == snapshot
    validate_identity_provider(spec)


def test_consumers_tenant_id() -> None:
    """Test the Microsoft consumers tenant ID stays stable."""
    assert CONSUMERS_TENANT_ID == "9188040d-6c67-4c5b-b112-36a304b66dad"


OTHER_TENANT_ID = "11111111-2222-4333-8444-555555555555"


def _microsoft_issuer(tenant: str) -> str:
    """Return a concrete Microsoft issuer URL."""
    return f"https://login.microsoftonline.com/{tenant}/v2.0"


def _microsoft_fake(
    aioclient_mock: AiohttpClientMocker,
    tenant: str,
    discovery_issuer: str,
) -> FakeOpenIDProvider:
    """Return a fake Microsoft OpenID provider."""
    base = f"https://login.microsoftonline.com/{tenant}"
    return FakeOpenIDProvider(
        aioclient_mock,
        discovery_issuer,
        client_id=CLIENT_ID,
        discovery_url=f"{base}/v2.0/.well-known/openid-configuration",
        authorization_endpoint=f"{base}/oauth2/v2.0/authorize",
        token_endpoint=f"{base}/oauth2/v2.0/token",
        jwks_uri=f"{base}/discovery/v2.0/keys",
    )


async def _async_setup_microsoft_entry(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    tenant: str,
    *,
    options: dict[str, object] | None = None,
) -> tuple[object, MockConfigEntry]:
    """Set up auth and a real Microsoft Sign-In config entry."""
    client = await async_setup_auth(hass, aiohttp_client, [{"type": "oidc"}])
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_TENANT: tenant,
            CONF_CLIENT_ID: CLIENT_ID,
            CONF_CLIENT_SECRET: CLIENT_SECRET,
        },
        options=options or {},
        unique_id=tenant,
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return client, entry


@pytest.mark.usefixtures("socket_enabled")
async def test_common_link_and_sign_in_e2e(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test common tenant link and sign-in through the real engine."""
    issuer = _microsoft_issuer(TENANT_ID)
    fake = _microsoft_fake(
        aioclient_mock,
        "common",
        "https://login.microsoftonline.com/{tenantid}/v2.0",
    )
    client, entry = await _async_setup_microsoft_entry(hass, aiohttp_client, "common")
    unlinked = await async_sign_in(
        client,
        entry.entry_id,
        fake,
        iss=issuer,
        tid=TENANT_ID,
        sub="unlinked",
    )
    user = await hass.auth.async_create_user("Alice")
    refresh_token = await hass.auth.async_create_refresh_token(user, HA_CLIENT_ID)
    access_token = hass.auth.async_create_access_token(refresh_token)

    await async_link(
        client,
        entry.entry_id,
        fake,
        access_token,
        iss=issuer,
        tid=TENANT_ID,
        preferred_username="alice@example.com",
    )
    credentials = [
        credential
        for credential in user.credentials
        if credential.auth_provider_type == "oidc"
        and credential.auth_provider_id == entry.entry_id
    ][0]
    linked = await async_sign_in(
        client,
        entry.entry_id,
        fake,
        iss=issuer,
        tid=TENANT_ID,
        preferred_username="alice@example.com",
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
    assert credentials.data == {
        "issuer": issuer,
        "subject": "user-1234",
        "account_name": "alice@example.com",
    }
    assert resp.status == HTTPStatus.OK


@pytest.mark.usefixtures("socket_enabled")
async def test_organizations_refuses_consumers_tenant_e2e(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test organizations tenant refuses personal Microsoft accounts."""
    fake = _microsoft_fake(
        aioclient_mock,
        "organizations",
        "https://login.microsoftonline.com/{tenantid}/v2.0",
    )
    client, entry = await _async_setup_microsoft_entry(
        hass, aiohttp_client, "organizations"
    )

    result = await async_sign_in(
        client,
        entry.entry_id,
        fake,
        iss=_microsoft_issuer(CONSUMERS_TENANT_ID),
        tid=CONSUMERS_TENANT_ID,
    )

    assert result["type"] == "abort"
    assert result["reason"] == "claim_rejected"


@pytest.mark.usefixtures("socket_enabled")
async def test_template_issuer_mismatch_refused_e2e(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test template issuer mismatch is refused."""
    fake = _microsoft_fake(
        aioclient_mock,
        "common",
        "https://login.microsoftonline.com/{tenantid}/v2.0",
    )
    client, entry = await _async_setup_microsoft_entry(hass, aiohttp_client, "common")

    result = await async_sign_in(
        client,
        entry.entry_id,
        fake,
        iss=_microsoft_issuer(OTHER_TENANT_ID),
        tid=TENANT_ID,
    )

    assert result["type"] == "abort"
    assert result["reason"] == "invalid_id_token"


@pytest.mark.usefixtures("socket_enabled")
async def test_guid_tenant_provision_creates_non_owner_user_e2e(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test GUID tenant provisioning creates a non-owner user."""
    issuer = _microsoft_issuer(TENANT_ID)
    fake = _microsoft_fake(aioclient_mock, TENANT_ID, issuer)
    client, entry = await _async_setup_microsoft_entry(
        hass,
        aiohttp_client,
        TENANT_ID,
        options={CONF_ACCOUNTS: "provision", CONF_REVALIDATE_INTERVAL: 60},
    )

    step = await async_sign_in(
        client,
        entry.entry_id,
        fake,
        iss=issuer,
        tid=TENANT_ID,
        preferred_username="alice@example.com",
    )
    resp = await client.post(
        "/auth/token",
        data={
            "client_id": HA_CLIENT_ID,
            "grant_type": "authorization_code",
            "code": step["result"],
        },
    )

    assert resp.status == HTTPStatus.OK
    tokens = await resp.json()
    refresh_token = hass.auth.async_validate_access_token(tokens["access_token"])
    assert refresh_token is not None
    assert refresh_token.user.name == "Alice"
    assert refresh_token.user.is_owner is False
