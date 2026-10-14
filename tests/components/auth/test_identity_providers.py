"""Tests for auth identity provider platform bridge."""

from datetime import timedelta
from http import HTTPStatus
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant import auth, config_entries
from homeassistant.auth.const import LOGIN_CALLBACK_PATH
from homeassistant.auth.providers.oidc import OidcAuthProvider, async_get_provider
from homeassistant.components.auth import (
    AccountPolicy,
    IdentityProvider,
    OpenIDConnect,
    async_get_redirect_uris,
    async_identity_providers_enabled,
)
from homeassistant.config_entries import ConfigEntryDisabler
from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.network import NoURLAvailableError
from homeassistant.setup import async_setup_component

from . import async_setup_auth
from .common import (
    PROFILE_AUTHORIZE_URL,
    PROFILE_TOKEN_URL,
    PROFILE_URL,
    FakeOAuth2ProfileProvider,
    FakeOpenIDProvider,
    ProfileProtocol,
    async_link,
    async_sign_in,
)

from tests.common import (
    CLIENT_ID,
    MockConfigEntry,
    MockModule,
    ensure_auth_manager_loaded,
    mock_integration,
    mock_platform,
)
from tests.test_util.aiohttp import AiohttpClientMocker
from tests.typing import ClientSessionGenerator

DOMAIN = "test_idp"
ISSUER = "https://idp.example.com"


class _MockFlow(config_entries.ConfigFlow):
    """Mock config flow handler."""

    VERSION = 1


async def _async_setup_entry_success(
    hass: HomeAssistant, entry: MockConfigEntry
) -> bool:
    """Set up a mock entry."""
    return True


async def _async_unload_entry_success(
    hass: HomeAssistant, entry: MockConfigEntry
) -> bool:
    """Unload a mock entry."""
    return True


def _oidc_spec(
    *,
    accounts: AccountPolicy = AccountPolicy.LINK,
    client_id: str = CLIENT_ID,
) -> IdentityProvider:
    """Return a valid OIDC identity provider spec."""
    return IdentityProvider(
        client_id=client_id,
        protocol=OpenIDConnect(issuer=ISSUER),
        accounts=accounts,
        revalidate_interval=timedelta(hours=1)
        if accounts is AccountPolicy.PROVISION
        else None,
    )


def _mock_platform(
    hass: HomeAssistant,
    spec: IdentityProvider | None = None,
    *,
    domain: str = DOMAIN,
    built_in: bool = True,
    setup_entry: Any = _async_setup_entry_success,
) -> Mock:
    """Mock an integration with an identity provider platform."""
    mock_integration(
        hass,
        MockModule(
            domain,
            async_setup_entry=setup_entry,
            async_unload_entry=_async_unload_entry_success,
            partial_manifest={"config_flow": False},
        ),
        built_in=built_in,
    )
    config_entries.HANDLERS[domain] = _MockFlow
    platform = Mock()
    platform.get_identity_provider.return_value = spec or _oidc_spec()
    mock_platform(hass, f"{domain}.config_flow", built_in=built_in)
    mock_platform(hass, f"{domain}.identity_provider", platform, built_in=built_in)
    return platform


async def _setup_auth_with_oidc(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
    *,
    fake: FakeOpenIDProvider | None = None,
) -> Any:
    """Set up auth with the OIDC engine enabled."""
    fake = fake or FakeOpenIDProvider(aioclient_mock, ISSUER)
    return await async_setup_auth(hass, aiohttp_client, [{"type": "oidc"}])


def _entry(*, domain: str = DOMAIN, title: str = "Example ID") -> MockConfigEntry:
    """Return a mock config entry."""
    return MockConfigEntry(domain=domain, title=title, entry_id=f"{domain}-entry")


def _root(hass: HomeAssistant) -> OidcAuthProvider:
    """Return the root OIDC provider."""
    provider = async_get_provider(hass)
    assert isinstance(provider, OidcAuthProvider)
    return provider


async def test_registers_entry_loaded_before_platform_processed(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test loaded entries are registered when the platform is processed."""
    entry = _entry()
    entry.add_to_hass(hass)
    platform = _mock_platform(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)

    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)

    child = _root(hass).async_get_child_provider(entry.entry_id)
    assert child is not None
    assert child.active
    platform.get_identity_provider.assert_called_once_with(entry.data, entry.options)


async def test_registers_entry_loaded_after_bridge_setup(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test a future loaded integration platform registers its entry."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(hass)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    child = _root(hass).async_get_child_provider(entry.entry_id)
    assert child is not None
    assert child.active


async def test_unrelated_entry_change_is_ignored(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test unrelated config entry updates do not schedule reconciliation."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    entry = MockConfigEntry(domain="unrelated")
    entry.add_to_hass(hass)

    with patch.object(hass, "async_create_task") as create_task:
        hass.config_entries.async_update_entry(entry, title="Updated unrelated")

    create_task.assert_not_called()


async def test_suspends_on_unload_and_failed_setup(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test entries are suspended when unloaded or setup fails."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    root = _root(hass)
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    child = root.async_get_child_provider(entry.entry_id)
    assert child is not None
    assert not child.active

    failed = _entry(domain="failed_idp")
    failed.add_to_hass(hass)
    await root.async_register_identity_provider(
        failed.entry_id,
        domain=failed.domain,
        title=failed.title,
        spec=_oidc_spec(),
    )
    _mock_platform(
        hass, domain=failed.domain, setup_entry=AsyncMock(return_value=False)
    )
    assert not await hass.config_entries.async_setup(failed.entry_id)
    await hass.async_block_till_done()
    child = root.async_get_child_provider(failed.entry_id)
    assert child is not None
    assert not child.active


async def test_reregisters_on_title_and_data_change_and_skips_unchanged(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test changed entries re-register and unchanged entries are skipped."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="Example ID",
        entry_id=f"{DOMAIN}-entry",
        data={"client_id": CLIENT_ID},
    )
    entry.add_to_hass(hass)
    platform = _mock_platform(hass)
    platform.get_identity_provider.side_effect = lambda data, options: _oidc_spec(
        client_id=data["client_id"]
    )
    root = _root(hass)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    with patch.object(
        root,
        "async_register_identity_provider",
        wraps=root.async_register_identity_provider,
    ) as register:
        hass.config_entries.async_update_entry(entry, title="New title")
        await hass.async_block_till_done()
        hass.config_entries.async_update_entry(entry, data={"client_id": "new-client"})
        await hass.async_block_till_done()
        assert register.call_count == 2
        register.reset_mock()
        hass.config_entries.async_update_entry(entry, options={"unrelated": True})
        await hass.async_block_till_done()

    register.assert_not_called()


async def test_disabled_entry_ends_sessions_once_per_transition(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test disabling ends sessions once per disabled transition."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(hass)
    root = _root(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    with patch.object(
        root,
        "async_end_identity_provider_sessions",
        wraps=root.async_end_identity_provider_sessions,
    ) as end_sessions:
        await hass.config_entries.async_set_disabled_by(
            entry.entry_id, ConfigEntryDisabler.USER
        )
        await hass.async_block_till_done()
        hass.config_entries.async_update_entry(entry, title="Disabled title")
        await hass.async_block_till_done()
        await hass.config_entries.async_set_disabled_by(entry.entry_id, None)
        await hass.async_block_till_done()
        await hass.config_entries.async_set_disabled_by(
            entry.entry_id, ConfigEntryDisabler.USER
        )
        await hass.async_block_till_done()

    assert end_sessions.call_count == 2


async def test_removal_creates_issue_for_users_left_without_login(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test removing a linked provider creates a repair issue for affected users."""
    fake = FakeOpenIDProvider(aioclient_mock, ISSUER)
    client = await _setup_auth_with_oidc(
        hass, aiohttp_client, aioclient_mock, fake=fake
    )
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    user = await hass.auth.async_create_user("Alice")
    refresh_token = await hass.auth.async_create_refresh_token(user, CLIENT_ID)
    access_token = hass.auth.async_create_access_token(refresh_token)
    await async_link(client, entry.entry_id, fake, access_token)

    await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()

    issue = issue_registry.async_get_issue(
        "auth", f"identity_provider_removed_{entry.entry_id}"
    )
    assert issue is not None
    assert issue.translation_placeholders == {
        "title": "Example ID",
        "users": "Alice",
    }


async def test_removal_when_platform_unknown(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test removal works when the platform was never loaded."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    root = _root(hass)
    entry = _entry(domain="custom_deleted")
    entry.add_to_hass(hass)
    await root.async_register_identity_provider(
        entry.entry_id, domain=entry.domain, title=entry.title, spec=_oidc_spec()
    )

    await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.entry_id not in root.identity_provider_ids


async def test_invalid_spec_issue_created_and_cleared(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test invalid specs create a repair issue and success clears it."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    entry = _entry()
    entry.add_to_hass(hass)
    platform = _mock_platform(hass, IdentityProvider(client_id="", protocol="bad"))  # type: ignore[arg-type]

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    issue_id = f"invalid_identity_provider_{entry.entry_id}"
    assert issue_registry.async_get_issue("auth", issue_id) is not None

    platform.get_identity_provider.return_value = _oidc_spec()
    hass.config_entries.async_update_entry(entry, data={"changed": True})
    await hass.async_block_till_done()

    assert issue_registry.async_get_issue("auth", issue_id) is None


async def test_get_identity_provider_exception_creates_issue(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test integration exceptions create an invalid provider issue."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    entry = _entry()
    entry.add_to_hass(hass)
    platform = _mock_platform(hass)
    platform.get_identity_provider.side_effect = RuntimeError("boom")

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert (
        issue_registry.async_get_issue(
            "auth", f"invalid_identity_provider_{entry.entry_id}"
        )
        is not None
    )


async def test_custom_integration_warning_logged_once(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test custom identity provider integrations log a warning once."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(hass, built_in=False)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    hass.config_entries.async_update_entry(entry, title="Another title")
    await hass.async_block_till_done()

    assert caplog.text.count("has not been reviewed by Home Assistant") == 1


async def test_custom_integration_cannot_bring_a_protocol(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
    caplog: pytest.LogCaptureFixture,
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test custom integrations are limited to the OpenID Connect protocol."""
    await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(
        hass,
        IdentityProvider(client_id=CLIENT_ID, protocol=ProfileProtocol()),
        built_in=False,
    )

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.entry_id not in _root(hass).identity_provider_ids
    assert "may only use the OpenIDConnect protocol" in caplog.text
    assert (
        issue_registry.async_get_issue(
            "auth", f"invalid_identity_provider_{entry.entry_id}"
        )
        is not None
    )


async def test_orphan_cleanup_at_started(
    hass: HomeAssistant,
) -> None:
    """Test stored providers with no config entry are removed after start."""
    hass.auth = await auth.auth_manager_from_config(hass, [{"type": "oidc"}], [])
    ensure_auth_manager_loaded(hass.auth)
    root = _root(hass)
    await root.async_register_identity_provider(
        "orphan", domain=DOMAIN, title="Orphan", spec=_oidc_spec()
    )
    assert await async_setup_component(hass, "auth", {})

    hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
    await hass.async_block_till_done()

    assert "orphan" not in root.identity_provider_ids


async def test_engine_missing_issue(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    issue_registry: ir.IssueRegistry,
) -> None:
    """Test a repair issue is created when the engine is disabled."""
    await async_setup_auth(hass, aiohttp_client)
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(hass)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert (
        issue_registry.async_get_issue("auth", "identity_providers_disabled")
        is not None
    )


async def test_redirect_uris(hass: HomeAssistant) -> None:
    """Test redirect URIs include external, cloud and internal URLs deduped."""
    with patch(
        "homeassistant.components.auth.identity_providers.get_url",
        side_effect=[
            "https://external.example.com",
            "https://cloud.example.com",
            "https://external.example.com",
        ],
    ):
        assert async_get_redirect_uris(hass) == [
            f"https://external.example.com{LOGIN_CALLBACK_PATH}",
            f"https://cloud.example.com{LOGIN_CALLBACK_PATH}",
        ]


async def test_redirect_uris_no_url(hass: HomeAssistant) -> None:
    """Test redirect URIs are empty when no URL is available."""
    with patch(
        "homeassistant.components.auth.identity_providers.get_url",
        side_effect=NoURLAvailableError,
    ):
        assert async_get_redirect_uris(hass) == []


async def test_identity_providers_enabled(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
) -> None:
    """Test identity provider engine enabled helper."""
    assert not async_identity_providers_enabled(hass)
    await async_setup_auth(hass, aiohttp_client, [{"type": "oidc"}])
    assert async_identity_providers_enabled(hass)


async def test_openid_connect_link_helper(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test OpenIDConnect LINK specs can link and then sign in."""
    fake = FakeOpenIDProvider(aioclient_mock, ISSUER)
    client = await _setup_auth_with_oidc(
        hass, aiohttp_client, aioclient_mock, fake=fake
    )
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    unlinked = await async_sign_in(client, entry.entry_id, fake, sub="unlinked")
    user = await hass.auth.async_create_user("Alice")
    refresh_token = await hass.auth.async_create_refresh_token(user, CLIENT_ID)
    access_token = hass.auth.async_create_access_token(refresh_token)

    await async_link(client, entry.entry_id, fake, access_token)
    linked = await async_sign_in(client, entry.entry_id, fake)
    resp = await client.post(
        "/auth/token",
        data={
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": linked["result"],
        },
    )

    assert unlinked["type"] == "abort"
    assert unlinked["reason"] == "user_not_allowed"
    assert resp.status == HTTPStatus.OK


async def test_openid_connect_provision_helper(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test OpenIDConnect PROVISION specs create a user."""
    fake = FakeOpenIDProvider(aioclient_mock, ISSUER)
    client = await _setup_auth_with_oidc(
        hass, aiohttp_client, aioclient_mock, fake=fake
    )
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(hass, _oidc_spec(accounts=AccountPolicy.PROVISION))
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    step = await async_sign_in(client, entry.entry_id, fake)
    resp = await client.post(
        "/auth/token",
        data={
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": step["result"],
        },
    )

    assert resp.status == HTTPStatus.OK
    tokens = await resp.json()
    refresh_token = hass.auth.async_validate_access_token(tokens["access_token"])
    assert refresh_token is not None
    assert refresh_token.user.name == "Alice"


async def test_oauth2_protocol_links_and_signs_in(
    hass: HomeAssistant,
    aiohttp_client: ClientSessionGenerator,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test a built-in integration's own protocol can link and then sign in."""
    fake = FakeOAuth2ProfileProvider(
        aioclient_mock,
        authorize_url=PROFILE_AUTHORIZE_URL,
        token_url=PROFILE_TOKEN_URL,
        profile_url=PROFILE_URL,
    )
    client = await _setup_auth_with_oidc(hass, aiohttp_client, aioclient_mock)
    entry = _entry()
    entry.add_to_hass(hass)
    _mock_platform(
        hass, IdentityProvider(client_id=CLIENT_ID, protocol=ProfileProtocol())
    )
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    user = await hass.auth.async_create_user("Alice")
    refresh_token = await hass.auth.async_create_refresh_token(user, CLIENT_ID)
    access_token = hass.auth.async_create_access_token(refresh_token)

    await async_link(client, entry.entry_id, fake, access_token)
    step = await async_sign_in(client, entry.entry_id, fake)

    assert step["type"] == "create_entry"
