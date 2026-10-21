"""Test the OpenID Connect auth provider configuration API."""

from collections.abc import Generator
from datetime import timedelta
from unittest.mock import patch

from aiohttp import WSMsgType
import pytest
from pytest_homeassistant.common import (
    CLIENT_ID as TEST_CLIENT_ID,
    MockConfigEntry,
    MockUser,
)
from pytest_homeassistant.typing import WebSocketGenerator

from homeassistant.auth import models as auth_models
from homeassistant.auth.models import Credentials
from homeassistant.auth.providers import insecure_example
from homeassistant.auth.providers.homeassistant import HassAuthProvider
from homeassistant.auth.providers.oidc import OidcAuthProvider
from homeassistant.auth.providers.oidc.const import PROVIDER_TYPE
from homeassistant.auth.providers.oidc.spec import (
    AccountPolicy,
    IdentityProvider,
    OpenIDConnect,
)
from homeassistant.components.config import auth_provider_oidc
from homeassistant.core import HomeAssistant

ISSUER = "https://idp.example.com"
CLIENT_ID = "home-assistant"
SUBJECT = "user-1234"
IDP_ID = "entry-id"


@pytest.fixture
async def oidc_provider(hass: HomeAssistant) -> OidcAuthProvider:
    """Load the OpenID Connect auth provider."""
    prv = OidcAuthProvider(hass, hass.auth._store, {"type": PROVIDER_TYPE})
    await prv.async_initialize()
    hass.auth._providers[(prv.type, prv.id)] = prv
    await prv.async_register_identity_provider(
        IDP_ID,
        domain="openid_connect",
        title="Example ID",
        spec=IdentityProvider(
            client_id=CLIENT_ID,
            protocol=OpenIDConnect(issuer=ISSUER),
        ),
    )
    return prv


@pytest.fixture(autouse=True)
def setup_config(hass: HomeAssistant, oidc_provider: OidcAuthProvider) -> None:
    """Set up the configuration API."""
    auth_provider_oidc.async_setup(hass)


async def _link(
    hass: HomeAssistant,
    oidc_provider: OidcAuthProvider,
    user: auth_models.User,
    *,
    idp_id: str = IDP_ID,
    issuer: str = ISSUER,
    account_name: str | None = None,
) -> Credentials:
    """Attach an identity provider login to a user."""
    child = oidc_provider.async_get_child_provider(idp_id)
    assert child is not None
    data = {"issuer": issuer, "subject": SUBJECT}
    if account_name is not None:
        data["account_name"] = account_name
    credentials = child.async_create_credentials(data)
    await hass.auth.async_link_user(user, credentials)
    return credentials


async def _register_identity_provider(
    oidc_provider: OidcAuthProvider,
    idp_id: str,
    *,
    title: str,
    domain: str = "openid_connect",
    issuer: str,
    accounts: AccountPolicy = AccountPolicy.LINK,
) -> None:
    """Register an identity provider."""
    spec = IdentityProvider(
        client_id=CLIENT_ID,
        protocol=OpenIDConnect(issuer=issuer),
        accounts=accounts,
        revalidate_interval=(
            timedelta(hours=1) if accounts is AccountPolicy.PROVISION else None
        ),
    )
    await oidc_provider.async_register_identity_provider(
        idp_id,
        domain=domain,
        title=title,
        spec=spec,
    )


async def _give_password(hass: HomeAssistant, user: auth_models.User) -> None:
    """Attach a password login to a user."""
    await hass.auth.async_link_user(
        user,
        Credentials(
            auth_provider_type="homeassistant",
            auth_provider_id=None,
            data={"username": "hello"},
            is_new=False,
        ),
    )


@pytest.fixture
def stepped_up() -> Generator[None]:
    """Treat every session as having just proved its user again."""
    with patch(
        "homeassistant.auth.AuthManager.async_consume_step_up", return_value=True
    ):
        yield


async def _step_up(
    hass: HomeAssistant,
    local_auth: HassAuthProvider,
    refresh_token: auth_models.RefreshToken,
) -> None:
    """Prove the session's user again, as the frontend does before unlinking."""
    username = local_auth.async_get_username(refresh_token.user)
    assert username is not None
    await hass.async_add_executor_job(local_auth.data.add_auth, username, "test-pass")
    await hass.auth.async_step_up(
        refresh_token.id, local_auth, {"password": "test-pass"}, None
    )


async def test_list_returns_active_providers_and_user_credentials_for_non_admin(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_read_only_user: MockUser,
    hass_read_only_access_token: str,
) -> None:
    """Test a non-admin can list available providers and their own credentials."""
    MockConfigEntry(
        domain="google_sign_in", entry_id=IDP_ID, title="Zulu Entry"
    ).add_to_hass(hass)
    await _register_identity_provider(
        oidc_provider,
        "alpha",
        title="Alpha Fallback",
        domain="alpha_brand",
        issuer="https://alpha.example.com",
    )
    await _register_identity_provider(
        oidc_provider,
        "provisioning",
        title="Provisioning Fallback",
        domain="github",
        issuer="https://provisioning.example.com",
        accounts=AccountPolicy.PROVISION,
    )
    link_credentials = await _link(
        hass,
        oidc_provider,
        hass_read_only_user,
        account_name="alice@example.com",
    )
    provisioning_credentials = await _link(
        hass,
        oidc_provider,
        hass_read_only_user,
        idp_id="provisioning",
        issuer="https://provisioning.example.com",
        account_name="alice-github",
    )
    await _give_password(hass, hass_read_only_user)

    client = await hass_ws_client(hass, hass_read_only_access_token)
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/list"})

    result = await client.receive_json()

    assert result["success"]
    assert result["result"] == {
        "identity_providers": [
            {
                "id": "alpha",
                "name": "Alpha Fallback",
                "domain": "alpha_brand",
                "accounts": "link",
            },
            {
                "id": "provisioning",
                "name": "Provisioning Fallback",
                "domain": "github",
                "accounts": "provision",
            },
            {
                "id": IDP_ID,
                "name": "Zulu Entry",
                "domain": "openid_connect",
                "accounts": "link",
            },
        ],
        "credentials": [
            {
                "credential_id": link_credentials.id,
                "identity_provider_id": IDP_ID,
                "name": "Zulu Entry",
                "domain": "openid_connect",
                "account_name": "alice@example.com",
                "available": True,
                "can_unlink": True,
                "has_other_login": True,
            },
            {
                "credential_id": provisioning_credentials.id,
                "identity_provider_id": "provisioning",
                "name": "Provisioning Fallback",
                "domain": "github",
                "account_name": "alice-github",
                "available": True,
                "can_unlink": False,
                "has_other_login": True,
            },
        ],
    }


async def test_list_includes_dormant_credentials_and_skips_missing_child(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
) -> None:
    """Test dormant credentials are listed and credentials without a child are skipped."""
    user = await hass.auth.async_create_user("Dormant")
    MockConfigEntry(
        domain="openid_connect", entry_id=IDP_ID, title="Dormant Entry"
    ).add_to_hass(hass)
    credentials = await _link(
        hass,
        oidc_provider,
        user,
        account_name="alice@example.com",
    )
    oidc_provider.async_suspend_identity_provider(IDP_ID)
    await hass.auth.async_link_user(
        user,
        Credentials(
            auth_provider_type=PROVIDER_TYPE,
            auth_provider_id="gone",
            data={"issuer": "https://gone.example.com", "subject": SUBJECT},
            is_new=False,
        ),
    )
    refresh_token = await hass.auth.async_create_refresh_token(user, TEST_CLIENT_ID)

    client = await hass_ws_client(
        hass, hass.auth.async_create_access_token(refresh_token)
    )
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/list"})

    result = await client.receive_json()

    assert result["success"]
    assert result["result"] == {
        "identity_providers": [],
        "credentials": [
            {
                "credential_id": credentials.id,
                "identity_provider_id": IDP_ID,
                "name": "Dormant Entry",
                "domain": "openid_connect",
                "account_name": "alice@example.com",
                "available": False,
                "can_unlink": True,
                "has_other_login": False,
            }
        ],
    }


async def test_list_when_engine_disabled(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
) -> None:
    """Test listing reports when the OIDC provider is disabled."""
    hass.auth._providers.pop((PROVIDER_TYPE, None))

    client = await hass_ws_client(hass)
    await client.send_json_auto_id({"type": "config/auth_provider/oidc/list"})

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "not_enabled"


@pytest.mark.usefixtures("stepped_up")
async def test_unlink_when_engine_disabled(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
) -> None:
    """Test unlink reports when the OIDC provider is disabled."""
    hass.auth._providers.pop((PROVIDER_TYPE, None))

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": "missing"}
    )

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "not_enabled"


async def test_unlink(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_admin_user: MockUser,
    hass_access_token: str,
    local_auth: HassAuthProvider,
) -> None:
    """Test a user can detach one of their identity provider logins."""
    credentials = await _link(hass, oidc_provider, hass_admin_user)
    await _give_password(hass, hass_admin_user)
    await _step_up(
        hass, local_auth, hass.auth.async_validate_access_token(hass_access_token)
    )

    client = await hass_ws_client(hass, hass_access_token)
    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": credentials.id}
    )

    result = await client.receive_json()

    assert result["success"]
    assert credentials not in hass_admin_user.credentials
    assert await hass.auth.async_get_user_by_credentials(credentials) is None


async def test_unlink_requires_a_step_up(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_admin_user: MockUser,
) -> None:
    """Test a session that did not prove the user again cannot unlink."""
    credentials = await _link(hass, oidc_provider, hass_admin_user)
    await _give_password(hass, hass_admin_user)

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": credentials.id}
    )

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "step_up_required"
    assert credentials in hass_admin_user.credentials


async def test_unlink_returns_result_before_disconnect(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_admin_user: MockUser,
    local_auth: HassAuthProvider,
) -> None:
    """Test unlink is acknowledged before its session closes."""
    credentials = await _link(hass, oidc_provider, hass_admin_user)
    await _give_password(hass, hass_admin_user)
    refresh_token = await hass.auth.async_create_refresh_token(
        hass_admin_user, TEST_CLIENT_ID, credential=credentials
    )
    await _step_up(hass, local_auth, refresh_token)
    access_token = hass.auth.async_create_access_token(refresh_token)
    client = await hass_ws_client(hass, access_token)
    peer = await hass_ws_client(hass, access_token)
    unrelated = await hass.auth.async_create_refresh_token(
        hass_admin_user, "https://other-client.example.com"
    )

    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": credentials.id}
    )

    result = await client.receive_json()
    assert result["success"]
    assert hass.auth.async_get_refresh_token(refresh_token.id) is None
    assert hass.auth.async_get_refresh_token(unrelated.id) is unrelated
    assert (await peer.receive()).type is WSMsgType.CLOSE
    assert (await client.receive()).type is WSMsgType.CLOSE


async def test_unlink_needs_another_way_in(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
) -> None:
    """Test a user cannot remove the only login they have."""
    user = await hass.auth.async_create_user("Alice")
    credentials = await _link(hass, oidc_provider, user)
    refresh_token = await hass.auth.async_create_refresh_token(
        user, TEST_CLIENT_ID, credential=credentials
    )

    client = await hass_ws_client(
        hass, hass.auth.async_create_access_token(refresh_token)
    )
    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": credentials.id}
    )

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "no_other_login"
    assert credentials in user.credentials


async def test_unlink_counts_any_other_configured_login(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
) -> None:
    """Test the login left behind does not have to be a password."""
    user = await hass.auth.async_create_user("Alice")
    credentials = await _link(hass, oidc_provider, user)
    example = insecure_example.ExampleAuthProvider(
        hass, hass.auth._store, {"type": "insecure_example", "users": []}
    )
    hass.auth._providers[(example.type, example.id)] = example
    other_login = example.async_create_credentials({"username": "alice"})
    await hass.auth.async_link_user(user, other_login)
    refresh_token = await hass.auth.async_create_refresh_token(
        user, TEST_CLIENT_ID, credential=other_login
    )

    client = await hass_ws_client(
        hass, hass.auth.async_create_access_token(refresh_token)
    )
    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": credentials.id}
    )

    result = await client.receive_json()

    assert result["success"]
    assert credentials not in user.credentials


@pytest.mark.usefixtures("stepped_up")
async def test_unlink_refuses_provisioning_provider(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_admin_user: MockUser,
) -> None:
    """Test provisioning credentials cannot be unlinked."""
    await oidc_provider.async_register_identity_provider(
        "provisioning",
        domain="openid_connect",
        title="Provisioning ID",
        spec=IdentityProvider(
            client_id=CLIENT_ID,
            protocol=OpenIDConnect(issuer="https://provisioning.example.com"),
            accounts=AccountPolicy.PROVISION,
            revalidate_interval=timedelta(hours=1),
        ),
    )
    child = oidc_provider.async_get_child_provider("provisioning")
    assert child is not None
    credentials = child.async_create_credentials(
        {"issuer": "https://provisioning.example.com", "subject": SUBJECT}
    )
    await hass.auth.async_link_user(hass_admin_user, credentials)
    await _give_password(hass, hass_admin_user)

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": credentials.id}
    )

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "provisioning_provider"
    assert credentials in hass_admin_user.credentials


@pytest.mark.usefixtures("stepped_up")
async def test_unlink_without_a_matching_linked_account(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    hass_admin_user: MockUser,
) -> None:
    """Test a user with no matching linked credential is told so."""
    await _give_password(hass, hass_admin_user)

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": "missing"}
    )

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "not_linked"


@pytest.mark.usefixtures("stepped_up")
async def test_unlink_without_registered_identity_provider(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    hass_admin_user: MockUser,
) -> None:
    """Test unlink reports a linked credential with no registered child."""
    credentials = Credentials(
        auth_provider_type=PROVIDER_TYPE,
        auth_provider_id="gone",
        data={"issuer": "https://gone.example.com", "subject": SUBJECT},
        is_new=False,
    )
    await hass.auth.async_link_user(hass_admin_user, credentials)
    await _give_password(hass, hass_admin_user)

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": credentials.id}
    )

    result = await client.receive_json()

    assert not result["success"]
    assert result["error"]["code"] == "not_linked"


async def test_unlink_is_allowed_for_non_admins(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    oidc_provider: OidcAuthProvider,
    hass_read_only_user: MockUser,
    hass_read_only_access_token: str,
    local_auth: HassAuthProvider,
) -> None:
    """Test detaching your own login does not need administrator rights."""
    credentials = await _link(hass, oidc_provider, hass_read_only_user)
    await _step_up(
        hass,
        local_auth,
        hass.auth.async_validate_access_token(hass_read_only_access_token),
    )

    client = await hass_ws_client(hass, hass_read_only_access_token)
    await client.send_json_auto_id(
        {"type": "config/auth_provider/oidc/unlink", "credential_id": credentials.id}
    )

    result = await client.receive_json()

    assert result["success"]
    assert credentials not in hass_read_only_user.credentials
