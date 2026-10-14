"""Test the OpenID Connect auth provider."""

import asyncio
import base64
from contextlib import suppress
from dataclasses import dataclass
from datetime import timedelta
import hashlib
from ipaddress import ip_address
import json
import math
import time
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
from freezegun.api import FrozenDateTimeFactory
import jwt
from jwt.algorithms import RSAAlgorithm
import pytest
from yarl import URL

from homeassistant import auth
from homeassistant.auth import auth_store, models as auth_models
from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_READ_ONLY, GROUP_ID_USER
from homeassistant.auth.models import AuthFlowResult
from homeassistant.auth.providers import insecure_example, oidc as oidc_auth
from homeassistant.auth.providers.oidc.client import (
    OidcClient,
    OidcDiscoveryError,
    OidcError,
    OidcIdTokenError,
    OidcInvalidGrantError,
    OidcTokenError,
    OidcTransientError,
)
from homeassistant.auth.providers.oidc.const import (
    DEFAULT_DISPLAY_NAME_CLAIM,
    DEFAULT_REVALIDATE_INTERVAL,
    DEFAULT_SCOPES,
    DEFAULT_USERNAME_CLAIM,
    MIN_REVALIDATE_INTERVAL,
    PROVIDER_TYPE,
    REVALIDATE_CHECK_INTERVAL,
    REVALIDATE_REFRESH_RATIO,
    STORAGE_KEY,
    STORAGE_VERSION,
    UNCLAIMED_SESSION_TIMEOUT,
)
from homeassistant.auth.providers.oidc.spec import (
    AccountPolicy,
    IdentityProvider,
    OpenIDConnect,
)
from homeassistant.auth.providers.oidc.store import (
    IdentityProviderRecord,
    OidcSession,
    OidcStore,
)
from homeassistant.const import EVENT_HOMEASSISTANT_FINAL_WRITE
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.util import dt as dt_util

from tests.common import async_fire_time_changed
from tests.components.auth.common import (
    PROFILE_ISSUER,
    PROFILE_TOKEN_URL,
    PROFILE_URL,
    ProfileProtocol,
)
from tests.test_util.aiohttp import AiohttpClientMocker

ISSUER = "https://idp.example.com"
CLIENT_ID = "home-assistant"
KEY_ID = "test-key"
REDIRECT_BASE = "https://ha.example.com"
SUBJECT = "user-1234"
IDP_ID = "test-idp"
IDP_DOMAIN = "openid_connect"

DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/jwks"
TOKEN_URL = f"{ISSUER}/token"
USERINFO_URL = f"{ISSUER}/userinfo"


def make_spec(
    *,
    issuer: str = ISSUER,
    client_id: str = CLIENT_ID,
    client_secret: str | None = None,
    scopes: tuple[str, ...] = DEFAULT_SCOPES,
    account_name_claim: str | None = None,
    username_claim: str = DEFAULT_USERNAME_CLAIM,
    display_name_claim: str = DEFAULT_DISPLAY_NAME_CLAIM,
    admin_group: str | None = "home_assistant_admin",
    accounts: AccountPolicy = AccountPolicy.PROVISION,
    revalidate_interval: int = DEFAULT_REVALIDATE_INTERVAL,
    allow_insecure_transport: bool = False,
) -> IdentityProvider:
    """Return an OIDC identity provider spec for tests."""
    return IdentityProvider(
        client_id=client_id,
        client_secret=client_secret,
        protocol=OpenIDConnect(
            issuer=issuer,
            scopes=scopes,
            account_name_claim=account_name_claim,
            username_claim=username_claim,
            display_name_claim=display_name_claim,
            admin_group=admin_group,
        ),
        accounts=accounts,
        revalidate_interval=(
            timedelta(seconds=revalidate_interval)
            if accounts is AccountPolicy.PROVISION
            else None
        ),
        allow_insecure_transport=allow_insecure_transport,
    )


@dataclass(slots=True)
class OidcProvider:
    """OIDC root and child used by tests."""

    root: oidc_auth.OidcAuthProvider
    child: oidc_auth.OidcIdentityProvider


@pytest.fixture(scope="module")
def signing_key() -> rsa.RSAPrivateKey:
    """Return an RSA key to sign ID tokens with."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(signing_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    """Return the key set of the identity provider."""
    key = json.loads(RSAAlgorithm.to_jwk(signing_key.public_key()))
    key |= {"kid": KEY_ID, "alg": "RS256", "use": "sig"}
    return {"keys": [key]}


def discovery_document(**overrides: Any) -> dict[str, Any]:
    """Return a discovery document for the identity provider."""
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": TOKEN_URL,
        "jwks_uri": JWKS_URL,
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "id_token_signing_alg_values_supported": ["RS256"],
    } | overrides


def make_id_token(
    signing_key: rsa.RSAPrivateKey,
    *,
    key_id: str = KEY_ID,
    algorithm: str = "RS256",
    key: Any = None,
    **overrides: Any,
) -> str:
    """Return a signed ID token."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": SUBJECT,
        "aud": CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
        "preferred_username": "alice",
        "name": "Alice",
    } | overrides
    return jwt.encode(
        {k: v for k, v in claims.items() if v is not None},
        key if key is not None else signing_key,
        algorithm=algorithm,
        headers={"kid": key_id} if key_id else None,
    )


@pytest.fixture
def mock_idp(
    aioclient_mock: AiohttpClientMocker, jwks: dict[str, Any]
) -> AiohttpClientMocker:
    """Mock the discovery document and key set of the identity provider."""
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document())
    aioclient_mock.get(JWKS_URL, json=jwks)
    return aioclient_mock


@pytest.fixture
def client(hass: HomeAssistant, mock_idp: AiohttpClientMocker) -> OidcClient:
    """Return a client for the mocked identity provider."""
    return OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)


@pytest.fixture
async def manager(
    hass: HomeAssistant, hass_storage: dict[str, Any]
) -> auth.AuthManager:
    """Return an auth manager with the OIDC provider enabled."""
    manager = await auth.auth_manager_from_config(hass, [{"type": PROVIDER_TYPE}], [])
    # The provider signs users out through hass.auth, so it has to be the same
    # manager that owns its store.
    hass.auth = manager
    return manager


@pytest.fixture
async def provider(manager: auth.AuthManager) -> OidcProvider:
    """Return a configured OIDC root and child provider."""
    root = manager.auth_providers[0]
    assert isinstance(root, oidc_auth.OidcAuthProvider)
    await root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(),
    )
    child = root.async_get_child_provider(IDP_ID)
    assert isinstance(child, oidc_auth.OidcIdentityProvider)
    return OidcProvider(root, child)


async def test_discovery_rejects_issuer_mismatch(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a discovery document served for another issuer is refused."""
    aioclient_mock.get(
        DISCOVERY_URL, json=discovery_document(issuer="https://evil.example.com")
    )
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="does not match"):
        await client.async_metadata()


async def test_discovery_rejects_trailing_slash_issuer_mismatch(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test issuer identifiers are compared exactly as OIDC requires."""
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document(issuer=f"{ISSUER}/"))
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="does not match"):
        await client.async_metadata()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_endpoint", "http://idp.example.com/authorize"),
        ("token_endpoint", "http://idp.example.com/token"),
        ("jwks_uri", "http://idp.example.com/jwks"),
        ("userinfo_endpoint", "http://idp.example.com/userinfo"),
        ("revocation_endpoint", "http://idp.example.com/revoke"),
    ],
)
async def test_discovery_requires_https(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    field: str,
    value: str,
) -> None:
    """Test plain http endpoints are refused."""
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document(**{field: value}))
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="https"):
        await client.async_metadata()


@pytest.mark.parametrize(
    "field",
    [
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "revocation_endpoint",
    ],
)
async def test_discovery_allows_http_when_insecure_transport_is_allowed(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, field: str
) -> None:
    """Test an administrator can let the provider use plain http endpoints."""
    value = f"http://idp.example.com/{field}"
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document(**{field: value}))
    client = OidcClient(
        hass, issuer=ISSUER, client_id=CLIENT_ID, allow_insecure_transport=True
    )

    metadata = await client.async_metadata()

    assert getattr(metadata, field) == value


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("token_endpoint", "http://user:password@idp.example.com/token"),
        ("jwks_uri", "http://idp.example.com/jwks#keys"),
        ("authorization_endpoint", "ftp://idp.example.com/authorize"),
    ],
    ids=["embedded-credentials", "fragment", "other-scheme"],
)
async def test_insecure_transport_keeps_the_other_endpoint_rules(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    field: str,
    value: str,
) -> None:
    """Test allowing http does not let through anything else."""
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document(**{field: value}))
    client = OidcClient(
        hass, issuer=ISSUER, client_id=CLIENT_ID, allow_insecure_transport=True
    )

    with pytest.raises(OidcDiscoveryError):
        await client.async_metadata()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("token_endpoint", "https://user:password@idp.example.com/token"),
        ("jwks_uri", "https://idp.example.com/jwks#keys"),
    ],
    ids=["embedded-credentials", "fragment"],
)
async def test_discovery_rejects_ambiguous_endpoints(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    field: str,
    value: str,
) -> None:
    """Test endpoints cannot carry credentials or a client-side fragment."""
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document(**{field: value}))
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="https"):
        await client.async_metadata()


async def test_discovery_requires_endpoints(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test an incomplete discovery document is refused."""
    document = discovery_document()
    del document["token_endpoint"]
    aioclient_mock.get(DISCOVERY_URL, json=document)
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="token_endpoint"):
        await client.async_metadata()


async def test_discovery_allows_an_issuer_with_a_trailing_slash(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test providers that end their issuer in a slash are usable."""
    issuer = f"{ISSUER}/"
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document(issuer=issuer))
    client = OidcClient(hass, issuer=issuer, client_id=CLIENT_ID)

    metadata = await client.async_metadata()

    assert metadata.issuer == issuer


async def test_discovery_requires_s256_pkce_when_advertised(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a provider that only offers plain PKCE is refused."""
    aioclient_mock.get(
        DISCOVERY_URL,
        json=discovery_document(code_challenge_methods_supported=["plain"]),
    )
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="S256"):
        await client.async_metadata()


async def test_discovery_rejects_malformed_string_arrays(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test malformed discovery arrays are not silently treated as absent."""
    aioclient_mock.get(
        DISCOVERY_URL,
        json=discovery_document(
            token_endpoint_auth_methods_supported=["client_secret_basic", 1]
        ),
    )
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="auth_methods"):
        await client.async_metadata()


async def test_token_response_must_be_a_bearer_token(
    client: OidcClient, mock_idp: AiohttpClientMocker
) -> None:
    """Test a token the provider does not call a bearer is refused."""
    mock_idp.post(TOKEN_URL, json={"access_token": "at", "token_type": "mac"})

    with pytest.raises(OidcTokenError, match="token_type"):
        await client.async_refresh_token("refresh")


@pytest.mark.parametrize("field", ["id_token", "refresh_token"])
async def test_token_response_rejects_non_string_tokens(
    client: OidcClient,
    mock_idp: AiohttpClientMocker,
    field: str,
) -> None:
    """Test every token in a successful response has the required type."""
    mock_idp.post(
        TOKEN_URL,
        json={"access_token": "at", "token_type": "Bearer", field: ["token"]},
    )

    with pytest.raises(OidcTokenError, match=field):
        await client.async_refresh_token("refresh")


async def test_discovery_does_not_follow_redirects(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a redirect cannot move discovery off the URL that was checked."""
    aioclient_mock.get(
        DISCOVERY_URL, status=302, headers={"Location": "http://evil.example.com/"}
    )
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="redirects"):
        await client.async_metadata()


async def test_token_endpoint_does_not_follow_redirects(
    client: OidcClient, mock_idp: AiohttpClientMocker
) -> None:
    """Test the client secret is not replayed to a redirect target."""
    mock_idp.post(
        TOKEN_URL, status=307, headers={"Location": "http://evil.example.com/"}
    )

    with pytest.raises(OidcTokenError, match=r"unusable response \(307\)"):
        await client.async_refresh_token("refresh")


async def test_userinfo_does_not_follow_redirects(
    client: OidcClient, mock_idp: AiohttpClientMocker
) -> None:
    """Test the access token is not replayed to a redirect target."""
    mock_idp.get(
        USERINFO_URL, status=302, headers={"Location": "http://evil.example.com/"}
    )

    with pytest.raises(OidcError, match="redirects"):
        await client.async_merge_userinfo({"sub": SUBJECT}, "at")


async def test_revocation_ignores_discovery_failure(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test an identity provider outage cannot block local token removal."""
    aioclient_mock.get(DISCOVERY_URL, status=503)
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    await client.async_revoke_token("refresh")


async def test_verify_id_token(
    client: OidcClient, signing_key: rsa.RSAPrivateKey
) -> None:
    """Test a valid ID token is accepted."""
    claims = await client.async_verify_id_token(
        make_id_token(signing_key, nonce="the-nonce"), nonce="the-nonce"
    )

    assert claims["sub"] == SUBJECT
    assert claims["preferred_username"] == "alice"


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"aud": "another-client"}, "Audience"),
        ({"iss": "https://evil.example.com"}, "issuer"),
        ({"exp": int(time.time()) - 3600}, "expired"),
        ({"sub": None}, "sub"),
    ],
    ids=["wrong-audience", "wrong-issuer", "expired", "missing-subject"],
)
async def test_verify_id_token_rejects_bad_claims(
    client: OidcClient,
    signing_key: rsa.RSAPrivateKey,
    overrides: dict[str, Any],
    match: str,
) -> None:
    """Test ID tokens with unusable registered claims are refused."""
    with pytest.raises(OidcIdTokenError, match=match):
        await client.async_verify_id_token(make_id_token(signing_key, **overrides))


async def test_verify_id_token_rejects_foreign_signature(client: OidcClient) -> None:
    """Test an ID token signed by another key is refused."""
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with pytest.raises(OidcIdTokenError):
        await client.async_verify_id_token(make_id_token(other_key, key=other_key))


async def test_verify_id_token_rejects_symmetric_algorithm(
    client: OidcClient,
) -> None:
    """Test an ID token signed with the client secret is refused."""
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": SUBJECT,
            "aud": CLIENT_ID,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        },
        "a-shared-secret-long-enough-for-hs256",
        algorithm="HS256",
        headers={"kid": KEY_ID},
    )

    with pytest.raises(OidcIdTokenError, match="unaccepted algorithm"):
        await client.async_verify_id_token(token)


async def test_verify_id_token_rejects_unsigned_token(client: OidcClient) -> None:
    """Test an unsigned ID token is refused."""
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": SUBJECT,
            "aud": CLIENT_ID,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        },
        None,
        algorithm="none",
    )

    with pytest.raises(OidcIdTokenError, match="unaccepted algorithm"):
        await client.async_verify_id_token(token)


async def test_verify_id_token_rejects_nonce_mismatch(
    client: OidcClient, signing_key: rsa.RSAPrivateKey
) -> None:
    """Test an ID token minted for another login attempt is refused."""
    with pytest.raises(OidcIdTokenError, match="nonce"):
        await client.async_verify_id_token(
            make_id_token(signing_key, nonce="other"), nonce="expected"
        )


def expected_at_hash(access_token: str) -> str:
    """Return the at_hash an RS256 ID token should carry for an access token."""
    digest = hashlib.sha256(access_token.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest[:16]).decode("ascii").rstrip("=")


async def test_verify_id_token_accepts_matching_at_hash(
    client: OidcClient, signing_key: rsa.RSAPrivateKey
) -> None:
    """Test an ID token bound to the access token it came with is accepted."""
    claims = await client.async_verify_id_token(
        make_id_token(signing_key, at_hash=expected_at_hash("the-access-token")),
        access_token="the-access-token",
    )

    assert claims["sub"] == SUBJECT


async def test_verify_id_token_rejects_foreign_at_hash(
    client: OidcClient, signing_key: rsa.RSAPrivateKey
) -> None:
    """Test an ID token issued for a different access token is refused."""
    with pytest.raises(OidcIdTokenError, match="at_hash"):
        await client.async_verify_id_token(
            make_id_token(signing_key, at_hash=expected_at_hash("another-token")),
            access_token="the-access-token",
        )


async def test_verify_id_token_rejects_non_ascii_access_token(
    client: OidcClient, signing_key: rsa.RSAPrivateKey
) -> None:
    """Test a non-ASCII access token fails the binding instead of crashing."""
    with pytest.raises(OidcIdTokenError, match="at_hash"):
        await client.async_verify_id_token(
            make_id_token(signing_key, at_hash="unused"),
            access_token="non-ascii-\u00e9",
        )


async def test_verify_id_token_without_at_hash(
    client: OidcClient, signing_key: rsa.RSAPrivateKey
) -> None:
    """Test at_hash stays optional, as the code flow allows."""
    claims = await client.async_verify_id_token(
        make_id_token(signing_key), access_token="the-access-token"
    )

    assert claims["sub"] == SUBJECT


async def test_verify_id_token_at_hash_needs_the_access_token(
    client: OidcClient, signing_key: rsa.RSAPrivateKey
) -> None:
    """Test at_hash is skipped when there is no access token to compare with."""
    claims = await client.async_verify_id_token(
        make_id_token(signing_key, at_hash=expected_at_hash("the-access-token"))
    )

    assert claims["sub"] == SUBJECT


async def test_verify_id_token_rejects_foreign_authorized_party(
    client: OidcClient, signing_key: rsa.RSAPrivateKey
) -> None:
    """Test an ID token authorized for another client is refused."""
    with pytest.raises(OidcIdTokenError, match="azp"):
        await client.async_verify_id_token(
            make_id_token(signing_key, azp="another-client")
        )


async def test_verify_id_token_requires_azp_for_multiple_audiences(
    client: OidcClient, signing_key: rsa.RSAPrivateKey
) -> None:
    """Test a multi audience ID token without an azp claim is refused."""
    with pytest.raises(OidcIdTokenError, match="azp"):
        await client.async_verify_id_token(
            make_id_token(signing_key, aud=[CLIENT_ID, "another-client"])
        )


async def test_verify_id_token_refetches_rotated_keys(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test an unknown key id makes the key set be fetched again."""
    stale = {"keys": [jwks["keys"][0] | {"kid": "retired-key"}]}
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document())
    aioclient_mock.get(JWKS_URL, json=stale)
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcIdTokenError, match="No key"):
        await client.async_verify_id_token(make_id_token(signing_key))

    aioclient_mock.clear_requests()
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document())
    aioclient_mock.get(JWKS_URL, json=jwks)

    # The cooldown keeps a bogus key id from hammering the identity provider.
    with patch("homeassistant.auth.providers.oidc.client.JWKS_REFETCH_COOLDOWN", 0):
        claims = await client.async_verify_id_token(make_id_token(signing_key))

    assert claims["sub"] == SUBJECT


async def test_verify_id_token_rejects_malformed_jwks(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a non-object key set is reported as an OIDC validation error."""
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document())
    aioclient_mock.get(JWKS_URL, json=[])
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcIdTokenError, match="key set"):
        await client.async_verify_id_token(make_id_token(signing_key))


def _jwk(signing_key: rsa.RSAPrivateKey, **overrides: Any) -> dict[str, Any]:
    """Return the provider's public key with adjusted JWK metadata."""
    key = json.loads(RSAAlgorithm.to_jwk(signing_key.public_key()))
    key |= {"kid": KEY_ID, "alg": "RS256", "use": "sig"}
    return {
        name: value for name, value in (key | overrides).items() if value is not None
    }


def _client_with_jwk(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    jwk: dict[str, Any],
    **discovery: Any,
) -> OidcClient:
    """Return a client whose provider publishes exactly this key."""
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document(**discovery))
    aioclient_mock.get(JWKS_URL, json={"keys": [jwk]})
    return OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)


@pytest.mark.parametrize(
    ("metadata", "match"),
    [
        ({"use": "enc"}, "not published"),
        ({"key_ops": ["encrypt"]}, "not published"),
        # A malformed key is dropped when the key set loads.
        ({"key_ops": "verify"}, "no usable key"),
        ({"use": 1}, "no usable key"),
    ],
    ids=["encryption-use", "no-verify-operation", "malformed-ops", "malformed-use"],
)
async def test_verify_id_token_rejects_a_key_not_published_for_signing(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    metadata: dict[str, Any],
    match: str,
) -> None:
    """Test a key the issuer did not publish for verifying is not trusted."""
    client = _client_with_jwk(hass, aioclient_mock, _jwk(signing_key, **metadata))

    with pytest.raises(OidcIdTokenError, match=match):
        await client.async_verify_id_token(make_id_token(signing_key))


@pytest.mark.parametrize(
    "metadata",
    [{}, {"use": None}, {"key_ops": ["verify"]}, {"use": None, "key_ops": None}],
    ids=["declared-sig", "no-use", "verify-operation", "no-metadata"],
)
async def test_verify_id_token_accepts_a_signing_key(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    metadata: dict[str, Any],
) -> None:
    """Test optional JWK metadata staying absent keeps normal providers working."""
    client = _client_with_jwk(hass, aioclient_mock, _jwk(signing_key, **metadata))

    claims = await client.async_verify_id_token(make_id_token(signing_key))

    assert claims["sub"] == SUBJECT


async def test_verify_id_token_binds_the_algorithm_the_key_declares(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a key declaring one algorithm cannot verify another."""
    client = _client_with_jwk(
        hass,
        aioclient_mock,
        _jwk(signing_key, alg="RS256"),
        id_token_signing_alg_values_supported=["RS256", "RS512"],
    )

    with pytest.raises(OidcIdTokenError):
        await client.async_verify_id_token(
            make_id_token(signing_key, algorithm="RS512")
        )


async def test_verify_id_token_allows_any_advertised_algorithm_without_a_declaration(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a key that declares no algorithm is not pinned to a guessed one."""
    client = _client_with_jwk(
        hass,
        aioclient_mock,
        _jwk(signing_key, alg=None),
        id_token_signing_alg_values_supported=["RS256", "RS512"],
    )

    claims = await client.async_verify_id_token(
        make_id_token(signing_key, algorithm="RS512")
    )

    assert claims["sub"] == SUBJECT


@pytest.mark.parametrize("error", ["invalid_grant", "invalid_client"])
async def test_token_request_reports_invalid_grant(
    client: OidcClient, aioclient_mock: AiohttpClientMocker, error: str
) -> None:
    """Test a rejected request is reported as permanent."""
    aioclient_mock.post(TOKEN_URL, status=400, json={"error": error})

    with pytest.raises(OidcInvalidGrantError):
        await client.async_refresh_token("dead-token")


async def test_token_request_reports_invalid_json(
    client: OidcClient, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a response that is not JSON is reported as a token error."""
    aioclient_mock.post(TOKEN_URL, text="<html>")

    with pytest.raises(OidcTokenError, match="invalid JSON"):
        await client.async_refresh_token("some-token")


async def test_token_request_reports_transient_error(
    client: OidcClient, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a server error is reported as retryable."""
    aioclient_mock.post(TOKEN_URL, status=503, json={})

    with pytest.raises(OidcTransientError):
        await client.async_refresh_token("some-token")


async def test_token_request_uses_basic_auth(
    hass: HomeAssistant, mock_idp: AiohttpClientMocker
) -> None:
    """Test the client secret is sent in the authorization header by default."""
    mock_idp.post(TOKEN_URL, json={"access_token": "at", "token_type": "Bearer"})
    client = OidcClient(
        hass, issuer=ISSUER, client_id=CLIENT_ID, client_secret="s3cret"
    )

    await client.async_refresh_token("refresh")

    headers = mock_idp.mock_calls[-1][3]
    assert headers["Authorization"].startswith("Basic ")
    assert "client_secret" not in mock_idp.mock_calls[-1][2]


async def test_token_request_uses_post_auth_when_advertised(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test the client secret goes in the body when basic auth is unsupported."""
    aioclient_mock.get(
        DISCOVERY_URL,
        json=discovery_document(
            token_endpoint_auth_methods_supported=["client_secret_post"]
        ),
    )
    aioclient_mock.post(TOKEN_URL, json={"access_token": "at", "token_type": "Bearer"})
    client = OidcClient(
        hass, issuer=ISSUER, client_id=CLIENT_ID, client_secret="s3cret"
    )

    await client.async_refresh_token("refresh")

    assert aioclient_mock.mock_calls[-1][2]["client_secret"] == "s3cret"


async def test_token_request_rejects_unsupported_client_auth(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a secret is not sent with an explicitly unsupported auth method."""
    aioclient_mock.get(
        DISCOVERY_URL,
        json=discovery_document(
            token_endpoint_auth_methods_supported=["private_key_jwt"]
        ),
    )
    aioclient_mock.post(TOKEN_URL, json={"access_token": "at", "token_type": "Bearer"})
    client = OidcClient(
        hass, issuer=ISSUER, client_id=CLIENT_ID, client_secret="s3cret"
    )

    with pytest.raises(OidcTokenError, match="authentication method"):
        await client.async_refresh_token("refresh")

    assert not any(call[0] == "POST" for call in aioclient_mock.mock_calls)


async def test_login_flow(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a full login creates a user and records the session."""
    mock_idp.get(USERINFO_URL, json={"sub": SUBJECT})
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )

    assert result["type"] is FlowResultType.EXTERNAL_STEP
    query = URL(result["url"]).query
    assert query["client_id"] == CLIENT_ID
    assert query["code_challenge_method"] == "S256"
    assert query["redirect_uri"] == f"{REDIRECT_BASE}/auth/login_callback"

    mock_idp.post(
        TOKEN_URL,
        json={
            "access_token": "at",
            "token_type": "Bearer",
            "refresh_token": "rt",
            "id_token": make_id_token(
                signing_key, nonce=query["nonce"], at_hash=expected_at_hash("at")
            ),
        },
    )

    result = await manager.login_flow.async_configure(
        result["flow_id"], {"code": "the-code"}
    )
    assert result["type"] is FlowResultType.EXTERNAL_STEP_DONE

    result = await manager.login_flow.async_configure(result["flow_id"])
    assert result["type"] is FlowResultType.CREATE_ENTRY

    credentials = result["result"]
    assert credentials.data["subject"] == SUBJECT

    user = await manager.async_get_or_create_user(credentials)
    assert user.name == "Alice"
    assert not user.is_admin

    session = provider.root.data.sessions[credentials.id]
    assert session.refresh_token == "rt"
    assert session.username == "alice"


async def test_login_flow_aborts_when_not_configured(
    manager: auth.AuthManager,
) -> None:
    """Test signing in is refused while the provider is unconfigured."""
    result = await manager.login_flow.async_init(
        (PROVIDER_TYPE, None),
        context={
            "ip_address": ip_address("127.0.0.1"),
            "redirect_uri": "https://ha.example.com/",
        },
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "not_configured"


async def test_login_flow_aborts_when_configuration_changes(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test a code from the old issuer is never sent to a replacement issuer."""
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )

    other_issuer = "https://other-idp.example.com"
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(issuer=other_issuer, client_id="new-client"),
    )
    mock_idp.get(
        f"{other_issuer}/.well-known/openid-configuration",
        json=discovery_document(
            issuer=other_issuer,
            authorization_endpoint=f"{other_issuer}/authorize",
            token_endpoint=f"{other_issuer}/token",
            jwks_uri=f"{other_issuer}/jwks",
        ),
    )
    mock_idp.post(
        f"{other_issuer}/token",
        json={"access_token": "at", "token_type": "Bearer"},
    )

    result = await manager.login_flow.async_configure(
        result["flow_id"], {"code": "code-from-the-old-provider"}
    )
    result = await manager.login_flow.async_configure(result["flow_id"])

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "configuration_changed"
    assert not any(
        call[1].host == "other-idp.example.com" for call in mock_idp.mock_calls
    )


async def test_login_flow_does_not_commit_after_configuration_changes(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a configuration change wins over an in-flight token exchange."""
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )

    nonce = URL(result["url"]).query["nonce"]
    result = await manager.login_flow.async_configure(
        result["flow_id"], {"code": "the-code"}
    )
    exchange_started = asyncio.Event()
    release_exchange = asyncio.Event()

    async def exchange_code(**kwargs: str) -> oidc_auth.TokenResponse:
        exchange_started.set()
        await release_exchange.wait()
        return oidc_auth.TokenResponse(
            access_token="at",
            id_token=make_id_token(signing_key, nonce=nonce),
            refresh_token="rt",
        )

    old_client = provider.child.async_client()
    with patch.object(old_client, "async_exchange_code", side_effect=exchange_code):
        finish_task = asyncio.create_task(
            manager.login_flow.async_configure(result["flow_id"])
        )
        await exchange_started.wait()
        await provider.root.async_register_identity_provider(
            IDP_ID,
            domain=IDP_DOMAIN,
            title="Example ID",
            spec=make_spec(
                issuer="https://other-idp.example.com", client_id="new-client"
            ),
        )
        release_exchange.set()
        result = await finish_task

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "configuration_changed"
    assert provider.root.data.sessions == {}


async def test_login_flow_aborts_on_provider_error(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    signing_key: rsa.RSAPrivateKey,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test an error from the identity provider does not sign anybody in."""
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )

    result = await manager.login_flow.async_configure(
        result["flow_id"], {"error": "access_denied"}
    )
    assert result["type"] is FlowResultType.EXTERNAL_STEP_DONE

    result = await manager.login_flow.async_configure(result["flow_id"])
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "authorize_rejected"


async def test_login_flow_revokes_refresh_token_after_abort(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test an unadopted refresh token is revoked when login aborts."""
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )
    client = provider.child.async_client()
    with (
        patch.object(
            client,
            "async_exchange_code",
            return_value=oidc_auth.TokenResponse(
                access_token="at", refresh_token="unadopted-rt"
            ),
        ),
        patch.object(client, "async_revoke_token") as revoke_token,
    ):
        result = await manager.login_flow.async_configure(
            result["flow_id"], {"code": "the-code"}
        )
        result = await manager.login_flow.async_configure(result["flow_id"])

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "missing_id_token"
    revoke_token.assert_awaited_once_with("unadopted-rt")


async def test_login_flow_revokes_replaced_refresh_token(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test replacing a session revokes its previous external refresh token."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="replaced-rt"),
    )
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )
    nonce = URL(result["url"]).query["nonce"]
    client = provider.child.async_client()
    with (
        patch.object(
            client,
            "async_exchange_code",
            return_value=oidc_auth.TokenResponse(
                access_token="at2",
                id_token=make_id_token(signing_key, nonce=nonce),
                refresh_token="new-rt",
            ),
        ),
        patch.object(client, "async_revoke_token") as revoke_token,
    ):
        result = await manager.login_flow.async_configure(
            result["flow_id"], {"code": "the-code"}
        )
        result = await manager.login_flow.async_configure(result["flow_id"])

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert provider.root.data.sessions[credentials.id].refresh_token == "new-rt"
    revoke_token.assert_awaited_once_with("replaced-rt")


async def test_login_flow_without_auto_create(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test an unknown user is refused when auto creation is off."""
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(accounts=AccountPolicy.LINK),
    )
    mock_idp.get(USERINFO_URL, json={"sub": SUBJECT})

    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )

    nonce = URL(result["url"]).query["nonce"]
    mock_idp.post(
        TOKEN_URL,
        json={
            "access_token": "at",
            "token_type": "Bearer",
            "id_token": make_id_token(signing_key, nonce=nonce),
        },
    )

    result = await manager.login_flow.async_configure(
        result["flow_id"], {"code": "the-code"}
    )
    result = await manager.login_flow.async_configure(result["flow_id"])

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "user_not_allowed"


async def test_login_flow_issues_credentials_for_linking(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test an unknown identity can still be linked to an existing account."""
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(accounts=AccountPolicy.LINK),
    )
    mock_idp.get(USERINFO_URL, json={"sub": SUBJECT})

    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
                "link_user": True,
            },
        )

    nonce = URL(result["url"]).query["nonce"]
    mock_idp.post(
        TOKEN_URL,
        json={
            "access_token": "at",
            "token_type": "Bearer",
            "id_token": make_id_token(signing_key, nonce=nonce),
        },
    )

    result = await manager.login_flow.async_configure(
        result["flow_id"], {"code": "the-code"}
    )
    result = await manager.login_flow.async_configure(result["flow_id"])

    assert result["type"] is FlowResultType.CREATE_ENTRY
    credentials = result["result"]
    assert credentials.is_new

    existing = await manager.async_create_user("Existing")
    await manager.async_link_user(existing, credentials)

    assert await manager.async_get_user_by_credentials(credentials) is existing


async def _complete_login(
    manager: auth.AuthManager,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
    *,
    userinfo: dict[str, Any] | None = None,
    **id_token_claims: Any,
) -> AuthFlowResult:
    """Run a login flow to the end and return its result."""
    mock_idp.clear_requests()
    mock_idp.get(DISCOVERY_URL, json=discovery_document())
    mock_idp.get(JWKS_URL, json=jwks)
    mock_idp.get(
        USERINFO_URL, json=userinfo if userinfo is not None else {"sub": SUBJECT}
    )

    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )

    mock_idp.post(
        TOKEN_URL,
        json={
            "access_token": "at",
            "token_type": "Bearer",
            "refresh_token": "rt",
            "id_token": make_id_token(
                signing_key,
                nonce=URL(result["url"]).query["nonce"],
                at_hash=expected_at_hash("at"),
                **id_token_claims,
            ),
        },
    )

    result = await manager.login_flow.async_configure(
        result["flow_id"], {"code": "the-code"}
    )
    return await manager.login_flow.async_configure(result["flow_id"])


async def _sign_in_twice(
    manager: auth.AuthManager,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
    *,
    first: dict[str, Any],
    second: dict[str, Any],
) -> auth_models.User:
    """Sign the same identity in twice and return the resulting user."""
    result = await _complete_login(manager, mock_idp, signing_key, jwks, **first)
    user = await manager.async_get_or_create_user(result["result"])

    await _complete_login(manager, mock_idp, signing_key, jwks, **second)
    return user


@pytest.mark.parametrize(
    ("second_groups", "expected_admin"),
    [
        (["home_assistant_admin"], True),
        (["something-else"], False),
        ([], False),
        (None, False),
    ],
    ids=["keeps-group", "loses-group", "empty-groups", "claim-gone"],
)
async def test_login_syncs_admin_from_the_groups_claim(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
    second_groups: list[str] | None,
    expected_admin: bool,
) -> None:
    """Test rights granted through the admin group are taken away with it."""
    user = await _sign_in_twice(
        manager,
        mock_idp,
        signing_key,
        jwks,
        first={"groups": ["home_assistant_admin"]},
        second={"groups": second_groups},
    )

    assert user.is_admin is expected_admin


async def test_login_promotes_a_user_who_gains_the_group(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test joining the admin group is picked up on the next login."""
    user = await _sign_in_twice(
        manager,
        mock_idp,
        signing_key,
        jwks,
        first={"groups": ["users"]},
        second={"groups": ["users", "home_assistant_admin"]},
    )

    assert user.is_admin


async def test_login_keeps_an_admin_the_identity_provider_never_granted(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test an account never seen in the admin group is left alone."""
    result = await _complete_login(manager, mock_idp, signing_key, jwks, groups=[])
    user = await manager.async_get_or_create_user(result["result"])
    await manager.async_update_user(user, group_ids=[GROUP_ID_ADMIN])

    await _complete_login(manager, mock_idp, signing_key, jwks, groups=[])

    assert user.is_admin


async def test_login_strips_a_pre_existing_admin_that_loses_the_group(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test seeing the group once puts the rights under the identity provider."""
    result = await _complete_login(manager, mock_idp, signing_key, jwks, groups=[])
    user = await manager.async_get_or_create_user(result["result"])
    await manager.async_update_user(user, group_ids=[GROUP_ID_ADMIN])

    await _complete_login(
        manager, mock_idp, signing_key, jwks, groups=["home_assistant_admin"]
    )
    await _complete_login(manager, mock_idp, signing_key, jwks, groups=[])

    assert not user.is_admin


async def test_login_restores_the_group_a_demoted_user_came_from(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a demotion gives back the rights the account had, not more."""
    result = await _complete_login(manager, mock_idp, signing_key, jwks, groups=[])
    user = await manager.async_get_or_create_user(result["result"])
    await manager.async_update_user(user, group_ids=[GROUP_ID_READ_ONLY])

    await _complete_login(
        manager, mock_idp, signing_key, jwks, groups=["home_assistant_admin"]
    )
    assert user.is_admin

    await _complete_login(manager, mock_idp, signing_key, jwks, groups=[])

    assert not user.is_admin
    assert [group.id for group in user.groups] == [GROUP_ID_READ_ONLY]


async def test_login_never_demotes_the_owner(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test the owner keeps their rights, so nobody can lock the instance out."""
    result = await _complete_login(
        manager, mock_idp, signing_key, jwks, groups=["home_assistant_admin"]
    )
    user = await manager.async_get_or_create_user(result["result"])
    user.is_owner = True

    await _complete_login(manager, mock_idp, signing_key, jwks, groups=[])

    assert user.is_admin


async def test_login_does_not_rename_an_existing_user(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test the display name is only read while the account is built."""
    user = await _sign_in_twice(
        manager,
        mock_idp,
        signing_key,
        jwks,
        first={"name": "Alice"},
        second={"name": "Alice Smith"},
    )

    assert user.name == "Alice"


async def test_login_refreshes_the_account_name(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test the account name follows the identity provider at every sign-in."""
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(account_name_claim="email"),
    )
    user = await _sign_in_twice(
        manager,
        mock_idp,
        signing_key,
        jwks,
        first={"email": "alice@example.com"},
        second={"email": "alice@example.org"},
    )

    assert user.credentials[0].data["account_name"] == "alice@example.org"


async def test_new_user_without_the_admin_group_is_a_regular_user(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test an identity outside the admin group never creates an administrator."""
    result = await _complete_login(manager, mock_idp, signing_key, jwks)
    user = await manager.async_get_or_create_user(result["result"])

    assert not user.is_admin


async def test_login_flow_reads_claims_from_userinfo(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test claims the ID token omits are picked up from the userinfo endpoint."""
    result = await _complete_login(
        manager,
        mock_idp,
        signing_key,
        jwks,
        userinfo={
            "sub": SUBJECT,
            "name": "Impostor",
            "preferred_username": "alice",
        },
        name="Alice",
        preferred_username=None,
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    credentials = result["result"]
    user = await manager.async_get_or_create_user(credentials)

    # The signed ID token wins over the userinfo response on conflicts.
    assert user.name == "Alice"


@pytest.mark.parametrize(
    ("groups", "expected_admin"),
    [
        pytest.param(None, False, id="userinfo-only-group"),
        pytest.param([], False, id="empty-id-token-groups"),
        pytest.param(["home_assistant_admin"], True, id="id-token-admin-group"),
    ],
)
@pytest.mark.usefixtures("provider")
async def test_login_flow_uses_id_token_groups_when_enriching_profile(
    manager: auth.AuthManager,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
    groups: list[str] | None,
    expected_admin: bool,
) -> None:
    """Test profile enrichment cannot change the source of admin grants."""
    userinfo = {
        "sub": SUBJECT,
        "name": "Alice",
        "preferred_username": "alice",
        "groups": ["home_assistant_admin"],
    }
    id_token_claims = {
        "name": None,
        "preferred_username": None,
        "groups": groups,
    }
    result = await _complete_login(
        manager, mock_idp, signing_key, jwks, userinfo=userinfo, **id_token_claims
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    user = await manager.async_get_or_create_user(result["result"])
    assert user.name == "Alice"
    assert user.is_admin is expected_admin
    assert any(call[1].path == "/userinfo" for call in mock_idp.mock_calls)

    result = await _complete_login(
        manager, mock_idp, signing_key, jwks, userinfo=userinfo, **id_token_claims
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert await manager.async_get_or_create_user(result["result"]) is user
    assert user.name == "Alice"
    assert user.is_admin is expected_admin
    assert not any(call[1].path == "/userinfo" for call in mock_idp.mock_calls)


async def test_login_flow_skips_userinfo_when_the_id_token_suffices(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test the userinfo endpoint is left alone while no claim is missing."""
    result = await _complete_login(manager, mock_idp, signing_key, jwks)

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert not any(call[1].path == "/userinfo" for call in mock_idp.mock_calls)


async def test_login_flow_skips_userinfo_for_a_known_account(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a returning user never costs a userinfo request."""
    result = await _complete_login(
        manager, mock_idp, signing_key, jwks, name=None, preferred_username=None
    )
    await manager.async_get_or_create_user(result["result"])

    await _complete_login(
        manager, mock_idp, signing_key, jwks, name=None, preferred_username=None
    )

    assert not any(call[1].path == "/userinfo" for call in mock_idp.mock_calls)


async def test_login_flow_rejects_userinfo_for_another_subject(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a mismatched userinfo subject stops the login."""
    result = await _complete_login(
        manager,
        mock_idp,
        signing_key,
        jwks,
        userinfo={"sub": "somebody-else", "name": "Mallory"},
        name=None,
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "userinfo_failed"


async def test_login_flow_rejects_userinfo_without_a_subject(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a userinfo response has to carry the subject it is required to."""
    result = await _complete_login(
        manager,
        mock_idp,
        signing_key,
        jwks,
        userinfo={"name": "Alice"},
        name=None,
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "userinfo_failed"


async def test_credentials_are_bound_to_the_issuer(
    manager: auth.AuthManager, provider: OidcProvider
) -> None:
    """Test the same subject at another issuer is a different account."""
    user = await manager.async_create_user("Alice")
    first = await provider.child.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, first)

    same = await provider.child.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    other = await provider.child.async_get_or_create_credentials(
        {"issuer": "https://other-idp.example.com", "subject": SUBJECT}
    )

    assert same.id == first.id
    assert other.id != first.id
    assert other.is_new


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        pytest.param(None, False, id="configuration-removed"),
        pytest.param(
            make_spec(issuer="https://other-idp.example.com", client_id=CLIENT_ID),
            False,
            id="issuer-changed",
        ),
        pytest.param(
            make_spec(issuer=f"{ISSUER}/", client_id=CLIENT_ID),
            False,
            id="issuer-trailing-slash-changed",
        ),
        pytest.param(
            make_spec(accounts=AccountPolicy.PROVISION),
            True,
            id="current-issuer-without-session",
        ),
    ],
)
async def test_login_fallback_requires_current_issuer_configuration(
    manager: auth.AuthManager,
    provider: OidcProvider,
    aioclient_mock: AiohttpClientMocker,
    config: IdentityProvider | None,
    expected: bool,
) -> None:
    """Test only credentials usable with the current issuer count as a fallback."""
    user = await manager.async_create_user("Alice")
    credentials = await provider.child.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)

    assert manager.async_has_other_login_method(user)

    if config is None:
        provider.root.async_suspend_identity_provider(IDP_ID)
        await provider.root.async_end_identity_provider_sessions(IDP_ID)
    else:
        await provider.root.async_register_identity_provider(
            IDP_ID,
            domain=IDP_DOMAIN,
            title="Example ID",
            spec=config,
        )

    assert manager.async_has_other_login_method(user) is expected
    assert credentials in user.credentials
    assert provider.root.data is not None
    assert provider.root.data.sessions == {}
    assert aioclient_mock.mock_calls == []


async def test_pending_credentials_are_deduplicated(
    provider: OidcProvider,
) -> None:
    """Test concurrent flows cannot create two credentials for one identity."""
    first = await provider.child.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    second = await provider.child.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )

    assert second is first


async def test_pending_credentials_create_one_user(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test concurrent redemption cannot create duplicate OIDC users."""
    credentials = await provider.child.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    first_ready = asyncio.Event()
    release = asyncio.Event()
    original = provider.child.async_user_meta_for_credentials

    async def user_meta(
        pending: auth_models.Credentials,
    ) -> auth_models.UserMeta:
        first_ready.set()
        await release.wait()
        return await original(pending)

    with patch.object(
        provider.child, "async_user_meta_for_credentials", side_effect=user_meta
    ):
        first = asyncio.create_task(manager.async_get_or_create_user(credentials))
        await first_ready.wait()
        second = asyncio.create_task(manager.async_get_or_create_user(credentials))
        await asyncio.sleep(0)
        release.set()
        users = await asyncio.gather(first, second)

    assert users[0] is users[1]


@pytest.mark.parametrize(
    ("groups", "expected_group"),
    [
        (["home_assistant_admin"], "system-admin"),
        (["users", "home_assistant_admin"], "system-admin"),
        ("users home_assistant_admin", "system-admin"),
        (["users"], "system-users"),
        ([], "system-users"),
        (None, "system-users"),
        ("home_assistant_admin", "system-admin"),
        ([{"name": "home_assistant_admin"}], "system-users"),
    ],
    ids=[
        "admin",
        "admin-among-others",
        "space-separated",
        "other-group",
        "empty",
        "missing",
        "single-string",
        "not-a-string",
    ],
)
async def test_user_meta_maps_the_admin_group(
    provider: OidcProvider,
    groups: object,
    expected_group: str,
) -> None:
    """Test the admin group decides whether a new user is an administrator."""
    claims: dict[str, Any] = {
        "sub": SUBJECT,
        "name": "Alice",
        "preferred_username": "alice",
    }
    if groups is not None:
        claims["groups"] = groups

    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims=claims,
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )

    meta = await provider.child.async_user_meta_for_credentials(credentials)

    assert meta.name == "Alice"
    assert meta.group == expected_group


async def test_user_meta_without_an_admin_group_configured(
    provider: OidcProvider,
) -> None:
    """Test nobody becomes an administrator while group mapping is turned off."""
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(admin_group=None),
    )
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": ["home_assistant_admin"]},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )

    meta = await provider.child.async_user_meta_for_credentials(credentials)

    assert meta.group == "system-users"


async def test_user_meta_defaults_to_plain_user(
    provider: OidcProvider,
) -> None:
    """Test a user without the admin group does not become an administrator."""
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "name": "Alice", "preferred_username": "alice"},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )

    meta = await provider.child.async_user_meta_for_credentials(credentials)

    assert meta.group == "system-users"


async def test_user_meta_rejects_credentials_without_a_session(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test a stale authorization code cannot create a sessionless user."""
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )

    with pytest.raises(auth.InvalidAuthError):
        await manager.async_get_or_create_user(credentials)


async def test_refresh_token_rejected_after_deadline(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test a session has to be confirmed by the identity provider again."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    # Still inside the window, so a new access token is handed out.
    assert manager.async_create_access_token(refresh_token)

    provider.root.data.sessions[credentials.id].revalidate_after = time.time() - 1

    with pytest.raises(auth.InvalidAuthError):
        manager.async_create_access_token(refresh_token)


async def test_refresh_token_rejected_without_session(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test a credential without a session cannot mint access tokens."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    with pytest.raises(auth.InvalidAuthError):
        manager.async_create_access_token(refresh_token)


async def test_refresh_token_rejected_when_provider_is_unconfigured(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test configuration loss cannot leave a persisted session trusted."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    provider.root.async_suspend_identity_provider(IDP_ID)
    provider.root.data.sessions[credentials.id].revalidate_after = time.time() - 1

    with pytest.raises(auth.InvalidAuthError):
        manager.async_create_access_token(refresh_token)


def test_revalidation_schedule_has_retry_margin() -> None:
    """Test the shortest session gets a retry before its hard deadline."""
    assert REVALIDATE_CHECK_INTERVAL.total_seconds() < (
        MIN_REVALIDATE_INTERVAL * (1 - REVALIDATE_REFRESH_RATIO)
    )


async def test_revalidation_ends_expired_session_without_refresh_token(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test a non-refreshable session is removed at its hard deadline."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    session = provider.root.data.sessions[credentials.id]
    session.refresh_after = time.time() - 2
    session.revalidate_after = time.time() - 1

    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=2))
    await hass.async_block_till_done()

    assert credentials.id not in provider.root.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is None


async def test_long_lived_access_token_skips_revalidation(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test long lived access tokens deliberately opt out of revalidation."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user,
        client_name="Some script",
        token_type=auth_models.TOKEN_TYPE_LONG_LIVED_ACCESS_TOKEN,
        access_token_expiration=dt_util.dt.timedelta(days=3650),
        credential=credentials,
    )

    provider.root.data.sessions[credentials.id].revalidate_after = time.time() - 1

    assert manager.async_create_access_token(refresh_token)


async def test_revalidation_extends_the_session(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test a silent refresh keeps the user signed in without interaction."""
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    session = provider.root.data.sessions[credentials.id]
    session.refresh_after = time.time() - 1
    deadline = session.revalidate_after

    mock_idp.post(
        TOKEN_URL,
        json={"access_token": "at2", "token_type": "Bearer", "refresh_token": "rt2"},
    )
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    session = provider.root.data.sessions[credentials.id]
    assert session.revalidate_after > deadline
    assert session.refresh_token == "rt2"


async def test_revalidation_rejects_id_token_for_another_subject(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a refresh response cannot switch the identity behind a session."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    session = provider.root.data.sessions[credentials.id]
    session.refresh_after = time.time() - 1
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    mock_idp.post(
        TOKEN_URL,
        json={
            "access_token": "at2",
            "token_type": "Bearer",
            "refresh_token": "rt2",
            "id_token": make_id_token(signing_key, sub="somebody-else"),
        },
    )
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert credentials.id not in provider.root.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is None


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(OidcTransientError("JWKS unavailable"), id="transient"),
        pytest.param(OidcIdTokenError("bad signature"), id="rejected"),
    ],
)
async def test_revalidation_keeps_rotated_token_when_id_token_fails(
    hass: HomeAssistant,
    provider: OidcProvider,
    error: OidcError,
) -> None:
    """Test token rotation survives a refreshed ID token that fails to verify."""
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="old-rt"),
    )
    session = provider.root.data.sessions[credentials.id]
    session.refresh_after = time.time() - 1
    deadline = session.revalidate_after
    client = provider.child.async_client()

    with (
        patch.object(
            client,
            "async_refresh_token",
            return_value=oidc_auth.TokenResponse(
                access_token="at2", id_token="new-id-token", refresh_token="new-rt"
            ),
        ),
        patch.object(client, "async_verify_id_token", side_effect=error),
    ):
        async_fire_time_changed(hass, dt_util.utcnow() + REVALIDATE_CHECK_INTERVAL)
        await hass.async_block_till_done()

    session = provider.root.data.sessions[credentials.id]
    assert session.refresh_token == "new-rt"
    assert session.revalidate_after == deadline


async def test_revalidation_cannot_remove_a_new_login_session(
    provider: OidcProvider,
) -> None:
    """Test an old invalid grant cannot remove a concurrently renewed session."""
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="old-rt"),
    )
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1
    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()

    async def refresh_token(_: str) -> oidc_auth.TokenResponse:
        refresh_started.set()
        await release_refresh.wait()
        raise OidcInvalidGrantError("revoked")

    with patch.object(
        provider.child.async_client(), "async_refresh_token", side_effect=refresh_token
    ):
        revalidate = asyncio.create_task(
            provider.root._async_revalidate_sessions(dt_util.utcnow())
        )
        await refresh_started.wait()
        renewed = asyncio.create_task(
            provider.child.async_record_session(
                credential_id=credentials.id,
                claims={"sub": SUBJECT},
                tokens=oidc_auth.TokenResponse(
                    access_token="at2", refresh_token="new-rt"
                ),
            )
        )
        await asyncio.sleep(0)
        release_refresh.set()
        await asyncio.gather(revalidate, renewed)

    assert provider.root.data.sessions[credentials.id].refresh_token == "new-rt"


@pytest.mark.usefixtures("mock_idp")
async def test_revalidation_cannot_restore_removed_credentials(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test an in-flight refresh cannot restore an explicitly removed session."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="old-rt"),
    )
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1
    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()

    async def refresh_token(_: str) -> oidc_auth.TokenResponse:
        refresh_started.set()
        await release_refresh.wait()
        return oidc_auth.TokenResponse(access_token="at2", refresh_token="rotated-rt")

    with patch.object(
        provider.child.async_client(), "async_refresh_token", side_effect=refresh_token
    ):
        revalidate = asyncio.create_task(
            provider.root._async_revalidate_sessions(dt_util.utcnow())
        )
        await refresh_started.wait()
        remove = asyncio.create_task(manager.async_remove_credentials(credentials))
        await asyncio.sleep(0)
        release_refresh.set()
        await asyncio.gather(revalidate, remove)

    assert credentials.id not in provider.root.data.sessions
    assert credentials not in user.credentials


async def test_unclaimed_login_session_is_dropped(
    hass: HomeAssistant,
    provider: OidcProvider,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test a login whose authorization code is never used leaves no session."""
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await provider.child.async_complete_login(
        credentials, {"sub": SUBJECT}, oidc_auth.TokenResponse(access_token="at")
    )
    assert credentials.id in provider.root.data.sessions

    freezer.tick(UNCLAIMED_SESSION_TIMEOUT)
    async_fire_time_changed(hass)
    await hass.async_block_till_done()

    assert credentials.id not in provider.root.data.sessions


async def test_claimed_login_session_is_kept(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test a login whose credentials were saved keeps its session."""
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await provider.child.async_complete_login(
        credentials, {"sub": SUBJECT}, oidc_auth.TokenResponse(access_token="at")
    )
    await manager.async_link_user(await _non_owner_user(manager), credentials)

    freezer.tick(UNCLAIMED_SESSION_TIMEOUT)
    async_fire_time_changed(hass)
    await hass.async_block_till_done()

    assert credentials.id in provider.root.data.sessions


async def test_unclaimed_login_of_suspended_provider_revokes_refresh_token(
    hass: HomeAssistant,
    provider: OidcProvider,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
) -> None:
    """Test an unclaimed login is revoked with the last client after suspension."""
    aioclient_mock.get(
        DISCOVERY_URL,
        json=discovery_document(revocation_endpoint=f"{ISSUER}/revoke"),
    )
    aioclient_mock.post(f"{ISSUER}/revoke", status=200)
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await provider.child.async_complete_login(
        credentials,
        {"sub": SUBJECT},
        oidc_auth.TokenResponse(access_token="at", refresh_token="unclaimed-rt"),
    )

    provider.root.async_suspend_identity_provider(IDP_ID)
    freezer.tick(UNCLAIMED_SESSION_TIMEOUT)
    async_fire_time_changed(hass)
    await hass.async_block_till_done()

    assert credentials.id not in provider.root.data.sessions
    assert any(call[1] == URL(f"{ISSUER}/revoke") for call in aioclient_mock.mock_calls)


async def test_revalidation_leaves_the_groups_alone(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test a background refresh does not restate the group membership."""
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": ["home_assistant_admin"]},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1

    mock_idp.post(
        TOKEN_URL,
        json={"access_token": "at2", "token_type": "Bearer", "refresh_token": "rt2"},
    )
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    session = provider.root.data.sessions[credentials.id]
    assert session.refresh_token == "rt2"
    assert session.is_admin is True


async def _non_owner_user(manager: auth.AuthManager) -> auth_models.User:
    """Return a user who is not the owner, who is never demoted."""
    await manager.async_create_user("Owner")
    return await manager.async_create_user("Alice")


async def _linked_admin(
    manager: auth.AuthManager,
    provider: OidcProvider,
    *,
    groups: list[str],
    extra_group_ids: list[str] | None = None,
) -> tuple[auth_models.User, auth_models.Credentials]:
    """Return a user whose administrator rights came from the provider."""
    user = await _non_owner_user(manager)
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await manager.async_update_user(
        user, group_ids=[GROUP_ID_ADMIN, *(extra_group_ids or [])]
    )
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": groups},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1
    return user, credentials


def _refresh_with_groups(
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    **claims: Any,
) -> None:
    """Answer the next refresh with a signed ID token."""
    mock_idp.post(
        TOKEN_URL,
        json={
            "access_token": "at2",
            "token_type": "Bearer",
            "refresh_token": "rt2",
            "id_token": make_id_token(
                signing_key, at_hash=expected_at_hash("at2"), **claims
            ),
        },
    )


async def test_revalidation_withdraws_admin_the_provider_took_away(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test losing the admin group is applied without a new interactive login."""
    user, credentials = await _linked_admin(
        manager, provider, groups=["home_assistant_admin"]
    )
    _refresh_with_groups(mock_idp, signing_key, groups=[])

    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert not user.is_admin
    assert provider.root.data.sessions[credentials.id].is_admin is False


async def test_revalidation_keeps_unrelated_groups_when_withdrawing_admin(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a withdrawal only removes the group the provider granted."""
    user, _ = await _linked_admin(
        manager,
        provider,
        groups=["home_assistant_admin"],
        extra_group_ids=[GROUP_ID_READ_ONLY],
    )
    _refresh_with_groups(mock_idp, signing_key, groups=[])

    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert not user.is_admin
    assert [group.id for group in user.groups] == [GROUP_ID_READ_ONLY]


async def test_revalidation_grants_admin_the_provider_added(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test joining the admin group is applied on the next refresh."""
    user = await _non_owner_user(manager)
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await manager.async_update_user(user, group_ids=[GROUP_ID_USER])
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": []},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1
    _refresh_with_groups(mock_idp, signing_key, groups=["home_assistant_admin"])

    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert user.is_admin
    assert provider.root.data.sessions[credentials.id].is_admin is True


async def test_revalidation_never_demotes_the_owner(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test the owner keeps their rights when the provider withdraws them."""
    user, _ = await _linked_admin(manager, provider, groups=["home_assistant_admin"])
    user.is_owner = True
    _refresh_with_groups(mock_idp, signing_key, groups=[])

    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert user.is_admin


async def test_revalidation_keeps_admin_the_provider_never_granted(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a locally appointed administrator is not demoted by a refresh."""
    user = await _non_owner_user(manager)
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": []},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    await manager.async_update_user(user, group_ids=[GROUP_ID_ADMIN])
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1
    _refresh_with_groups(mock_idp, signing_key, groups=[])

    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert user.is_admin


async def test_revalidation_without_group_claims_leaves_admin_alone(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test an ID token that omits the groups says nothing about entitlement."""
    user, credentials = await _linked_admin(
        manager, provider, groups=["home_assistant_admin"]
    )
    _refresh_with_groups(mock_idp, signing_key)

    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert user.is_admin
    assert provider.root.data.sessions[credentials.id].is_admin is True


async def test_revalidation_signs_out_revoked_users(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test a revoked identity provider session drops the Home Assistant tokens."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1

    mock_idp.post(TOKEN_URL, status=400, json={"error": "invalid_grant"})
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert credentials.id not in provider.root.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is None


async def test_revalidation_removes_provider_admin_grant(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test ending the granting session withdraws provider-derived admin rights."""
    await manager.async_create_user("Owner")
    user = await manager.async_create_user("Alice", group_ids=[GROUP_ID_READ_ONLY])
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": ["home_assistant_admin"]},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    await manager.async_update_user(
        user, group_ids=[GROUP_ID_ADMIN, GROUP_ID_READ_ONLY]
    )
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1

    mock_idp.post(TOKEN_URL, status=400, json={"error": "invalid_grant"})
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert not user.is_admin
    assert [group.id for group in user.groups] == [GROUP_ID_READ_ONLY]


async def test_revalidation_keeps_session_on_transient_error(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test an unreachable identity provider does not sign anybody out."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1

    mock_idp.post(TOKEN_URL, status=503, json={})
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert credentials.id in provider.root.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is refresh_token


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (503, {}),
        (400, {"error": "invalid_client"}),
    ],
    ids=["transient", "generic"],
)
async def test_revalidation_ends_a_session_past_its_deadline(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    status: int,
    body: dict[str, Any],
) -> None:
    """Test the deadline terminates access even while refreshes keep failing."""
    user = await _non_owner_user(manager)
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    session = provider.root.data.sessions[credentials.id]
    session.refresh_after = time.time() - 1
    session.revalidate_after = time.time() - 1

    mock_idp.post(TOKEN_URL, status=status, json=body)
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert credentials.id not in provider.root.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is None


async def test_expiry_is_not_delayed_by_a_slow_identity_provider(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test one stuck refresh cannot hold up another session's deadline."""
    slow = provider.child.async_create_credentials({"subject": "slow-user"})
    await provider.child.async_record_session(
        credential_id=slow.id,
        claims={"sub": "slow-user"},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    provider.root.data.sessions[slow.id].refresh_after = time.time() - 1

    user = await _non_owner_user(manager)
    expired = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, expired)
    await provider.child.async_record_session(
        credential_id=expired.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=expired
    )
    provider.root.data.sessions[expired.id].revalidate_after = time.time() - 1

    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()

    async def hang(_: str) -> oidc_auth.TokenResponse:
        refresh_started.set()
        await release_refresh.wait()
        return oidc_auth.TokenResponse(access_token="at2")

    with patch.object(
        provider.child.async_client(), "async_refresh_token", side_effect=hang
    ):
        stuck = asyncio.create_task(
            provider.root._async_revalidate_sessions(dt_util.utcnow())
        )
        await refresh_started.wait()

        # The next tick arrives while the previous pass is still waiting.
        await provider.root._async_revalidate_sessions(dt_util.utcnow())

        assert expired.id not in provider.root.data.sessions
        assert manager.async_get_refresh_token(refresh_token.id) is None

        release_refresh.set()
        await stuck


async def test_revalidation_does_not_overwrite_a_newer_login(
    provider: OidcProvider,
) -> None:
    """Test a slow refresh cannot undo a login that finished while it ran."""
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="old-rt"),
    )
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1
    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()

    async def refresh(_: str) -> oidc_auth.TokenResponse:
        refresh_started.set()
        await release_refresh.wait()
        return oidc_auth.TokenResponse(access_token="at2", refresh_token="stale-rt")

    with patch.object(
        provider.child.async_client(), "async_refresh_token", side_effect=refresh
    ):
        revalidate = asyncio.create_task(
            provider.root._async_revalidate_sessions(dt_util.utcnow())
        )
        await refresh_started.wait()
        renewed = asyncio.create_task(
            provider.child.async_record_session(
                credential_id=credentials.id,
                claims={"sub": SUBJECT},
                tokens=oidc_auth.TokenResponse(
                    access_token="at3", refresh_token="new-rt"
                ),
            )
        )
        await asyncio.sleep(0)
        release_refresh.set()
        await asyncio.gather(revalidate, renewed)

    assert provider.root.data.sessions[credentials.id].refresh_token == "new-rt"


async def test_removing_credentials_drops_the_session(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test removing a user cleans up the identity provider session."""
    user = await _non_owner_user(manager)
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )

    await manager.async_remove_user(user)

    assert credentials.id not in provider.root.data.sessions


async def test_removing_credentials_cannot_race_with_login_commit(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test external revocation cannot let stale credentials restore a session."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="old-rt"),
    )
    revoke_started = asyncio.Event()
    release_revoke = asyncio.Event()

    async def revoke_token(_: str) -> None:
        revoke_started.set()
        await release_revoke.wait()

    with patch.object(
        provider.child.async_client(), "async_revoke_token", side_effect=revoke_token
    ):
        remove = asyncio.create_task(manager.async_remove_credentials(credentials))
        await revoke_started.wait()
        try:
            with suppress(auth.InvalidAuthError):
                await provider.child.async_complete_login(
                    credentials,
                    {"sub": SUBJECT},
                    oidc_auth.TokenResponse(
                        access_token="at2", refresh_token="stale-login-rt"
                    ),
                )
        finally:
            release_revoke.set()
            await remove

    assert credentials not in user.credentials
    assert credentials.id not in provider.root.data.sessions


async def test_deleting_the_config_clears_sessions(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test removing the configuration signs every OIDC user out."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    provider.root.async_suspend_identity_provider(IDP_ID)
    await provider.root.async_end_identity_provider_sessions(IDP_ID)

    assert not provider.child.active
    assert provider.root.data.sessions == {}
    assert manager.async_get_refresh_token(refresh_token.id) is None


@pytest.mark.usefixtures("mock_idp")
async def test_reconfiguring_clears_existing_sessions(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test provider changes cannot carry sessions across trust boundaries."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(issuer="https://other-idp.example.com", client_id="new-client"),
    )

    assert provider.root.data.sessions == {}
    assert manager.async_get_refresh_token(refresh_token.id) is None


@pytest.mark.parametrize(
    "change",
    [
        {"account_name_claim": "email"},
        {"display_name_claim": "given_name"},
        {"revalidate_interval": 3600},
    ],
    ids=["account-name-claim", "display-name-claim", "interval"],
)
async def test_editing_settings_keeps_existing_sessions(
    manager: auth.AuthManager,
    provider: OidcProvider,
    change: dict[str, Any],
) -> None:
    """Test an edit that keeps the same issuer does not sign everybody out."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await manager.async_update_user(user, group_ids=[GROUP_ID_ADMIN])
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": ["home_assistant_admin"]},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(**change),
    )

    assert credentials.id in provider.root.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is not None
    assert user.is_admin


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "https://other-idp.example.com"},
        {"client_id": "other-client"},
        {"client_secret": "rotated"},
        {"scopes": ("openid", "profile")},
        {"admin_group": "other-admins"},
    ],
    ids=["issuer", "client-id", "client-secret", "scopes", "admin-group"],
)
@pytest.mark.usefixtures("mock_idp")
async def test_security_relevant_settings_clear_sessions(
    provider: OidcProvider,
    change: dict[str, Any],
) -> None:
    """Test sessions do not survive a change to who issued or authorized them."""
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(**change),
    )

    assert provider.root.data.sessions == {}


async def _start_login(
    manager: auth.AuthManager, url: str, *, internal: bool
) -> AuthFlowResult:
    """Start a login flow with Home Assistant reachable at a given URL."""
    with (
        patch("homeassistant.auth.providers.oidc.get_url", return_value=url),
        patch(
            "homeassistant.auth.providers.oidc.is_internal_request",
            return_value=internal,
        ),
    ):
        return await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )


@pytest.mark.usefixtures("provider", "mock_idp")
async def test_login_refuses_plain_http_reachable_from_outside(
    manager: auth.AuthManager,
) -> None:
    """Test a login is not started over a connection strangers can read."""
    result = await _start_login(manager, "http://ha.example.com", internal=False)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "insecure_transport"


@pytest.mark.usefixtures("mock_idp")
async def test_login_over_plain_http_when_insecure_transport_is_allowed(
    manager: auth.AuthManager, provider: OidcProvider
) -> None:
    """Test an administrator can waive HTTPS for an install they trust."""
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(
            accounts=AccountPolicy.PROVISION,
            allow_insecure_transport=True,
        ),
    )

    result = await _start_login(manager, "http://ha.example.com", internal=False)

    assert result["type"] is FlowResultType.EXTERNAL_STEP


@pytest.mark.usefixtures("mock_idp")
async def test_changing_transport_security_ends_sessions(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test sessions made under one transport setting do not outlive it."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    old_client = provider.child.async_client()

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(
            accounts=AccountPolicy.PROVISION,
            allow_insecure_transport=True,
        ),
    )

    assert provider.root.data.sessions == {}
    assert manager.async_get_refresh_token(refresh_token.id) is None
    # The client enforces the setting, so it has to be rebuilt with it.
    new_client = provider.child.async_client()
    assert new_client is not old_client
    assert new_client.allow_insecure_transport is True


@pytest.mark.parametrize(
    ("url", "internal"),
    [
        ("https://ha.example.com", False),
        ("http://homeassistant.local:8123", True),
        ("http://192.168.1.10:8123", True),
    ],
    ids=["external-https", "internal-hostname", "internal-address"],
)
@pytest.mark.usefixtures("provider", "mock_idp")
async def test_login_starts_over_a_usable_transport(
    manager: auth.AuthManager,
    url: str,
    internal: bool,
) -> None:
    """Test HTTPS and the internal URL both remain usable."""
    result = await _start_login(manager, url, internal=internal)

    assert result["type"] is FlowResultType.EXTERNAL_STEP


@pytest.mark.parametrize(
    "raw_data",
    [
        [],
        {"records": []},
        {
            "records": {
                IDP_ID: {
                    "idp_id": IDP_ID,
                    "domain": 1,
                    "accounts": "link",
                    "trust_key": "key",
                }
            }
        },
        {
            "records": {
                IDP_ID: {
                    "idp_id": IDP_ID,
                    "domain": IDP_DOMAIN,
                    "accounts": "bad",
                    "trust_key": "key",
                }
            }
        },
        {"sessions": ["not-a-mapping"]},
        {
            "records": {
                IDP_ID: {
                    "idp_id": IDP_ID,
                    "domain": IDP_DOMAIN,
                    "accounts": "link",
                    "trust_key": "key",
                }
            },
            "sessions": {"credential-id": []},
        },
        {
            "records": {
                IDP_ID: {
                    "idp_id": IDP_ID,
                    "domain": IDP_DOMAIN,
                    "accounts": "link",
                    "trust_key": "key",
                }
            },
            "sessions": {
                "credential-id": {
                    "credential_id": "credential-id",
                    "idp_id": IDP_ID,
                    "subject": SUBJECT,
                    "revalidate_after": "tomorrow",
                }
            },
        },
    ],
    ids=[
        "root",
        "records-container",
        "record-field",
        "record-policy",
        "sessions-container",
        "session-container",
        "session-field",
    ],
)
async def test_store_discards_malformed_data(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    raw_data: Any,
) -> None:
    """Test malformed persisted data cannot break auth initialization."""
    hass_storage[STORAGE_KEY] = {
        "version": STORAGE_VERSION,
        "minor_version": 1,
        "key": STORAGE_KEY,
        "data": raw_data,
    }
    store = OidcStore(hass)

    await store.async_load()

    assert store.sessions == {}
    if raw_data == [] or not isinstance(raw_data.get("records", {}), dict):
        assert store.records == {}


async def test_store_records_that_records_were_discarded(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
) -> None:
    """Test losing registry records to corrupt storage is remembered."""
    hass_storage[STORAGE_KEY] = {
        "version": STORAGE_VERSION,
        "minor_version": 1,
        "key": STORAGE_KEY,
        "data": {"records": {IDP_ID: {"idp_id": IDP_ID, "domain": 1}}},
    }
    store = OidcStore(hass)

    await store.async_load()

    assert store.records == {}

    store.async_set_record(
        IdentityProviderRecord(
            idp_id=IDP_ID,
            domain=IDP_DOMAIN,
            accounts=AccountPolicy.LINK,
            trust_key="key",
        )
    )


async def test_store_survives_a_restart(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test the configuration and sessions are restored from disk."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    hass.bus.async_fire(EVENT_HOMEASSISTANT_FINAL_WRITE)
    await hass.async_block_till_done()

    store = auth_store.AuthStore(hass)
    await store.async_load()
    restored = oidc_auth.OidcAuthProvider(
        hass, store, oidc_auth.CONFIG_SCHEMA({"type": PROVIDER_TYPE})
    )
    await restored.async_initialize()

    assert restored.data is not None
    assert IDP_ID in restored.data.records
    assert restored.data.sessions[credentials.id].refresh_token == "rt"


async def test_manager_initializes_oidc_and_prunes_orphan_session(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    provider: OidcProvider,
) -> None:
    """Test restart loads OIDC config and drops sessions without credentials."""
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    hass.bus.async_fire(EVENT_HOMEASSISTANT_FINAL_WRITE)
    await hass.async_block_till_done()

    restored_manager = await auth.auth_manager_from_config(
        hass, [{"type": PROVIDER_TYPE}], []
    )
    restored = restored_manager.auth_providers[0]
    assert isinstance(restored, oidc_auth.OidcAuthProvider)

    assert restored.data is not None
    assert IDP_ID in restored.identity_provider_ids
    assert restored.data.sessions == {}


PROFILE_IDP_ID = "profile-idp"


async def _register_profile_provider(
    manager: auth.AuthManager,
) -> oidc_auth.OidcIdentityProvider:
    """Register and return a child provider that signs in with plain OAuth2."""
    root = manager.auth_providers[0]
    assert isinstance(root, oidc_auth.OidcAuthProvider)
    await root.async_register_identity_provider(
        PROFILE_IDP_ID,
        domain="profile",
        title="Profile",
        spec=oidc_auth.IdentityProvider(
            client_id=CLIENT_ID, protocol=ProfileProtocol()
        ),
    )
    child = root.async_get_child_provider(PROFILE_IDP_ID)
    assert isinstance(child, oidc_auth.OidcIdentityProvider)
    return child


async def _finish_profile_flow(
    manager: auth.AuthManager,
    aioclient_mock: AiohttpClientMocker,
    *,
    context: dict[str, Any] | None = None,
    token_response: dict[str, Any] | None = None,
) -> AuthFlowResult:
    """Complete a plain OAuth2 flow."""
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, PROFILE_IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            }
            | (context or {}),
        )
    assert result["type"] is FlowResultType.EXTERNAL_STEP
    assert "nonce" not in URL(result["url"]).query
    aioclient_mock.post(
        PROFILE_TOKEN_URL,
        json=token_response or {"access_token": "profile-at", "token_type": "Bearer"},
    )
    aioclient_mock.get(PROFILE_URL, json={"id": 123, "login": "octocat"})

    result = await manager.login_flow.async_configure(
        result["flow_id"], {"code": "the-code"}
    )
    return await manager.login_flow.async_configure(result["flow_id"])


async def test_oauth2_linked_sign_in(
    manager: auth.AuthManager, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a plain OAuth2 provider signs in a linked account without storing tokens."""
    child = await _register_profile_provider(manager)
    user = await manager.async_create_user("Alice")
    credentials = child.async_create_credentials(
        {"issuer": PROFILE_ISSUER, "subject": "123"}
    )
    await manager.async_link_user(user, credentials)

    result = await _finish_profile_flow(manager, aioclient_mock)

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].id == credentials.id
    assert child.root.data is not None
    assert child.root.data.sessions == {}


async def test_oauth2_link_flow(
    manager: auth.AuthManager, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a plain OAuth2 provider issues link credentials from its lookup."""
    await _register_profile_provider(manager)

    result = await _finish_profile_flow(
        manager, aioclient_mock, context={"link_user": True}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].data == {
        "issuer": PROFILE_ISSUER,
        "subject": "123",
        "account_name": "octocat",
    }
    assert aioclient_mock.mock_calls[-1][3]["X-Api-Version"] == "1"


async def test_oauth2_token_error_body_fails(
    manager: auth.AuthManager, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test HTTP 200 token responses carrying an error abort the flow."""
    await _register_profile_provider(manager)

    result = await _finish_profile_flow(
        manager,
        aioclient_mock,
        context={"link_user": True},
        token_response={"error": "bad_verification_code"},
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "authorize_failed"


async def test_finish_oauth2_abort_branches(manager: auth.AuthManager) -> None:
    """Test plain OAuth2 finish abort branches."""
    child = await _register_profile_provider(manager)
    flow = oidc_auth.OidcLoginFlow(child)
    flow._code = "code"
    flow._redirect_uri = f"{REDIRECT_BASE}/auth/login_callback"
    client = AsyncMock()
    client.issuer = PROFILE_ISSUER
    client.async_exchange_code.return_value = oidc_auth.TokenResponse(access_token="at")
    client.async_fetch_identity.return_value = (SUBJECT, None)

    result = await flow._async_finish_oauth2(client, child.generation)
    assert result["reason"] == "user_not_allowed"

    flow = oidc_auth.OidcLoginFlow(child)
    flow._code = "code"
    flow._redirect_uri = f"{REDIRECT_BASE}/auth/login_callback"
    child.async_suspend()
    result = await flow._async_finish_oauth2(client, child.generation - 1)
    assert result["reason"] == "configuration_changed"


class _TenantClient(OidcClient):
    """OIDC client that keys credentials by a tenant claim."""

    def canonical_issuer(self, claims: dict[str, Any]) -> str:
        """Return the issuer of the tenant."""
        return f"{self.issuer}/{claims['tid']}"

    def accepts_issuer(self, issuer: str) -> bool:
        """Accept the issuer of any tenant."""
        return issuer.startswith(f"{self.issuer}/")


@dataclass(frozen=True, slots=True, kw_only=True)
class _TenantOpenIDConnect(OpenIDConnect):
    """OpenID Connect with an issuer per tenant."""

    client_class = _TenantClient


async def test_client_hooks_key_credentials(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a protocol's client decides the issuer credentials are keyed by."""
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=IdentityProvider(
            client_id=CLIENT_ID,
            protocol=_TenantOpenIDConnect(issuer=ISSUER),
            accounts=AccountPolicy.PROVISION,
            revalidate_interval=timedelta(minutes=5),
        ),
    )
    child = provider.root.async_get_child_provider(IDP_ID)
    assert isinstance(child, oidc_auth.OidcIdentityProvider)

    result = await _complete_login(manager, mock_idp, signing_key, jwks, tid="abc")

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].data["issuer"] == f"{ISSUER}/abc"
    assert child.async_can_login_with_credentials(result["result"])


async def test_required_claims_at_sign_in_and_revalidation(
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test required claim rules reject sign-in and refreshed ID tokens."""
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=oidc_auth.IdentityProvider(
            client_id=CLIENT_ID,
            protocol=oidc_auth.OpenIDConnect(
                issuer=ISSUER,
                required_claims={
                    "hd": oidc_auth.Equals(value="example.com"),
                    "blocked": oidc_auth.NotEquals(value="true"),
                    "tier": oidc_auth.OneOf(values=frozenset({"gold", "silver"})),
                },
                admin_group="home_assistant_admin",
            ),
            accounts=AccountPolicy.PROVISION,
            revalidate_interval=timedelta(minutes=5),
        ),
    )
    child = provider.root.async_get_child_provider(IDP_ID)
    assert isinstance(child, oidc_auth.OidcIdentityProvider)
    provider.child = child
    result = await _complete_login(
        manager, mock_idp, signing_key, jwks, hd="evil.example", tier="gold"
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "claim_rejected"

    result = await _complete_login(
        manager,
        mock_idp,
        signing_key,
        jwks,
        hd="example.com",
        blocked="false",
        tier="gold",
    )
    credentials = result["result"]
    provider.root.data.sessions[credentials.id].refresh_after = time.time() - 1
    with (
        patch.object(
            child.async_client(),
            "async_refresh_token",
            return_value=oidc_auth.TokenResponse(access_token="at", id_token="id"),
        ),
        patch.object(
            child.async_client(),
            "async_verify_id_token",
            return_value={"sub": SUBJECT, "hd": "evil.example", "tier": "gold"},
        ),
    ):
        await provider.root._async_revalidate_sessions(dt_util.utcnow())

    assert credentials.id not in provider.root.data.sessions


async def test_dormant_children_after_restart_validate_existing_tokens(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test dormant children keep LINK valid and PROVISION until deadline."""
    link_root = provider.root
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(accounts=AccountPolicy.LINK),
    )
    user = await manager.async_create_user("Alice")
    link_credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, link_credentials)
    link_token = await manager.async_create_refresh_token(
        user, "client", credential=link_credentials
    )
    link_token.last_used_at = dt_util.utcnow()
    link_root.async_suspend_identity_provider(IDP_ID)
    child = link_root.async_get_child_provider(IDP_ID)
    assert isinstance(child, oidc_auth.OidcIdentityProvider)
    child.async_validate_refresh_token(link_token)
    assert not child.async_can_start_login({})
    assert not child.async_can_login_with_credentials(link_credentials)
    with pytest.raises(OidcError):
        child.async_client()

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(accounts=AccountPolicy.PROVISION),
    )
    provision_credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": "provision"}
    )
    await manager.async_link_user(user, provision_credentials)
    await provider.child.async_record_session(
        credential_id=provision_credentials.id,
        claims={"sub": "provision"},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    provision_token = await manager.async_create_refresh_token(
        user, "client2", credential=provision_credentials
    )
    provision_token.last_used_at = dt_util.utcnow()
    link_root.async_suspend_identity_provider(IDP_ID)
    child = link_root.async_get_child_provider(IDP_ID)
    assert isinstance(child, oidc_auth.OidcIdentityProvider)
    child.async_validate_refresh_token(provision_token)
    provider.root.data.sessions[provision_credentials.id].revalidate_after = (
        time.time() - 1
    )
    with pytest.raises(auth.InvalidAuthError):
        child.async_validate_refresh_token(provision_token)


async def test_discover_and_validate_identity_provider_helpers(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test helper validation maps network and discovery failures."""
    aioclient_mock.get("https://bad.example.com/discovery", status=503, json={})
    with pytest.raises(oidc_auth.IdentityProviderError) as err:
        await oidc_auth.async_discover_identity_provider(
            hass, "https://bad.example.com/discovery"
        )
    assert err.value.reason == "invalid_discovery"

    aioclient_mock.get("https://malformed.example.com/discovery", json=[])
    with pytest.raises(oidc_auth.IdentityProviderError) as err:
        await oidc_auth.async_discover_identity_provider(
            hass, "https://malformed.example.com/discovery"
        )
    assert err.value.reason == "invalid_discovery"

    with pytest.raises(oidc_auth.IdentityProviderError) as err:
        await oidc_auth.async_validate_identity_provider(
            hass,
            oidc_auth.IdentityProvider(
                client_id="",
                protocol=oidc_auth.OpenIDConnect(issuer=ISSUER),
            ),
        )
    assert err.value.reason == "invalid_client_id"

    aioclient_mock.get(DISCOVERY_URL, json=discovery_document())
    spec = oidc_auth.IdentityProvider(
        client_id=CLIENT_ID, protocol=oidc_auth.OpenIDConnect(issuer=ISSUER)
    )
    assert await oidc_auth.async_validate_identity_provider(hass, spec) == spec


async def test_remove_identity_provider_suspends_revokes_and_reports_locked_users(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test removing an IdP suspends flows, revokes, removes credentials and reports users."""
    aioclient_mock.get(
        DISCOVERY_URL,
        json=discovery_document(revocation_endpoint=f"{ISSUER}/revoke"),
    )
    aioclient_mock.post(f"{ISSUER}/revoke", status=200)
    await provider.child.async_client().async_metadata()
    locked = await manager.async_create_user("Locked")
    kept = await manager.async_create_user("Kept")
    locked_credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": "locked"}
    )
    kept_credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": "kept"}
    )
    await manager.async_link_user(locked, locked_credentials)
    await manager.async_link_user(kept, kept_credentials)
    example = insecure_example.ExampleAuthProvider(
        hass, manager._store, {"type": "insecure_example", "users": []}
    )
    manager._providers[(example.type, example.id)] = example
    await manager.async_link_user(
        kept, example.async_create_credentials({"username": "kept"})
    )
    for credentials, subject, token in (
        (locked_credentials, "locked", "locked-rt"),
        (kept_credentials, "kept", "kept-rt"),
    ):
        await provider.child.async_record_session(
            credential_id=credentials.id,
            claims={"sub": subject},
            tokens=oidc_auth.TokenResponse(access_token="at", refresh_token=token),
        )

    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        flow = await manager.login_flow.async_init(
            (PROVIDER_TYPE, IDP_ID),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )
    removed = await provider.root.async_remove_identity_provider(IDP_ID)
    await hass.async_block_till_done()
    flow = await manager.login_flow.async_configure(flow["flow_id"], {"code": "code"})
    flow = await manager.login_flow.async_configure(flow["flow_id"])

    assert flow["type"] is FlowResultType.ABORT
    assert flow["reason"] == "configuration_changed"
    assert removed == [locked]
    assert locked_credentials not in locked.credentials
    assert kept_credentials not in kept.credentials
    assert any(call[1] == URL(f"{ISSUER}/revoke") for call in aioclient_mock.mock_calls)


async def test_trust_key_change_revokes_with_old_client(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test trust changes end sessions and revoke through the old client."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="old-rt"),
    )
    old_client = provider.child.async_client()
    old_client.async_revoke_token = AsyncMock()  # type: ignore[method-assign]

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(issuer="https://new-idp.example.com"),
    )
    await hass.async_block_till_done()

    assert provider.root.data.sessions == {}
    old_client.async_revoke_token.assert_awaited_once_with("old-rt")


async def test_suspend_then_end_sessions_still_revokes(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test suspended children keep their last client for revocation."""
    aioclient_mock.get(
        DISCOVERY_URL,
        json=discovery_document(revocation_endpoint=f"{ISSUER}/revoke"),
    )
    aioclient_mock.post(f"{ISSUER}/revoke", status=200)
    await provider.child.async_client().async_metadata()
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="suspended-rt"),
    )

    provider.root.async_suspend_identity_provider(IDP_ID)
    await provider.root.async_end_identity_provider_sessions(IDP_ID)
    await hass.async_block_till_done()

    assert any(call[1] == URL(f"{ISSUER}/revoke") for call in aioclient_mock.mock_calls)


async def test_suspend_then_remove_still_revokes(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test removing a previously suspended child still revokes sessions."""
    aioclient_mock.get(
        DISCOVERY_URL,
        json=discovery_document(revocation_endpoint=f"{ISSUER}/revoke"),
    )
    aioclient_mock.post(f"{ISSUER}/revoke", status=200)
    await provider.child.async_client().async_metadata()
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="remove-rt"),
    )

    provider.root.async_suspend_identity_provider(IDP_ID)
    await provider.root.async_remove_identity_provider(IDP_ID)
    await hass.async_block_till_done()

    assert any(call[1] == URL(f"{ISSUER}/revoke") for call in aioclient_mock.mock_calls)


async def test_dormant_restart_end_sessions_cannot_revoke(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test dormant children loaded from storage have no revocation client."""
    aioclient_mock.post(f"{ISSUER}/revoke", status=200)
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    hass.bus.async_fire(EVENT_HOMEASSISTANT_FINAL_WRITE)
    await hass.async_block_till_done()
    store = auth_store.AuthStore(hass)
    await store.async_load()
    restored = oidc_auth.OidcAuthProvider(
        hass, store, oidc_auth.CONFIG_SCHEMA({"type": PROVIDER_TYPE})
    )
    await restored.async_initialize()

    await restored.async_end_identity_provider_sessions(IDP_ID)
    await hass.async_block_till_done()

    assert not aioclient_mock.mock_calls


async def test_reactivation_replaces_revocation_client(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test a later activation revokes with the newly activated client."""
    new_issuer = "https://new-idp.example.com"
    new_discovery = f"{new_issuer}/.well-known/openid-configuration"
    aioclient_mock.get(
        new_discovery,
        json=discovery_document(
            issuer=new_issuer,
            authorization_endpoint=f"{new_issuer}/authorize",
            token_endpoint=f"{new_issuer}/token",
            jwks_uri=f"{new_issuer}/jwks",
            revocation_endpoint=f"{new_issuer}/revoke",
        ),
    )
    aioclient_mock.post(f"{new_issuer}/revoke", status=200)
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(issuer=new_issuer, accounts=AccountPolicy.PROVISION),
    )
    await provider.child.async_client().async_metadata()
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": new_issuer, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="new-rt"),
    )

    provider.root.async_suspend_identity_provider(IDP_ID)
    await provider.root.async_end_identity_provider_sessions(IDP_ID)
    await hass.async_block_till_done()

    assert any(
        call[1] == URL(f"{new_issuer}/revoke") for call in aioclient_mock.mock_calls
    )


@pytest.mark.parametrize(
    "raw_data",
    [
        pytest.param({"records": {1: {}}}, id="record-key"),
        pytest.param(
            {
                "records": {
                    IDP_ID: {
                        "idp_id": IDP_ID,
                        "domain": IDP_DOMAIN,
                        "accounts": AccountPolicy.LINK.value,
                        "trust_key": "key",
                    }
                },
                "sessions": {1: {}},
            },
            id="session-key",
        ),
        pytest.param(
            {
                "records": {
                    IDP_ID: {
                        "idp_id": IDP_ID,
                        "domain": IDP_DOMAIN,
                        "accounts": AccountPolicy.LINK.value,
                        "trust_key": "key",
                    }
                },
                "sessions": {
                    "credential-id": {
                        "credential_id": "other-credential-id",
                        "idp_id": IDP_ID,
                        "subject": SUBJECT,
                    }
                },
            },
            id="session-key-mismatch",
        ),
        pytest.param(
            {
                "records": {
                    IDP_ID: {
                        "idp_id": IDP_ID,
                        "domain": IDP_DOMAIN,
                        "accounts": AccountPolicy.LINK.value,
                        "trust_key": "key",
                    }
                },
                "sessions": {
                    "credential-id": {
                        "credential_id": "credential-id",
                        "idp_id": "missing-idp",
                        "subject": SUBJECT,
                    }
                },
            },
            id="unregistered-session",
        ),
        pytest.param(
            {
                "records": {
                    IDP_ID: {
                        "idp_id": "other-idp",
                        "domain": IDP_DOMAIN,
                        "accounts": AccountPolicy.LINK.value,
                        "trust_key": "key",
                    }
                },
                "sessions": {
                    "credential-id": {
                        "credential_id": "credential-id",
                        "idp_id": IDP_ID,
                        "subject": SUBJECT,
                    }
                },
            },
            id="record-key-mismatch",
        ),
        pytest.param(
            {
                "records": {
                    IDP_ID: {
                        "idp_id": IDP_ID,
                        "domain": IDP_DOMAIN,
                        "accounts": AccountPolicy.LINK.value,
                        "trust_key": "key",
                    }
                },
                "sessions": {
                    "credential-id": {
                        "credential_id": "credential-id",
                        "idp_id": IDP_ID,
                        "subject": SUBJECT,
                        "revalidate_after": math.inf,
                    }
                },
            },
            id="non-finite-deadline",
        ),
    ],
)
async def test_store_discards_additional_malformed_entries(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    raw_data: dict[str, Any],
) -> None:
    """Test malformed record and session edge cases are discarded."""
    hass_storage[STORAGE_KEY] = {
        "version": STORAGE_VERSION,
        "minor_version": 1,
        "key": STORAGE_KEY,
        "data": raw_data,
    }
    store = OidcStore(hass)

    await store.async_load()

    assert store.sessions == {}


def test_store_remove_record_prunes_its_sessions(hass: HomeAssistant) -> None:
    """Test removing records drops only matching sessions and saves on changes."""
    store = OidcStore(hass)
    store.records[IDP_ID] = IdentityProviderRecord(
        idp_id=IDP_ID,
        domain=IDP_DOMAIN,
        accounts=AccountPolicy.LINK,
        trust_key="key",
    )
    store.sessions["first"] = OidcSession(
        credential_id="first", idp_id=IDP_ID, subject=SUBJECT
    )
    store.sessions["second"] = OidcSession(
        credential_id="second", idp_id="other-idp", subject=SUBJECT
    )

    with patch.object(store, "async_schedule_save") as schedule_save:
        store.async_remove_record("unknown-idp")
        schedule_save.assert_not_called()

        store.async_remove_record(IDP_ID)

    assert IDP_ID not in store.records
    assert "first" not in store.sessions
    assert "second" in store.sessions
    schedule_save.assert_called_once()


def test_config_schema_rejects_root_provider_id() -> None:
    """Test the root OIDC engine cannot be configured with an ID."""
    with pytest.raises(Exception, match="ID is not allowed"):
        oidc_auth.CONFIG_SCHEMA({"type": PROVIDER_TYPE, "id": "child"})


async def test_async_get_provider_and_root_helpers(
    hass: HomeAssistant, manager: auth.AuthManager
) -> None:
    """Test root provider lookup and simple root helpers."""
    root = oidc_auth.async_get_provider(hass)
    assert isinstance(root, oidc_auth.OidcAuthProvider)
    assert not root.async_can_start_login({})
    root_flow = await root.async_login_flow({})
    result = await root_flow.async_step_init()
    assert result["reason"] == "not_configured"

    with patch.object(hass.auth, "get_auth_provider", return_value=None):
        assert oidc_auth.async_get_provider(hass) is None


async def test_async_get_data_initializes_unloaded_root(hass: HomeAssistant) -> None:
    """Test async_get_data initializes a fresh root provider."""
    store = auth_store.AuthStore(hass)
    await store.async_load()
    root = oidc_auth.OidcAuthProvider(
        hass, store, oidc_auth.CONFIG_SCHEMA({"type": PROVIDER_TYPE})
    )

    data = await root.async_get_data()

    assert root.data is data
    assert root.identity_provider_ids == frozenset()


async def test_child_basic_properties_and_dormant_errors(
    provider: OidcProvider,
) -> None:
    """Test child properties and dormant accessors."""
    assert provider.child.name == "Example ID"
    assert provider.child.domain == IDP_DOMAIN
    assert not provider.child.support_mfa
    assert provider.child.protocol is not None

    record = IdentityProviderRecord(
        idp_id="dormant",
        domain="example",
        accounts=AccountPolicy.LINK,
        trust_key="key",
    )
    dormant = oidc_auth.OidcIdentityProvider(provider.root, record)
    assert dormant.name == oidc_auth.OidcIdentityProvider.DEFAULT_TITLE
    assert dormant.domain == "example"
    assert dormant.support_mfa
    with pytest.raises(OidcError, match="dormant"):
        _ = dormant.spec
    with pytest.raises(OidcError, match="dormant"):
        dormant.async_client()


async def test_link_provider_rejects_user_meta(
    manager: auth.AuthManager,
) -> None:
    """Test LINK providers cannot provision user metadata."""
    root = manager.auth_providers[0]
    assert isinstance(root, oidc_auth.OidcAuthProvider)
    await root.async_register_identity_provider(
        "link-idp",
        domain=IDP_DOMAIN,
        title="Link IDP",
        spec=IdentityProvider(
            client_id=CLIENT_ID,
            protocol=OpenIDConnect(issuer=ISSUER),
            accounts=AccountPolicy.LINK,
        ),
    )
    child = root.async_get_child_provider("link-idp")
    assert isinstance(child, oidc_auth.OidcIdentityProvider)
    credentials = child.async_create_credentials({"issuer": ISSUER, "subject": SUBJECT})

    with pytest.raises(auth.InvalidAuthError, match="may only link"):
        await child.async_user_meta_for_credentials(credentials)


async def test_revalidate_missing_user_for_admin_grant(
    provider: OidcProvider,
) -> None:
    """Test admin grant updates ignore missing users."""
    user = await provider.child._async_user_for_credential("missing-credential")
    assert user is None

    await provider.child._async_apply_admin_grant(
        user, granted_by_provider=False, grants_admin=True
    )


async def test_register_wraps_runtime_client_error(manager: auth.AuthManager) -> None:
    """Test runtime client construction failures become invalid_spec."""
    root = manager.auth_providers[0]
    assert isinstance(root, oidc_auth.OidcAuthProvider)

    with (
        patch.object(
            OpenIDConnect, "client_class", Mock(side_effect=ValueError("bad issuer"))
        ),
        pytest.raises(oidc_auth.IdentityProviderError) as err,
    ):
        await root.async_register_identity_provider(
            "bad-client",
            domain=IDP_DOMAIN,
            title="Bad client",
            spec=IdentityProvider(
                client_id=CLIENT_ID,
                protocol=OpenIDConnect(issuer=ISSUER),
            ),
        )

    assert err.value.reason == "invalid_spec"


async def test_discover_helper_maps_transient_error(hass: HomeAssistant) -> None:
    """Test discovery helper maps transient failures."""
    with (
        patch.object(
            oidc_auth,
            "async_discover",
            AsyncMock(side_effect=OidcTransientError("timeout")),
        ),
        pytest.raises(oidc_auth.IdentityProviderError) as err,
    ):
        await oidc_auth.async_discover_identity_provider(hass, DISCOVERY_URL)

    assert err.value.reason == "cannot_connect"


async def test_child_flow_start_abort_branches(provider: OidcProvider) -> None:
    """Test child login start abort branches."""
    flow = oidc_auth.OidcLoginFlow(provider.child)
    provider.root.async_suspend_identity_provider(IDP_ID)
    result = await flow.async_step_init()
    assert result["reason"] == "not_configured"

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(),
    )
    flow = oidc_auth.OidcLoginFlow(provider.child)
    with patch.object(
        provider.child,
        "async_redirect_uri",
        side_effect=oidc_auth.NoURLAvailableError,
    ):
        result = await flow.async_step_init()
    assert result["reason"] == "no_url_available"


async def test_child_flow_provider_unavailable(
    provider: OidcProvider,
) -> None:
    """Test unavailable provider aborts the authorize step."""
    client = provider.child.async_client()
    flow = oidc_auth.OidcLoginFlow(provider.child)
    with (
        patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE),
        patch.object(
            client, "async_metadata", AsyncMock(side_effect=OidcError("down"))
        ),
    ):
        result = await flow.async_step_init()

    assert result["reason"] == "provider_unavailable"


@pytest.mark.parametrize(
    ("exchange_result", "verify_result", "reason"),
    [
        pytest.param(
            OidcError("token failed"), None, "token_request_failed", id="token"
        ),
        pytest.param(
            oidc_auth.TokenResponse(
                access_token="at", refresh_token="rt", id_token="id"
            ),
            OidcError("bad id"),
            "invalid_id_token",
            id="id-token",
        ),
        pytest.param(
            oidc_auth.TokenResponse(
                access_token="at", refresh_token="rt", id_token="id"
            ),
            {"iss": ISSUER},
            "missing_subject",
            id="subject",
        ),
    ],
)
async def test_finish_oidc_abort_branches(
    provider: OidcProvider,
    exchange_result: oidc_auth.TokenResponse | OidcError,
    verify_result: dict[str, Any] | OidcError | None,
    reason: str,
) -> None:
    """Test OIDC finish abort branches."""
    flow = oidc_auth.OidcLoginFlow(provider.child)
    flow._code = "code"
    flow._redirect_uri = f"{REDIRECT_BASE}/auth/login_callback"
    client = AsyncMock()
    if isinstance(exchange_result, OidcError):
        client.async_exchange_code.side_effect = exchange_result
    else:
        client.async_exchange_code.return_value = exchange_result
    if isinstance(verify_result, OidcError):
        client.async_verify_id_token.side_effect = verify_result
    else:
        client.async_verify_id_token.return_value = verify_result

    result = await flow._async_finish_oidc(
        client, provider.child.spec.protocol, provider.child.generation
    )

    assert result["reason"] == reason


async def test_root_remaining_lifecycle_branches(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test remaining root lifecycle branches."""
    store = auth_store.AuthStore(hass)
    await store.async_load()
    fresh = oidc_auth.OidcAuthProvider(
        hass, store, oidc_auth.CONFIG_SCHEMA({"type": PROVIDER_TYPE})
    )
    assert fresh.identity_provider_ids == frozenset()
    await fresh._async_revalidate_sessions(dt_util.utcnow())

    await provider.root.async_initialize()
    await provider.root.async_initialize()

    with pytest.raises(oidc_auth.IdentityProviderError, match="invalid_idp"):
        await provider.root.async_register_identity_provider(
            "",
            domain=IDP_DOMAIN,
            title="Invalid",
            spec=IdentityProvider(
                client_id=CLIENT_ID,
                protocol=OpenIDConnect(issuer=ISSUER),
            ),
        )

    await manager.async_create_user("Bob")
    await provider.root.async_remove_identity_provider(IDP_ID)


async def test_revalidation_lock_and_dormant_deadline_branches(
    provider: OidcProvider,
) -> None:
    """Test revalidation skips while locked and expires dormant sessions."""
    root = provider.root
    data = provider.root.data
    await root.revalidate_lock.acquire()
    try:
        await root._async_revalidate_sessions(dt_util.utcnow())
    finally:
        root.revalidate_lock.release()

    data.async_set_session(
        OidcSession(
            credential_id="future-refresh-credential",
            idp_id="missing-idp",
            subject=SUBJECT,
            refresh_after=time.time() + 60,
            revalidate_after=time.time() + 120,
        )
    )
    data.async_set_session(
        OidcSession(
            credential_id="dormant-credential",
            idp_id="missing-idp",
            subject=SUBJECT,
            refresh_after=0,
            revalidate_after=0,
        )
    )
    with patch.object(root, "_async_expire_sessions", AsyncMock()):
        await root._async_revalidate_sessions(dt_util.utcnow())

    assert "dormant-credential" not in data.sessions
    assert "future-refresh-credential" in data.sessions


async def test_end_admin_session_skips_owner_group_update(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test ending an admin session never edits owner groups."""
    owner = await manager.async_create_user("Owner")
    assert owner.is_owner
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(owner, credentials)
    session = OidcSession(
        credential_id=credentials.id,
        idp_id=IDP_ID,
        subject=SUBJECT,
        is_admin=True,
    )
    provider.root.data.async_set_session(session)

    await provider.root.async_end_sessions([session])

    assert credentials.id not in provider.root.data.sessions


async def test_refresh_token_validation_no_credential_or_data(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test refresh validation ignores unrelated tokens and rejects unloaded data."""
    user = await manager.async_create_user("Alice")
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/"
    )
    provider.child.async_validate_refresh_token(refresh_token)

    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    data = provider.root.data
    provider.root.data = None
    try:
        with pytest.raises(auth.InvalidAuthError, match="Sign in"):
            provider.child.async_validate_refresh_token(refresh_token)
    finally:
        provider.root.data = data


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        pytest.param("no-refresh-token", True, id="no-refresh-token"),
        pytest.param("stale-after-refresh", False, id="stale-after-refresh"),
        pytest.param("oidc-error", True, id="oidc-error"),
        pytest.param("stale-after-success", False, id="stale-after-success"),
    ],
)
async def test_revalidate_session_remaining_branches(
    provider: OidcProvider,
    setup: str,
    expected: bool,
) -> None:
    """Test remaining session revalidation branches."""
    data = provider.root.data
    session = OidcSession(
        credential_id=f"credential-{setup}",
        idp_id=IDP_ID,
        subject=SUBJECT,
        refresh_token="rt" if setup != "no-refresh-token" else None,
        refresh_after=0,
        revalidate_after=time.time() - 1,
    )
    data.async_set_session(session)
    client = provider.child.async_client()

    if setup == "no-refresh-token":
        assert await provider.child.async_revalidate_session(data, session) is expected
        return

    if setup == "oidc-error":
        refresh = AsyncMock(side_effect=OidcError("bad"))
        current = None
    else:
        refresh = AsyncMock(return_value=oidc_auth.TokenResponse(access_token="at"))
        current = Mock(side_effect=[setup != "stale-after-refresh", False])

    patches = [patch.object(client, "async_refresh_token", refresh)]
    if current is not None:
        patches.append(
            patch.object(provider.child, "_async_session_is_current", current)
        )
    with patches[0]:
        if len(patches) == 2:
            with patches[1]:
                result = await provider.child.async_revalidate_session(data, session)
        else:
            result = await provider.child.async_revalidate_session(data, session)

    assert result is expected


async def test_finish_without_authorization_code(provider: OidcProvider) -> None:
    """Test finish aborts when the callback has no code."""
    flow = oidc_auth.OidcLoginFlow(provider.child)

    result = await flow.async_step_finish()

    assert result["reason"] == "authorize_failed"


async def test_finish_oidc_login_completion_failure(
    provider: OidcProvider,
) -> None:
    """Test InvalidAuthError while completing login aborts the flow."""
    flow = oidc_auth.OidcLoginFlow(provider.child)
    flow._code = "code"
    flow._redirect_uri = f"{REDIRECT_BASE}/auth/login_callback"
    client = AsyncMock()
    client.async_exchange_code.return_value = oidc_auth.TokenResponse(
        access_token="at", refresh_token="rt", id_token="id"
    )
    client.async_verify_id_token.return_value = {"iss": ISSUER, "sub": SUBJECT}
    client.canonical_issuer = Mock(return_value=ISSUER)

    with patch.object(
        provider.child,
        "async_complete_login",
        AsyncMock(side_effect=auth.InvalidAuthError("failed")),
    ):
        result = await flow._async_finish_oidc(
            client, provider.child.spec.protocol, provider.child.generation
        )

    assert result["reason"] == "authorize_failed"


async def test_end_admin_session_skips_user_without_admin_group(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test ending an admin session leaves users without admin group unchanged."""
    await manager.async_create_user("Owner")
    user = await manager.async_create_user("Alice", group_ids=[GROUP_ID_USER])
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    session = OidcSession(
        credential_id=credentials.id,
        idp_id=IDP_ID,
        subject=SUBJECT,
        is_admin=True,
    )
    provider.root.data.async_set_session(session)

    await provider.root.async_end_sessions([session])

    assert {group.id for group in user.groups} == {GROUP_ID_USER}


async def test_link_first_refresh_token_use_rejected_while_suspended(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test a LINK code cannot start a session after suspension."""
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(accounts=AccountPolicy.LINK),
    )
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    refresh_token = await manager.async_create_refresh_token(
        user, "client", credential=credentials
    )
    provider.root.async_suspend_identity_provider(IDP_ID)

    with pytest.raises(auth.InvalidAuthError):
        provider.child.async_validate_refresh_token(refresh_token)


async def test_link_used_refresh_token_accepted_while_suspended(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test a used LINK refresh token remains valid after suspension."""
    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(accounts=AccountPolicy.LINK),
    )
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    refresh_token = await manager.async_create_refresh_token(
        user, "client", credential=credentials
    )
    refresh_token.last_used_at = dt_util.utcnow()
    provider.root.async_suspend_identity_provider(IDP_ID)

    provider.child.async_validate_refresh_token(refresh_token)


async def test_provision_first_refresh_token_use_rejected_while_suspended(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test a PROVISION code cannot start a session after suspension."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "client", credential=credentials
    )
    provider.root.async_suspend_identity_provider(IDP_ID)

    with pytest.raises(auth.InvalidAuthError):
        provider.child.async_validate_refresh_token(refresh_token)


async def test_active_child_accepts_first_refresh_token_use(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test an active child accepts the first refresh token use."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    await provider.child.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "client", credential=credentials
    )

    provider.child.async_validate_refresh_token(refresh_token)
