"""Test the OpenID Connect auth provider."""

import asyncio
import base64
from dataclasses import dataclass
import hashlib
from ipaddress import ip_address
import json
import time
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from jwt.algorithms import RSAAlgorithm
import pytest
from pytest_homeassistant.test_util.aiohttp import AiohttpClientMocker
from yarl import URL

from homeassistant import auth
from homeassistant.auth import auth_store
from homeassistant.auth.models import AuthFlowResult
from homeassistant.auth.providers import insecure_example, oidc as oidc_auth
from homeassistant.auth.providers.oidc.client import (
    OidcClient,
    OidcDiscoveryError,
    OidcError,
    OidcIdTokenError,
    OidcTokenError,
    OidcTransientError,
    TokenResponse,
)
from homeassistant.auth.providers.oidc.const import (
    DEFAULT_SCOPES,
    PROVIDER_TYPE,
    STORAGE_KEY,
    STORAGE_VERSION,
)
from homeassistant.auth.providers.oidc.spec import IdentityProvider, OpenIDConnect
from homeassistant.auth.providers.oidc.store import IdentityProviderRecord, OidcStore
from homeassistant.const import EVENT_HOMEASSISTANT_FINAL_WRITE
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType, UnknownHandler
from homeassistant.util import dt as dt_util

ISSUER = "https://idp.example.com"
CLIENT_ID = "home-assistant"
KEY_ID = "test-key"
REDIRECT_BASE = "https://ha.example.com"
REDIRECT_URI = f"{REDIRECT_BASE}/auth/login_callback"
SUBJECT = "user-1234"
IDP_ID = "test-idp"
IDP_DOMAIN = "openid_connect"

DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/jwks"
TOKEN_URL = f"{ISSUER}/token"


def make_spec(
    *,
    issuer: str = ISSUER,
    client_id: str = CLIENT_ID,
    client_secret: str | None = None,
    scopes: tuple[str, ...] = DEFAULT_SCOPES,
    account_name_claim: str | None = None,
) -> IdentityProvider:
    """Return an OIDC identity provider spec for tests."""
    return IdentityProvider(
        client_id=client_id,
        client_secret=client_secret,
        protocol=OpenIDConnect(
            issuer=issuer, scopes=scopes, account_name_claim=account_name_claim
        ),
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
        await client.async_exchange_code(code="code", redirect_uri=REDIRECT_URI, code_verifier="verifier")


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
        await client.async_exchange_code(code="code", redirect_uri=REDIRECT_URI, code_verifier="verifier")


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
        await client.async_exchange_code(code="code", redirect_uri=REDIRECT_URI, code_verifier="verifier")


async def test_revocation_ignores_discovery_failure(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test an identity provider outage cannot block local token removal."""
    aioclient_mock.get(DISCOVERY_URL, status=503)
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    await client.async_revoke_token("refresh")


async def test_revocation_posts_the_refresh_token(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a refresh token is revoked at the advertised endpoint."""
    aioclient_mock.get(
        DISCOVERY_URL,
        json=discovery_document(revocation_endpoint=f"{ISSUER}/revoke"),
    )
    aioclient_mock.post(f"{ISSUER}/revoke")
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    await client.async_revoke_token("refresh")

    assert aioclient_mock.mock_calls[-1][1] == URL(f"{ISSUER}/revoke")
    assert aioclient_mock.mock_calls[-1][2] == {
        "token": "refresh",
        "token_type_hint": "refresh_token",
        "client_id": CLIENT_ID,
    }


async def test_revocation_without_an_endpoint_does_nothing(
    client: OidcClient, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test nothing is sent to a provider that offers no revocation."""
    await client.async_revoke_token("refresh")

    assert not any(call[0] == "POST" for call in aioclient_mock.mock_calls)


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
async def test_token_request_reports_rejected_grant(
    client: OidcClient, aioclient_mock: AiohttpClientMocker, error: str
) -> None:
    """Test a rejected request is reported as a token error."""
    aioclient_mock.post(TOKEN_URL, status=400, json={"error": error})

    with pytest.raises(OidcTokenError, match="rejected the grant"):
        await client.async_exchange_code(code="code", redirect_uri=REDIRECT_URI, code_verifier="verifier")


async def test_token_request_reports_invalid_json(
    client: OidcClient, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a response that is not JSON is reported as a token error."""
    aioclient_mock.post(TOKEN_URL, text="<html>")

    with pytest.raises(OidcTokenError, match="invalid JSON"):
        await client.async_exchange_code(code="code", redirect_uri=REDIRECT_URI, code_verifier="verifier")


async def test_token_request_reports_transient_error(
    client: OidcClient, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a server error is reported as retryable."""
    aioclient_mock.post(TOKEN_URL, status=503, json={})

    with pytest.raises(OidcTransientError):
        await client.async_exchange_code(code="code", redirect_uri=REDIRECT_URI, code_verifier="verifier")


async def test_token_request_uses_basic_auth(
    hass: HomeAssistant, mock_idp: AiohttpClientMocker
) -> None:
    """Test the client secret is sent in the authorization header by default."""
    mock_idp.post(TOKEN_URL, json={"access_token": "at", "token_type": "Bearer"})
    client = OidcClient(
        hass, issuer=ISSUER, client_id=CLIENT_ID, client_secret="s3cret"
    )

    await client.async_exchange_code(code="code", redirect_uri=REDIRECT_URI, code_verifier="verifier")

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

    await client.async_exchange_code(code="code", redirect_uri=REDIRECT_URI, code_verifier="verifier")

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
        await client.async_exchange_code(code="code", redirect_uri=REDIRECT_URI, code_verifier="verifier")

    assert not any(call[0] == "POST" for call in aioclient_mock.mock_calls)


async def test_login_flow(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a full login signs a linked identity in to its user."""
    user = await manager.async_create_user("Alice")
    await manager.async_link_user(
        user,
        provider.child.async_create_credentials({"issuer": ISSUER, "subject": SUBJECT}),
    )
    revoke_token = AsyncMock()
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

    with patch.object(OidcClient, "async_revoke_token", revoke_token):
        result = await manager.login_flow.async_configure(result["flow_id"])
    assert result["type"] is FlowResultType.CREATE_ENTRY

    credentials = result["result"]
    assert not credentials.is_new
    assert await manager.async_get_user_by_credentials(credentials) is user
    # Nothing needs the identity provider later, so its refresh token is dropped.
    revoke_token.assert_awaited_once_with("rt")


async def test_login_flow_refused_when_not_configured(
    manager: auth.AuthManager,
) -> None:
    """Test signing in can't be started while the provider is unconfigured."""
    with pytest.raises(UnknownHandler):
        await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )


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

    async def exchange_code(**kwargs: str) -> TokenResponse:
        exchange_started.set()
        await release_exchange.wait()
        return TokenResponse(
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
            return_value=TokenResponse(
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


async def test_login_flow_refuses_an_unlinked_identity(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test an identity that nobody linked cannot sign in."""

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
    **id_token_claims: Any,
) -> AuthFlowResult:
    """Run a login flow to the end and return its result."""
    mock_idp.clear_requests()
    mock_idp.get(DISCOVERY_URL, json=discovery_document())
    mock_idp.get(JWKS_URL, json=jwks)

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


async def test_login_flow_asks_linked_accounts_for_mfa(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test signing in with a linked identity still asks for the user's MFA."""
    manager = await auth.auth_manager_from_config(
        hass, [{"type": PROVIDER_TYPE}], [{"type": "insecure_example", "data": []}]
    )
    hass.auth = manager
    root = manager.auth_providers[0]
    assert isinstance(root, oidc_auth.OidcAuthProvider)
    await root.async_register_identity_provider(
        IDP_ID, domain=IDP_DOMAIN, title="Example ID", spec=make_spec()
    )
    child = root.async_get_child_provider(IDP_ID)
    assert child is not None
    user = await manager.async_create_user("Alice")
    await manager.async_link_user(
        user, child.async_create_credentials({"issuer": ISSUER, "subject": SUBJECT})
    )
    await manager.async_enable_user_mfa(user, "insecure_example", {"pin": "123456"})

    result = await _complete_login(manager, mock_idp, signing_key, jwks)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "mfa"


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
    user = await manager.async_create_user("Alice")
    await manager.async_link_user(
        user,
        provider.child.async_create_credentials(
            {"issuer": ISSUER, "subject": SUBJECT, "account_name": "alice@example.com"}
        ),
    )

    result = await _complete_login(
        manager, mock_idp, signing_key, jwks, email="alice@example.org"
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert user.credentials[0].data["account_name"] == "alice@example.org"


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
        pytest.param(make_spec(), True, id="current-issuer"),
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


async def test_deleting_the_config_clears_sessions(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test removing the configuration signs every OIDC user out."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    provider.root.async_suspend_identity_provider(IDP_ID)
    await provider.root.async_end_identity_provider_sessions(IDP_ID)

    assert not provider.child.active
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
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(issuer="https://other-idp.example.com", client_id="new-client"),
    )

    assert manager.async_get_refresh_token(refresh_token.id) is None


async def test_editing_the_account_name_claim_keeps_existing_sessions(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test an edit that only labels identities does not sign everybody out."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(account_name_claim="email"),
    )

    assert manager.async_get_refresh_token(refresh_token.id) is not None


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "https://other-idp.example.com"},
        {"client_id": "other-client"},
        {"client_secret": "rotated"},
        {"scopes": ("openid", "profile")},
    ],
    ids=["issuer", "client-id", "client-secret", "scopes"],
)
@pytest.mark.usefixtures("mock_idp")
async def test_security_relevant_settings_clear_sessions(
    manager: auth.AuthManager,
    provider: OidcProvider,
    change: dict[str, Any],
) -> None:
    """Test sessions do not survive a change to who issued or authorized them."""
    user = await manager.async_create_user("Alice")
    credentials = provider.child.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    await provider.root.async_register_identity_provider(
        IDP_ID,
        domain=IDP_DOMAIN,
        title="Example ID",
        spec=make_spec(**change),
    )

    assert manager.async_get_refresh_token(refresh_token.id) is None


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
            trust_key="key",
        )
    )


async def test_store_survives_a_restart(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test the registry is restored from disk."""
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


async def test_dormant_children_after_restart_validate_existing_tokens(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test dormant children keep sessions that were already in use valid."""
    link_root = provider.root
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


async def test_remove_identity_provider_suspends_and_reports_locked_users(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: OidcProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test removing an IdP suspends flows, removes credentials and reports users."""
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

    record = IdentityProviderRecord(
        idp_id="dormant",
        domain="example",
        trust_key="key",
    )
    dormant = oidc_auth.OidcIdentityProvider(provider.root, record)
    assert dormant.name == oidc_auth.OidcIdentityProvider.DEFAULT_TITLE
    assert dormant.domain == "example"
    with pytest.raises(OidcError, match="dormant"):
        _ = dormant.spec
    with pytest.raises(OidcError, match="dormant"):
        dormant.async_client()


async def test_link_provider_rejects_user_meta(
    manager: auth.AuthManager,
) -> None:
    """Test identity providers cannot create users."""
    root = manager.auth_providers[0]
    assert isinstance(root, oidc_auth.OidcAuthProvider)
    await root.async_register_identity_provider(
        "link-idp",
        domain=IDP_DOMAIN,
        title="Link IDP",
        spec=IdentityProvider(
            client_id=CLIENT_ID,
            protocol=OpenIDConnect(issuer=ISSUER),
        ),
    )
    child = root.async_get_child_provider("link-idp")
    assert isinstance(child, oidc_auth.OidcIdentityProvider)
    credentials = child.async_create_credentials({"issuer": ISSUER, "subject": SUBJECT})

    with pytest.raises(auth.InvalidAuthError, match="may only link"):
        await child.async_user_meta_for_credentials(credentials)


async def test_register_wraps_runtime_client_error(manager: auth.AuthManager) -> None:
    """Test runtime client construction failures become invalid_spec."""
    root = manager.auth_providers[0]
    assert isinstance(root, oidc_auth.OidcAuthProvider)

    with (
        patch(
            "homeassistant.auth.providers.oidc.OidcClient",
            Mock(side_effect=OidcError("bad issuer")),
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
            TokenResponse(
                access_token="at", refresh_token="rt", id_token="id"
            ),
            OidcError("bad id"),
            "invalid_id_token",
            id="id-token",
        ),
        pytest.param(
            TokenResponse(
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
    exchange_result: TokenResponse | OidcError,
    verify_result: dict[str, Any] | OidcError | None,
    reason: str,
) -> None:
    """Test OIDC finish abort branches."""
    flow = oidc_auth.OidcLoginFlow(provider.child)
    flow._code = "code"
    flow._redirect_uri = REDIRECT_URI
    flow._client = client = AsyncMock()
    flow._protocol = provider.child.spec.protocol
    flow._generation = provider.child.generation
    if isinstance(exchange_result, OidcError):
        client.async_exchange_code.side_effect = exchange_result
    else:
        client.async_exchange_code.return_value = exchange_result
    if isinstance(verify_result, OidcError):
        client.async_verify_id_token.side_effect = verify_result
    else:
        client.async_verify_id_token.return_value = verify_result

    result = await flow.async_step_finish()

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


async def test_finish_without_authorization_code(provider: OidcProvider) -> None:
    """Test finish aborts when the callback has no code."""
    flow = oidc_auth.OidcLoginFlow(provider.child)

    result = await flow.async_step_finish()

    assert result["reason"] == "authorize_failed"


async def test_link_first_refresh_token_use_rejected_while_suspended(
    manager: auth.AuthManager,
    provider: OidcProvider,
) -> None:
    """Test a LINK code cannot start a session after suspension."""
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
    refresh_token = await manager.async_create_refresh_token(
        user, "client", credential=credentials
    )

    provider.child.async_validate_refresh_token(refresh_token)
