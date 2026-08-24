"""Test the OpenID Connect auth provider."""

import asyncio
import base64
from contextlib import suppress
from dataclasses import replace
import hashlib
from ipaddress import ip_address
import json
import time
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from jwt.algorithms import RSAAlgorithm
import pytest
from yarl import URL

from homeassistant import auth
from homeassistant.auth import auth_store, models as auth_models
from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_READ_ONLY
from homeassistant.auth.models import AuthFlowResult
from homeassistant.auth.providers import oidc as oidc_auth
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
    MIN_REVALIDATE_INTERVAL,
    PROVIDER_TYPE,
    REVALIDATE_CHECK_INTERVAL,
    REVALIDATE_REFRESH_RATIO,
    STORAGE_KEY,
    STORAGE_VERSION,
)
from homeassistant.auth.providers.oidc.store import OidcConfig, OidcStore
from homeassistant.const import EVENT_HOMEASSISTANT_FINAL_WRITE
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.util import dt as dt_util

from tests.common import async_fire_time_changed
from tests.test_util.aiohttp import AiohttpClientMocker

ISSUER = "https://idp.example.com"
CLIENT_ID = "home-assistant"
KEY_ID = "test-key"
REDIRECT_BASE = "https://ha.example.com"
SUBJECT = "user-1234"

DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URL = f"{ISSUER}/jwks"
TOKEN_URL = f"{ISSUER}/token"
USERINFO_URL = f"{ISSUER}/userinfo"


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
async def provider(manager: auth.AuthManager) -> oidc_auth.OidcAuthProvider:
    """Return a configured OIDC auth provider."""
    provider = manager.auth_providers[0]
    assert isinstance(provider, oidc_auth.OidcAuthProvider)
    await provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=True)
    )
    return provider


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
    """Test providers that end their issuer in a slash are usable.

    Providers disagree on the trailing slash, and the advertised value is what
    the ID token has to match.
    """
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

    with pytest.raises(OidcTokenError, match="token type"):
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

    with pytest.raises(OidcTokenError, match="redirects"):
        await client.async_refresh_token("refresh")


async def test_userinfo_does_not_follow_redirects(
    client: OidcClient, mock_idp: AiohttpClientMocker
) -> None:
    """Test the access token is not replayed to a redirect target."""
    mock_idp.get(
        USERINFO_URL, status=302, headers={"Location": "http://evil.example.com/"}
    )

    with pytest.raises(OidcError, match="redirects"):
        await client.async_userinfo("at")


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
    """Test an ID token signed with the client secret is refused.

    Accepting HS256 would let anyone holding the client secret mint tokens.
    """
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": SUBJECT,
            "aud": CLIENT_ID,
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        },
        "a-shared-secret",
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
    """Test malformed access-token encoding is reported as an OIDC error."""
    with pytest.raises(OidcIdTokenError, match="ASCII"):
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


async def test_token_request_reports_invalid_grant(
    client: OidcClient, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test a rejected grant is reported as permanent."""
    aioclient_mock.post(TOKEN_URL, status=400, json={"error": "invalid_grant"})

    with pytest.raises(OidcInvalidGrantError):
        await client.async_refresh_token("dead-token")


async def test_token_request_reports_client_error(
    client: OidcClient, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test other client errors are not treated as a revoked session."""
    aioclient_mock.post(TOKEN_URL, status=400, json={"error": "invalid_client"})

    with pytest.raises(OidcTokenError):
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a full login creates a user and records the session."""
    mock_idp.get(USERINFO_URL, json={"sub": SUBJECT})
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )

    assert result["type"] is FlowResultType.EXTERNAL_STEP
    query = URL(result["url"]).query
    assert query["client_id"] == CLIENT_ID
    assert query["code_challenge_method"] == "S256"
    assert query["redirect_uri"] == f"{REDIRECT_BASE}/auth/oidc/callback"

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

    session = provider.data.sessions[credentials.id]
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test a code from the old issuer is never sent to a replacement issuer."""
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )

    other_issuer = "https://other-idp.example.com"
    await provider.async_set_config(
        OidcConfig(issuer=other_issuer, client_id="new-client")
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a configuration change wins over an in-flight token exchange."""
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
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

    old_client = provider.async_client()
    with patch.object(old_client, "async_exchange_code", side_effect=exchange_code):
        finish_task = asyncio.create_task(
            manager.login_flow.async_configure(result["flow_id"])
        )
        await exchange_started.wait()
        await provider.async_set_config(
            OidcConfig(issuer="https://other-idp.example.com", client_id="new-client")
        )
        release_exchange.set()
        result = await finish_task

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "configuration_changed"
    assert provider.data.sessions == {}


async def test_login_flow_aborts_on_provider_error(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    signing_key: rsa.RSAPrivateKey,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test an error from the identity provider does not sign anybody in."""
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test an unadopted refresh token is revoked when login aborts."""
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )
    client = provider.async_client()
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test replacing a session revokes its previous external refresh token."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="replaced-rt"),
    )
    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
            context={
                "ip_address": ip_address("127.0.0.1"),
                "redirect_uri": "https://ha.example.com/",
            },
        )
    nonce = URL(result["url"]).query["nonce"]
    client = provider.async_client()
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
    assert provider.data.sessions[credentials.id].refresh_token == "new-rt"
    revoke_token.assert_awaited_once_with("replaced-rt")


async def test_login_flow_without_auto_create(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test an unknown user is refused when auto creation is off."""
    await provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=False)
    )
    mock_idp.get(USERINFO_URL, json={"sub": SUBJECT})

    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test an unknown identity can still be linked to an existing account.

    Without auto creation there is no other way in, so the flow has to hand out
    credentials that /auth/link_user can attach to the signed in user.
    """
    await provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=False)
    )
    mock_idp.get(USERINFO_URL, json={"sub": SUBJECT})

    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
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
    """Run a login flow to the end and return its result.

    The mocks are rebuilt every time because the mocker answers with the first
    registration that matches, which would replay a stale nonce.
    """
    mock_idp.clear_requests()
    mock_idp.get(DISCOVERY_URL, json=discovery_document())
    mock_idp.get(JWKS_URL, json=jwks)
    mock_idp.get(
        USERINFO_URL, json=userinfo if userinfo is not None else {"sub": SUBJECT}
    )

    with patch("homeassistant.auth.providers.oidc.get_url", return_value=REDIRECT_BASE):
        result = await manager.login_flow.async_init(
            (PROVIDER_TYPE, None),
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
    provider: oidc_auth.OidcAuthProvider,
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
    provider: oidc_auth.OidcAuthProvider,
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
    provider: oidc_auth.OidcAuthProvider,
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test seeing the group once puts the rights under the identity provider.

    The account was made an administrator inside Home Assistant, so losing the
    group has to demote it all the same.
    """
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a demotion gives back the rights the account had, not more.

    Permissions come from the groups, so dropping a read only user into the
    regular group would quietly widen their access.
    """
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
    provider: oidc_auth.OidcAuthProvider,
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
    provider: oidc_auth.OidcAuthProvider,
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


async def test_new_user_without_the_admin_group_is_a_regular_user(
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
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
    provider: oidc_auth.OidcAuthProvider,
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


async def test_login_flow_skips_userinfo_when_the_id_token_suffices(
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a returning user never costs a userinfo request.

    The claims it fills in are only read while the account is built.
    """
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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a mismatched userinfo subject stops the login.

    OIDC Core 5.3.2 requires the response to be discarded, because a substituted
    access token would otherwise import somebody else's claims.
    """
    await provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=True)
    )

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
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
    jwks: dict[str, Any],
) -> None:
    """Test a userinfo response has to carry the subject it is required to."""
    await provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, allow_auto_create=True)
    )

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
    manager: auth.AuthManager, provider: oidc_auth.OidcAuthProvider
) -> None:
    """Test the same subject at another issuer is a different account.

    A subject is only unique within an issuer, so repointing Home Assistant at
    another identity provider must not hand over the existing accounts.
    """
    user = await manager.async_create_user("Alice")
    first = await provider.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await manager.async_link_user(user, first)

    same = await provider.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    other = await provider.async_get_or_create_credentials(
        {"issuer": "https://other-idp.example.com", "subject": SUBJECT}
    )

    assert same.id == first.id
    assert other.id != first.id
    assert other.is_new


async def test_pending_credentials_are_deduplicated(
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test concurrent flows cannot create two credentials for one identity."""
    first = await provider.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    second = await provider.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )

    assert second is first


async def test_pending_credentials_create_one_user(
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test concurrent redemption cannot create duplicate OIDC users."""
    credentials = await provider.async_get_or_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    first_ready = asyncio.Event()
    release = asyncio.Event()
    original = provider.async_user_meta_for_credentials

    async def user_meta(
        pending: auth_models.Credentials,
    ) -> auth_models.UserMeta:
        first_ready.set()
        await release.wait()
        return await original(pending)

    with patch.object(
        provider, "async_user_meta_for_credentials", side_effect=user_meta
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
    provider: oidc_auth.OidcAuthProvider,
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

    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await provider.async_record_session(
        credential_id=credentials.id,
        claims=claims,
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )

    meta = await provider.async_user_meta_for_credentials(credentials)

    assert meta.name == "Alice"
    assert meta.group == expected_group


async def test_user_meta_without_an_admin_group_configured(
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test nobody becomes an administrator while group mapping is turned off."""
    await provider.async_set_config(
        OidcConfig(issuer=ISSUER, client_id=CLIENT_ID, admin_group=None)
    )
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": ["home_assistant_admin"]},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )

    meta = await provider.async_user_meta_for_credentials(credentials)

    assert meta.group == "system-users"


async def test_user_meta_defaults_to_plain_user(
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test a user without the admin group does not become an administrator."""
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "name": "Alice", "preferred_username": "alice"},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )

    meta = await provider.async_user_meta_for_credentials(credentials)

    assert meta.group == "system-users"


async def test_user_meta_rejects_credentials_without_a_session(
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test a stale authorization code cannot create a sessionless user."""
    credentials = provider.async_create_credentials(
        {"issuer": ISSUER, "subject": SUBJECT}
    )

    with pytest.raises(auth.InvalidAuthError):
        await manager.async_get_or_create_user(credentials)


async def test_refresh_token_rejected_after_deadline(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test a session has to be confirmed by the identity provider again."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    # Still inside the window, so a new access token is handed out.
    assert manager.async_create_access_token(refresh_token)

    provider.data.sessions[credentials.id].revalidate_after = time.time() - 1

    with pytest.raises(auth.InvalidAuthError):
        manager.async_create_access_token(refresh_token)


async def test_refresh_token_rejected_without_session(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test a credential without a session cannot mint access tokens."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    with pytest.raises(auth.InvalidAuthError):
        manager.async_create_access_token(refresh_token)


async def test_refresh_token_rejected_when_provider_is_unconfigured(
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test configuration loss cannot leave a persisted session trusted."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    provider.data.config = None

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
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test a non-refreshable session is removed at its hard deadline."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    session = provider.data.sessions[credentials.id]
    session.refresh_after = time.time() - 2
    session.revalidate_after = time.time() - 1

    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=2))
    await hass.async_block_till_done()

    assert credentials.id not in provider.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is None


async def test_long_lived_access_token_skips_revalidation(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test long lived access tokens deliberately opt out of revalidation."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
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

    provider.data.sessions[credentials.id].revalidate_after = time.time() - 1

    assert manager.async_create_access_token(refresh_token)


async def test_revalidation_extends_the_session(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test a silent refresh keeps the user signed in without interaction."""
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    session = provider.data.sessions[credentials.id]
    session.refresh_after = time.time() - 1
    deadline = session.revalidate_after

    mock_idp.post(
        TOKEN_URL,
        json={"access_token": "at2", "token_type": "Bearer", "refresh_token": "rt2"},
    )
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    session = provider.data.sessions[credentials.id]
    assert session.revalidate_after > deadline
    assert session.refresh_token == "rt2"


async def test_revalidation_rejects_id_token_for_another_subject(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a refresh response cannot switch the identity behind a session."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    session = provider.data.sessions[credentials.id]
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

    assert credentials.id not in provider.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is None


async def test_revalidation_keeps_rotated_token_on_transient_validation_error(
    hass: HomeAssistant,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test token rotation survives a transient refreshed-ID-token failure."""
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="old-rt"),
    )
    session = provider.data.sessions[credentials.id]
    session.refresh_after = time.time() - 1
    deadline = session.revalidate_after
    client = provider.async_client()

    with (
        patch.object(
            client,
            "async_refresh_token",
            return_value=oidc_auth.TokenResponse(
                access_token="at2", id_token="new-id-token", refresh_token="new-rt"
            ),
        ),
        patch.object(
            client,
            "async_verify_id_token",
            side_effect=OidcTransientError("JWKS unavailable"),
        ),
    ):
        async_fire_time_changed(hass, dt_util.utcnow() + REVALIDATE_CHECK_INTERVAL)
        await hass.async_block_till_done()

    session = provider.data.sessions[credentials.id]
    assert session.refresh_token == "new-rt"
    assert session.revalidate_after == deadline


async def test_revalidation_cannot_remove_a_new_login_session(
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test an old invalid grant cannot remove a concurrently renewed session."""
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="old-rt"),
    )
    provider.data.sessions[credentials.id].refresh_after = time.time() - 1
    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()

    async def refresh_token(_: str) -> oidc_auth.TokenResponse:
        refresh_started.set()
        await release_refresh.wait()
        raise OidcInvalidGrantError("revoked")

    with patch.object(
        provider.async_client(), "async_refresh_token", side_effect=refresh_token
    ):
        revalidate = asyncio.create_task(
            provider._async_revalidate_sessions(dt_util.utcnow())
        )
        await refresh_started.wait()
        renewed = asyncio.create_task(
            provider.async_record_session(
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

    assert provider.data.sessions[credentials.id].refresh_token == "new-rt"


@pytest.mark.usefixtures("mock_idp")
async def test_revalidation_cannot_restore_removed_credentials(
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test an in-flight refresh cannot restore an explicitly removed session."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="old-rt"),
    )
    provider.data.sessions[credentials.id].refresh_after = time.time() - 1
    refresh_started = asyncio.Event()
    release_refresh = asyncio.Event()

    async def refresh_token(_: str) -> oidc_auth.TokenResponse:
        refresh_started.set()
        await release_refresh.wait()
        return oidc_auth.TokenResponse(access_token="at2", refresh_token="rotated-rt")

    with patch.object(
        provider.async_client(), "async_refresh_token", side_effect=refresh_token
    ):
        revalidate = asyncio.create_task(
            provider._async_revalidate_sessions(dt_util.utcnow())
        )
        await refresh_started.wait()
        remove = asyncio.create_task(manager.async_remove_credentials(credentials))
        await asyncio.sleep(0)
        release_refresh.set()
        await asyncio.gather(revalidate, remove)

    assert credentials.id not in provider.data.sessions
    assert credentials not in user.credentials


async def test_revalidation_leaves_the_groups_alone(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test a background refresh does not restate the group membership.

    Groups are only read while somebody signs in, so revalidation must not
    reinterpret a session it never had claims for.
    """
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": ["home_assistant_admin"]},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    provider.data.sessions[credentials.id].refresh_after = time.time() - 1

    mock_idp.post(
        TOKEN_URL,
        json={"access_token": "at2", "token_type": "Bearer", "refresh_token": "rt2"},
    )
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    session = provider.data.sessions[credentials.id]
    assert session.refresh_token == "rt2"
    assert session.is_admin is True


async def test_revalidation_signs_out_revoked_users(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test a revoked identity provider session drops the Home Assistant tokens."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    provider.data.sessions[credentials.id].refresh_after = time.time() - 1

    mock_idp.post(TOKEN_URL, status=400, json={"error": "invalid_grant"})
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert credentials.id not in provider.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is None


async def test_revalidation_removes_provider_admin_grant(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test ending the granting session withdraws provider-derived admin rights."""
    await manager.async_create_user("Owner")
    user = await manager.async_create_user("Alice", group_ids=[GROUP_ID_READ_ONLY])
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": ["home_assistant_admin"]},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    await manager.async_update_user(
        user, group_ids=[GROUP_ID_ADMIN, GROUP_ID_READ_ONLY]
    )
    provider.data.sessions[credentials.id].refresh_after = time.time() - 1

    mock_idp.post(TOKEN_URL, status=400, json={"error": "invalid_grant"})
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert not user.is_admin
    assert [group.id for group in user.groups] == [GROUP_ID_READ_ONLY]


async def test_revalidation_keeps_session_on_transient_error(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test an unreachable identity provider does not sign anybody out."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )
    provider.data.sessions[credentials.id].refresh_after = time.time() - 1

    mock_idp.post(TOKEN_URL, status=503, json={})
    async_fire_time_changed(hass, dt_util.utcnow() + dt_util.dt.timedelta(minutes=6))
    await hass.async_block_till_done()

    assert credentials.id in provider.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is refresh_token


async def test_removing_credentials_drops_the_session(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    mock_idp: AiohttpClientMocker,
) -> None:
    """Test removing a user cleans up the identity provider session."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )

    await manager.async_remove_user(user)

    assert credentials.id not in provider.data.sessions


async def test_removing_credentials_cannot_race_with_login_commit(
    hass: HomeAssistant,
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test external revocation cannot let stale credentials restore a session."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
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
        provider.async_client(), "async_revoke_token", side_effect=revoke_token
    ):
        remove = asyncio.create_task(manager.async_remove_credentials(credentials))
        await revoke_started.wait()
        try:
            with suppress(auth.InvalidAuthError):
                await provider.async_complete_login(
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
    assert credentials.id not in provider.data.sessions


async def test_deleting_the_config_clears_sessions(
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test removing the configuration signs every OIDC user out."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    await provider.async_set_config(None)

    assert not provider.is_configured
    assert provider.data.sessions == {}
    assert manager.async_get_refresh_token(refresh_token.id) is None


@pytest.mark.usefixtures("mock_idp")
async def test_reconfiguring_clears_existing_sessions(
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test provider changes cannot carry sessions across trust boundaries."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    await provider.async_set_config(
        OidcConfig(issuer="https://other-idp.example.com", client_id="new-client")
    )

    assert provider.data.sessions == {}
    assert manager.async_get_refresh_token(refresh_token.id) is None


@pytest.mark.parametrize(
    "change",
    [
        {"name": "Contoso ID"},
        {"display_name_claim": "given_name"},
        {"allow_auto_create": False},
        {"revalidate_interval": 3600},
        {"admin_group": "other-admins"},
    ],
    ids=["name", "display-name-claim", "auto-create", "interval", "admin-group"],
)
async def test_editing_settings_keeps_existing_sessions(
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
    change: dict[str, Any],
) -> None:
    """Test an edit that keeps the same issuer does not sign everybody out.

    Renaming the provider used to log out every user, revoke their tokens and
    strip administrator rights the provider had granted.
    """
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await manager.async_update_user(user, group_ids=[GROUP_ID_ADMIN])
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT, "groups": ["home_assistant_admin"]},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )
    refresh_token = await manager.async_create_refresh_token(
        user, "https://ha.example.com/", credential=credentials
    )

    await provider.async_set_config(replace(provider.oidc_config, **change))

    assert credentials.id in provider.data.sessions
    assert manager.async_get_refresh_token(refresh_token.id) is not None
    assert user.is_admin


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "https://other-idp.example.com"},
        {"client_id": "other-client"},
        {"client_secret": "rotated"},
        {"scopes": ["openid", "profile"]},
    ],
    ids=["issuer", "client-id", "client-secret", "scopes"],
)
@pytest.mark.usefixtures("mock_idp")
async def test_changing_who_issues_tokens_clears_sessions(
    provider: oidc_auth.OidcAuthProvider,
    change: dict[str, Any],
) -> None:
    """Test sessions do not survive a change to who issued them."""
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await provider.async_record_session(
        credential_id=credentials.id,
        claims={"sub": SUBJECT},
        tokens=oidc_auth.TokenResponse(access_token="at", refresh_token="rt"),
    )

    await provider.async_set_config(replace(provider.oidc_config, **change))

    assert provider.data.sessions == {}


async def test_state_is_signed(provider: oidc_auth.OidcAuthProvider) -> None:
    """Test a tampered state parameter is not accepted."""
    state = provider.async_encode_state("the-flow-id")

    assert provider.async_decode_state(state) == "the-flow-id"
    assert provider.async_decode_state(f"{state}x") is None
    assert provider.async_decode_state("not-a-token") is None


async def test_state_expires(provider: oidc_auth.OidcAuthProvider) -> None:
    """Test an old state parameter cannot be replayed."""
    with patch("time.time", return_value=time.time() - 3600):
        state = provider.async_encode_state("the-flow-id")

    assert provider.async_decode_state(state) is None


async def test_state_requires_expiration(provider: oidc_auth.OidcAuthProvider) -> None:
    """Test a state without an explicit expiration is refused."""
    state = jwt.encode(
        {"flow_id": "the-flow-id"}, provider._state_secret, algorithm="HS256"
    )

    assert provider.async_decode_state(state) is None


@pytest.mark.parametrize(
    "raw_data",
    [
        [],
        {"config": []},
        {"config": {"issuer": 1, "client_id": CLIENT_ID}},
        {
            "config": {"issuer": 1, "client_id": CLIENT_ID},
            "sessions": {
                "credential-id": {
                    "credential_id": "credential-id",
                    "subject": SUBJECT,
                    "revalidate_after": time.time() + 3600,
                    "refresh_after": time.time() + 1800,
                }
            },
        },
        {"sessions": ["not-a-mapping"]},
        {"sessions": {"credential-id": []}},
        {
            "sessions": {
                "credential-id": {
                    "credential_id": "credential-id",
                    "subject": SUBJECT,
                    "revalidate_after": "tomorrow",
                }
            }
        },
    ],
    ids=[
        "root",
        "config-container",
        "config-field",
        "config-field-with-session",
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

    assert store.config is None
    assert store.sessions == {}


async def test_store_records_that_a_configuration_was_discarded(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
) -> None:
    """Test losing settings to corrupt storage is remembered, not just logged."""
    hass_storage[STORAGE_KEY] = {
        "version": STORAGE_VERSION,
        "minor_version": 1,
        "key": STORAGE_KEY,
        "data": {"config": {"issuer": 1, "client_id": CLIENT_ID}},
    }
    store = OidcStore(hass)

    await store.async_load()

    assert store.config is None
    assert store.config_discarded

    store.async_set_config(OidcConfig(issuer=ISSUER, client_id=CLIENT_ID))

    assert not store.config_discarded


async def test_store_survives_a_restart(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    manager: auth.AuthManager,
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test the configuration and sessions are restored from disk."""
    user = await manager.async_create_user("Alice")
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await manager.async_link_user(user, credentials)
    await provider.async_record_session(
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

    assert restored.oidc_config.issuer == ISSUER
    assert restored.data.sessions[credentials.id].refresh_token == "rt"


async def test_manager_initializes_oidc_and_prunes_orphan_session(
    hass: HomeAssistant,
    hass_storage: dict[str, Any],
    provider: oidc_auth.OidcAuthProvider,
) -> None:
    """Test restart loads OIDC config and drops sessions without credentials."""
    credentials = provider.async_create_credentials({"subject": SUBJECT})
    await provider.async_record_session(
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

    assert restored.is_configured
    assert restored.data is not None
    assert restored.data.sessions == {}
