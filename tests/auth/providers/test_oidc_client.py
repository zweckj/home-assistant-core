"""Test the OIDC protocol clients."""

import json
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from jwt.algorithms import RSAAlgorithm
import pytest

from homeassistant.auth.providers.oidc.client import (
    OAuth2ProfileClient,
    OidcClient,
    OidcDiscoveryError,
    OidcError,
    OidcIdTokenError,
    OidcInvalidGrantError,
    OidcTokenError,
    OidcTransientError,
    async_discover,
)
from homeassistant.core import HomeAssistant

from tests.test_util.aiohttp import AiohttpClientMocker

ISSUER = "https://idp.example.com"
ALIAS_ISSUER = "idp.example.com"
TEMPLATE_ISSUER = "https://login.example.com/{tenantid}/v2.0"
TENANT_ISSUER = "https://login.example.com/contoso/v2.0"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
TEMPLATE_DISCOVERY_URL = (
    "https://login.example.com/common/v2.0/.well-known/openid-configuration"
)
JWKS_URL = f"{ISSUER}/jwks"
TEMPLATE_JWKS_URL = "https://login.example.com/common/jwks"
TOKEN_URL = f"{ISSUER}/token"
AUTHORIZE_URL = f"{ISSUER}/authorize"
PROFILE_URL = "https://api.example.com/user"
CLIENT_ID = "home-assistant"
KEY_ID = "test-key"
SUBJECT = "user-1234"
CODE_VERIFIER = "v" * 43


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
    """Return a discovery document."""
    return {
        "issuer": ISSUER,
        "authorization_endpoint": AUTHORIZE_URL,
        "token_endpoint": TOKEN_URL,
        "jwks_uri": JWKS_URL,
        "id_token_signing_alg_values_supported": ["RS256"],
    } | overrides


def make_id_token(
    signing_key: rsa.RSAPrivateKey, *, issuer: str = ISSUER, **overrides: Any
) -> str:
    """Return a signed ID token."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": SUBJECT,
        "aud": CLIENT_ID,
        "exp": now + 3600,
        "iat": now,
    } | overrides
    return jwt.encode(
        {key: value for key, value in claims.items() if value is not None},
        signing_key,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )


def mock_discovery(
    aioclient_mock: AiohttpClientMocker,
    jwks: dict[str, Any],
    **overrides: Any,
) -> None:
    """Mock default discovery and JWKS."""
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document(**overrides))
    aioclient_mock.get(JWKS_URL, json=jwks)


def mock_template_discovery(
    aioclient_mock: AiohttpClientMocker,
    jwks: dict[str, Any],
    **overrides: Any,
) -> None:
    """Mock templated discovery and JWKS."""
    aioclient_mock.get(
        TEMPLATE_DISCOVERY_URL,
        json=discovery_document(
            issuer=TEMPLATE_ISSUER,
            jwks_uri=TEMPLATE_JWKS_URL,
            **overrides,
        ),
    )
    aioclient_mock.get(TEMPLATE_JWKS_URL, json=jwks)


async def test_templated_issuer_happy_path(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    jwks: dict[str, Any],
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test a token from a tenant-specific issuer is accepted."""
    mock_template_discovery(aioclient_mock, jwks)
    client = OidcClient(
        hass,
        issuer=TEMPLATE_ISSUER,
        discovery_url=TEMPLATE_DISCOVERY_URL,
        issuer_claim="tid",
        client_id=CLIENT_ID,
    )

    claims = await client.async_verify_id_token(
        make_id_token(signing_key, issuer=TENANT_ISSUER, tid="contoso")
    )

    assert claims["sub"] == SUBJECT
    assert client.canonical_issuer(claims) == TENANT_ISSUER


@pytest.mark.parametrize(
    ("issuer", "tid", "match"),
    [
        pytest.param(TENANT_ISSUER, None, "unsafe", id="missing-tid"),
        pytest.param(
            "https://login.example.com/fabrikam/v2.0",
            "contoso",
            "template",
            id="wrong-tid",
        ),
        pytest.param(TENANT_ISSUER, "../contoso", "unsafe", id="unsafe-tid"),
    ],
)
async def test_templated_issuer_rejects_bad_tenant_claims(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    jwks: dict[str, Any],
    signing_key: rsa.RSAPrivateKey,
    issuer: str,
    tid: str | None,
    match: str,
) -> None:
    """Test the tenant claim has to safely fill the issuer template."""
    mock_template_discovery(aioclient_mock, jwks)
    client = OidcClient(
        hass,
        issuer=TEMPLATE_ISSUER,
        discovery_url=TEMPLATE_DISCOVERY_URL,
        issuer_claim="tid",
        client_id=CLIENT_ID,
    )

    with pytest.raises(OidcIdTokenError, match=match):
        await client.async_verify_id_token(
            make_id_token(signing_key, issuer=issuer, tid=tid)
        )


async def test_templated_issuer_requires_exact_discovery_issuer(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test template discovery must publish the template literally."""
    aioclient_mock.get(
        TEMPLATE_DISCOVERY_URL,
        json=discovery_document(issuer=TENANT_ISSUER, jwks_uri=TEMPLATE_JWKS_URL),
    )
    client = OidcClient(
        hass,
        issuer=TEMPLATE_ISSUER,
        discovery_url=TEMPLATE_DISCOVERY_URL,
        issuer_claim="tid",
        client_id=CLIENT_ID,
    )

    with pytest.raises(OidcDiscoveryError, match="does not match"):
        await client.async_metadata()


@pytest.mark.parametrize(
    "kwargs",
    [
        pytest.param({"issuer": TEMPLATE_ISSUER, "issuer_claim": None}, id="missing"),
        pytest.param({"issuer": ISSUER, "issuer_claim": "tid"}, id="unexpected"),
        pytest.param(
            {"issuer": "https://login.example.com/{tenant}/{other}"},
            id="two-placeholders",
        ),
    ],
)
def test_templated_issuer_constructor_errors(
    hass: HomeAssistant, kwargs: dict[str, str | None]
) -> None:
    """Test invalid issuer template configuration is rejected."""
    with pytest.raises(ValueError):
        OidcClient(hass, client_id=CLIENT_ID, **kwargs)


async def test_alias_issuer_is_accepted_for_tokens_only(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    jwks: dict[str, Any],
    signing_key: rsa.RSAPrivateKey,
) -> None:
    """Test aliases verify tokens but discovery remains exact."""
    mock_discovery(aioclient_mock, jwks)
    client = OidcClient(
        hass, issuer=ISSUER, issuer_aliases=[ALIAS_ISSUER], client_id=CLIENT_ID
    )

    claims = await client.async_verify_id_token(
        make_id_token(signing_key, issuer=ALIAS_ISSUER)
    )

    assert client.canonical_issuer(claims) == ISSUER
    assert not client.accepts_issuer(ALIAS_ISSUER)


async def test_alias_discovery_still_requires_configured_issuer(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
) -> None:
    """Test an alias is not accepted in the discovery document."""
    aioclient_mock.get(DISCOVERY_URL, json=discovery_document(issuer=ALIAS_ISSUER))
    client = OidcClient(
        hass, issuer=ISSUER, issuer_aliases=[ALIAS_ISSUER], client_id=CLIENT_ID
    )

    with pytest.raises(OidcDiscoveryError, match="does not match"):
        await client.async_metadata()


def test_alias_rejects_placeholders(hass: HomeAssistant) -> None:
    """Test aliases cannot be issuer templates."""
    with pytest.raises(ValueError, match="aliases"):
        OidcClient(
            hass,
            issuer=ISSUER,
            issuer_aliases=["https://login.example.com/{tenantid}/v2.0"],
            client_id=CLIENT_ID,
        )


def test_accepts_issuer(hass: HomeAssistant) -> None:
    """Test stored credential issuer matching."""
    exact = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)
    templated = OidcClient(
        hass, issuer=TEMPLATE_ISSUER, issuer_claim="tid", client_id=CLIENT_ID
    )

    assert exact.accepts_issuer(ISSUER)
    assert not exact.accepts_issuer(ALIAS_ISSUER)
    assert templated.accepts_issuer(TENANT_ISSUER)
    assert not templated.accepts_issuer("https://login.example.com/../bad/v2.0")


async def test_async_discover_does_not_compare_issuer(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test standalone discovery validates metadata without issuer binding."""
    aioclient_mock.get(
        DISCOVERY_URL, json=discovery_document(issuer="https://other.example.com")
    )

    metadata = await async_discover(hass, DISCOVERY_URL)

    assert metadata.issuer == "https://other.example.com"


def test_oauth2_profile_authorize_url(hass: HomeAssistant) -> None:
    """Test the profile client builds a PKCE authorization URL."""
    client = OAuth2ProfileClient(
        hass,
        authorize_url=f"{AUTHORIZE_URL}?prompt=login",
        token_url=TOKEN_URL,
        profile_url=PROFILE_URL,
        client_id=CLIENT_ID,
        client_secret="secret",
        subject_field="id",
        scopes=("read:user", "user:email"),
    )

    url = client.async_authorize_url(
        redirect_uri="https://ha.example.com/auth/callback",
        state="state",
        code_verifier=CODE_VERIFIER,
    )
    query = parse_qs(urlparse(url).query)

    assert query["prompt"] == ["login"]
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["scope"] == ["read:user user:email"]
    assert query["code_challenge_method"] == ["S256"]


@pytest.mark.parametrize(
    ("client_secret", "token_auth_method", "expected_body", "has_auth"),
    [
        pytest.param("secret", "client_secret_basic", {}, True, id="basic"),
        pytest.param(
            "secret",
            "client_secret_post",
            {"client_id": CLIENT_ID, "client_secret": "secret"},
            False,
            id="post",
        ),
        pytest.param(
            None, "client_secret_basic", {"client_id": CLIENT_ID}, False, id="public"
        ),
    ],
)
async def test_oauth2_profile_exchange_auth_methods(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    client_secret: str | None,
    token_auth_method: str,
    expected_body: dict[str, str],
    has_auth: bool,
) -> None:
    """Test supported token endpoint client authentication methods."""
    aioclient_mock.post(TOKEN_URL, json={"access_token": "at", "token_type": "Bearer"})
    client = OAuth2ProfileClient(
        hass,
        authorize_url=AUTHORIZE_URL,
        token_url=TOKEN_URL,
        profile_url=PROFILE_URL,
        client_id=CLIENT_ID,
        client_secret=client_secret,
        subject_field="id",
        token_auth_method=token_auth_method,  # type: ignore[arg-type]
    )

    tokens = await client.async_exchange_code(
        code="code",
        redirect_uri="https://ha.example.com/cb",
        code_verifier=CODE_VERIFIER,
    )

    assert tokens.access_token == "at"
    assert expected_body.items() <= aioclient_mock.mock_calls[-1][2].items()
    assert ("Authorization" in aioclient_mock.mock_calls[-1][3]) is has_auth
    assert aioclient_mock.mock_calls[-1][3]["Accept"] == "application/json"


@pytest.mark.parametrize(
    ("status", "body", "error"),
    [
        pytest.param(
            200, {"error": "bad_verification_code"}, OidcTokenError, id="ok-error"
        ),
        pytest.param(
            400, {"error": "invalid_grant"}, OidcInvalidGrantError, id="invalid-grant"
        ),
        pytest.param(
            200, {"access_token": "at", "token_type": "mac"}, OidcTokenError, id="mac"
        ),
        pytest.param(503, {}, OidcTransientError, id="transient"),
    ],
)
async def test_oauth2_profile_exchange_errors(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    status: int,
    body: dict[str, str],
    error: type[OidcError],
) -> None:
    """Test token endpoint failures are mapped to OIDC errors."""
    aioclient_mock.post(TOKEN_URL, status=status, json=body)
    client = OAuth2ProfileClient(
        hass,
        authorize_url=AUTHORIZE_URL,
        token_url=TOKEN_URL,
        profile_url=PROFILE_URL,
        client_id=CLIENT_ID,
        client_secret="secret",
        subject_field="id",
    )

    with pytest.raises(error):
        await client.async_exchange_code(
            code="code",
            redirect_uri="https://ha.example.com/cb",
            code_verifier=CODE_VERIFIER,
        )


async def test_oauth2_profile_exchange_refuses_redirects(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test token endpoint redirects are refused."""
    aioclient_mock.post(
        TOKEN_URL, status=307, headers={"Location": "https://evil.example.com"}
    )
    client = OAuth2ProfileClient(
        hass,
        authorize_url=AUTHORIZE_URL,
        token_url=TOKEN_URL,
        profile_url=PROFILE_URL,
        client_id=CLIENT_ID,
        client_secret="secret",
        subject_field="id",
    )

    with pytest.raises(OidcTokenError, match="307"):
        await client.async_exchange_code(
            code="code",
            redirect_uri="https://ha.example.com/cb",
            code_verifier=CODE_VERIFIER,
        )


@pytest.mark.parametrize(
    ("profile", "subject", "account_name"),
    [
        pytest.param({"id": 123, "login": "octo"}, "123", "octo", id="int-id"),
        pytest.param({"id": "abc", "login": "octo"}, "abc", "octo", id="str-id"),
        pytest.param({"id": "abc", "login": 123}, "abc", None, id="bad-name"),
    ],
)
async def test_oauth2_profile_fetch_profile(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    profile: dict[str, Any],
    subject: str,
    account_name: str | None,
) -> None:
    """Test profile subjects and optional account names are extracted."""
    aioclient_mock.get(PROFILE_URL, json=profile)
    client = OAuth2ProfileClient(
        hass,
        authorize_url=AUTHORIZE_URL,
        token_url=TOKEN_URL,
        profile_url=PROFILE_URL,
        client_id=CLIENT_ID,
        client_secret="secret",
        subject_field="id",
        account_name_field="login",
        headers={"X-GitHub-Api-Version": "2022-11-28"},
    )

    result = await client.async_fetch_profile("token")

    assert result == (subject, account_name)
    assert aioclient_mock.mock_calls[-1][3]["Authorization"] == "Bearer " + "token"
    assert aioclient_mock.mock_calls[-1][3]["Accept"] == "application/json"


@pytest.mark.parametrize(
    "profile",
    [
        pytest.param({}, id="missing"),
        pytest.param({"id": True}, id="bool"),
        pytest.param({"id": ""}, id="empty"),
    ],
)
async def test_oauth2_profile_fetch_rejects_bad_subjects(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, profile: dict[str, Any]
) -> None:
    """Test unusable profile subjects are rejected."""
    aioclient_mock.get(PROFILE_URL, json=profile)
    client = OAuth2ProfileClient(
        hass,
        authorize_url=AUTHORIZE_URL,
        token_url=TOKEN_URL,
        profile_url=PROFILE_URL,
        client_id=CLIENT_ID,
        client_secret="secret",
        subject_field="id",
    )

    with pytest.raises(OidcError, match="subject"):
        await client.async_fetch_profile("token")


async def test_oauth2_profile_fetch_rejects_non_object_json(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test profile data must be a JSON object."""
    aioclient_mock.get(PROFILE_URL, json=[])
    client = OAuth2ProfileClient(
        hass,
        authorize_url=AUTHORIZE_URL,
        token_url=TOKEN_URL,
        profile_url=PROFILE_URL,
        client_id=CLIENT_ID,
        client_secret="secret",
        subject_field="id",
    )

    with pytest.raises(OidcError, match="JSON object"):
        await client.async_fetch_profile("token")


@pytest.mark.parametrize("url_field", ["authorize_url", "token_url", "profile_url"])
def test_oauth2_profile_rejects_insecure_urls(
    hass: HomeAssistant, url_field: str
) -> None:
    """Test OAuth2 profile endpoint URLs have to be HTTPS."""
    kwargs = {
        "authorize_url": AUTHORIZE_URL,
        "token_url": TOKEN_URL,
        "profile_url": PROFILE_URL,
        url_field: "http://api.example.com/plain",
    }

    with pytest.raises(OidcDiscoveryError, match="https"):
        OAuth2ProfileClient(
            hass,
            **kwargs,
            client_id=CLIENT_ID,
            client_secret="secret",
            subject_field="id",
        )


def test_oauth2_profile_allows_insecure_transport(hass: HomeAssistant) -> None:
    """Test an administrator can allow plain HTTP endpoints."""
    client = OAuth2ProfileClient(
        hass,
        authorize_url="http://idp.example.com/authorize",
        token_url="http://idp.example.com/token",
        profile_url="http://api.example.com/user",
        client_id=CLIENT_ID,
        client_secret="secret",
        subject_field="id",
        allow_insecure_transport=True,
    )

    assert client.issuer == "http://api.example.com"
    assert client.accepts_issuer("http://api.example.com")


@pytest.mark.parametrize(
    "header",
    [
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "Host",
        "Content-Length",
        "Content-Type",
        "Transfer-Encoding",
        "Connection",
    ],
)
def test_oauth2_profile_rejects_reserved_headers(
    hass: HomeAssistant, header: str
) -> None:
    """Test callers cannot override security-sensitive headers."""
    with pytest.raises(ValueError, match="Reserved"):
        OAuth2ProfileClient(
            hass,
            authorize_url=AUTHORIZE_URL,
            token_url=TOKEN_URL,
            profile_url=PROFILE_URL,
            client_id=CLIENT_ID,
            client_secret="secret",
            subject_field="id",
            headers={header: "value"},
        )


async def test_oidc_metadata_refuses_redirects(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test OIDC discovery redirects are refused."""
    aioclient_mock.get(
        DISCOVERY_URL, status=302, headers={"Location": "https://evil.example.com"}
    )
    client = OidcClient(hass, issuer=ISSUER, client_id=CLIENT_ID)

    with pytest.raises(OidcDiscoveryError, match="redirects"):
        await client.async_metadata()


async def test_oauth2_profile_fetch_refuses_redirects(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Test OAuth2 profile endpoint redirects are refused."""
    aioclient_mock.get(
        PROFILE_URL, status=302, headers={"Location": "https://evil.example.com"}
    )
    client = OAuth2ProfileClient(
        hass,
        authorize_url=AUTHORIZE_URL,
        token_url=TOKEN_URL,
        profile_url=PROFILE_URL,
        client_id=CLIENT_ID,
        client_secret="secret",
        subject_field="id",
    )

    with pytest.raises(OidcError, match="redirects"):
        await client.async_fetch_profile("token")


def test_oidc_client_requires_an_https_issuer(hass: HomeAssistant) -> None:
    """Test the client refuses an issuer reached over plain HTTP."""
    with pytest.raises(OidcDiscoveryError, match="must be an https URL"):
        OidcClient(hass, issuer="http://idp.example.com", client_id=CLIENT_ID)
