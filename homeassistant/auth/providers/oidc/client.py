"""OpenID Connect relying party client.

Cryptography and claim validation come from PyJWT; all I/O goes through aiohttp,
since PyJWT's own key client fetches with blocking urllib.
"""

import asyncio
import base64
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import logging
import re
import time
from typing import Any

from aiohttp import ClientError
import jwt
import probatio
from yarl import URL

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import (
    HomeAssistantError,
    OAuth2TokenRequestConnectionError,
    OAuth2TokenRequestError,
    OAuth2TokenRequestReauthError,
    OAuth2TokenRequestTransientError,
)
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.oauth2 import (
    ClientAuthMethod,
    async_token_request,
    build_authorize_url,
    client_auth,
    compute_code_challenge,
)

from .const import (
    ALLOWED_ID_TOKEN_ALGORITHMS,
    CLOCK_SKEW_LEEWAY,
    DEFAULT_ID_TOKEN_ALGORITHM,
    DISCOVERY_CACHE_TTL,
    DISCOVERY_PATH,
    HTTP_TIMEOUT,
    ISSUER_PLACEHOLDER_PATTERN,
    ISSUER_PLACEHOLDER_VALUE_PATTERN,
    JWKS_CACHE_TTL,
    JWKS_REFETCH_COOLDOWN,
    PKCE_CHALLENGE_METHOD,
    RESERVED_PROFILE_HEADERS,
)

_LOGGER = logging.getLogger(__name__)

# Names the token request errors; OIDC runs under the auth component.
AUTH_DOMAIN = "auth"

# The at_hash digest follows the signing algorithm. OpenID Connect pins none for
# EdDSA, so it is left out and its at_hash goes unchecked.
_AT_HASH_ALGORITHMS: dict[str, str] = {
    "RS256": "sha256",
    "PS256": "sha256",
    "ES256": "sha256",
    "RS384": "sha384",
    "PS384": "sha384",
    "ES384": "sha384",
    "RS512": "sha512",
    "PS512": "sha512",
    "ES512": "sha512",
}

_ISSUER_TEMPLATE_RE = re.compile(ISSUER_PLACEHOLDER_PATTERN)
_ISSUER_PLACEHOLDER_VALUE_RE = re.compile(ISSUER_PLACEHOLDER_VALUE_PATTERN)


def _compute_at_hash(access_token: str, algorithm: str) -> str | None:
    """Return the at_hash an access token should have for a signing algorithm."""
    if (hash_name := _AT_HASH_ALGORITHMS.get(algorithm)) is None:
        return None
    digest = hashlib.new(hash_name, access_token.encode()).digest()
    # OpenID Connect hashes the token and keeps the left-most half.
    half = digest[: len(digest) // 2]
    return base64.urlsafe_b64encode(half).decode("ascii").rstrip("=")


type JWKDict = dict[str, Any]


def _may_verify_signatures(jwk: JWKDict) -> bool:
    """Return if a JWK may verify signatures; use and key_ops are optional."""
    if (use := jwk.get("use")) is not None and use != "sig":
        return False
    if (key_ops := jwk.get("key_ops")) is not None:
        return "verify" in key_ops
    return True


class OidcError(HomeAssistantError):
    """Base class for OpenID Connect errors."""


class OidcDiscoveryError(OidcError):
    """Raised when the provider metadata cannot be retrieved or is unusable."""


class OidcTokenError(OidcError):
    """Raised when the token endpoint rejects a request."""


class OidcInvalidGrantError(OidcTokenError):
    """Raised when the identity provider revoked a grant for good."""


class OidcTransientError(OidcError):
    """Raised when the identity provider is temporarily unreachable."""


class OidcIdTokenError(OidcError):
    """Raised when an ID token fails validation."""


class OidcInsecureTransportError(OidcError):
    """Raised when a login would run over a connection that is not private."""


@dataclass(frozen=True, kw_only=True, slots=True)
class ProviderMetadata:
    """The parts of the discovery document that we use."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    revocation_endpoint: str | None = None
    id_token_signing_alg_values_supported: tuple[str, ...] = ()
    token_endpoint_auth_methods_supported: tuple[str, ...] = ()
    scopes_supported: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True, slots=True)
class TokenResponse:
    """A successful response from the token endpoint."""

    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None


def _https_url(allow_http: bool) -> Callable[[str], str]:
    """Return a validator for an unambiguous HTTPS endpoint URL."""
    schemes = {"https", "http"} if allow_http else {"https"}

    def validate(value: str) -> str:
        try:
            url = URL(value)
        except ValueError as err:
            raise probatio.Invalid("must be an https URL") from err
        if (
            url.scheme not in schemes
            or not url.host
            or url.user is not None
            or url.fragment
        ):
            raise probatio.Invalid(
                "must be an https URL without credentials or a fragment"
            )
        return value

    return validate


def _require_https(url: str, field: str, *, allow_http: bool = False) -> str:
    """Return an unambiguous HTTPS endpoint URL from the configuration."""
    try:
        return _https_url(allow_http)(url)
    except probatio.Invalid as err:
        raise OidcDiscoveryError(f"{field} {err.msg}") from err


_STRINGS = probatio.All([str], probatio.Coerce(tuple))


def _discovery_schema(allow_http: bool) -> probatio.Schema:
    """Return the schema for the parts of a discovery document that we use."""
    endpoint = probatio.All(str, _https_url(allow_http))
    return probatio.Schema(
        {
            probatio.Required("issuer"): str,
            probatio.Required("authorization_endpoint"): endpoint,
            probatio.Required("token_endpoint"): endpoint,
            probatio.Required("jwks_uri"): endpoint,
            # Both carry tokens, so they are held to the same rule.
            probatio.Optional("userinfo_endpoint"): probatio.Any(endpoint, None),
            probatio.Optional("revocation_endpoint"): probatio.Any(endpoint, None),
            probatio.Optional("id_token_signing_alg_values_supported"): _STRINGS,
            probatio.Optional("token_endpoint_auth_methods_supported"): _STRINGS,
            probatio.Optional("scopes_supported"): _STRINGS,
            probatio.Optional("code_challenge_methods_supported"): _STRINGS,
        },
        extra=probatio.REMOVE_EXTRA,
    )


_TOKEN_RESPONSE_SCHEMA = probatio.Schema(
    {
        probatio.Required("access_token"): str,
        # Sent to userinfo as a bearer, so any other token type is refused.
        probatio.Required("token_type"): probatio.All(str, probatio.Lower, "bearer"),
        probatio.Optional("id_token"): probatio.Any(str, None),
        probatio.Optional("refresh_token"): probatio.Any(str, None),
    },
    extra=probatio.REMOVE_EXTRA,
)

_JWKS_SCHEMA = probatio.Schema(
    {probatio.Required("keys"): list}, extra=probatio.ALLOW_EXTRA
)

# Checked per key, so one malformed key does not take the whole set down.
_JWK_SCHEMA = probatio.Schema(
    {probatio.Optional("use"): str, probatio.Optional("key_ops"): [str]},
    extra=probatio.ALLOW_EXTRA,
)

_USERINFO_SCHEMA = probatio.Schema(
    {probatio.Required("sub"): str}, extra=probatio.ALLOW_EXTRA
)


def _origin(url: str) -> str:
    """Return the origin of a URL."""
    parsed = URL(url)
    origin = f"{parsed.scheme}://{parsed.host}"
    default_port = 443 if parsed.scheme == "https" else 80
    if parsed.port is not None and parsed.port != default_port:
        origin = f"{origin}:{parsed.port}"
    return origin


def _find_issuer_placeholder(issuer: str) -> str | None:
    """Return the issuer template placeholder, if the issuer has one."""
    placeholders: list[str] = []
    for segment in URL(issuer).path.split("/"):
        if "{" in segment or "}" in segment:
            if (match := _ISSUER_TEMPLATE_RE.fullmatch(segment)) is None:
                raise ValueError(
                    "issuer templates must use exactly one placeholder path segment"
                )
            placeholders.append(match.group(1))
    if len(placeholders) > 1:
        raise ValueError("issuer templates may only contain one placeholder")
    return placeholders[0] if placeholders else None


def _filled_template_issuer(
    issuer: str, issuer_claim: str, claims: Mapping[str, Any]
) -> str:
    """Return the issuer template filled from claims."""
    value = claims.get(issuer_claim)
    if not isinstance(value, str) or not _ISSUER_PLACEHOLDER_VALUE_RE.fullmatch(value):
        raise OidcIdTokenError("ID token issuer template claim is missing or unsafe")
    return issuer.replace(f"{{{_find_issuer_placeholder(issuer)}}}", value, 1)


def _template_issuer_pattern(issuer: str) -> re.Pattern[str]:
    """Return a regex matching a filled issuer template."""
    placeholder = _find_issuer_placeholder(issuer)
    assert placeholder is not None
    return re.compile(
        "^"
        + re.escape(issuer).replace(
            re.escape(f"{{{placeholder}}}"),
            f"({ISSUER_PLACEHOLDER_VALUE_PATTERN})",
            1,
        )
        + "$"
    )


def _parse_provider_metadata(
    document: Any,
    *,
    expected_issuer: str | None,
    allow_http: bool,
) -> ProviderMetadata:
    """Validate and convert a discovery document."""
    try:
        parsed = _discovery_schema(allow_http)(document)
    except probatio.Invalid as err:
        raise OidcDiscoveryError(f"Discovery document is invalid: {err}") from err

    # Compared exactly, trailing slash included, to keep issuer binding.
    if expected_issuer is not None and parsed["issuer"] != expected_issuer:
        raise OidcDiscoveryError(
            f"Discovery document issuer {parsed['issuer']!r} does not"
            f" match the configured issuer {expected_issuer!r}"
        )

    challenge_methods = parsed.pop("code_challenge_methods_supported", ())
    if challenge_methods and PKCE_CHALLENGE_METHOD not in challenge_methods:
        raise OidcDiscoveryError(
            f"The provider does not offer the {PKCE_CHALLENGE_METHOD} PKCE"
            f" challenge method, it only offers {', '.join(challenge_methods)}"
        )

    return ProviderMetadata(
        **{key: value for key, value in parsed.items() if value is not None}
    )


async def _async_fetch_json(hass: HomeAssistant, url: str, what: str) -> Any:
    """Fetch and decode a JSON document."""
    session = async_get_clientsession(hass)
    try:
        async with asyncio.timeout(HTTP_TIMEOUT):
            # Following a redirect would defeat the HTTPS check on the URL.
            response = await session.get(url, allow_redirects=False)
            if 300 <= response.status < 400:
                raise OidcDiscoveryError(f"The {what} URL redirects elsewhere")
            if response.status >= 400:
                raise OidcDiscoveryError(
                    f"Got status {response.status} fetching the {what}"
                )
            return await response.json(content_type=None)
    except TimeoutError as err:
        raise OidcTransientError(f"Timeout fetching the {what}") from err
    except ClientError as err:
        raise OidcTransientError(f"Error fetching the {what}: {err}") from err
    except ValueError as err:
        raise OidcDiscoveryError(f"The {what} is not valid JSON") from err


async def async_discover(
    hass: HomeAssistant,
    discovery_url: str,
    *,
    allow_insecure_transport: bool = False,
) -> ProviderMetadata:
    """Fetch and validate provider metadata without enforcing an issuer."""
    discovery_url = _require_https(
        discovery_url, "discovery_url", allow_http=allow_insecure_transport
    )
    document = await _async_fetch_json(hass, discovery_url, "discovery document")
    return _parse_provider_metadata(
        document, expected_issuer=None, allow_http=allow_insecure_transport
    )


async def _async_token_request(
    hass: HomeAssistant,
    token_url: str,
    data: Mapping[str, Any],
    *,
    headers: Mapping[str, str],
) -> TokenResponse:
    """Post to a token endpoint and parse the token response."""
    try:
        async with asyncio.timeout(HTTP_TIMEOUT):
            # A 307 or 308 would replay the client secret to the new target.
            body = await async_token_request(
                hass,
                token_url,
                data,
                domain=AUTH_DOMAIN,
                headers={"Accept": "application/json", **headers},
                allow_redirects=False,
            )
    except OAuth2TokenRequestReauthError as err:
        raise OidcInvalidGrantError("The identity provider rejected the grant") from err
    except (
        TimeoutError,
        OAuth2TokenRequestConnectionError,
        OAuth2TokenRequestTransientError,
    ) as err:
        raise OidcTransientError("Could not reach the token endpoint") from err
    except OAuth2TokenRequestError as err:
        raise OidcTokenError(
            f"Token endpoint returned an unusable response ({err.status})"
        ) from err
    except ValueError as err:
        raise OidcTokenError("Token endpoint returned invalid JSON") from err

    # Also refuses a 200 carrying an error, which is how GitHub reports them.
    try:
        body = _TOKEN_RESPONSE_SCHEMA(body)
    except probatio.Invalid as err:
        raise OidcTokenError(f"Token endpoint response is invalid: {err}") from err

    return TokenResponse(
        access_token=body["access_token"],
        id_token=body.get("id_token"),
        refresh_token=body.get("refresh_token"),
    )


class OidcClient:
    """Talk to an OpenID Connect provider on behalf of Home Assistant."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        issuer: str,
        client_id: str,
        client_secret: str | None = None,
        discovery_url: str | None = None,
        issuer_aliases: Iterable[str] = (),
        issuer_claim: str | None = None,
        allow_insecure_transport: bool = False,
    ) -> None:
        """Initialize the client."""
        _require_https(issuer, "issuer", allow_http=allow_insecure_transport)
        placeholder = _find_issuer_placeholder(issuer)
        if (placeholder is None) != (issuer_claim is None):
            raise ValueError(
                "issuer_claim is required exactly when issuer is a template"
            )
        aliases = tuple(issuer_aliases)
        for alias in aliases:
            if _find_issuer_placeholder(alias) is not None:
                raise ValueError("issuer aliases may not contain placeholders")

        self.hass = hass
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.discovery_url = _require_https(
            discovery_url or f"{issuer.rstrip('/')}{DISCOVERY_PATH}",
            "discovery_url",
            allow_http=allow_insecure_transport,
        )
        self.issuer_aliases = aliases
        self.issuer_claim = issuer_claim
        self.allow_insecure_transport = allow_insecure_transport
        self._issuer_pattern = (
            _template_issuer_pattern(issuer) if placeholder is not None else None
        )

        self._metadata: ProviderMetadata | None = None
        self._metadata_fetched_at = 0.0
        self._metadata_lock = asyncio.Lock()

        self._jwks: list[tuple[JWKDict, jwt.PyJWK]] | None = None
        self._jwks_fetched_at = 0.0
        self._jwks_lock = asyncio.Lock()

    async def async_metadata(self) -> ProviderMetadata:
        """Return the provider metadata, fetching it when the cache is cold."""
        async with self._metadata_lock:
            if (
                self._metadata is not None
                and time.time() - self._metadata_fetched_at < DISCOVERY_CACHE_TTL
            ):
                return self._metadata

            document = await _async_fetch_json(
                self.hass, self.discovery_url, "discovery document"
            )
            metadata = _parse_provider_metadata(
                document,
                expected_issuer=self.issuer,
                allow_http=self.allow_insecure_transport,
            )
            self._metadata = metadata
            self._metadata_fetched_at = time.time()
            return metadata

    def async_authorize_url(
        self,
        metadata: ProviderMetadata,
        *,
        redirect_uri: str,
        state: str,
        nonce: str,
        code_verifier: str,
        scopes: list[str],
    ) -> str:
        """Return the URL to send the user to."""
        return build_authorize_url(
            metadata.authorization_endpoint,
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            state=state,
            extra={
                "scope": " ".join(scopes),
                "nonce": nonce,
                "code_challenge": compute_code_challenge(code_verifier),
                "code_challenge_method": PKCE_CHALLENGE_METHOD,
            },
        )

    async def async_exchange_code(
        self, *, code: str, redirect_uri: str, code_verifier: str
    ) -> TokenResponse:
        """Exchange an authorization code for tokens."""
        return await self._async_token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }
        )

    async def async_refresh_token(self, refresh_token: str) -> TokenResponse:
        """Exchange a refresh token for a fresh set of tokens."""
        return await self._async_token_request(
            {"grant_type": "refresh_token", "refresh_token": refresh_token}
        )

    async def _async_token_request(self, data: dict[str, str]) -> TokenResponse:
        """Post to the token endpoint and parse the response."""
        metadata = await self.async_metadata()
        payload, headers = self._client_auth(metadata, data)
        return await _async_token_request(
            self.hass, metadata.token_endpoint, payload, headers=headers
        )

    def _client_auth(
        self, metadata: ProviderMetadata, data: dict[str, str]
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """Return the payload and headers that authenticate us as the client."""
        methods = metadata.token_endpoint_auth_methods_supported
        method: ClientAuthMethod
        if not methods or "client_secret_basic" in methods:
            method = "client_secret_basic"
        elif "client_secret_post" in methods or self.client_secret is None:
            method = "client_secret_post"
        else:
            raise OidcTokenError(
                "The provider offers no supported client authentication method"
            )
        return client_auth(data, self.client_id, self.client_secret, method)

    async def async_merge_userinfo(
        self, claims: dict[str, Any], access_token: str
    ) -> dict[str, Any]:
        """Complete the ID token claims with the userinfo endpoint."""
        metadata = await self.async_metadata()
        if not metadata.userinfo_endpoint:
            return claims

        session = async_get_clientsession(self.hass)
        try:
            async with asyncio.timeout(HTTP_TIMEOUT):
                response = await session.get(
                    metadata.userinfo_endpoint,
                    headers={"Authorization": f"Bearer {access_token}"},
                    allow_redirects=False,
                )
                status = response.status
                if 300 <= status < 400:
                    raise OidcError("The userinfo endpoint URL redirects elsewhere")
                body = await response.json(content_type=None)
        except TimeoutError as err:
            raise OidcTransientError("Timeout fetching userinfo") from err
        except ClientError as err:
            raise OidcTransientError(f"Error fetching userinfo: {err}") from err
        except ValueError as err:
            raise OidcError("Userinfo endpoint returned invalid JSON") from err

        if status in (401, 403):
            raise OidcInvalidGrantError("The identity provider rejected the token")
        if status >= 500:
            raise OidcTransientError(f"Userinfo endpoint returned status {status}")
        if status >= 400:
            raise OidcError(f"Userinfo endpoint returned status {status}")

        try:
            info: dict[str, Any] = _USERINFO_SCHEMA(body)
        except probatio.Invalid as err:
            raise OidcError(f"Userinfo response is invalid: {err}") from err
        if info["sub"] != claims["sub"]:
            raise OidcIdTokenError("Userinfo response describes a different subject")
        return info | claims

    async def async_revoke_token(self, token: str) -> None:
        """Ask the provider to revoke a token, ignoring failures."""
        try:
            metadata = await self.async_metadata()
            if not metadata.revocation_endpoint:
                return

            payload, headers = self._client_auth(
                metadata, {"token": token, "token_type_hint": "refresh_token"}
            )
            session = async_get_clientsession(self.hass)
            async with asyncio.timeout(HTTP_TIMEOUT):
                async with session.post(
                    metadata.revocation_endpoint,
                    data=payload,
                    headers=headers,
                    allow_redirects=False,
                ):
                    pass
        except (TimeoutError, ClientError, OidcError) as err:
            _LOGGER.debug("Could not revoke token at the identity provider: %s", err)

    def _allowed_algorithms(self, metadata: ProviderMetadata) -> list[str]:
        """Return the signing algorithms we accept for ID tokens."""
        advertised = set(metadata.id_token_signing_alg_values_supported) or {
            DEFAULT_ID_TOKEN_ALGORITHM
        }
        if allowed := advertised & ALLOWED_ID_TOKEN_ALGORITHMS:
            return sorted(allowed)
        raise OidcIdTokenError(
            "The provider offers no ID token signing algorithm we accept"
        )

    def canonical_issuer(self, claims: Mapping[str, Any]) -> str:
        """Return the issuer used to key credentials for verified claims."""
        if self.issuer_claim is not None:
            return _filled_template_issuer(self.issuer, self.issuer_claim, claims)
        return self.issuer

    def accepts_issuer(self, issuer: str) -> bool:
        """Return whether a stored credential issuer belongs to this client."""
        if self._issuer_pattern is not None:
            return self._issuer_pattern.fullmatch(issuer) is not None
        return issuer == self.issuer

    def _verify_issuer_claim(self, claims: Mapping[str, Any]) -> None:
        """Verify the issuer claim follows this client's issuer rules."""
        issuer = claims.get("iss")
        if not isinstance(issuer, str):
            raise OidcIdTokenError("ID token issuer claim is missing or invalid")
        if self.issuer_claim is not None:
            expected = self.canonical_issuer(claims)
            if issuer != expected:
                raise OidcIdTokenError("ID token issuer does not match its template")
            return
        if issuer != self.issuer and issuer not in self.issuer_aliases:
            raise OidcIdTokenError("ID token issuer does not match this provider")

    async def _async_signing_key(self, kid: str | None) -> tuple[JWKDict, jwt.PyJWK]:
        """Return the public key for a key id, refetching the JWKS if needed."""
        entry = await self._async_lookup_key(kid)

        # An unknown key id usually means rotation; the refetch is rate limited.
        if entry is None and (
            time.time() - self._jwks_fetched_at >= JWKS_REFETCH_COOLDOWN
        ):
            entry = await self._async_lookup_key(kid, force_refresh=True)

        if entry is None:
            raise OidcIdTokenError(f"No key {kid!r} in the provider key set")

        raw, _ = entry
        if not _may_verify_signatures(raw):
            raise OidcIdTokenError(
                f"Key {kid!r} is not published for verifying signatures"
            )

        return entry

    async def _async_lookup_key(
        self, kid: str | None, *, force_refresh: bool = False
    ) -> tuple[JWKDict, jwt.PyJWK] | None:
        """Return the matching key from the cached key set."""
        async with self._jwks_lock:
            if (
                force_refresh
                or self._jwks is None
                or time.time() - self._jwks_fetched_at >= JWKS_CACHE_TTL
            ):
                metadata = await self.async_metadata()
                document = await _async_fetch_json(
                    self.hass, metadata.jwks_uri, "key set"
                )
                try:
                    keys = _JWKS_SCHEMA(document)["keys"]
                except probatio.Invalid as err:
                    raise OidcIdTokenError(
                        "Provider key set is not a JWKS object"
                    ) from err
                # One by one, so each key stays paired with its JWK metadata.
                parsed: list[tuple[JWKDict, jwt.PyJWK]] = []
                for key in keys:
                    try:
                        _JWK_SCHEMA(key)
                        parsed.append((key, jwt.PyJWK(key)))
                    except (probatio.Invalid, jwt.PyJWTError, ValueError) as err:
                        _LOGGER.debug("Ignoring unusable JWK: %s", err)
                if not parsed:
                    raise OidcIdTokenError("Provider key set has no usable key")
                self._jwks = parsed
                self._jwks_fetched_at = time.time()

            if kid is not None:
                return next(
                    (entry for entry in self._jwks if entry[1].key_id == kid), None
                )
            # A key set with a single key does not have to label it.
            return self._jwks[0] if len(self._jwks) == 1 else None

    async def async_verify_id_token(
        self,
        id_token: str,
        *,
        nonce: str | None = None,
        access_token: str | None = None,
    ) -> dict[str, Any]:
        """Verify an ID token and return its claims."""
        metadata = await self.async_metadata()
        algorithms = self._allowed_algorithms(metadata)

        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.InvalidTokenError as err:
            raise OidcIdTokenError(f"Malformed ID token: {err}") from err

        # Checked up front for a clear error; jwt.decode still matches the list.
        if (algorithm := header.get("alg")) not in algorithms:
            raise OidcIdTokenError(f"ID token uses unaccepted algorithm {algorithm!r}")

        raw, jwk = await self._async_signing_key(header.get("kid"))

        # A JWK that declares its algorithm pins verification to it. One that
        # does not would get a key-type default that rejects valid RS384/RS512.
        key: Any = jwk if raw.get("alg") else jwk.key

        try:
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key,
                algorithms=algorithms,
                audience=self.client_id,
                leeway=CLOCK_SKEW_LEEWAY,
                options={
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_iss": False,
                },
            )
        except jwt.InvalidTokenError as err:
            raise OidcIdTokenError(f"ID token rejected: {err}") from err

        self._verify_issuer_claim(claims)

        # With several audiences, azp has to name us so another client's token
        # cannot be replayed here. PyJWT already checked that aud includes us.
        authorized_party = claims.get("azp")
        if not authorized_party and claims["aud"] not in (
            self.client_id,
            [self.client_id],
        ):
            raise OidcIdTokenError("ID token has multiple audiences but no azp claim")
        if authorized_party is not None and authorized_party != self.client_id:
            raise OidcIdTokenError("ID token azp claim names a different client")

        if nonce is not None and claims.get("nonce") != nonce:
            raise OidcIdTokenError("ID token nonce does not match the login attempt")

        self._verify_at_hash(claims, algorithm, access_token)

        return claims

    def _verify_at_hash(
        self, claims: dict[str, Any], algorithm: str, access_token: str | None
    ) -> None:
        """Check the ID token was issued with this access token, if it says so."""
        if (at_hash := claims.get("at_hash")) is None or access_token is None:
            return

        if (expected := _compute_at_hash(access_token, algorithm)) is None:
            # Only EdDSA gets here; warn since an offered binding goes unchecked.
            _LOGGER.warning(
                "ID token carries an at_hash that cannot be checked for"
                " algorithm %s, the access token binding is unverified",
                algorithm,
            )
            return

        # at_hash is public, so there is no timing to protect.
        if at_hash != expected:
            raise OidcIdTokenError(
                "ID token at_hash does not match the access token it came with"
            )


class OAuth2ProfileClient:
    """OAuth2 authorization-code client that identifies users from a profile."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        authorize_url: str,
        token_url: str,
        profile_url: str,
        client_id: str,
        client_secret: str | None,
        subject_field: str,
        account_name_field: str | None = None,
        scopes: Sequence[str] = (),
        headers: Mapping[str, str] | None = None,
        token_auth_method: ClientAuthMethod = "client_secret_basic",  # noqa: S107
        allow_insecure_transport: bool = False,
    ) -> None:
        """Initialize the OAuth2 profile client."""
        if token_auth_method not in {"client_secret_basic", "client_secret_post"}:
            raise ValueError("Unsupported token authentication method")
        configured_headers = dict(headers or {})
        reserved = RESERVED_PROFILE_HEADERS & {
            header.lower() for header in configured_headers
        }
        if reserved:
            raise ValueError(f"Reserved profile headers are not allowed: {reserved}")

        self.hass = hass
        self.authorize_url = _require_https(
            authorize_url, "authorize_url", allow_http=allow_insecure_transport
        )
        self.token_url = _require_https(
            token_url, "token_url", allow_http=allow_insecure_transport
        )
        self.profile_url = _require_https(
            profile_url, "profile_url", allow_http=allow_insecure_transport
        )
        self.client_id = client_id
        self.client_secret = client_secret
        self.subject_field = subject_field
        self.account_name_field = account_name_field
        self.scopes = tuple(scopes)
        self.headers = configured_headers
        self.token_auth_method = token_auth_method
        self.issuer = _origin(self.profile_url)

    def async_authorize_url(
        self, *, redirect_uri: str, state: str, code_verifier: str
    ) -> str:
        """Return the URL to send the user to."""
        extra = {
            "code_challenge": compute_code_challenge(code_verifier),
            "code_challenge_method": PKCE_CHALLENGE_METHOD,
        }
        if self.scopes:
            extra["scope"] = " ".join(self.scopes)
        return build_authorize_url(
            self.authorize_url,
            client_id=self.client_id,
            redirect_uri=redirect_uri,
            state=state,
            extra=extra,
        )

    async def async_exchange_code(
        self, *, code: str, redirect_uri: str, code_verifier: str
    ) -> TokenResponse:
        """Exchange an authorization code for tokens."""
        payload: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        }
        body, headers = client_auth(
            payload, self.client_id, self.client_secret, self.token_auth_method
        )
        return await _async_token_request(
            self.hass, self.token_url, body, headers=headers
        )

    async def async_fetch_profile(self, access_token: str) -> tuple[str, str | None]:
        """Fetch the user's profile and return the subject and account name."""
        session = async_get_clientsession(self.hass)
        headers = {"Accept": "application/json", **self.headers}
        headers["Authorization"] = "Bearer " + access_token
        try:
            async with asyncio.timeout(HTTP_TIMEOUT):
                response = await session.get(
                    self.profile_url, headers=headers, allow_redirects=False
                )
                status = response.status
                if 300 <= status < 400:
                    raise OidcError("The profile endpoint URL redirects elsewhere")
                body = await response.json(content_type=None)
        except TimeoutError as err:
            raise OidcTransientError("Timeout fetching the profile") from err
        except ClientError as err:
            raise OidcTransientError(f"Error fetching the profile: {err}") from err
        except ValueError as err:
            raise OidcError("Profile endpoint returned invalid JSON") from err

        if status in (401, 403):
            raise OidcInvalidGrantError("The identity provider rejected the token")
        if status >= 500:
            raise OidcTransientError(f"Profile endpoint returned status {status}")
        if status >= 400:
            raise OidcError(f"Profile endpoint returned status {status}")
        if not isinstance(body, dict):
            raise OidcError("Profile endpoint did not return a JSON object")

        subject_value = body.get(self.subject_field)
        if isinstance(subject_value, bool):
            raise OidcError("Profile subject is not a usable string")
        if isinstance(subject_value, int):
            subject = str(subject_value)
        elif isinstance(subject_value, str) and subject_value:
            subject = subject_value
        else:
            raise OidcError("Profile subject is not a usable string")

        account_name = None
        if self.account_name_field is not None:
            account_name_value = body.get(self.account_name_field)
            if isinstance(account_name_value, str) and account_name_value:
                account_name = account_name_value

        return subject, account_name

    def accepts_issuer(self, issuer: str) -> bool:
        """Return whether a stored credential issuer belongs to this client."""
        return issuer == self.issuer

    async def async_revoke_token(self, token: str) -> None:
        """Do nothing; the profile flow does not keep external tokens."""
