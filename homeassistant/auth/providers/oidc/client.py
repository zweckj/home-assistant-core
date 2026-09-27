"""OpenID Connect relying party client.

Cryptography and claim validation come from PyJWT; all I/O goes through aiohttp,
since PyJWT's own key client fetches with blocking urllib.
"""

import asyncio
import base64
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import logging
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
    JWKS_CACHE_TTL,
    JWKS_REFETCH_COOLDOWN,
    PKCE_CHALLENGE_METHOD,
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


class OidcClient:
    """Talk to an OpenID Connect provider on behalf of Home Assistant."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        issuer: str,
        client_id: str,
        client_secret: str | None = None,
        allow_insecure_transport: bool = False,
    ) -> None:
        """Initialize the client."""
        self.hass = hass
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.allow_insecure_transport = allow_insecure_transport

        self._metadata: ProviderMetadata | None = None
        self._metadata_fetched_at = 0.0
        self._metadata_lock = asyncio.Lock()

        self._jwks: list[tuple[JWKDict, jwt.PyJWK]] | None = None
        self._jwks_fetched_at = 0.0
        self._jwks_lock = asyncio.Lock()

    async def async_metadata(self, *, force_refresh: bool = False) -> ProviderMetadata:
        """Return the provider metadata, fetching it when the cache is cold."""
        async with self._metadata_lock:
            if (
                not force_refresh
                and self._metadata is not None
                and time.time() - self._metadata_fetched_at < DISCOVERY_CACHE_TTL
            ):
                return self._metadata

            document = await self._async_fetch_json(
                f"{self.issuer.rstrip('/')}{DISCOVERY_PATH}", "discovery document"
            )
            metadata = self._parse_metadata(document)
            self._metadata = metadata
            self._metadata_fetched_at = time.time()
            return metadata

    def _parse_metadata(self, document: Any) -> ProviderMetadata:
        """Validate and convert a discovery document."""
        try:
            parsed = _discovery_schema(self.allow_insecure_transport)(document)
        except probatio.Invalid as err:
            raise OidcDiscoveryError(f"Discovery document is invalid: {err}") from err

        # Compared exactly, trailing slash included, to keep issuer binding.
        if parsed["issuer"] != self.issuer:
            raise OidcDiscoveryError(
                f"Discovery document issuer {parsed['issuer']!r} does not"
                f" match the configured issuer {self.issuer!r}"
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

    async def _async_fetch_json(self, url: str, what: str) -> Any:
        """Fetch and decode a JSON document."""
        session = async_get_clientsession(self.hass)
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

        try:
            async with asyncio.timeout(HTTP_TIMEOUT):
                # A 307 or 308 would replay the client secret to the new target.
                body = await async_token_request(
                    self.hass,
                    metadata.token_endpoint,
                    payload,
                    domain=AUTH_DOMAIN,
                    headers=headers,
                    allow_redirects=False,
                )
        except OAuth2TokenRequestReauthError as err:
            raise OidcInvalidGrantError(
                "The identity provider rejected the grant"
            ) from err
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

        try:
            body = _TOKEN_RESPONSE_SCHEMA(body)
        except probatio.Invalid as err:
            raise OidcTokenError(f"Token endpoint response is invalid: {err}") from err

        return TokenResponse(
            access_token=body["access_token"],
            id_token=body.get("id_token"),
            refresh_token=body.get("refresh_token"),
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
                document = await self._async_fetch_json(metadata.jwks_uri, "key set")
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
                issuer=metadata.issuer,
                leeway=CLOCK_SKEW_LEEWAY,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.InvalidTokenError as err:
            raise OidcIdTokenError(f"ID token rejected: {err}") from err

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
