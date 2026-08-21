"""OpenID Connect relying party client.

Home Assistant already depends on PyJWT, so the cryptography and the registered
claim validation are delegated to it. Everything that needs I/O is done here with
aiohttp, because PyJWT's own ``PyJWKClient`` fetches over blocking urllib.
"""

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import hmac
import logging
import secrets
import time
from typing import Any
from urllib.parse import quote

from aiohttp import ClientError
import jwt
from yarl import URL

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession

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

# The hash an at_hash claim is built with is dictated by the signing algorithm.
# EdDSA is left out on purpose: OpenID Connect does not pin a hash for it, so
# rather than guess we skip the check for it.
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
    digest = hashlib.new(hash_name, access_token.encode("ascii")).digest()
    # OpenID Connect hashes the token and keeps the left-most half.
    half = digest[: len(digest) // 2]
    return base64.urlsafe_b64encode(half).decode("ascii").rstrip("=")


class OidcError(HomeAssistantError):
    """Base class for OpenID Connect errors."""


class OidcDiscoveryError(OidcError):
    """Raised when the provider metadata cannot be retrieved or is unusable."""


class OidcTokenError(OidcError):
    """Raised when the token endpoint rejects a request."""


class OidcInvalidGrantError(OidcTokenError):
    """Raised when a grant is rejected and will never succeed again.

    This is how an identity provider reports that a session was revoked or that
    the user is no longer allowed to sign in.
    """


class OidcTransientError(OidcError):
    """Raised when the identity provider is temporarily unreachable."""


class OidcIdTokenError(OidcError):
    """Raised when an ID token fails validation."""


def generate_code_verifier() -> str:
    """Return a new PKCE code verifier."""
    return secrets.token_urlsafe(64)


def compute_code_challenge(code_verifier: str) -> str:
    """Return the S256 PKCE challenge for a code verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


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


def _require_https(url: str, field: str) -> str:
    """Return an unambiguous HTTPS endpoint URL."""
    try:
        parsed = URL(url)
    except (TypeError, ValueError) as err:
        raise OidcDiscoveryError(f"{field} must be an https URL") from err
    if (
        parsed.scheme != "https"
        or not parsed.host
        or parsed.user is not None
        or parsed.fragment
    ):
        raise OidcDiscoveryError(
            f"{field} must be an https URL without credentials or a fragment"
        )
    return url


def _optional_https(url: Any, field: str) -> str | None:
    """Return an optional endpoint, rejecting anything that is not HTTPS."""
    if url is None:
        return None
    if not isinstance(url, str):
        raise OidcDiscoveryError(f"{field} is not a URL")
    return _require_https(url, field)


def _string_tuple(value: Any, field: str) -> tuple[str, ...]:
    """Return a validated tuple of strings from discovery metadata."""
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise OidcDiscoveryError(f"{field} must be an array of strings")
    return tuple(value)


class OidcClient:
    """Talk to an OpenID Connect provider on behalf of Home Assistant."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        issuer: str,
        client_id: str,
        client_secret: str | None = None,
    ) -> None:
        """Initialize the client."""
        self.hass = hass
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret

        self._metadata: ProviderMetadata | None = None
        self._metadata_fetched_at = 0.0
        self._metadata_lock = asyncio.Lock()

        self._jwks: jwt.PyJWKSet | None = None
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
        if not isinstance(document, dict):
            raise OidcDiscoveryError("Discovery document is not a JSON object")

        # Issuer identifiers are compared exactly, including a trailing slash.
        # Accepting metadata for another identifier would break issuer binding.
        advertised = document.get("issuer")
        if not isinstance(advertised, str) or advertised != self.issuer:
            raise OidcDiscoveryError(
                f"Discovery document issuer {advertised!r} does not"
                f" match the configured issuer {self.issuer!r}"
            )

        challenge_methods = _string_tuple(
            document.get("code_challenge_methods_supported"),
            "code_challenge_methods_supported",
        )
        if challenge_methods and PKCE_CHALLENGE_METHOD not in challenge_methods:
            raise OidcDiscoveryError(
                f"The provider does not offer the {PKCE_CHALLENGE_METHOD} PKCE"
                f" challenge method, it only offers {', '.join(challenge_methods)}"
            )

        try:
            return ProviderMetadata(
                issuer=advertised,
                authorization_endpoint=_require_https(
                    document["authorization_endpoint"], "authorization_endpoint"
                ),
                token_endpoint=_require_https(
                    document["token_endpoint"], "token_endpoint"
                ),
                jwks_uri=_require_https(document["jwks_uri"], "jwks_uri"),
                # Both carry credentials, so they get the same treatment as the
                # endpoints the spec makes mandatory.
                userinfo_endpoint=_optional_https(
                    document.get("userinfo_endpoint"), "userinfo_endpoint"
                ),
                revocation_endpoint=_optional_https(
                    document.get("revocation_endpoint"), "revocation_endpoint"
                ),
                id_token_signing_alg_values_supported=_string_tuple(
                    document.get("id_token_signing_alg_values_supported"),
                    "id_token_signing_alg_values_supported",
                ),
                token_endpoint_auth_methods_supported=_string_tuple(
                    document.get("token_endpoint_auth_methods_supported"),
                    "token_endpoint_auth_methods_supported",
                ),
                scopes_supported=_string_tuple(
                    document.get("scopes_supported"), "scopes_supported"
                ),
            )
        except KeyError as err:
            raise OidcDiscoveryError(
                f"Discovery document is missing {err.args[0]}"
            ) from err
        except TypeError as err:
            raise OidcDiscoveryError(f"Discovery document is malformed: {err}") from err

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
        return str(
            URL(metadata.authorization_endpoint).update_query(
                {
                    "response_type": "code",
                    "client_id": self.client_id,
                    "redirect_uri": redirect_uri,
                    "scope": " ".join(scopes),
                    "state": state,
                    "nonce": nonce,
                    "code_challenge": compute_code_challenge(code_verifier),
                    "code_challenge_method": PKCE_CHALLENGE_METHOD,
                }
            )
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
        session = async_get_clientsession(self.hass)
        payload, headers = self._client_auth(metadata, data)

        try:
            async with asyncio.timeout(HTTP_TIMEOUT):
                # A 307 or 308 would replay the client secret to the new target.
                response = await session.post(
                    metadata.token_endpoint,
                    data=payload,
                    headers=headers,
                    allow_redirects=False,
                )
                status = response.status
                if 300 <= status < 400:
                    raise OidcTokenError("The token endpoint URL redirects elsewhere")
                body = await response.json(content_type=None)
        except TimeoutError as err:
            raise OidcTransientError("Timeout talking to the token endpoint") from err
        except ClientError as err:
            raise OidcTransientError(f"Token request failed: {err}") from err
        except ValueError as err:
            raise OidcTokenError("Token endpoint returned invalid JSON") from err

        if status >= 400:
            error = body.get("error") if isinstance(body, dict) else None
            if status >= 500:
                raise OidcTransientError(
                    f"Token endpoint returned status {status}: {error}"
                )
            if error == "invalid_grant":
                raise OidcInvalidGrantError("The identity provider rejected the grant")
            raise OidcTokenError(f"Token endpoint returned {error or status}")

        if not isinstance(body, dict) or not isinstance(
            access_token := body.get("access_token"), str
        ):
            raise OidcTokenError("Token endpoint response is missing an access token")

        id_token = body.get("id_token")
        if id_token is not None and not isinstance(id_token, str):
            raise OidcTokenError("Token endpoint returned a non-string id_token")
        refresh_token = body.get("refresh_token")
        if refresh_token is not None and not isinstance(refresh_token, str):
            raise OidcTokenError("Token endpoint returned a non-string refresh_token")

        # The token is sent to the userinfo endpoint as a bearer, so anything the
        # provider labels differently would be used in a way it did not intend.
        token_type = body.get("token_type")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise OidcTokenError(
                f"Token endpoint returned unsupported token type {token_type!r}"
            )

        return TokenResponse(
            access_token=access_token,
            id_token=id_token,
            refresh_token=refresh_token,
        )

    def _client_auth(
        self, metadata: ProviderMetadata, data: dict[str, str]
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Return the payload and headers that authenticate us as the client."""
        methods = metadata.token_endpoint_auth_methods_supported
        if self.client_secret is None:
            return {**data, "client_id": self.client_id}, {}
        if not methods or "client_secret_basic" in methods:
            return data, {"Authorization": self._basic_auth_header()}
        if "client_secret_post" in methods:
            return {
                **data,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }, {}
        raise OidcTokenError(
            "The provider offers no supported client authentication method"
        )

    def _basic_auth_header(self) -> str:
        """Return the HTTP basic authorization header value."""
        assert self.client_secret is not None
        # RFC 6749 section 2.3.1 requires form encoding before base64.
        credentials = (
            f"{quote(self.client_id, safe='')}:{quote(self.client_secret, safe='')}"
        )
        encoded = base64.b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"

    async def async_userinfo(self, access_token: str) -> dict[str, Any]:
        """Return the claims from the userinfo endpoint."""
        metadata = await self.async_metadata()
        if not metadata.userinfo_endpoint:
            raise OidcError("The provider does not offer a userinfo endpoint")

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
        if status >= 400 or not isinstance(body, dict):
            raise OidcError(f"Userinfo endpoint returned status {status}")

        return body

    async def async_merge_userinfo(
        self, claims: dict[str, Any], access_token: str
    ) -> dict[str, Any]:
        """Complete the ID token claims with the userinfo endpoint."""
        metadata = await self.async_metadata()
        if not metadata.userinfo_endpoint:
            return claims

        info = await self.async_userinfo(access_token)
        if info.get("sub") != claims["sub"]:
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

    async def _async_signing_key(self, kid: str | None) -> Any:
        """Return the public key for a key id, refetching the JWKS if needed."""
        key = await self._async_lookup_key(kid)

        # An unknown key id usually means the provider rotated its keys, but the
        # refetch is rate limited so bogus ones cannot hammer the provider.
        if key is None and (
            time.time() - self._jwks_fetched_at >= JWKS_REFETCH_COOLDOWN
        ):
            key = await self._async_lookup_key(kid, force_refresh=True)

        if key is None:
            raise OidcIdTokenError(f"No key {kid!r} in the provider key set")

        return key

    async def _async_lookup_key(
        self, kid: str | None, *, force_refresh: bool = False
    ) -> Any:
        """Return the matching key from the cached key set."""
        async with self._jwks_lock:
            if (
                force_refresh
                or self._jwks is None
                or time.time() - self._jwks_fetched_at >= JWKS_CACHE_TTL
            ):
                metadata = await self.async_metadata()
                document = await self._async_fetch_json(metadata.jwks_uri, "key set")
                if (
                    not isinstance(document, dict)
                    or not isinstance(keys := document.get("keys"), list)
                    or any(not isinstance(key, dict) for key in keys)
                ):
                    raise OidcIdTokenError("Provider key set is not a JWKS object")
                try:
                    self._jwks = jwt.PyJWKSet.from_dict(document)
                except (jwt.PyJWTError, TypeError, ValueError) as err:
                    raise OidcIdTokenError(
                        f"Provider key set is unusable: {err}"
                    ) from err
                self._jwks_fetched_at = time.time()

            keys = self._jwks.keys
            if kid is not None:
                return next((key.key for key in keys if key.key_id == kid), None)
            # A key set with a single key does not have to label it.
            return keys[0].key if len(keys) == 1 else None

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

        # Checked up front so an unacceptable algorithm gives a clear error, but
        # jwt.decode is still handed the full list so it does its own matching.
        if (algorithm := header.get("alg")) not in algorithms:
            raise OidcIdTokenError(f"ID token uses unaccepted algorithm {algorithm!r}")

        key = await self._async_signing_key(header.get("kid"))

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

        # With more than one audience the authorized party has to name us, so a
        # token minted for another client cannot be replayed here.
        audience = claims["aud"]
        authorized_party = claims.get("azp")
        if isinstance(audience, list) and len(audience) > 1 and not authorized_party:
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
        """Check that the ID token was issued with this access token.

        Optional for the authorization code flow, so it is only enforced when the
        provider sends it.
        """
        if (at_hash := claims.get("at_hash")) is None or access_token is None:
            return

        if not isinstance(at_hash, str):
            raise OidcIdTokenError("ID token at_hash claim is not a string")

        try:
            expected = _compute_at_hash(access_token, algorithm)
        except UnicodeEncodeError as err:
            raise OidcIdTokenError("Access token is not ASCII encoded") from err

        if expected is None:
            _LOGGER.debug("Cannot check at_hash for algorithm %s", algorithm)
            return

        if not hmac.compare_digest(at_hash, expected):
            raise OidcIdTokenError(
                "ID token at_hash does not match the access token it came with"
            )
