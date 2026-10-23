"""Public identity provider specification for the OIDC auth engine."""

from dataclasses import dataclass, replace
import hashlib
import json
from typing import NoReturn, cast
from urllib.parse import urlsplit

from homeassistant.exceptions import HomeAssistantError

from .const import DEFAULT_SCOPES


@dataclass(frozen=True, slots=True, kw_only=True)
class OpenIDConnect:
    """OpenID Connect protocol settings."""

    issuer: str
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    account_name_claim: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class IdentityProvider:
    """Data-only identity provider specification."""

    client_id: str
    client_secret: str | None = None
    protocol: OpenIDConnect


class IdentityProviderError(HomeAssistantError):
    """Raised for a stable identity provider validation reason."""

    def __init__(self, reason: str, message: str | None = None) -> None:
        """Initialize the error."""
        super().__init__(message or reason)
        self.reason = reason


def _raise(reason: str, message: str | None = None) -> NoReturn:
    """Raise an identity provider validation error."""
    raise IdentityProviderError(reason, message)


def _validate_str(value: object, reason: str, *, non_empty: bool = False) -> str:
    """Validate an exact string."""
    if type(value) is not str or (non_empty and not value):
        _raise(reason)
    return value


def _validate_optional_str(value: object, reason: str) -> str | None:
    """Validate an exact optional string."""
    if value is None:
        return None
    return _validate_str(value, reason)


def _validate_scopes(value: object) -> tuple[str, ...]:
    """Validate a tuple of exact strings that includes openid."""
    if type(value) is not tuple or any(type(item) is not str for item in value):
        _raise("invalid_scopes")
    scopes = cast(tuple[str, ...], value)
    if "openid" not in scopes:
        _raise("invalid_scopes")
    return scopes


def _validate_url(value: object, reason: str) -> str:
    """Validate an https URL with no credentials or fragment."""
    url = _validate_str(value, reason, non_empty=True)
    try:
        parsed = urlsplit(url)
    except ValueError:
        _raise(reason)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        _raise(reason)
    return url


def _validate_oidc(protocol: object) -> OpenIDConnect:
    """Validate OIDC protocol settings."""
    if type(protocol) is not OpenIDConnect:
        _raise("invalid_protocol")
    return replace(
        protocol,
        issuer=_validate_url(protocol.issuer, "invalid_issuer"),
        scopes=_validate_scopes(protocol.scopes),
        account_name_claim=_validate_optional_str(
            protocol.account_name_claim, "invalid_account_name_claim"
        ),
    )


def validate_identity_provider(spec: object) -> IdentityProvider:
    """Validate and return an immutable identity provider specification."""
    if type(spec) is not IdentityProvider:
        _raise("invalid_spec")
    return IdentityProvider(
        client_id=_validate_str(spec.client_id, "invalid_client_id", non_empty=True),
        client_secret=_validate_optional_str(
            spec.client_secret, "invalid_client_secret"
        ),
        protocol=_validate_oidc(spec.protocol),
    )


def trust_key(spec: IdentityProvider) -> str:
    """Return the trust key digest for an identity provider specification."""
    # The account name claim only labels an identity, so changing it keeps sessions.
    payload = {
        "client_id": spec.client_id,
        "client_secret": spec.client_secret,
        "issuer": spec.protocol.issuer,
        "scopes": list(spec.protocol.scopes),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
