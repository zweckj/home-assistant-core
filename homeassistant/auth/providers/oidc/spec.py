"""Public identity provider specification for the OIDC auth engine."""

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import timedelta
from enum import StrEnum
import hashlib
import json
from types import MappingProxyType
from typing import Any, ClassVar, NoReturn, Self, cast, override
from urllib.parse import urlsplit

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .client import IdentityClient, OidcClient
from .const import (
    DEFAULT_DISPLAY_NAME_CLAIM,
    DEFAULT_SCOPES,
    DEFAULT_USERNAME_CLAIM,
    MAX_REVALIDATE_INTERVAL,
    MIN_REVALIDATE_INTERVAL,
)


class AccountPolicy(StrEnum):
    """How accounts from an identity provider may be used."""

    LINK = "link"
    PROVISION = "provision"


@dataclass(frozen=True, slots=True, kw_only=True)
class Equals:
    """Require a claim to equal one value."""

    value: str


@dataclass(frozen=True, slots=True, kw_only=True)
class NotEquals:
    """Require a claim to not equal one value."""

    value: str


@dataclass(frozen=True, slots=True, kw_only=True)
class OneOf:
    """Require a claim to be one of multiple values."""

    values: frozenset[str]


type ClaimRule = Equals | NotEquals | OneOf


@dataclass(frozen=True, slots=True, kw_only=True)
class ProtocolSpec(ABC):
    """How the engine talks to an identity provider.

    Only built-in integrations may bring their own subclass; a custom
    integration is limited to OpenIDConnect.
    """

    def validate(self, *, allow_insecure_transport: bool) -> Self:
        """Return a validated copy, raising IdentityProviderError."""
        return self

    def trust_data(self) -> Any:
        """Return the settings whose change ends existing sessions."""
        return _jsonable(self)

    @abstractmethod
    def create_client(
        self, hass: HomeAssistant, spec: IdentityProvider
    ) -> IdentityClient:
        """Return the client that signs users in."""


@dataclass(frozen=True, slots=True, kw_only=True)
class OpenIDConnect(ProtocolSpec):
    """OpenID Connect protocol settings."""

    client_class: ClassVar[type[OidcClient]] = OidcClient

    issuer: str
    discovery_url: str | None = None
    required_claims: Mapping[str, ClaimRule] = field(default_factory=dict)
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    account_name_claim: str | None = None
    username_claim: str = DEFAULT_USERNAME_CLAIM
    display_name_claim: str = DEFAULT_DISPLAY_NAME_CLAIM
    admin_group: str | None = None

    @override
    def validate(self, *, allow_insecure_transport: bool) -> Self:
        """Return a validated copy, raising IdentityProviderError."""
        return _validate_oidc(self, allow_insecure_transport=allow_insecure_transport)

    @override
    def trust_data(self) -> Any:
        """Return the settings whose change ends existing sessions."""
        # Claims that only label an account do not change who signs in.
        return _jsonable(
            replace(
                self, account_name_claim=None, username_claim="", display_name_claim=""
            )
        )

    @override
    def create_client(self, hass: HomeAssistant, spec: IdentityProvider) -> OidcClient:
        """Return the client that signs users in."""
        return self.client_class(
            hass,
            issuer=self.issuer,
            client_id=spec.client_id,
            client_secret=spec.client_secret,
            discovery_url=self.discovery_url,
            allow_insecure_transport=spec.allow_insecure_transport,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class IdentityProvider:
    """Data-only identity provider specification."""

    client_id: str
    client_secret: str | None = None
    protocol: ProtocolSpec
    accounts: AccountPolicy = AccountPolicy.LINK
    revalidate_interval: timedelta | None = None
    allow_insecure_transport: bool = False


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


def _validate_tuple(
    value: object, reason: str, *, required: str | None = None
) -> tuple[str, ...]:
    """Validate a tuple of exact strings."""
    if type(value) is not tuple or any(type(item) is not str for item in value):
        _raise(reason)
    tuple_value = cast(tuple[str, ...], value)
    if required is not None and required not in tuple_value:
        _raise(reason)
    return tuple_value


def _validate_url(value: object, reason: str, *, allow_insecure_transport: bool) -> str:
    """Validate an https URL with no credentials or fragment."""
    url = _validate_str(value, reason, non_empty=True)
    try:
        parsed = urlsplit(url)
    except ValueError:
        _raise(reason)
    schemes = {"https", "http"} if allow_insecure_transport else {"https"}
    if (
        parsed.scheme not in schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        _raise(reason)
    return url


def _validate_claim_rule(value: object) -> ClaimRule:
    """Validate a claim rule."""
    if type(value) is Equals or type(value) is NotEquals:
        _validate_str(value.value, "invalid_claim_rule")
        return value
    if type(value) is OneOf:
        if (
            type(value.values) is not frozenset
            or not value.values
            or any(type(item) is not str for item in value.values)
        ):
            _raise("invalid_claim_rule")
        return value
    _raise("invalid_claim_rule")


def _validate_required_claims(value: object) -> Mapping[str, ClaimRule]:
    """Validate required claim rules."""
    if not isinstance(value, Mapping):
        _raise("invalid_required_claims")
    claims = cast(Mapping[object, object], value)
    return MappingProxyType(
        {
            _validate_str(
                key, "invalid_required_claims", non_empty=True
            ): _validate_claim_rule(rule)
            for key, rule in claims.items()
        }
    )


def _validate_bool(value: object, reason: str) -> bool:
    """Validate an exact bool."""
    if type(value) is not bool:
        _raise(reason)
    return value


def _validate_account_policy(value: object) -> AccountPolicy:
    """Validate an exact account policy."""
    if type(value) is not AccountPolicy:
        _raise("invalid_account_policy")
    return value


def _validate_oidc[T: OpenIDConnect](
    protocol: T, *, allow_insecure_transport: bool
) -> T:
    """Validate OIDC protocol settings."""
    issuer = _validate_url(
        protocol.issuer,
        "invalid_issuer",
        allow_insecure_transport=allow_insecure_transport,
    )
    discovery_url = None
    if protocol.discovery_url is not None:
        discovery_url = _validate_url(
            protocol.discovery_url,
            "invalid_discovery_url",
            allow_insecure_transport=allow_insecure_transport,
        )
    scopes = _validate_tuple(protocol.scopes, "invalid_scopes", required="openid")
    required_claims = _validate_required_claims(protocol.required_claims)
    account_name_claim = _validate_optional_str(
        protocol.account_name_claim, "invalid_account_name_claim"
    )
    username_claim = _validate_str(
        protocol.username_claim, "invalid_username_claim", non_empty=True
    )
    display_name_claim = _validate_str(
        protocol.display_name_claim, "invalid_display_name_claim", non_empty=True
    )
    admin_group = _validate_optional_str(protocol.admin_group, "invalid_admin_group")
    return replace(
        protocol,
        issuer=issuer,
        discovery_url=discovery_url,
        required_claims=required_claims,
        scopes=scopes,
        account_name_claim=account_name_claim,
        username_claim=username_claim,
        display_name_claim=display_name_claim,
        admin_group=admin_group,
    )


def validate_identity_provider(spec: object) -> IdentityProvider:
    """Validate and return an immutable identity provider specification."""
    if type(spec) is not IdentityProvider:
        _raise("invalid_spec")
    client_id = _validate_str(spec.client_id, "invalid_client_id", non_empty=True)
    client_secret = _validate_optional_str(spec.client_secret, "invalid_client_secret")
    allow_insecure_transport = _validate_bool(
        spec.allow_insecure_transport, "invalid_allow_insecure_transport"
    )
    accounts = _validate_account_policy(spec.accounts)
    if spec.revalidate_interval is not None:
        if type(spec.revalidate_interval) is not timedelta:
            _raise("invalid_revalidate_interval")
        seconds = spec.revalidate_interval.total_seconds()
        if seconds < MIN_REVALIDATE_INTERVAL or seconds > MAX_REVALIDATE_INTERVAL:
            _raise("invalid_revalidate_interval")
    if accounts is AccountPolicy.LINK and spec.revalidate_interval is not None:
        _raise("revalidate_interval_not_allowed")

    if not isinstance(spec.protocol, ProtocolSpec):
        _raise("invalid_protocol")
    protocol = spec.protocol.validate(allow_insecure_transport=allow_insecure_transport)
    # Creating users needs the verified claims of an ID token.
    if accounts is AccountPolicy.PROVISION and not isinstance(protocol, OpenIDConnect):
        _raise("provision_requires_oidc")

    if accounts is AccountPolicy.PROVISION and spec.revalidate_interval is None:
        _raise("revalidate_interval_required")

    return IdentityProvider(
        client_id=client_id,
        client_secret=client_secret,
        protocol=protocol,
        accounts=accounts,
        revalidate_interval=spec.revalidate_interval,
        allow_insecure_transport=allow_insecure_transport,
    )


def _jsonable(value: Any) -> Any:
    """Convert dataclass and mapping values to canonical JSON values."""
    if is_dataclass(value):
        return {
            field.name: _jsonable(getattr(value, field.name)) for field in fields(value)
        }
    if isinstance(value, Mapping):
        return {
            str(key): _jsonable(map_value) for key, map_value in sorted(value.items())
        }
    if isinstance(value, frozenset | tuple):
        return (
            sorted(value)
            if isinstance(value, frozenset)
            else [_jsonable(item) for item in value]
        )
    return value


def trust_key(spec: IdentityProvider) -> str:
    """Return the trust key digest for an identity provider specification."""
    protocol_type = type(spec.protocol)
    payload = {
        "client_id": spec.client_id,
        "client_secret": spec.client_secret,
        "protocol_type": f"{protocol_type.__module__}.{protocol_type.__qualname__}",
        "protocol": spec.protocol.trust_data(),
        "accounts": spec.accounts.value,
        "allow_insecure_transport": spec.allow_insecure_transport,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
