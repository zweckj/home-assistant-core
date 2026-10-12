"""Public identity provider specification for the OIDC auth engine."""

from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import timedelta
from enum import StrEnum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Literal, NoReturn, cast
from urllib.parse import urlsplit

from homeassistant.exceptions import HomeAssistantError

from .const import (
    DEFAULT_DISPLAY_NAME_CLAIM,
    DEFAULT_SCOPES,
    DEFAULT_USERNAME_CLAIM,
    ISSUER_PLACEHOLDER_PATTERN,
    MAX_REVALIDATE_INTERVAL,
    MIN_REVALIDATE_INTERVAL,
    RESERVED_PROFILE_HEADERS,
)

_ISSUER_PLACEHOLDER_RE = re.compile(ISSUER_PLACEHOLDER_PATTERN)


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
class OpenIDConnect:
    """OpenID Connect protocol settings."""

    issuer: str
    discovery_url: str | None = None
    issuer_aliases: frozenset[str] = frozenset()
    issuer_claim: str | None = None
    required_claims: Mapping[str, ClaimRule] = field(default_factory=dict)
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    account_name_claim: str | None = None
    username_claim: str = DEFAULT_USERNAME_CLAIM
    display_name_claim: str = DEFAULT_DISPLAY_NAME_CLAIM
    admin_group: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class OAuth2Profile:
    """OAuth2 profile endpoint protocol settings."""

    authorize_url: str
    token_url: str
    profile_url: str
    subject_field: str
    account_name_field: str | None = None
    scopes: tuple[str, ...] = ()
    headers: Mapping[str, str] = field(default_factory=dict)
    token_auth_method: Literal["client_secret_basic", "client_secret_post"] = (
        "client_secret_basic"
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class IdentityProvider:
    """Data-only identity provider specification."""

    client_id: str
    client_secret: str | None = None
    protocol: OpenIDConnect | OAuth2Profile
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


def _contains_issuer_template(issuer: str) -> bool:
    """Return whether an issuer contains template syntax."""
    return "{" in issuer or "}" in issuer


def _validate_issuer_template(protocol: OpenIDConnect) -> None:
    """Validate issuer template rules."""
    if not _contains_issuer_template(protocol.issuer):
        if protocol.issuer_claim is not None:
            _raise("issuer_claim_without_template")
        return

    parsed = urlsplit(protocol.issuer)
    segments = [
        segment
        for segment in parsed.path.split("/")
        if _contains_issuer_template(segment)
    ]
    if (
        _contains_issuer_template(parsed.netloc)
        or _contains_issuer_template(parsed.query)
        or len(segments) != 1
        or _ISSUER_PLACEHOLDER_RE.fullmatch(segments[0]) is None
    ):
        _raise("invalid_issuer_template")
    if protocol.issuer_claim is None:
        _raise("issuer_claim_required")


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


def _validate_headers(value: object) -> Mapping[str, str]:
    """Validate profile request headers."""
    if not isinstance(value, Mapping):
        _raise("invalid_headers")
    raw_headers = cast(Mapping[object, object], value)
    headers: dict[str, str] = {}
    for key, header_value in raw_headers.items():
        key = _validate_str(key, "invalid_headers", non_empty=True)
        header_value = _validate_str(header_value, "invalid_headers")
        if key.lower() in RESERVED_PROFILE_HEADERS:
            _raise("reserved_header")
        headers[key] = header_value
    return MappingProxyType(headers)


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


def _validate_oidc(
    protocol: OpenIDConnect, *, allow_insecure_transport: bool
) -> OpenIDConnect:
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
    if type(protocol.issuer_aliases) is not frozenset or any(
        type(alias) is not str or _contains_issuer_template(alias)
        for alias in protocol.issuer_aliases
    ):
        _raise("invalid_issuer_aliases")
    issuer_claim = (
        None
        if protocol.issuer_claim is None
        else _validate_str(
            protocol.issuer_claim, "invalid_issuer_claim", non_empty=True
        )
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
    validated = replace(
        protocol,
        issuer=issuer,
        discovery_url=discovery_url,
        issuer_aliases=frozenset(protocol.issuer_aliases),
        issuer_claim=issuer_claim,
        required_claims=required_claims,
        scopes=scopes,
        account_name_claim=account_name_claim,
        username_claim=username_claim,
        display_name_claim=display_name_claim,
        admin_group=admin_group,
    )
    _validate_issuer_template(validated)
    return validated


def _validate_oauth2_profile(
    protocol: OAuth2Profile, *, allow_insecure_transport: bool
) -> OAuth2Profile:
    """Validate OAuth2 profile protocol settings."""
    if protocol.token_auth_method not in ("client_secret_basic", "client_secret_post"):
        _raise("invalid_token_auth_method")
    return replace(
        protocol,
        authorize_url=_validate_url(
            protocol.authorize_url,
            "invalid_authorize_url",
            allow_insecure_transport=allow_insecure_transport,
        ),
        token_url=_validate_url(
            protocol.token_url,
            "invalid_token_url",
            allow_insecure_transport=allow_insecure_transport,
        ),
        profile_url=_validate_url(
            protocol.profile_url,
            "invalid_profile_url",
            allow_insecure_transport=allow_insecure_transport,
        ),
        subject_field=_validate_str(
            protocol.subject_field, "invalid_subject_field", non_empty=True
        ),
        account_name_field=_validate_optional_str(
            protocol.account_name_field, "invalid_account_name_field"
        ),
        scopes=_validate_tuple(protocol.scopes, "invalid_scopes"),
        headers=_validate_headers(protocol.headers),
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

    protocol = spec.protocol
    if type(protocol) is OpenIDConnect:
        protocol = _validate_oidc(
            protocol, allow_insecure_transport=allow_insecure_transport
        )
    elif type(protocol) is OAuth2Profile:
        if accounts is AccountPolicy.PROVISION:
            _raise("provision_requires_oidc")
        protocol = _validate_oauth2_profile(
            protocol, allow_insecure_transport=allow_insecure_transport
        )
    else:
        _raise("invalid_protocol")

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
    protocol = spec.protocol
    if type(protocol) is OpenIDConnect:
        protocol = replace(
            protocol,
            account_name_claim=None,
            username_claim="",
            display_name_claim="",
        )
    elif type(protocol) is OAuth2Profile:
        protocol = replace(protocol, account_name_field=None)
    payload = {
        "client_id": spec.client_id,
        "client_secret": spec.client_secret,
        "protocol": _jsonable(protocol),
        "accounts": spec.accounts.value,
        "allow_insecure_transport": spec.allow_insecure_transport,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
