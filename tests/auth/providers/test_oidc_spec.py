"""Test OIDC identity provider specifications."""

from dataclasses import asdict
from datetime import timedelta
from types import MappingProxyType

import pytest

from homeassistant.auth.providers.oidc.const import (
    MAX_REVALIDATE_INTERVAL,
    MIN_REVALIDATE_INTERVAL,
)
from homeassistant.auth.providers.oidc.spec import (
    AccountPolicy,
    Equals,
    IdentityProvider,
    IdentityProviderError,
    NotEquals,
    OAuth2Profile,
    OneOf,
    OpenIDConnect,
    trust_key,
    validate_identity_provider,
)

ISSUER = "https://idp.example.com"


def oidc_spec(**kwargs: object) -> IdentityProvider:
    """Return a valid OIDC identity provider spec."""
    return IdentityProvider(
        client_id=kwargs.pop("client_id", "client-id"),
        protocol=kwargs.pop("protocol", OpenIDConnect(issuer=ISSUER)),
        **kwargs,
    )


def profile_spec(**kwargs: object) -> IdentityProvider:
    """Return a valid OAuth2 profile identity provider spec."""
    return IdentityProvider(
        client_id=kwargs.pop("client_id", "client-id"),
        protocol=kwargs.pop(
            "protocol",
            OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="id",
            ),
        ),
        **kwargs,
    )


def reason_for(spec: object) -> str:
    """Return the validation error reason."""
    with pytest.raises(IdentityProviderError) as err:
        validate_identity_provider(spec)
    return err.value.reason


def test_validate_identity_provider_returns_immutable_copy() -> None:
    """Test a valid specification is accepted and normalized."""
    spec = oidc_spec(
        protocol=OpenIDConnect(
            issuer=ISSUER,
            required_claims={"hd": Equals(value="example.com")},
        )
    )

    validated = validate_identity_provider(spec)

    assert validated == spec
    assert isinstance(validated.protocol.required_claims, MappingProxyType)


@pytest.mark.parametrize(
    ("spec", "reason"),
    [
        (object(), "invalid_spec"),
        (oidc_spec(client_id=""), "invalid_client_id"),
        (oidc_spec(client_secret=123), "invalid_client_secret"),
        (oidc_spec(accounts="link"), "invalid_account_policy"),
        (oidc_spec(allow_insecure_transport="yes"), "invalid_allow_insecure_transport"),
        (oidc_spec(protocol=object()), "invalid_protocol"),
    ],
    ids=[
        "not-spec",
        "empty-client-id",
        "bad-secret",
        "bad-policy",
        "bad-insecure-flag",
        "bad-protocol",
    ],
)
def test_validate_identity_provider_rejects_wrong_types(
    spec: object, reason: str
) -> None:
    """Test strict type validation."""
    assert reason_for(spec) == reason


@pytest.mark.parametrize(
    ("url", "allow_insecure_transport", "reason"),
    [
        ("http://idp.example.com", False, "invalid_issuer"),
        ("https://user@idp.example.com", False, "invalid_issuer"),
        ("https://idp.example.com#fragment", False, "invalid_issuer"),
        ("http://idp.example.com", True, "valid"),
    ],
    ids=["http", "credentials", "fragment", "allowed-http"],
)
def test_validate_identity_provider_url_rules(
    url: str, allow_insecure_transport: bool, reason: str
) -> None:
    """Test URL validation rules."""
    spec = oidc_spec(
        protocol=OpenIDConnect(issuer=url),
        allow_insecure_transport=allow_insecure_transport,
    )

    if reason == "valid":
        assert validate_identity_provider(spec).protocol.issuer == url
    else:
        assert reason_for(spec) == reason


@pytest.mark.parametrize(
    ("protocol", "reason"),
    [
        (
            OpenIDConnect(
                issuer="https://login.example.com/{tenant}/v2.0",
                issuer_claim=None,
            ),
            "issuer_claim_required",
        ),
        (
            OpenIDConnect(issuer=ISSUER, issuer_claim="tid"),
            "issuer_claim_without_template",
        ),
        (
            OpenIDConnect(
                issuer="https://login.example.com/{tenant}/{other}",
                issuer_claim="tid",
            ),
            "invalid_issuer_template",
        ),
        (
            OpenIDConnect(issuer=ISSUER, issuer_aliases=frozenset({"https://{bad}"})),
            "invalid_issuer_aliases",
        ),
    ],
    ids=["missing-claim", "claim-without-template", "two-templates", "alias-template"],
)
def test_validate_identity_provider_template_rules(
    protocol: OpenIDConnect, reason: str
) -> None:
    """Test issuer template validation."""
    assert reason_for(oidc_spec(protocol=protocol)) == reason


def test_validate_identity_provider_accepts_issuer_template() -> None:
    """Test one issuer template segment with a claim is valid."""
    spec = validate_identity_provider(
        oidc_spec(
            protocol=OpenIDConnect(
                issuer="https://login.example.com/{tenant}/v2.0",
                issuer_claim="tid",
            )
        )
    )

    assert isinstance(spec.protocol, OpenIDConnect)
    assert spec.protocol.issuer_claim == "tid"


@pytest.mark.parametrize(
    ("protocol", "reason"),
    [
        (OpenIDConnect(issuer=ISSUER, scopes=("profile",)), "invalid_scopes"),
        (
            OpenIDConnect(issuer=ISSUER, required_claims={"hd": object()}),
            "invalid_claim_rule",
        ),
        (
            OpenIDConnect(
                issuer=ISSUER, required_claims={"hd": OneOf(values=frozenset())}
            ),
            "invalid_claim_rule",
        ),
    ],
    ids=["missing-openid", "bad-rule", "empty-one-of"],
)
def test_validate_identity_provider_claim_rules(
    protocol: OpenIDConnect, reason: str
) -> None:
    """Test OIDC scopes and claim rules."""
    assert reason_for(oidc_spec(protocol=protocol)) == reason


@pytest.mark.parametrize(
    ("spec", "reason"),
    [
        (
            profile_spec(accounts=AccountPolicy.PROVISION),
            "provision_requires_oidc",
        ),
        (
            oidc_spec(
                accounts=AccountPolicy.LINK,
                revalidate_interval=timedelta(seconds=MIN_REVALIDATE_INTERVAL),
            ),
            "revalidate_interval_not_allowed",
        ),
        (
            oidc_spec(accounts=AccountPolicy.PROVISION),
            "revalidate_interval_required",
        ),
        (
            oidc_spec(
                accounts=AccountPolicy.PROVISION,
                revalidate_interval=timedelta(seconds=MIN_REVALIDATE_INTERVAL - 1),
            ),
            "invalid_revalidate_interval",
        ),
        (
            oidc_spec(
                accounts=AccountPolicy.PROVISION,
                revalidate_interval=timedelta(seconds=MAX_REVALIDATE_INTERVAL + 1),
            ),
            "invalid_revalidate_interval",
        ),
    ],
    ids=[
        "profile-provision",
        "link-interval",
        "provision-missing-interval",
        "interval-too-low",
        "interval-too-high",
    ],
)
def test_validate_identity_provider_account_policy_rules(
    spec: IdentityProvider, reason: str
) -> None:
    """Test account policy validation."""
    assert reason_for(spec) == reason


@pytest.mark.parametrize(
    ("headers", "reason"),
    [
        ({"Accept": "application/json"}, "valid"),
        ({"Authorization": "Bearer secret"}, "reserved_header"),
        ({"Host": "idp.example.com"}, "reserved_header"),
        ({"X-Test": object()}, "invalid_headers"),
    ],
    ids=["valid", "authorization", "host", "bad-value"],
)
def test_validate_identity_provider_profile_headers(
    headers: dict[str, object], reason: str
) -> None:
    """Test OAuth2 profile header rules."""
    spec = profile_spec(
        protocol=OAuth2Profile(
            authorize_url="https://idp.example.com/authorize",
            token_url="https://idp.example.com/token",
            profile_url="https://idp.example.com/profile",
            subject_field="id",
            headers=headers,
        )
    )

    if reason == "valid":
        assert (
            validate_identity_provider(spec).protocol.headers["Accept"]
            == "application/json"
        )
    else:
        assert reason_for(spec) == reason


def test_trust_key_ignores_display_only_claims() -> None:
    """Test profile-only and display-only fields do not change trust."""
    base = validate_identity_provider(
        oidc_spec(
            protocol=OpenIDConnect(
                issuer=ISSUER,
                account_name_claim="email",
                username_claim="preferred_username",
                display_name_claim="name",
            )
        )
    )
    changed = validate_identity_provider(
        oidc_spec(
            protocol=OpenIDConnect(
                issuer=ISSUER,
                account_name_claim="upn",
                username_claim="nickname",
                display_name_claim="displayName",
            )
        )
    )

    assert trust_key(base) == trust_key(changed)


@pytest.mark.parametrize(
    "changed",
    [
        oidc_spec(client_id="other"),
        oidc_spec(client_secret="secret"),
        oidc_spec(protocol=OpenIDConnect(issuer="https://other.example.com")),
        oidc_spec(
            protocol=OpenIDConnect(
                issuer=ISSUER,
                required_claims={"hd": NotEquals(value="blocked.example")},
            )
        ),
        oidc_spec(
            accounts=AccountPolicy.PROVISION, revalidate_interval=timedelta(hours=1)
        ),
        oidc_spec(allow_insecure_transport=True),
    ],
    ids=["client-id", "secret", "issuer", "claims", "policy", "transport"],
)
def test_trust_key_changes_security_relevant_fields(changed: IdentityProvider) -> None:
    """Test security-relevant settings change trust."""
    base = validate_identity_provider(oidc_spec())

    assert trust_key(base) != trust_key(validate_identity_provider(changed))


def test_validate_identity_provider_rejects_non_mapping_required_claims() -> None:
    """Test required claims must be a mapping."""
    spec = oidc_spec(
        protocol=OpenIDConnect(issuer=ISSUER, required_claims=("hd", "example.com"))
    )

    assert reason_for(spec) == "invalid_required_claims"


@pytest.mark.parametrize(
    ("spec", "reason"),
    [
        pytest.param(
            oidc_spec(protocol=OpenIDConnect(issuer="https://[::1")),
            "invalid_issuer",
            id="bad-url",
        ),
        pytest.param(
            oidc_spec(
                protocol=OpenIDConnect(
                    issuer=ISSUER, discovery_url="http://idp.example.com/discovery"
                )
            ),
            "invalid_discovery_url",
            id="discovery-url",
        ),
        pytest.param(
            profile_spec(
                protocol=OAuth2Profile(
                    authorize_url="https://idp.example.com/authorize",
                    token_url="https://idp.example.com/token",
                    profile_url="https://idp.example.com/profile",
                    subject_field="id",
                    token_auth_method="bad",  # type: ignore[arg-type]
                )
            ),
            "invalid_token_auth_method",
            id="token-auth-method",
        ),
        pytest.param(
            oidc_spec(protocol=OpenIDConnect(issuer=ISSUER, scopes=["openid"])),  # type: ignore[arg-type]
            "invalid_scopes",
            id="scopes-type",
        ),
        pytest.param(
            profile_spec(
                protocol=OAuth2Profile(
                    authorize_url="https://idp.example.com/authorize",
                    token_url="https://idp.example.com/token",
                    profile_url="https://idp.example.com/profile",
                    subject_field="id",
                    headers={"authorization": "Bearer token"},
                )
            ),
            "reserved_header",
            id="reserved-header",
        ),
        pytest.param(
            profile_spec(
                protocol=OAuth2Profile(
                    authorize_url="https://idp.example.com/authorize",
                    token_url="https://idp.example.com/token",
                    profile_url="https://idp.example.com/profile",
                    subject_field="id",
                    headers=(("x-api-version", "1"),),  # type: ignore[arg-type]
                )
            ),
            "invalid_headers",
            id="headers-type",
        ),
        pytest.param(
            oidc_spec(
                accounts=AccountPolicy.PROVISION,
                revalidate_interval=300,  # type: ignore[arg-type]
            ),
            "invalid_revalidate_interval",
            id="interval-type",
        ),
    ],
)
def test_validate_identity_provider_additional_invalid_fields(
    spec: IdentityProvider, reason: str
) -> None:
    """Test additional validation branches."""
    assert reason_for(spec) == reason


def test_trust_key_serializes_oauth2_profile_tuple_fields() -> None:
    """Test OAuth2 profile tuple fields participate in trust hashing."""
    first = validate_identity_provider(
        profile_spec(
            protocol=OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="id",
                scopes=("read:user",),
            )
        )
    )
    second = validate_identity_provider(
        profile_spec(
            protocol=OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="id",
                scopes=("read:user", "user:email"),
            )
        )
    )

    assert trust_key(first) != trust_key(second)


def test_trust_key_ignores_oauth2_profile_account_name_field() -> None:
    """Test OAuth2 profile account name field does not change trust."""
    base = validate_identity_provider(
        profile_spec(
            protocol=OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="id",
                account_name_field="login",
            )
        )
    )
    changed = validate_identity_provider(
        profile_spec(
            protocol=OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="id",
                account_name_field="name",
            )
        )
    )

    assert trust_key(base) == trust_key(changed)


@pytest.mark.parametrize(
    "protocol",
    [
        pytest.param(
            OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="node_id",
                account_name_field="login",
            ),
            id="subject-field",
        ),
        pytest.param(
            OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://api.example.com/me",
                subject_field="id",
                account_name_field="login",
            ),
            id="profile-url",
        ),
        pytest.param(
            OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="id",
                account_name_field="login",
                headers={"X-Api-Version": "2"},
            ),
            id="headers",
        ),
        pytest.param(
            OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="id",
                account_name_field="login",
                token_auth_method="client_secret_post",
            ),
            id="token-auth-method",
        ),
    ],
)
def test_trust_key_changes_oauth2_profile_security_fields(
    protocol: OAuth2Profile,
) -> None:
    """Test OAuth2 profile security-relevant fields change trust."""
    base = validate_identity_provider(
        profile_spec(
            protocol=OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="id",
                account_name_field="login",
            )
        )
    )

    assert trust_key(base) != trust_key(
        validate_identity_provider(profile_spec(protocol=protocol))
    )


def test_default_oidc_spec_can_be_serialized_with_asdict() -> None:
    """Test default OIDC mapping fields work with dataclasses.asdict."""
    data = asdict(
        IdentityProvider(
            client_id="client-id",
            protocol=OpenIDConnect(issuer=ISSUER),
        )
    )

    assert data["protocol"]["required_claims"] == {}


def test_default_oauth2_profile_spec_can_be_serialized_with_asdict() -> None:
    """Test default OAuth2 profile mapping fields work with dataclasses.asdict."""
    data = asdict(
        IdentityProvider(
            client_id="client-id",
            protocol=OAuth2Profile(
                authorize_url="https://idp.example.com/authorize",
                token_url="https://idp.example.com/token",
                profile_url="https://idp.example.com/profile",
                subject_field="id",
            ),
        )
    )

    assert data["protocol"]["headers"] == {}
