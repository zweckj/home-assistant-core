"""Test OIDC identity provider specifications."""

from dataclasses import dataclass

import pytest

from homeassistant.auth.providers.oidc.spec import (
    IdentityProvider,
    IdentityProviderError,
    OpenIDConnect,
    trust_key,
    validate_identity_provider,
)

ISSUER = "https://idp.example.com"


@dataclass(frozen=True, slots=True, kw_only=True)
class _OtherOpenIDConnect(OpenIDConnect):
    """OpenID Connect protocol of another integration."""


def oidc_spec(**kwargs: object) -> IdentityProvider:
    """Return a valid OIDC identity provider spec."""
    return IdentityProvider(
        client_id=kwargs.pop("client_id", "client-id"),
        protocol=kwargs.pop("protocol", OpenIDConnect(issuer=ISSUER)),
        **kwargs,
    )


def reason_for(spec: object) -> str:
    """Return the validation error reason."""
    with pytest.raises(IdentityProviderError) as err:
        validate_identity_provider(spec)
    return err.value.reason


def test_validate_identity_provider_returns_an_equal_copy() -> None:
    """Test a valid specification is accepted unchanged."""
    spec = oidc_spec(
        client_secret="secret",
        protocol=OpenIDConnect(issuer=ISSUER, account_name_claim="email"),
    )

    validated = validate_identity_provider(spec)

    assert validated == spec
    assert validated is not spec


@pytest.mark.parametrize(
    ("spec", "reason"),
    [
        pytest.param(object(), "invalid_spec", id="not-spec"),
        pytest.param(oidc_spec(client_id=""), "invalid_client_id", id="empty-client-id"),
        pytest.param(
            oidc_spec(client_secret=123), "invalid_client_secret", id="bad-secret"
        ),
        pytest.param(oidc_spec(protocol=object()), "invalid_protocol", id="bad-protocol"),
        pytest.param(
            oidc_spec(protocol=_OtherOpenIDConnect(issuer=ISSUER)),
            "invalid_protocol",
            id="protocol-subclass",
        ),
        pytest.param(
            oidc_spec(protocol=OpenIDConnect(issuer=ISSUER, scopes=("profile",))),
            "invalid_scopes",
            id="missing-openid",
        ),
        pytest.param(
            oidc_spec(protocol=OpenIDConnect(issuer=ISSUER, scopes=["openid"])),  # type: ignore[arg-type]
            "invalid_scopes",
            id="scopes-type",
        ),
        pytest.param(
            oidc_spec(protocol=OpenIDConnect(issuer=ISSUER, account_name_claim=1)),  # type: ignore[arg-type]
            "invalid_account_name_claim",
            id="account-name-claim-type",
        ),
    ],
)
def test_validate_identity_provider_rejects_wrong_values(
    spec: object, reason: str
) -> None:
    """Test strict type and value validation."""
    assert reason_for(spec) == reason


@pytest.mark.parametrize(
    "url",
    [
        "http://idp.example.com",
        "https://user@idp.example.com",
        "https://idp.example.com#fragment",
        "https://",
        "https://[::1",
    ],
    ids=["http", "credentials", "fragment", "no-host", "bad-url"],
)
def test_validate_identity_provider_issuer_rules(url: str) -> None:
    """Test the issuer has to be an unambiguous https URL."""
    assert reason_for(oidc_spec(protocol=OpenIDConnect(issuer=url))) == (
        "invalid_issuer"
    )


def test_trust_key_ignores_the_account_name_claim() -> None:
    """Test a field that only labels identities does not change trust."""
    base = validate_identity_provider(
        oidc_spec(protocol=OpenIDConnect(issuer=ISSUER, account_name_claim="email"))
    )
    changed = validate_identity_provider(
        oidc_spec(protocol=OpenIDConnect(issuer=ISSUER, account_name_claim="upn"))
    )

    assert trust_key(base) == trust_key(changed)


@pytest.mark.parametrize(
    "changed",
    [
        oidc_spec(client_id="other"),
        oidc_spec(client_secret="secret"),
        oidc_spec(protocol=OpenIDConnect(issuer="https://other.example.com")),
        oidc_spec(protocol=OpenIDConnect(issuer=ISSUER, scopes=("openid",))),
    ],
    ids=["client-id", "secret", "issuer", "scopes"],
)
def test_trust_key_changes_security_relevant_fields(changed: IdentityProvider) -> None:
    """Test security-relevant settings change trust."""
    base = validate_identity_provider(oidc_spec())

    assert trust_key(base) != trust_key(validate_identity_provider(changed))
