"""Tests for the Entra ID client of Microsoft Sign-In."""

from typing import Any

import pytest

from homeassistant.components.auth import OidcIdTokenError
from homeassistant.components.microsoft_sign_in.client import EntraClient
from homeassistant.core import HomeAssistant

TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0"
TENANT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
TENANT_ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"


@pytest.fixture
def client(hass: HomeAssistant) -> EntraClient:
    """Return a client for the shared Entra ID endpoint."""
    return EntraClient(hass, issuer=TEMPLATE, client_id="client-id")


def test_canonical_issuer_names_the_tenant(client: EntraClient) -> None:
    """Test credentials are keyed by the issuer of the signing tenant."""
    assert client.canonical_issuer({"tid": TENANT_ID}) == TENANT_ISSUER


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({}, id="missing"),
        pytest.param({"tid": 1}, id="not-a-string"),
        pytest.param({"tid": "contoso"}, id="not-a-guid"),
        pytest.param({"tid": "../other"}, id="path"),
        pytest.param({"tid": TENANT_ID.upper()}, id="upper-case"),
    ],
)
def test_canonical_issuer_rejects_bad_tenant_claims(
    client: EntraClient, claims: dict[str, Any]
) -> None:
    """Test only a tenant ID can fill in the issuer."""
    with pytest.raises(OidcIdTokenError, match="tenant claim"):
        client.canonical_issuer(claims)


def test_verify_issuer_claim_accepts_the_tenant_issuer(client: EntraClient) -> None:
    """Test an issuer matching the tenant claim is accepted."""
    client.verify_issuer_claim({"iss": TENANT_ISSUER, "tid": TENANT_ID})


@pytest.mark.parametrize(
    "issuer",
    [
        pytest.param(TEMPLATE, id="template"),
        pytest.param(
            "https://login.microsoftonline.com/bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee/v2.0",
            id="other-tenant",
        ),
        pytest.param(None, id="missing"),
    ],
)
def test_verify_issuer_claim_rejects_another_tenant(
    client: EntraClient, issuer: str | None
) -> None:
    """Test the issuer has to be that of the tenant claim."""
    with pytest.raises(OidcIdTokenError, match="its tenant"):
        client.verify_issuer_claim({"iss": issuer, "tid": TENANT_ID})


@pytest.mark.parametrize(
    ("issuer", "accepted"),
    [
        pytest.param(TENANT_ISSUER, True, id="tenant"),
        pytest.param(TEMPLATE, False, id="template"),
        pytest.param("https://login.microsoftonline.com/../bad/v2.0", False, id="path"),
        pytest.param(f"https://evil.example.com/{TENANT_ID}/v2.0", False, id="host"),
        pytest.param(f"{TENANT_ISSUER}/extra", False, id="suffix"),
    ],
)
def test_accepts_issuer(client: EntraClient, issuer: str, accepted: bool) -> None:
    """Test stored issuers of any tenant belong to the client."""
    assert client.accepts_issuer(issuer) is accepted
