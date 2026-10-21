"""Tests for the Google Sign-In client."""

import pytest

from homeassistant.components.auth import OidcIdTokenError
from homeassistant.components.google_sign_in.client import ISSUER, GoogleClient
from homeassistant.core import HomeAssistant


@pytest.mark.parametrize("issuer", [ISSUER, "accounts.google.com"])
def test_verify_issuer_claim_accepts_both_spellings(
    hass: HomeAssistant, issuer: str
) -> None:
    """Test Google's issuer is accepted with and without its scheme."""
    client = GoogleClient(hass, issuer=ISSUER, client_id="client-id")

    client.verify_issuer_claim({"iss": issuer})
    assert client.canonical_issuer({"iss": issuer}) == ISSUER


@pytest.mark.parametrize("issuer", ["https://evil.example.com", None])
def test_verify_issuer_claim_rejects_other_issuers(
    hass: HomeAssistant, issuer: str | None
) -> None:
    """Test any other issuer is refused."""
    client = GoogleClient(hass, issuer=ISSUER, client_id="client-id")

    with pytest.raises(OidcIdTokenError, match="Google"):
        client.verify_issuer_claim({"iss": issuer})
