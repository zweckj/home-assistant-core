"""Google protocol for Google Sign-In."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, override

from homeassistant.components.auth import OidcClient, OidcIdTokenError, OpenIDConnect

ISSUER = "https://accounts.google.com"
# Google documents ID tokens carrying the issuer without its scheme as well.
ISSUER_WITHOUT_SCHEME = "accounts.google.com"


class GoogleClient(OidcClient):
    """OpenID Connect client accepting both spellings of Google's issuer."""

    @override
    def verify_issuer_claim(self, claims: Mapping[str, Any]) -> None:
        """Verify the issuer claim names Google."""
        if claims.get("iss") not in (self.issuer, ISSUER_WITHOUT_SCHEME):
            raise OidcIdTokenError("ID token issuer does not match Google")


@dataclass(frozen=True, slots=True, kw_only=True)
class GoogleOpenIDConnect(OpenIDConnect):
    """OpenID Connect with Google's issuer."""

    client_class = GoogleClient
