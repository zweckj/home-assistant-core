"""Entra ID protocol for Microsoft Sign-In."""

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any, override

from homeassistant.components.auth import OidcClient, OidcIdTokenError, OpenIDConnect

TENANT_PLACEHOLDER = "{tenantid}"

_TENANT_ID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_TENANT_ID_RE = re.compile(_TENANT_ID)


class EntraClient(OidcClient):
    """OpenID Connect client for an Entra ID endpoint shared by many tenants.

    Its issuer names the tenant that signed the user in, so a subject is only
    unique together with the issuer filled in from the verified tid claim.
    """

    @override
    def canonical_issuer(self, claims: Mapping[str, Any]) -> str:
        """Return the issuer of the tenant that signed the user in."""
        tenant = claims.get("tid")
        if not isinstance(tenant, str) or not _TENANT_ID_RE.fullmatch(tenant):
            raise OidcIdTokenError("ID token tenant claim is missing or invalid")
        return self.issuer.replace(TENANT_PLACEHOLDER, tenant)

    @override
    def accepts_issuer(self, issuer: str) -> bool:
        """Return whether a stored issuer is that of any tenant."""
        prefix, _, suffix = self.issuer.partition(TENANT_PLACEHOLDER)
        return (
            issuer.startswith(prefix)
            and issuer.endswith(suffix)
            and _TENANT_ID_RE.fullmatch(issuer[len(prefix) : len(issuer) - len(suffix)])
            is not None
        )

    @override
    def verify_issuer_claim(self, claims: Mapping[str, Any]) -> None:
        """Verify the issuer claim names the tenant of the tid claim."""
        if claims.get("iss") != self.canonical_issuer(claims):
            raise OidcIdTokenError("ID token issuer does not match its tenant")


@dataclass(frozen=True, slots=True, kw_only=True)
class EntraOpenIDConnect(OpenIDConnect):
    """OpenID Connect for an Entra ID endpoint shared by many tenants.

    The issuer contains the tenant placeholder.
    """

    client_class = EntraClient
