"""Compatibility imports for the Home Assistant pytest helpers."""

import pytest

from homeassistant.auth.providers import oidc
from homeassistant.core import HomeAssistant


@pytest.fixture
def custom_integrations_enabled() -> bool:
    """Control custom integration loading."""
    return False


@pytest.fixture
async def oidc_auth(hass: HomeAssistant) -> oidc.OidcAuthProvider:
    """Load the identity provider engine."""
    prv = oidc.OidcAuthProvider(hass, hass.auth._store, {"type": "oidc"})
    await prv.async_initialize()
    hass.auth._providers[(prv.type, prv.id)] = prv
    return prv
