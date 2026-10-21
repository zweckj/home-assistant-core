"""Tests for the OpenID Connect integration setup."""

from pytest_homeassistant.common import MockConfigEntry

from homeassistant.components.openid_connect.const import DOMAIN
from homeassistant.core import HomeAssistant


async def test_setup_unload_entry(hass: HomeAssistant) -> None:
    """Test setting up and unloading an entry."""
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(entry.entry_id)
    assert await hass.config_entries.async_unload(entry.entry_id)
