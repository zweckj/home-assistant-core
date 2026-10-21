"""Test Microsoft Sign-In setup."""

from pytest_homeassistant.common import MockConfigEntry

from homeassistant.components.microsoft_sign_in.const import DOMAIN
from homeassistant.core import HomeAssistant


async def test_setup_and_unload_entry(hass: HomeAssistant) -> None:
    """Test setup and unload entry."""
    entry = MockConfigEntry(domain=DOMAIN)
    entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert await hass.config_entries.async_unload(entry.entry_id)
