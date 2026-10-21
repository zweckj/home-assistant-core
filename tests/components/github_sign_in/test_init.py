"""Tests for the GitHub Sign-In integration setup."""

from pytest_homeassistant.common import MockConfigEntry

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant


async def test_setup_unload_entry(
    hass: HomeAssistant, github_sign_in_entry: MockConfigEntry
) -> None:
    """Test setting up and unloading the integration."""
    github_sign_in_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(github_sign_in_entry.entry_id)
    await hass.async_block_till_done()
    assert github_sign_in_entry.state is ConfigEntryState.LOADED

    assert await hass.config_entries.async_unload(github_sign_in_entry.entry_id)
    await hass.async_block_till_done()
    assert github_sign_in_entry.state is ConfigEntryState.NOT_LOADED
