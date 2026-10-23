"""OpenID Connect identity provider integration."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Set up OpenID Connect from a config entry."""


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Unload OpenID Connect."""
