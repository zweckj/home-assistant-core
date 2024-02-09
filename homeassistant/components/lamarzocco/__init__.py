"""The La Marzocco integration."""

import logging

from lmcloud.client_cloud import LaMarzoccoCloudClient
from lmcloud.const import MachineModel
from lmcloud.exceptions import AuthFail, RequestNotSuccessful

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_MODEL,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_TOKEN,
    CONF_USERNAME,
    Platform,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryError

from .const import DOMAIN
from .coordinator import LaMarzoccoMachineUpdateCoordinator

PLATFORMS = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.NUMBER,
    Platform.SELECT,
    Platform.SENSOR,
    Platform.SWITCH,
    Platform.UPDATE,
]

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up La Marzocco as config entry."""

    if (model := entry.data[CONF_MODEL]) in MachineModel:
        coordinator = LaMarzoccoMachineUpdateCoordinator(hass)
    else:
        raise ConfigEntryError(f"Invalid model {model}")

    await coordinator.async_config_entry_first_refresh()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def async_migrate_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Migrate config entry."""
    if entry.version == 1:
        cloud_client = LaMarzoccoCloudClient(
            username=entry.data[CONF_USERNAME],
            password=entry.data[CONF_PASSWORD],
        )
        try:
            fleet = await cloud_client.get_customer_fleet()
        except (AuthFail, RequestNotSuccessful) as exc:
            raise ConfigEntryError("Migration failed") from exc

        assert entry.unique_id
        device = fleet[entry.unique_id]
        v2_data = {
            CONF_USERNAME: entry.data[CONF_USERNAME],
            CONF_PASSWORD: entry.data[CONF_PASSWORD],
            CONF_MODEL: device.model,
            CONF_NAME: device.name,
            CONF_TOKEN: device.communication_key,
        }

        if CONF_HOST in entry.data:
            v2_data[CONF_HOST] = entry.data[CONF_HOST]

        entry.version = 2
        hass.config_entries.async_update_entry(
            entry,
            data=v2_data,
        )
        _LOGGER.debug("Migrated La Marzocco config entry to version 2")
    return True
