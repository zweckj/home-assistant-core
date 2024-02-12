"""The La Marzocco integration."""

import logging

from lmcloud.client_bluetooth import LaMarzoccoBluetoothClient
from lmcloud.client_cloud import LaMarzoccoCloudClient
from lmcloud.exceptions import AuthFail, RequestNotSuccessful

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_MAC,
    CONF_MODEL,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_TOKEN,
    CONF_USERNAME,
    Platform,
)
from homeassistant.core import HomeAssistant

from .const import CONF_USE_BLUETOOTH, DOMAIN
from .coordinator import LaMarzoccoMachineUpdateCoordinator

PLATFORMS = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.CALENDAR,
    Platform.NUMBER,
    Platform.SELECT,
    Platform.SENSOR,
    Platform.SWITCH,
    Platform.UPDATE,
]

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up La Marzocco as config entry."""

    if entry.data.get(CONF_USE_BLUETOOTH, True):
        assert entry.unique_id

        # check if there are any bluetooth adapters to use
        count = bluetooth.async_scanner_count(hass, connectable=True)
        if count > 0:
            _LOGGER.debug("Found Bluetooth adapters, initializing with Bluetooth")
            bt_devices = await LaMarzoccoBluetoothClient.discover_devices(
                scanner=bluetooth.async_get_scanner(hass)
            )
            for bt_device in bt_devices:
                if bt_device.name is not None and entry.unique_id in bt_device.name:
                    # found a device, add MAC address to config entry
                    _LOGGER.debug("Found Bluetooth device %s", bt_device.name)
                    new_data = entry.data.copy()
                    new_data[CONF_MAC] = bt_device.address
                    hass.config_entries.async_update_entry(
                        entry,
                        data=new_data,
                    )

    coordinator = LaMarzoccoMachineUpdateCoordinator(hass)

    await coordinator.async_config_entry_first_refresh()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    async def update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
        await hass.config_entries.async_reload(entry.entry_id)

    entry.async_on_unload(entry.add_update_listener(update_listener))

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
            _LOGGER.error("Migration failed with error %s", exc)
            return False

        assert entry.unique_id is not None
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

        if CONF_MAC in entry.data:
            v2_data[CONF_MAC] = entry.data[CONF_MAC]

        entry.version = 2
        hass.config_entries.async_update_entry(
            entry,
            data=v2_data,
        )
        _LOGGER.debug("Migrated La Marzocco config entry to version 2")
    return True
