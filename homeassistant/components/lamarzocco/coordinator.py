"""Coordinator for La Marzocco API."""

from abc import abstractmethod
from datetime import timedelta
import logging
from typing import Any, Generic, TypeVar

from lmcloud.client_cloud import LaMarzoccoCloudClient
from lmcloud.client_local import LaMarzoccoLocalClient
from lmcloud.exceptions import AuthFail, RequestNotSuccessful
from lmcloud.lm_device import LaMarzoccoDevice
from lmcloud.lm_machine import LaMarzoccoMachine

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_MODEL,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_TOKEN,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import CONF_MACHINE, DOMAIN

SCAN_INTERVAL = timedelta(seconds=30)

_LOGGER = logging.getLogger(__name__)

_DeviceT = TypeVar("_DeviceT", bound=LaMarzoccoDevice)


class LaMarzoccoUpdateCoordinator(DataUpdateCoordinator[None], Generic[_DeviceT]):
    """Class to handle fetching data from the La Marzocco API centrally."""

    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize coordinator."""
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=SCAN_INTERVAL)
        self.local_connection_configured = (
            self.config_entry.data.get(CONF_HOST) is not None
        )

        cloud_client = LaMarzoccoCloudClient(
            username=self.config_entry.data[CONF_USERNAME],
            password=self.config_entry.data[CONF_PASSWORD],
        )

        # initialize local API
        local_client: LaMarzoccoLocalClient | None = None
        if (host := self.config_entry.data.get(CONF_HOST)) is not None:
            _LOGGER.debug("Initializing local API")
            local_client = LaMarzoccoLocalClient(
                host=host,
                local_bearer=self.config_entry.data[CONF_TOKEN],
                client=get_async_client(self.hass),
            )

        self.device = self._init_device(
            model=self.config_entry.data[CONF_MODEL],
            serial_number=self.config_entry.data[CONF_MACHINE],
            name=self.config_entry.data[CONF_NAME],
            cloud_client=cloud_client,
            local_client=local_client,
        )

    @abstractmethod
    def _init_device(*args: Any, **kwargs: Any) -> _DeviceT:
        """Initialize the La Marzocco Device."""

    async def _async_update_data(self) -> None:
        """Fetch data from API endpoint."""

        try:
            await self.device.get_config()
        except AuthFail as ex:
            msg = "Authentication failed."
            _LOGGER.debug(msg, exc_info=True)
            raise ConfigEntryAuthFailed(msg) from ex
        except RequestNotSuccessful as ex:
            _LOGGER.debug(ex, exc_info=True)
            raise UpdateFailed("Querying API failed. Error: %s" % ex) from ex

        _LOGGER.debug("Current status: %s", str(self.device.config))


class LaMarzoccoMachineUpdateCoordinator(
    LaMarzoccoUpdateCoordinator[LaMarzoccoMachine]
):
    """Class to handle fetching data from the La Marzocco API for a machine."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize coordinator."""

        super().__init__(hass)

        if self.config_entry.data.get(CONF_HOST) is not None:
            _LOGGER.debug("Init WebSocket in background task")

            self.config_entry.async_create_background_task(
                hass=self.hass,
                target=self.device.websocket_connect(
                    notify_callback=self.async_update_listeners
                ),
                name="lm_websocket_task",
            )

    def _init_device(self, *args: Any, **kwargs: Any) -> LaMarzoccoMachine:
        """Initialize the La Marzocco Machine."""
        return LaMarzoccoMachine(*args, **kwargs)
