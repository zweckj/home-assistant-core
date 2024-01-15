"""Support for La Marzocco Switches."""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from lmcloud import LMCloud as LaMarzoccoClient
from lmcloud.const import LaMarzoccoUpdateableComponent

from homeassistant.components.update import (
    UpdateDeviceClass,
    UpdateEntity,
    UpdateEntityDescription,
    UpdateEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import LaMarzoccoUpdateCoordinator
from .entity import LaMarzoccoEntity, LaMarzoccoEntityDescription


@dataclass(frozen=True, kw_only=True)
class LaMarzoccoUpdateEntityDescription(
    LaMarzoccoEntityDescription,
    UpdateEntityDescription,
):
    """Description of an La Marzocco Switch."""

    current_fw_fn: Callable[[LaMarzoccoClient], str]
    latest_fw_fn: Callable[[LaMarzoccoClient], str]
    update_fn: Callable[[LaMarzoccoClient], Coroutine[Any, Any, bool]]


ENTITIES: tuple[LaMarzoccoUpdateEntityDescription, ...] = (
    LaMarzoccoUpdateEntityDescription(
        key="machine_firmware",
        translation_key="machine_firmware",
        device_class=UpdateDeviceClass.FIRMWARE,
        icon="mdi:cloud-download",
        current_fw_fn=lambda lm: lm.firmware_version,
        latest_fw_fn=lambda lm: lm.latest_firmware_version,
        update_fn=lambda lm: lm.update_firmware(LaMarzoccoUpdateableComponent.MACHINE),
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    LaMarzoccoUpdateEntityDescription(
        key="gateway_firmware",
        translation_key="gateway_firmware",
        device_class=UpdateDeviceClass.FIRMWARE,
        icon="mdi:cloud-download",
        current_fw_fn=lambda lm: lm.gateway_version,
        latest_fw_fn=lambda lm: lm.latest_gateway_version,
        update_fn=lambda lm: lm.update_firmware(LaMarzoccoUpdateableComponent.GATEWAY),
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create update entities."""

    coordinator = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities(
        LaMarzoccoUpdateEntity(coordinator, description)
        for description in ENTITIES
        if coordinator.lm.model_name in description.supported_models
    )


class LaMarzoccoUpdateEntity(LaMarzoccoEntity, UpdateEntity):
    """Entity representing the update state."""

    entity_description: LaMarzoccoUpdateEntityDescription

    def __init__(
        self,
        coordinator: LaMarzoccoUpdateCoordinator,
        description: LaMarzoccoUpdateEntityDescription,
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator, description)
        self._update_in_progress = False

    @property
    def supported_features(self) -> UpdateEntityFeature:
        """Flag supported features."""
        return UpdateEntityFeature.INSTALL

    @property
    def in_progress(self) -> bool:
        """Return if an update is in progress."""
        return self._update_in_progress

    @property
    def installed_version(self) -> str | None:
        """Return the current firmware version."""
        return self.entity_description.current_fw_fn(self.coordinator.lm)

    @property
    def latest_version(self) -> str:
        """Return the latest firmware version."""
        return self.entity_description.latest_fw_fn(self.coordinator.lm)

    async def async_install(
        self, version: str | None, backup: bool, **kwargs: Any
    ) -> None:
        """Install an update."""
        self._update_in_progress = True
        self.async_write_ha_state()
        success = await self.entity_description.update_fn(self.coordinator.lm)
        if not success:
            raise HomeAssistantError("Update failed")
        self._update_in_progress = False
        self.async_write_ha_state()
