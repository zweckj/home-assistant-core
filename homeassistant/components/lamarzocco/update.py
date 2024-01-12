"""Support for La Marzocco Switches."""

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.update import (
    UpdateDeviceClass,
    UpdateEntity,
    UpdateEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
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

    current_fw_fn: Callable[[LaMarzoccoUpdateCoordinator], str]
    latest_fw_fn: Callable[[LaMarzoccoUpdateCoordinator], str]


ENTITIES: tuple[LaMarzoccoUpdateEntityDescription, ...] = (
    LaMarzoccoUpdateEntityDescription(
        key="machine_firmware",
        translation_key="machine_firmware",
        device_class=UpdateDeviceClass.FIRMWARE,
        icon="mdi:cloud-download",
        current_fw_fn=lambda coordinator: coordinator.lm.firmware_version,
        latest_fw_fn=lambda coordinator: coordinator.lm.latest_firmware_version,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    LaMarzoccoUpdateEntityDescription(
        key="gateway_firmware",
        translation_key="gateway_firmware",
        device_class=UpdateDeviceClass.FIRMWARE,
        icon="mdi:cloud-download",
        current_fw_fn=lambda coordinator: coordinator.lm.gateway_version,
        latest_fw_fn=lambda coordinator: coordinator.lm.latest_gateway_version,
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

    @property
    def installed_version(self) -> str | None:
        """Return the current firmware version."""
        return self.entity_description.current_fw_fn(self.coordinator)

    @property
    def latest_version(self) -> str:
        """Return the latest firmware version."""
        return self.entity_description.latest_fw_fn(self.coordinator)
