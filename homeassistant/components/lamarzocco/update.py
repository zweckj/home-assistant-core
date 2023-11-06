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
from .entity import LaMarzoccoEntity, LaMarzoccoEntityDescription
from .lm_client import LaMarzoccoClient


@dataclass
class LaMarzoccoUpdateEntityDescriptionMixin:
    """Description of an La Marzocco Update."""

    current_fw_fn: Callable[[LaMarzoccoClient], str]
    latest_fw_fn: Callable[[LaMarzoccoClient], str]


@dataclass
class LaMarzoccoUpdateEntityDescription(
    UpdateEntityDescription,
    LaMarzoccoEntityDescription,
    LaMarzoccoUpdateEntityDescriptionMixin,
):
    """Description of an La Marzocco Switch."""


ENTITIES: tuple[LaMarzoccoUpdateEntityDescription, ...] = (
    LaMarzoccoUpdateEntityDescription(
        key="machine_firmware",
        translation_key="machine_firmware",
        device_class=UpdateDeviceClass.FIRMWARE,
        icon="mdi:cloud-download",
        current_fw_fn=lambda client: client.firmware_version,
        latest_fw_fn=lambda client: client.latest_firmware_version,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    LaMarzoccoUpdateEntityDescription(
        key="gateway_firmware",
        translation_key="gateway_firmware",
        device_class=UpdateDeviceClass.FIRMWARE,
        icon="mdi:cloud-download",
        current_fw_fn=lambda client: client.gateway_version,
        latest_fw_fn=lambda client: client.latest_gateway_version,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up update entities and services."""

    coordinator = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities(
        LaMarzoccoUpdateEntity(coordinator, config_entry, description)
        for description in ENTITIES
        if not description.extra_attributes
        or coordinator.lm.model_name in description.extra_attributes
    )


class LaMarzoccoUpdateEntity(LaMarzoccoEntity, UpdateEntity):
    """Entity representing the update state."""

    entity_description: LaMarzoccoUpdateEntityDescription

    @property
    def installed_version(self) -> str | None:
        """Return the current firmware version."""
        return self.entity_description.current_fw_fn(self._lm_client)

    @property
    def latest_version(self) -> str:
        """Return the latest firmware version."""
        return self.entity_description.latest_fw_fn(self._lm_client)
