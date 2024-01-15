"""Binary Sensor platform for La Marzocco espresso machines."""

from collections.abc import Callable
from dataclasses import dataclass

from lmcloud import LMCloud as LaMarzoccoClient

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import LaMarzoccoEntity, LaMarzoccoEntityDescription


@dataclass(frozen=True, kw_only=True)
class LaMarzoccoBinarySensorEntityDescription(
    LaMarzoccoEntityDescription,
    BinarySensorEntityDescription,
):
    """Description of a La Marzocco binary sensor."""

    is_on_fn: Callable[[LaMarzoccoClient], bool]


ENTITIES: tuple[LaMarzoccoBinarySensorEntityDescription, ...] = (
    LaMarzoccoBinarySensorEntityDescription(
        key="water_reservoir",
        translation_key="water_reservoir",
        device_class=BinarySensorDeviceClass.PROBLEM,
        icon="mdi:water-well",
        is_on_fn=lambda lm: not lm.current_status.get("water_reservoir_contact"),
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    LaMarzoccoBinarySensorEntityDescription(
        key="brew_active",
        translation_key="brew_active",
        device_class=BinarySensorDeviceClass.RUNNING,
        icon="mdi:cup-water",
        is_on_fn=lambda lm: bool(lm.current_status.get("brew_active")),
        available_fn=lambda lm: lm.websocket_connected,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up binary sensor entities."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]

    entities: list[LaMarzoccoBinarySensorEntity] = []
    for description in ENTITIES:
        if coordinator.lm.model_name in description.supported_models:
            if (
                description.key == "brew_active"
                and config_entry.data.get(CONF_HOST) is None
            ):
                continue
            entities.append(LaMarzoccoBinarySensorEntity(coordinator, description))

    async_add_entities(entities)


class LaMarzoccoBinarySensorEntity(LaMarzoccoEntity, BinarySensorEntity):
    """Binary Sensor representing espresso machine water reservoir status."""

    entity_description: LaMarzoccoBinarySensorEntityDescription

    @property
    def is_on(self) -> bool:
        """Return true if the binary sensor is on."""
        return self.entity_description.is_on_fn(self.coordinator.lm)
