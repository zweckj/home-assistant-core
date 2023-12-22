"""Water heater platform for La Marzocco espresso machines."""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from homeassistant.components.number import (
    NumberDeviceClass,
    NumberEntity,
    NumberEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PRECISION_TENTHS, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from lmcloud.const import LaMarzoccoModel

from .const import DOMAIN
from .entity import LaMarzoccoEntity, LaMarzoccoEntityDescription
from .lm_client import LaMarzoccoClient


@dataclass
class LaMarzoccoNumberEntityDescriptionMixin:
    """Description of an La Marzocco Water Heater."""

    native_value_fn: Callable[[LaMarzoccoClient], float | int]
    set_value_fn: Callable[[LaMarzoccoClient, float | int], Coroutine[Any, Any, bool]]
    supported_models: tuple[LaMarzoccoModel, ...]


@dataclass
class LaMarzoccoNumberEntityDescription(
    NumberEntityDescription,
    LaMarzoccoEntityDescription,
    LaMarzoccoNumberEntityDescriptionMixin,
):
    """Description of an La Marzocco Water Heater."""


ENTITIES: tuple[LaMarzoccoNumberEntityDescription, ...] = (
    LaMarzoccoNumberEntityDescription(
        key="coffee_temp",
        translation_key="coffee_temp",
        icon="mdi:coffee-maker",
        device_class=NumberDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        native_step=PRECISION_TENTHS,
        native_min_value=85,
        native_max_value=104,
        set_value_fn=lambda client, temp: client.set_coffee_temp(temp),
        native_value_fn=lambda client: client.current_status.get("coffee_set_temp", 0),
        supported_models=(
            LaMarzoccoModel.GS3_AV,
            LaMarzoccoModel.GS3_MP,
            LaMarzoccoModel.LINEA_MICRA,
            LaMarzoccoModel.LINEA_MINI,
        ),
    ),
    LaMarzoccoNumberEntityDescription(
        key="steam_temp",
        translation_key="steam_temp",
        icon="mdi:kettle-steam",
        device_class=NumberDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        native_step=PRECISION_TENTHS,
        native_min_value=126,
        native_max_value=131,
        set_value_fn=lambda client, temp: client.set_steam_temp(round(temp)),
        native_value_fn=lambda client: client.current_status.get("steam_set_temp", 0),
        supported_models=(
            LaMarzoccoModel.GS3_AV,
            LaMarzoccoModel.GS3_MP,
        ),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up water heater type entities."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]

    async_add_entities(
        LaMarzoccoNumberEntity(coordinator, hass, description)
        for description in ENTITIES
        if coordinator.data.model_name in description.supported_models
    )


class LaMarzoccoNumberEntity(LaMarzoccoEntity, NumberEntity):
    """Water heater representing espresso machine temperature data."""

    entity_description: LaMarzoccoNumberEntityDescription

    @property
    def native_value(self) -> float:
        """Return the current value."""
        return self.entity_description.native_value_fn(self._lm_client)

    async def async_set_native_value(self, value: float) -> None:
        """Set the value."""
        await self.entity_description.set_value_fn(self._lm_client, value)
        self.async_write_ha_state()
