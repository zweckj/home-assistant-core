"""Water heater platform for La Marzocco espresso machines."""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from homeassistant.components.water_heater import (
    STATE_ELECTRIC,
    STATE_OFF,
    WaterHeaterEntity,
    WaterHeaterEntityEntityDescription,
    WaterHeaterEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PRECISION_TENTHS, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import LaMarzoccoEntity, LaMarzoccoEntityDescription
from .lm_client import LaMarzoccoClient

OPERATION_MODES = [STATE_ELECTRIC, STATE_OFF]


@dataclass
class LaMarzoccoWaterHeaterEntityDescriptionMixin:
    """Description of an La Marzocco Water Heater."""

    min_temp: float
    max_temp: float
    current_op_fn: Callable[[LaMarzoccoClient], bool]
    current_temp_fn: Callable[[LaMarzoccoClient], float | int]
    target_temp_fn: Callable[[LaMarzoccoClient], float | int]
    control_fn: Callable[[LaMarzoccoClient, bool], Coroutine[Any, Any, bool]]
    set_temp_fn: Callable[[LaMarzoccoClient, float | int], Coroutine[Any, Any, bool]]


@dataclass
class LaMarzoccoWaterHeaterEntityDescription(
    WaterHeaterEntityEntityDescription,
    LaMarzoccoEntityDescription,
    LaMarzoccoWaterHeaterEntityDescriptionMixin,
):
    """Description of an La Marzocco Water Heater."""


ENTITIES: tuple[LaMarzoccoWaterHeaterEntityDescription, ...] = (
    LaMarzoccoWaterHeaterEntityDescription(
        key="coffee_boiler",
        translation_key="coffee_boiler",
        icon="mdi:coffee-maker",
        min_temp=85,
        max_temp=104,
        set_temp_fn=lambda client, temp: client.set_coffee_temp(temp),
        current_op_fn=lambda client: client.current_status.get(
            "coffee_boiler_on", False
        ),
        control_fn=lambda client, state: client.set_power(state),
        current_temp_fn=lambda client: client.current_status.get("coffee_temp", 0),
        target_temp_fn=lambda client: client.current_status.get("coffee_set_temp", 0),
    ),
    LaMarzoccoWaterHeaterEntityDescription(
        key="steam_boiler",
        translation_key="steam_boiler",
        icon="mdi:kettle-steam",
        min_temp=126,
        max_temp=131,
        set_temp_fn=lambda client, temp: client.set_steam_temp(round(temp)),
        current_op_fn=lambda client: client.current_status.get(
            "steam_boiler_on", False
        ),
        control_fn=lambda client, state: client.set_steam_boiler_enable(state),
        current_temp_fn=lambda client: client.current_status.get("steam_temp", 0),
        target_temp_fn=lambda client: client.current_status.get("steam_set_temp", 0),
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
        LaMarzoccoWaterHeater(coordinator, hass, description)
        for description in ENTITIES
    )


class LaMarzoccoWaterHeater(LaMarzoccoEntity, WaterHeaterEntity):
    """Water heater representing espresso machine temperature data."""

    entity_description: LaMarzoccoWaterHeaterEntityDescription

    _attr_supported_features = (
        WaterHeaterEntityFeature.TARGET_TEMPERATURE
        | WaterHeaterEntityFeature.ON_OFF
        | WaterHeaterEntityFeature.OPERATION_MODE
    )

    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_precision = PRECISION_TENTHS
    _attr_operation_list = OPERATION_MODES

    @property
    def current_temperature(self) -> float | None:
        """Return the current temperature."""
        return self.entity_description.current_temp_fn(self._lm_client)

    @property
    def target_temperature(self) -> float | None:
        """Return the target temperature."""
        return self.entity_description.target_temp_fn(self._lm_client)

    @property
    def min_temp(self) -> float:
        """Return the minimum temperature."""
        return self.entity_description.min_temp

    @property
    def max_temp(self) -> float:
        """Return the maximum temperature."""
        return self.entity_description.max_temp

    @property
    def current_operation(self) -> str | None:
        """Return current operation."""
        return (
            STATE_ELECTRIC
            if self.entity_description.current_op_fn(self._lm_client)
            else STATE_OFF
        )

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Service call to set the temp of either the coffee or steam boilers."""
        temperature = kwargs.get("temperature", None)
        await self.entity_description.set_temp_fn(
            self._lm_client, round(temperature, 1)
        )
        self.async_write_ha_state()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the water heater on."""
        await self.entity_description.control_fn(self._lm_client, True)
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the water heater off."""
        await self.entity_description.control_fn(self._lm_client, False)
        self.async_write_ha_state()

    async def async_set_operation_mode(self, operation_mode: str) -> None:
        """Set the operation mode."""
        if operation_mode == STATE_ELECTRIC:
            await self.async_turn_on()
        else:
            await self.async_turn_off()
