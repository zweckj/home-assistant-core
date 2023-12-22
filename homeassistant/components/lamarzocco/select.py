"""Water heater platform for La Marzocco espresso machines."""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from homeassistant.components.select import (
    SelectEntity,
    SelectEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from lmcloud.const import LaMarzoccoModel

from .const import DOMAIN
from .entity import LaMarzoccoEntity, LaMarzoccoEntityDescription
from .lm_client import LaMarzoccoClient


@dataclass
class LaMarzoccoSelectEntityDescriptionMixin:
    """Description of an La Marzocco Water Heater."""

    current_option_fn: Callable[[LaMarzoccoClient], int]
    select_option_fn: Callable[[LaMarzoccoClient, int], Coroutine[Any, Any, bool]]


@dataclass
class LaMarzoccoSelectEntityDescription(
    SelectEntityDescription,
    LaMarzoccoEntityDescription,
    LaMarzoccoSelectEntityDescriptionMixin,
):
    """Description of an La Marzocco Water Heater."""


ENTITIES: tuple[LaMarzoccoSelectEntityDescription, ...] = (
    LaMarzoccoSelectEntityDescription(
        key="steam_temp_select",
        translation_key="steam_temp_select",
        icon="mdi:kettle-steam",
        select_option_fn=lambda client, option: client.set_steam_level(option),
        current_option_fn=lambda client: client.current_status.get(
            "steam_level_set", 3
        ),
        supported_models=(LaMarzoccoModel.LINEA_MICRA,),
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


class LaMarzoccoNumberEntity(LaMarzoccoEntity, SelectEntity):
    """Water heater representing espresso machine temperature data."""

    entity_description: LaMarzoccoSelectEntityDescription
    _attr_options = ["1", "2", "3"]

    @property
    def current_option(self) -> str:
        """Return the current selected option."""
        return str(self.entity_description.current_option_fn(self._lm_client))

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        await self.entity_description.select_option_fn(self._lm_client, int(option))
        self.async_write_ha_state()
