"""Button platform for La Marzocco espresso machines."""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import LaMarzoccoUpdateCoordinator
from .entity import LaMarzoccoEntity, LaMarzoccoEntityDescription


@dataclass(frozen=True, kw_only=True)
class LaMarzoccoButtonEntityDescription(
    LaMarzoccoEntityDescription,
    ButtonEntityDescription,
):
    """Description of an La Marzocco button."""

    press_fn: Callable[[LaMarzoccoUpdateCoordinator], Coroutine[Any, Any, None]]


ENTITIES: tuple[LaMarzoccoButtonEntityDescription, ...] = (
    LaMarzoccoButtonEntityDescription(
        key="start_backflush",
        translation_key="start_backflush",
        icon="mdi:water-sync",
        press_fn=lambda coordinator: coordinator.lm.start_backflush(),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up button entities."""

    coordinator = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities(
        LaMarzoccoButtonEntity(coordinator, description)
        for description in ENTITIES
        if coordinator.lm.model_name in description.supported_models
    )


class LaMarzoccoButtonEntity(LaMarzoccoEntity, ButtonEntity):
    """La Marzocco Button Entity."""

    entity_description: LaMarzoccoButtonEntityDescription

    async def async_press(self) -> None:
        """Press button."""
        await self.entity_description.press_fn(self.coordinator)
