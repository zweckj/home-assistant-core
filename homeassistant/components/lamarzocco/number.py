"""Water heater platform for La Marzocco espresso machines."""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from lmcloud import LMCloud as LaMarzoccoClient
from lmcloud.const import LaMarzoccoModel

from homeassistant.components.number import (
    NumberDeviceClass,
    NumberEntity,
    NumberEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PRECISION_TENTHS,
    EntityCategory,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, NUMBER_KEYS_GS3_AV
from .coordinator import LaMarzoccoUpdateCoordinator
from .entity import LaMarzoccoEntity, LaMarzoccoEntityDescription


@dataclass(frozen=True, kw_only=True)
class LaMarzoccoNumberEntityDescription(
    LaMarzoccoEntityDescription,
    NumberEntityDescription,
):
    """Description of an La Marzocco number entity."""

    native_value_fn: Callable[[LaMarzoccoClient], float | int]
    set_value_fn: Callable[[LaMarzoccoClient, float | int], Coroutine[Any, Any, bool]]


@dataclass(frozen=True, kw_only=True)
class LaMarzoccoKeyNumberEntityDescription(
    LaMarzoccoEntityDescription,
    NumberEntityDescription,
):
    """Description of an La Marzocco number entity with keys."""

    native_value_fn: Callable[[LaMarzoccoClient, int], float | int]
    set_value_fn: Callable[
        [LaMarzoccoClient, float | int, int], Coroutine[Any, Any, bool]
    ]
    enabled_fn: Callable[[LaMarzoccoClient], bool]
    not_settable_reason: str


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
        set_value_fn=lambda lm, temp: lm.set_coffee_temp(temp),
        native_value_fn=lambda lm: lm.current_status.get("coffee_set_temp", 0),
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
        set_value_fn=lambda lm, temp: lm.set_steam_temp(round(temp)),
        native_value_fn=lambda lm: lm.current_status.get("steam_set_temp", 0),
        supported_models=(
            LaMarzoccoModel.GS3_AV,
            LaMarzoccoModel.GS3_MP,
        ),
    ),
)

KEY_ENTITIES: tuple[LaMarzoccoKeyNumberEntityDescription, ...] = (
    LaMarzoccoKeyNumberEntityDescription(
        key="prebrew_off",
        translation_key="prebrew_off",
        icon="mdi:water-off",
        device_class=NumberDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        native_step=PRECISION_TENTHS,
        native_min_value=1,
        native_max_value=10,
        entity_category=EntityCategory.CONFIG,
        set_value_fn=lambda lm, off_time, key: lm.configure_prebrew(
            on_time=int(lm.current_status.get(f"prebrewing_ton_k{key}", 5) * 1000),
            off_time=int(off_time * 1000),
            key=key,
        ),
        native_value_fn=lambda lm, key: lm.current_status.get(
            f"prebrewing_ton_k{key}", 5
        ),
        enabled_fn=lambda lm: lm.current_status.get("enable_prebrewing", False),
        not_settable_reason="Prebrewing is not enabled",
        supported_models=(
            LaMarzoccoModel.LINEA_MICRA,
            LaMarzoccoModel.LINEA_MINI,
            LaMarzoccoModel.GS3_AV,
        ),
    ),
    LaMarzoccoKeyNumberEntityDescription(
        key="prebrew_on",
        translation_key="prebrew_on",
        icon="mdi:water",
        device_class=NumberDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        native_step=PRECISION_TENTHS,
        native_min_value=2,
        native_max_value=10,
        entity_category=EntityCategory.CONFIG,
        set_value_fn=lambda lm, on_time, key: lm.configure_prebrew(
            on_time=int(on_time * 1000),
            off_time=int(lm.current_status.get(f"prebrewing_toff_k{key}", 5) * 1000),
            key=key,
        ),
        native_value_fn=lambda lm, key: lm.current_status.get(
            f"prebrewing_toff_k{key}]", 5
        ),
        enabled_fn=lambda lm: lm.current_status.get("enable_prebrewing", False),
        not_settable_reason="Prebrewing is not enabled",
        supported_models=(
            LaMarzoccoModel.LINEA_MICRA,
            LaMarzoccoModel.LINEA_MINI,
            LaMarzoccoModel.GS3_AV,
        ),
    ),
    LaMarzoccoKeyNumberEntityDescription(
        key="preinfusion_off",
        translation_key="preinfusion_off",
        icon="mdi:water-off",
        device_class=NumberDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        native_step=PRECISION_TENTHS,
        native_min_value=2,
        native_max_value=29,
        entity_category=EntityCategory.CONFIG,
        set_value_fn=lambda lm, off_time, key: lm.configure_prebrew(
            off_time=int(off_time * 1000), key=key
        ),
        native_value_fn=lambda lm, key: lm.current_status.get(f"preinfusion_k{key}", 5),
        enabled_fn=lambda lm: lm.current_status.get("enable_preinfusion", False),
        not_settable_reason="Preinfusion is not enabled",
        supported_models=(
            LaMarzoccoModel.LINEA_MICRA,
            LaMarzoccoModel.LINEA_MINI,
            LaMarzoccoModel.GS3_AV,
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
        LaMarzoccoNumberEntity(coordinator, description)
        for description in ENTITIES
        if coordinator.lm.model_name in description.supported_models
    )

    entities: list[LaMarzoccoKeyNumberEntity] = []
    for description in KEY_ENTITIES:
        if coordinator.lm.model_name in description.supported_models:
            if coordinator.lm.model_name == LaMarzoccoModel.GS3_AV:
                for key in range(1, NUMBER_KEYS_GS3_AV + 1):
                    entities.append(
                        LaMarzoccoKeyNumberEntity(
                            coordinator, description, key=key, single_key=False
                        )
                    )
            else:
                entities.append(LaMarzoccoKeyNumberEntity(coordinator, description))

    async_add_entities(entities)


class LaMarzoccoNumberEntity(LaMarzoccoEntity, NumberEntity):
    """Number entity representing espresso machine temperature data."""

    entity_description: LaMarzoccoNumberEntityDescription

    @property
    def native_value(self) -> float:
        """Return the current value."""
        return self.entity_description.native_value_fn(self.coordinator.lm)

    async def async_set_native_value(self, value: float) -> None:
        """Set the value."""
        await self.entity_description.set_value_fn(self.coordinator.lm, value)
        self.async_write_ha_state()


class LaMarzoccoKeyNumberEntity(LaMarzoccoEntity, NumberEntity):
    """Number representing espresso machine temperature data with keys."""

    entity_description: LaMarzoccoKeyNumberEntityDescription

    def __init__(
        self,
        coordinator: LaMarzoccoUpdateCoordinator,
        description: LaMarzoccoKeyNumberEntityDescription,
        key: int = 1,
        single_key: bool = True,
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator, description)
        self.key = key
        if not single_key:
            self._attr_translation_key = f"{description.translation_key}_key"
            self._attr_translation_placeholders = {"key": str(key)}
            self._attr_unique_id = f"{super()._attr_unique_id}_key{key}"
            self._attr_entity_registry_enabled_default = False

    @property
    def native_value(self) -> float:
        """Return the current value."""
        return self.entity_description.native_value_fn(self.coordinator.lm, self.key)

    async def async_set_native_value(self, value: float) -> None:
        """Set the value."""
        if not self.entity_description.enabled_fn(self.coordinator.lm):
            raise HomeAssistantError(
                f"Not possible to set: {self.entity_description.not_settable_reason}"
            )
        await self.entity_description.set_value_fn(self.coordinator.lm, value, self.key)
        self.async_write_ha_state()
