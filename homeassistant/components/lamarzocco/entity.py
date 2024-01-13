"""Base class for the La Marzocco entities."""

from dataclasses import dataclass

from lmcloud.const import LaMarzoccoModel

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import LaMarzoccoUpdateCoordinator


@dataclass(frozen=True, kw_only=True)
class LaMarzoccoEntityDescription(EntityDescription):
    """Description for all LM entities."""

    supported_models: tuple[LaMarzoccoModel, ...] = (
        LaMarzoccoModel.GS3_AV,
        LaMarzoccoModel.GS3_MP,
        LaMarzoccoModel.LINEA_MICRA,
        LaMarzoccoModel.LINEA_MINI,
    )


class LaMarzoccoBaseEntity(CoordinatorEntity[LaMarzoccoUpdateCoordinator]):
    """Base class for all LM entities."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: LaMarzoccoUpdateCoordinator,
        key: str,
    ) -> None:
        """Initialize the entity."""
        super().__init__(coordinator)

        self._attr_unique_id = f"{self.coordinator.lm.serial_number}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self.coordinator.lm.serial_number)},
            name=self.coordinator.lm.machine_name,
            manufacturer="La Marzocco",
            model=self.coordinator.lm.true_model_name,
            serial_number=self.coordinator.lm.serial_number,
            sw_version=self.coordinator.lm.firmware_version,
        )


class LaMarzoccoEntity(LaMarzoccoBaseEntity):
    """Common elements for all entities."""

    entity_description: LaMarzoccoEntityDescription

    def __init__(
        self,
        coordinator: LaMarzoccoUpdateCoordinator,
        entity_description: LaMarzoccoEntityDescription,
    ) -> None:
        """Initialize the entity."""

        super().__init__(coordinator, entity_description.key)
        self.entity_description = entity_description
