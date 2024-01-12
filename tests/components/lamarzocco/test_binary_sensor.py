"""Tests for La Marzocco binary sensors."""
from unittest.mock import MagicMock

import pytest
from syrupy import SnapshotAssertion

from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


BINARY_SENSORS = (
    "brew_active",
    "water_reservoir",
)


async def test_binary_sensors(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco binary sensors."""

    serial_number = mock_lamarzocco.serial_number

    for binary_sensor in BINARY_SENSORS:
        state = hass.states.get(f"binary_sensor.{serial_number}_{binary_sensor}")
        assert state
        assert state == snapshot(name=f"{serial_number}_{binary_sensor}-binary_sensor")

        entry = entity_registry.async_get(state.entity_id)
        assert entry
        assert entry.device_id
        assert entry == snapshot(name=f"{serial_number}_{binary_sensor}-entry")
