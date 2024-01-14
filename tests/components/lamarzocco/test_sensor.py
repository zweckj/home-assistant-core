"""Tests for La Marzocco sensors."""
from unittest.mock import MagicMock

import pytest
from syrupy import SnapshotAssertion

from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from tests.common import MockConfigEntry

pytestmark = pytest.mark.usefixtures("init_integration")


SENSORS = (
    "drink_statistics_coffee",
    "drink_statistics_coffee",
    "shot_timer",
    "current_coffee_temperature",
    "current_steam_temperature",
)


async def test_sensors(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco sensors."""

    serial_number = mock_lamarzocco.serial_number

    for sensor in SENSORS:
        state = hass.states.get(f"sensor.{serial_number}_{sensor}")
        assert state
        assert state == snapshot(name=f"{serial_number}_{sensor}-sensor")

        entry = entity_registry.async_get(state.entity_id)
        assert entry
        assert entry.device_id
        assert entry == snapshot(name=f"{serial_number}_{sensor}-entry")


async def test_shot_timer_not_exists(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco sensors."""

    data = mock_config_entry.data.copy()
    data["shot_timer"] = False
    hass.config_entries.async_update_entry(mock_config_entry, data=data)
