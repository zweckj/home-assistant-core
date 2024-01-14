"""Tests for La Marzocco binary sensors."""
from unittest.mock import MagicMock

from syrupy import SnapshotAssertion

from homeassistant.const import CONF_HOST, STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from . import async_init_integration

from tests.common import MockConfigEntry

BINARY_SENSORS = (
    "brew_active",
    "water_reservoir",
)


async def test_binary_sensors(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco binary sensors."""

    await async_init_integration(hass, mock_config_entry)

    serial_number = mock_lamarzocco.serial_number

    for binary_sensor in BINARY_SENSORS:
        state = hass.states.get(f"binary_sensor.{serial_number}_{binary_sensor}")
        assert state
        assert state == snapshot(name=f"{serial_number}_{binary_sensor}-binary_sensor")

        entry = entity_registry.async_get(state.entity_id)
        assert entry
        assert entry.device_id
        assert entry == snapshot(name=f"{serial_number}_{binary_sensor}-entry")


async def test_brew_active_does_not_exists(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco doesn't exist if host not set."""

    data = mock_config_entry.data.copy()
    del data[CONF_HOST]
    hass.config_entries.async_update_entry(mock_config_entry, data=data)

    await async_init_integration(hass, mock_config_entry)
    state = hass.states.get(f"sensor.{mock_lamarzocco.serial_number}_brew_active")
    assert state is None


async def test_brew_active_unavailable(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco brew_active becomes unavailable."""

    mock_lamarzocco.websocket_connected = False
    await async_init_integration(hass, mock_config_entry)
    state = hass.states.get(
        f"binary_sensor.{mock_lamarzocco.serial_number}_brew_active"
    )
    assert state
    assert state.state == STATE_UNAVAILABLE
