"""Tests for the La Marzocco Water Heaters."""


from unittest.mock import MagicMock

from lmcloud.const import LaMarzoccoModel
import pytest
from syrupy import SnapshotAssertion

from homeassistant.components.number import (
    ATTR_VALUE,
    DOMAIN as NUMBER_DOMAIN,
    SERVICE_SET_VALUE,
)
from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


async def test_coffee_boiler(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco coffee temperature Number."""
    serial_number = mock_lamarzocco.serial_number

    mock_lamarzocco.set_power.return_value = None
    mock_lamarzocco.set_coffee_temp.return_value = None

    state = hass.states.get(f"number.{serial_number}_coffee_temperature")

    assert state
    assert state == snapshot

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry == snapshot

    # on/off service calls
    await hass.services.async_call(
        NUMBER_DOMAIN,
        SERVICE_SET_VALUE,
        {
            ATTR_ENTITY_ID: f"number.{serial_number}_coffee_temperature",
            ATTR_VALUE: 95,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_coffee_temp.mock_calls) == 1
    mock_lamarzocco.set_coffee_temp.assert_called_once_with(temperature=95)


async def test_steam_boiler(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco steam temperature number."""

    serial_number = mock_lamarzocco.serial_number

    mock_lamarzocco.set_power.return_value = None
    mock_lamarzocco.set_coffee_temp.return_value = None

    state = hass.states.get(f"number.{serial_number}_steam_temperature")
    if mock_lamarzocco.model_name in (
        LaMarzoccoModel.LINEA_MICRA,
        LaMarzoccoModel.LINEA_MINI,
    ):
        assert state is None
        return
    assert state
    assert state == snapshot

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry == snapshot

    # on/off service calls
    await hass.services.async_call(
        NUMBER_DOMAIN,
        SERVICE_SET_VALUE,
        {
            ATTR_ENTITY_ID: f"number.{serial_number}_steam_temperature",
            ATTR_VALUE: 131,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_steam_temp.mock_calls) == 1
    mock_lamarzocco.set_steam_temp.assert_called_once_with(temperature=131)
