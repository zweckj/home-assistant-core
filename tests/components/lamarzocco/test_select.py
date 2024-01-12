"""Tests for the La Marzocco Water Heaters."""


from unittest.mock import MagicMock

from lmcloud.const import LaMarzoccoModel
import pytest
from syrupy import SnapshotAssertion

from homeassistant.components.select import (
    ATTR_OPTION,
    DOMAIN as SELECT_DOMAIN,
    SERVICE_SELECT_OPTION,
)
from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


async def test_steam_boiler_level(
    hass: HomeAssistant,
    entity_registry: er.EntityRegistry,
    mock_lamarzocco: MagicMock,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco Steam Level Select (only for Micra Models)."""

    serial_number = mock_lamarzocco.serial_number

    state = hass.states.get(f"select.{serial_number}_steam_level")

    if mock_lamarzocco.model_name != LaMarzoccoModel.LINEA_MICRA:
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
        SELECT_DOMAIN,
        SERVICE_SELECT_OPTION,
        {
            ATTR_ENTITY_ID: f"select.{serial_number}_steam_level",
            ATTR_OPTION: "1",
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_steam_level.mock_calls) == 1
    mock_lamarzocco.set_steam_level.assert_called_once_with(level=1)
