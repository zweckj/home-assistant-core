"""Tests for the La Marzocco Water Heaters."""


from unittest.mock import MagicMock

import pytest

from homeassistant.components.lamarzocco.const import DOMAIN
from homeassistant.components.select import (
    ATTR_OPTION,
    DOMAIN as SELECT_DOMAIN,
    SERVICE_SELECT_OPTION,
)
from homeassistant.const import (
    ATTR_ENTITY_ID,
    ATTR_FRIENDLY_NAME,
    ATTR_ICON,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


async def test_steam_boiler_level(
    hass: HomeAssistant,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
    mock_lamarzocco: MagicMock,
) -> None:
    """Test the La Marzocco Steam Level Select (only for Micra Models)."""

    state = hass.states.get(f"select.{mock_lamarzocco.serial_number}_steam_level")

    if mock_lamarzocco.model_name in ("Linea Mini", "GS3 AV"):
        assert state is None
        return

    assert state
    assert state.attributes.get(ATTR_FRIENDLY_NAME) == "MR01234 Steam Level"
    assert state.attributes.get(ATTR_ICON) == "mdi:kettle-steam"
    assert state.state == "2"

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry.unique_id == "MR01234_steam_temp_select"

    device = device_registry.async_get(entry.device_id)
    assert device
    assert device.configuration_url is None
    assert device.entry_type is None
    assert device.hw_version is None
    assert device.identifiers == {(DOMAIN, "MR01234")}
    assert device.manufacturer == "La Marzocco"
    assert device.name == "MR01234"
    assert device.sw_version == "1.1"

    # on/off service calls
    await hass.services.async_call(
        SELECT_DOMAIN,
        SERVICE_SELECT_OPTION,
        {
            ATTR_ENTITY_ID: "select.MR01234_steam_level",
            ATTR_OPTION: "1",
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_steam_level.mock_calls) == 1
    mock_lamarzocco.set_steam_level.assert_called_once_with(level=1)
