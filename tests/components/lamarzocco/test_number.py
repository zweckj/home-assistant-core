"""Tests for the La Marzocco Water Heaters."""


from unittest.mock import MagicMock

import pytest

from homeassistant.components.lamarzocco.const import DOMAIN
from homeassistant.components.number import (
    ATTR_MAX,
    ATTR_MIN,
    ATTR_STEP,
    ATTR_VALUE,
    DOMAIN as NUMBER_DOMAIN,
    SERVICE_SET_VALUE,
    NumberDeviceClass,
)
from homeassistant.const import (
    ATTR_DEVICE_CLASS,
    ATTR_ENTITY_ID,
    ATTR_FRIENDLY_NAME,
    ATTR_ICON,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


async def test_coffee_boiler(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test the La Marzocco Coffee Temperature Number."""
    mock_lamarzocco.set_power.return_value = None
    mock_lamarzocco.set_coffee_temp.return_value = None

    state = hass.states.get("number.GS01234_coffee_temperature")
    assert state
    assert state.attributes.get(ATTR_DEVICE_CLASS) == NumberDeviceClass.TEMPERATURE
    assert state.attributes.get(ATTR_FRIENDLY_NAME) == "GS01234 Coffee Temperature"
    assert state.attributes.get(ATTR_ICON) == "mdi:coffee-maker"
    assert state.attributes.get(ATTR_MIN) == 85
    assert state.attributes.get(ATTR_MAX) == 104
    assert state.attributes.get(ATTR_STEP) == 0.1
    assert state.state == "95"

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry.unique_id == "GS01234_coffee_temp"

    device = device_registry.async_get(entry.device_id)
    assert device
    assert device.configuration_url is None
    assert device.entry_type is None
    assert device.hw_version is None
    assert device.identifiers == {(DOMAIN, "GS01234")}
    assert device.manufacturer == "La Marzocco"
    assert device.name == "GS01234"
    assert device.sw_version == "1.1"

    # on/off service calls
    await hass.services.async_call(
        NUMBER_DOMAIN,
        SERVICE_SET_VALUE,
        {
            ATTR_ENTITY_ID: "number.GS01234_coffee_temperature",
            ATTR_VALUE: 95,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_coffee_temp.mock_calls) == 1
    mock_lamarzocco.set_coffee_temp.assert_called_once_with(temperature=95)


async def test_steam_boiler(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test the La Marzocco Steam Temperature Number."""
    mock_lamarzocco.set_power.return_value = None
    mock_lamarzocco.set_coffee_temp.return_value = None

    state = hass.states.get("number.GS01234_steam_temperature")
    assert state
    assert state.attributes.get(ATTR_DEVICE_CLASS) == NumberDeviceClass.TEMPERATURE
    assert state.attributes.get(ATTR_FRIENDLY_NAME) == "GS01234 Steam Temperature"
    assert state.attributes.get(ATTR_ICON) == "mdi:kettle-steam"
    assert state.attributes.get(ATTR_MIN) == 126
    assert state.attributes.get(ATTR_MAX) == 131
    assert state.attributes.get(ATTR_STEP) == 0.1
    assert state.state == "128"

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry.unique_id == "GS01234_steam_temp"

    device = device_registry.async_get(entry.device_id)
    assert device
    assert device.configuration_url is None
    assert device.entry_type is None
    assert device.hw_version is None
    assert device.identifiers == {(DOMAIN, "GS01234")}
    assert device.manufacturer == "La Marzocco"
    assert device.name == "GS01234"
    assert device.sw_version == "1.1"

    # on/off service calls
    await hass.services.async_call(
        NUMBER_DOMAIN,
        SERVICE_SET_VALUE,
        {
            ATTR_ENTITY_ID: "number.GS01234_steam_temperature",
            ATTR_VALUE: 131,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_steam_temp.mock_calls) == 1
    mock_lamarzocco.set_steam_temp.assert_called_once_with(temperature=131)
