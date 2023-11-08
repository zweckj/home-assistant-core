"""Tests for the Tedee Sensors."""


from unittest.mock import MagicMock

import pytest

from homeassistant.components.binary_sensor import BinarySensorDeviceClass
from homeassistant.components.tedee.const import DOMAIN
from homeassistant.const import ATTR_DEVICE_CLASS, ATTR_FRIENDLY_NAME, ATTR_ICON
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


async def test_battery_charging(
    hass: HomeAssistant,
    mock_tedee: MagicMock,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test tedee battery charging sensor."""
    state = hass.states.get("binary_sensor.lock_1a2b_charging")
    assert state
    assert (
        state.attributes.get(ATTR_DEVICE_CLASS)
        == BinarySensorDeviceClass.BATTERY_CHARGING
    )
    assert state.attributes.get(ATTR_FRIENDLY_NAME) == "Lock-1A2B Charging"
    assert state.attributes.get(ATTR_ICON) is None

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry.unique_id == "12345-battery-charging-sensor"

    device = device_registry.async_get(entry.device_id)
    assert device
    assert device.configuration_url is None
    assert device.entry_type is None
    assert device.hw_version is None
    assert device.identifiers == {(DOMAIN, "12345")}
    assert device.manufacturer == "tedee"
    assert device.name == "Lock-1A2B"
    assert device.model == "Tedee PRO"

    state = hass.states.get("binary_sensor.lock_2c3d_charging")
    assert not state
