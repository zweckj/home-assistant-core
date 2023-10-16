"""Tests for Acaia sensor entities."""

from homeassistant.components.acaia.const import DOMAIN
from homeassistant.components.sensor import (
    ATTR_STATE_CLASS,
    SensorDeviceClass,
    SensorStateClass,
)
from homeassistant.const import (
    ATTR_DEVICE_CLASS,
    ATTR_FRIENDLY_NAME,
    ATTR_ICON,
    ATTR_UNIT_OF_MEASUREMENT,
    PERCENTAGE,
    UnitOfMass,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

from . import init_integration


async def test_weight(
    hass: HomeAssistant,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test the Acaia Weight sensor."""
    await init_integration(hass)

    state = hass.states.get("sensor.lunar_1234_weight")
    assert state
    assert state.attributes.get(ATTR_DEVICE_CLASS) == SensorDeviceClass.WEIGHT
    assert state.attributes.get(ATTR_FRIENDLY_NAME) == "LUNAR_1234 Weight"
    assert state.attributes.get(ATTR_ICON) == "mdi:scale"
    assert state.attributes.get(ATTR_STATE_CLASS) is SensorStateClass.MEASUREMENT
    assert state.attributes.get(ATTR_UNIT_OF_MEASUREMENT) == UnitOfMass.GRAMS
    assert state.state == "227.2"

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry.unique_id == "aa:bb:cc:dd:ee:ff_weight"

    device = device_registry.async_get(entry.device_id)
    assert device
    assert device.identifiers == {(DOMAIN, str.upper("aa:bb:cc:dd:ee:ff"))}
    assert device.manufacturer == "acaia"
    assert device.name == "LUNAR_1234"


async def test_battery(
    hass: HomeAssistant,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test the Acaia Battery sensor."""
    await init_integration(hass)

    state = hass.states.get("sensor.lunar_1234_battery")
    assert state
    assert state.attributes.get(ATTR_DEVICE_CLASS) == SensorDeviceClass.BATTERY
    assert state.attributes.get(ATTR_FRIENDLY_NAME) == "LUNAR_1234 Battery"
    assert state.attributes.get(ATTR_ICON) == "mdi:battery"
    assert state.attributes.get(ATTR_STATE_CLASS) is SensorStateClass.MEASUREMENT
    assert state.attributes.get(ATTR_UNIT_OF_MEASUREMENT) == PERCENTAGE
    assert state.state == "90"

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry.unique_id == "aa:bb:cc:dd:ee:ff_battery_level"

    device = device_registry.async_get(entry.device_id)
    assert device
    assert device.identifiers == {(DOMAIN, str.upper("aa:bb:cc:dd:ee:ff"))}
    assert device.manufacturer == "acaia"
    assert device.name == "LUNAR_1234"
