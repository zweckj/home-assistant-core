"""Tests for La Marzocco switches."""

from unittest.mock import MagicMock

import pytest
from syrupy import SnapshotAssertion

from homeassistant.components.switch import (
    DOMAIN as SWITCH_DOMAIN,
    SERVICE_TURN_OFF,
    SERVICE_TURN_ON,
)
from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


@pytest.mark.parametrize(
    (
        "entity_name",
        "method_name",
        "on_call",
        "off_call",
    ),
    [
        (
            "",
            "set_power",
            (True, None),
            (False, None),
        ),
        (
            "_auto_on_off",
            "enable_schedule_globally",
            (True,),
            (False,),
        ),
        (
            "_steam_boiler",
            "set_steam",
            (True, None),
            (False, None),
        ),
    ],
)
async def test_switches(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
    entity_name: str,
    method_name: str,
    on_call: tuple,
    off_call: tuple,
) -> None:
    """Test the La Marzocco switches."""
    serial_number = mock_lamarzocco.serial_number

    control_fn = getattr(mock_lamarzocco, method_name)

    state = hass.states.get(f"switch.{serial_number}{entity_name}")
    assert state
    assert state == snapshot

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry == snapshot

    await hass.services.async_call(
        SWITCH_DOMAIN,
        SERVICE_TURN_OFF,
        {
            ATTR_ENTITY_ID: f"switch.{serial_number}{entity_name}",
        },
        blocking=True,
    )

    assert len(control_fn.mock_calls) == 1
    control_fn.assert_called_once_with(*off_call)

    await hass.services.async_call(
        SWITCH_DOMAIN,
        SERVICE_TURN_ON,
        {
            ATTR_ENTITY_ID: f"switch.{serial_number}{entity_name}",
        },
        blocking=True,
    )

    assert len(control_fn.mock_calls) == 2
    control_fn.assert_called_with(*on_call)


async def test_device(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    device_registry: dr.DeviceRegistry,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the device for one switch."""

    state = hass.states.get(f"switch.{mock_lamarzocco.serial_number}")
    assert state

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id

    device = device_registry.async_get(entry.device_id)
    assert device
    assert device == snapshot
