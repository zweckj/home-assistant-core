"""Tests for the La Marzocco Update Entities."""


from unittest.mock import MagicMock

import pytest
from syrupy import SnapshotAssertion

from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


async def test_machine_firmware(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco Machine Firmware."""

    serial_number = mock_lamarzocco.serial_number

    state = hass.states.get(f"update.{serial_number}_machine_firmware")
    assert state
    assert state == snapshot

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry == snapshot


async def test_gateway_firmware(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco Gateway Firmware."""

    serial_number = mock_lamarzocco.serial_number

    state = hass.states.get(f"update.{serial_number}_gateway_firmware")
    assert state
    assert state == snapshot

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry == snapshot
