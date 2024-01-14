"""Tests for the La Marzocco Update Entities."""


from unittest.mock import MagicMock

import pytest
from syrupy import SnapshotAssertion

from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


async def test_update_entites(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco update entities."""

    serial_number = mock_lamarzocco.serial_number

    for entity_name in ("machine_firmware", "gateway_firmware"):
        state = hass.states.get(f"update.{serial_number}_{entity_name}")
        assert state
        assert state == snapshot(name=f"{entity_name}-state")

        entry = entity_registry.async_get(state.entity_id)
        assert entry
        assert entry == snapshot(name=f"{entity_name}-entry")
