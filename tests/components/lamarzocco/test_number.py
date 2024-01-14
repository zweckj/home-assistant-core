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
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr, entity_registry as er

pytestmark = pytest.mark.usefixtures("init_integration")


async def test_coffee_boiler(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    device_registry: dr.DeviceRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco coffee temperature Number."""
    serial_number = mock_lamarzocco.serial_number

    state = hass.states.get(f"number.{serial_number}_coffee_temperature")

    assert state
    assert state == snapshot

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry == snapshot

    device = device_registry.async_get(entry.device_id)
    assert device

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


@pytest.mark.parametrize(
    "device_fixture", [LaMarzoccoModel.GS3_AV, LaMarzoccoModel.GS3_MP]
)
async def test_steam_boiler(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    device_registry: dr.DeviceRegistry,
    snapshot: SnapshotAssertion,
) -> None:
    """Test the La Marzocco steam temperature number."""

    serial_number = mock_lamarzocco.serial_number

    state = hass.states.get(f"number.{serial_number}_steam_temperature")
    assert state
    assert state == snapshot

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry == snapshot

    device = device_registry.async_get(entry.device_id)
    assert device

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


@pytest.mark.parametrize(
    "device_fixture", [LaMarzoccoModel.LINEA_MICRA, LaMarzoccoModel.LINEA_MINI]
)
async def test_steam_boiler_none(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
) -> None:
    """Ensure steam boiler number is None for unsupported models."""

    serial_number = mock_lamarzocco.serial_number

    state = hass.states.get(f"number.{serial_number}_steam_temperature")
    assert state is None


@pytest.mark.parametrize(
    "device_fixture", [LaMarzoccoModel.LINEA_MICRA, LaMarzoccoModel.LINEA_MINI]
)
@pytest.mark.parametrize(
    ("entity_name", "value", "kwargs"),
    [
        ("prebrew_off_time", 6, {"on_time": 3000, "off_time": 6000}),
        ("prebrew_on_time", 6, {"on_time": 6000, "off_time": 5000}),
        ("preinfusion_off_time", 7, {"off_time": 7000}),
    ],
)
async def test_pre_brew_infusion_numbers(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    entity_registry: er.EntityRegistry,
    device_registry: dr.DeviceRegistry,
    snapshot: SnapshotAssertion,
    entity_name: str,
    value: float,
    kwargs: dict[str, float],
) -> None:
    """Test the La Marzocco coffee temperature Number."""

    mock_lamarzocco.current_status["enable_preinfusion"] = True

    serial_number = mock_lamarzocco.serial_number

    state = hass.states.get(f"number.{serial_number}_{entity_name}")

    assert state
    assert state == snapshot

    entry = entity_registry.async_get(state.entity_id)
    assert entry
    assert entry.device_id
    assert entry == snapshot

    device = device_registry.async_get(entry.device_id)
    assert device

    # on/off service calls
    await hass.services.async_call(
        NUMBER_DOMAIN,
        SERVICE_SET_VALUE,
        {
            ATTR_ENTITY_ID: f"number.{serial_number}_{entity_name}",
            ATTR_VALUE: value,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.configure_prebrew.mock_calls) == 1
    mock_lamarzocco.configure_prebrew.assert_called_once_with(**kwargs)


@pytest.mark.parametrize(
    "device_fixture", [LaMarzoccoModel.GS3_AV, LaMarzoccoModel.GS3_MP]
)
async def test_not_existing_entites(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
) -> None:
    """Assert not available entities."""

    serial_number = mock_lamarzocco.serial_number

    for entity in ("prebrew_off_time", "prebrew_on_time", "preinfusion_off_time"):
        state = hass.states.get(f"number.{serial_number}_{entity}")
        assert state is None


@pytest.mark.parametrize("device_fixture", [LaMarzoccoModel.LINEA_MICRA])
async def test_not_settable_entites(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
) -> None:
    """Assert not settable causes error."""

    serial_number = mock_lamarzocco.serial_number

    state = hass.states.get(f"number.{serial_number}_preinfusion_off_time")
    assert state

    with pytest.raises(
        HomeAssistantError, match="Not possible to set: Preinfusion is not enabled"
    ):
        await hass.services.async_call(
            NUMBER_DOMAIN,
            SERVICE_SET_VALUE,
            {
                ATTR_ENTITY_ID: f"number.{serial_number}_preinfusion_off_time",
                ATTR_VALUE: 6,
            },
            blocking=True,
        )
