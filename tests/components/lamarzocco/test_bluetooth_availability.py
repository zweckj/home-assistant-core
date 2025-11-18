"""Tests for La Marzocco Bluetooth availability."""

from unittest.mock import MagicMock, patch

from pylamarzocco.const import ModelName, WidgetType
import pytest

from homeassistant.const import STATE_OFF, STATE_ON, STATE_UNAVAILABLE, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from . import async_init_integration

from tests.common import MockConfigEntry


@pytest.mark.parametrize(
    "device_fixture",
    [ModelName.LINEA_MICRA],
)
async def test_bluetooth_entities_available_when_cloud_disconnected(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test Bluetooth-capable entities remain available when cloud is disconnected."""
    # Set up with Bluetooth client available
    mock_bluetooth_client = MagicMock()
    mock_lamarzocco.bluetooth_client = mock_bluetooth_client
    
    # Set device as disconnected from cloud
    mock_lamarzocco.dashboard.connected = False
    
    with patch("homeassistant.components.lamarzocco.PLATFORMS", [Platform.SWITCH, Platform.NUMBER, Platform.SELECT]):
        await async_init_integration(hass, mock_config_entry)
    
    serial_number = mock_lamarzocco.serial_number
    
    # Check main boiler switch (available via Bluetooth)
    main_switch = hass.states.get(f"switch.{serial_number}")
    assert main_switch
    assert main_switch.state != STATE_UNAVAILABLE
    
    # Check steam boiler switch (available via Bluetooth)
    steam_switch = hass.states.get(f"switch.{serial_number}_steam_boiler")
    assert steam_switch
    assert steam_switch.state != STATE_UNAVAILABLE
    
    # Check coffee temperature (available via Bluetooth)
    coffee_temp = hass.states.get(f"number.{serial_number}_coffee_temp")
    assert coffee_temp
    assert coffee_temp.state != STATE_UNAVAILABLE
    
    # Check steam temperature select (available via Bluetooth for MICRA)
    steam_temp = hass.states.get(f"select.{serial_number}_steam_temp_select")
    assert steam_temp
    assert steam_temp.state != STATE_UNAVAILABLE


@pytest.mark.parametrize(
    "device_fixture",
    [ModelName.GS3_AV],
)
async def test_non_bluetooth_entities_unavailable_when_cloud_disconnected(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
    entity_registry: er.EntityRegistry,
) -> None:
    """Test non-Bluetooth entities are unavailable when cloud is disconnected."""
    # Set up with Bluetooth client available
    mock_bluetooth_client = MagicMock()
    mock_lamarzocco.bluetooth_client = mock_bluetooth_client
    
    # Set device as disconnected from cloud
    mock_lamarzocco.dashboard.connected = False
    
    with patch("homeassistant.components.lamarzocco.PLATFORMS", [Platform.SWITCH, Platform.SELECT]):
        await async_init_integration(hass, mock_config_entry)
    
    serial_number = mock_lamarzocco.serial_number
    
    # Check main boiler switch (available via Bluetooth)
    main_switch = hass.states.get(f"switch.{serial_number}")
    assert main_switch
    assert main_switch.state != STATE_UNAVAILABLE
    
    # Check steam boiler switch (available via Bluetooth)
    steam_switch = hass.states.get(f"switch.{serial_number}_steam_boiler")
    assert steam_switch
    assert steam_switch.state != STATE_UNAVAILABLE
    
    # Check smart standby enabled switch (NOT available via Bluetooth)
    smart_standby = hass.states.get(f"switch.{serial_number}_smart_standby_enabled")
    assert smart_standby
    assert smart_standby.state == STATE_UNAVAILABLE
    
    # Check prebrew/preinfusion select (NOT available via Bluetooth)
    prebrew_select = hass.states.get(f"select.{serial_number}_prebrew_infusion_select")
    assert prebrew_select
    assert prebrew_select.state == STATE_UNAVAILABLE


@pytest.mark.parametrize(
    "device_fixture",
    [ModelName.LINEA_MICRA],
)
async def test_all_entities_available_when_cloud_connected(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test all entities are available when cloud is connected."""
    # Set up with Bluetooth client available
    mock_bluetooth_client = MagicMock()
    mock_lamarzocco.bluetooth_client = mock_bluetooth_client
    
    # Set device as connected to cloud (default in fixtures)
    mock_lamarzocco.dashboard.connected = True
    
    with patch("homeassistant.components.lamarzocco.PLATFORMS", [Platform.SWITCH, Platform.NUMBER, Platform.SELECT]):
        await async_init_integration(hass, mock_config_entry)
    
    serial_number = mock_lamarzocco.serial_number
    
    # Check main boiler switch
    main_switch = hass.states.get(f"switch.{serial_number}")
    assert main_switch
    assert main_switch.state != STATE_UNAVAILABLE
    
    # Check steam boiler switch
    steam_switch = hass.states.get(f"switch.{serial_number}_steam_boiler")
    assert steam_switch
    assert steam_switch.state != STATE_UNAVAILABLE
    
    # Check coffee temperature
    coffee_temp = hass.states.get(f"number.{serial_number}_coffee_temp")
    assert coffee_temp
    assert coffee_temp.state != STATE_UNAVAILABLE
    
    # Check steam temperature select
    steam_temp = hass.states.get(f"select.{serial_number}_steam_temp_select")
    assert steam_temp
    assert steam_temp.state != STATE_UNAVAILABLE
    
    # Check smart standby enabled switch (not Bluetooth but should be available)
    smart_standby = hass.states.get(f"switch.{serial_number}_smart_standby_enabled")
    assert smart_standby
    assert smart_standby.state != STATE_UNAVAILABLE
    
    # Check prebrew/preinfusion select (not Bluetooth but should be available)
    prebrew_select = hass.states.get(f"select.{serial_number}_prebrew_infusion_select")
    assert prebrew_select
    assert prebrew_select.state != STATE_UNAVAILABLE


@pytest.mark.parametrize(
    "device_fixture",
    [ModelName.LINEA_MICRA],
)
async def test_all_entities_unavailable_when_no_bluetooth_and_cloud_disconnected(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test all entities are unavailable when no Bluetooth and cloud is disconnected."""
    # Set up without Bluetooth client
    mock_lamarzocco.bluetooth_client = None
    
    # Set device as disconnected from cloud
    mock_lamarzocco.dashboard.connected = False
    
    with patch("homeassistant.components.lamarzocco.PLATFORMS", [Platform.SWITCH, Platform.NUMBER, Platform.SELECT]):
        await async_init_integration(hass, mock_config_entry)
    
    serial_number = mock_lamarzocco.serial_number
    
    # All entities should be unavailable without any connection
    main_switch = hass.states.get(f"switch.{serial_number}")
    assert main_switch
    assert main_switch.state == STATE_UNAVAILABLE
    
    steam_switch = hass.states.get(f"switch.{serial_number}_steam_boiler")
    assert steam_switch
    assert steam_switch.state == STATE_UNAVAILABLE
    
    coffee_temp = hass.states.get(f"number.{serial_number}_coffee_temp")
    assert coffee_temp
    assert coffee_temp.state == STATE_UNAVAILABLE
    
    steam_temp = hass.states.get(f"select.{serial_number}_steam_temp_select")
    assert steam_temp
    assert steam_temp.state == STATE_UNAVAILABLE
