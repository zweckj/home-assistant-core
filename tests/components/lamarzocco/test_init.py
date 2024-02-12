"""Test initialization of lamarzocco."""

from unittest.mock import MagicMock, patch

from bleak.backends.device import BLEDevice
from lmcloud.exceptions import AuthFail, RequestNotSuccessful

from homeassistant.components.lamarzocco.config_flow import CONF_MACHINE
from homeassistant.components.lamarzocco.const import DOMAIN
from homeassistant.config_entries import SOURCE_REAUTH, ConfigEntryState
from homeassistant.const import CONF_HOST, CONF_MAC
from homeassistant.core import HomeAssistant

from . import USER_INPUT

from tests.common import MockConfigEntry


async def test_load_unload_config_entry(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_lamarzocco: MagicMock,
) -> None:
    """Test loading and unloading the integration."""
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.LOADED

    await hass.config_entries.async_unload(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.NOT_LOADED


async def test_config_entry_not_ready(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_lamarzocco: MagicMock,
) -> None:
    """Test the La Marzocco configuration entry not ready."""
    mock_lamarzocco.get_config.side_effect = RequestNotSuccessful("")

    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert len(mock_lamarzocco.get_config.mock_calls) == 1
    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY


async def test_invalid_auth(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_lamarzocco: MagicMock,
) -> None:
    """Test auth error during setup."""
    mock_lamarzocco.get_config.side_effect = AuthFail("")
    mock_config_entry.add_to_hass(hass)
    await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.SETUP_ERROR
    assert len(mock_lamarzocco.get_config.mock_calls) == 1

    flows = hass.config_entries.flow.async_progress()
    assert len(flows) == 1

    flow = flows[0]
    assert flow.get("step_id") == "reauth_confirm"
    assert flow.get("handler") == DOMAIN

    assert "context" in flow
    assert flow["context"].get("source") == SOURCE_REAUTH
    assert flow["context"].get("entry_id") == mock_config_entry.entry_id


async def test_init_with_bluetooth(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_lamarzocco: MagicMock,
    mock_cloud_client: MagicMock,
    mock_ble_device: BLEDevice,
) -> None:
    """Test the La Marzocco configuration entry with Bluetooth."""
    with (
        patch(
            "homeassistant.components.lamarzocco.LaMarzoccoBluetoothClient.discover_devices",
            return_value=[mock_ble_device],
        ),
        patch(
            "homeassistant.components.lamarzocco.coordinator.bluetooth.async_ble_device_from_address",
            return_value=mock_ble_device,
        ),
    ):
        mock_config_entry.add_to_hass(hass)
        await hass.config_entries.async_setup(mock_config_entry.entry_id)
        await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.LOADED


async def test_v1_migration(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_cloud_client: MagicMock,
    mock_lamarzocco: MagicMock,
) -> None:
    """Test v1 -> v2 Migration."""
    entry_v1 = MockConfigEntry(
        domain=DOMAIN,
        version=1,
        unique_id=mock_lamarzocco.serial_number,
        data={
            **USER_INPUT,
            CONF_HOST: "host",
            CONF_MACHINE: mock_lamarzocco.serial_number,
            CONF_MAC: "aa:bb:cc:dd:ee:ff",
        },
    )

    entry_v1.add_to_hass(hass)
    await hass.config_entries.async_setup(entry_v1.entry_id)
    await hass.async_block_till_done()

    assert entry_v1.version == 2
    assert dict(entry_v1.data) == dict(mock_config_entry.data) | {
        CONF_MAC: "aa:bb:cc:dd:ee:ff"
    }


async def test_migration_errors(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    mock_cloud_client: MagicMock,
    mock_lamarzocco: MagicMock,
) -> None:
    """Test errors during migration."""

    mock_cloud_client.get_customer_fleet.side_effect = RequestNotSuccessful("Error")

    entry_v1 = MockConfigEntry(
        domain=DOMAIN,
        version=1,
        unique_id=mock_lamarzocco.serial_number,
        data={
            **USER_INPUT,
            CONF_MACHINE: mock_lamarzocco.serial_number,
        },
    )
    entry_v1.add_to_hass(hass)

    assert not await hass.config_entries.async_setup(entry_v1.entry_id)
    assert entry_v1.state is ConfigEntryState.MIGRATION_ERROR
