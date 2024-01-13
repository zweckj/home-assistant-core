"""Lamarzocco session fixtures."""

from collections.abc import Generator
import json
from unittest.mock import MagicMock, patch

from lmcloud.const import LaMarzoccoModel
import pytest

from homeassistant.components.lamarzocco.const import CONF_MACHINE, DOMAIN
from homeassistant.core import HomeAssistant

from . import USER_INPUT, async_init_integration

from tests.common import (
    MockConfigEntry,
    load_fixture,
    load_json_array_fixture,
    load_json_object_fixture,
)


@pytest.fixture
def mock_config_entry(mock_lamarzocco: MagicMock) -> MockConfigEntry:
    """Return the default mocked config entry."""
    return MockConfigEntry(
        title="My LaMarzocco",
        domain=DOMAIN,
        data=USER_INPUT | {CONF_MACHINE: mock_lamarzocco.serial_number},
        unique_id=mock_lamarzocco.serial_number,
    )


@pytest.fixture
async def init_integration(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_lamarzocco: MagicMock
) -> MockConfigEntry:
    """Set up the LaMetric integration for testing."""

    await async_init_integration(hass, mock_config_entry)
    return mock_config_entry


@pytest.fixture
def device_fixture() -> LaMarzoccoModel:
    """Return the device fixture for a specific device."""
    return LaMarzoccoModel.GS3_AV


@pytest.fixture
def mock_lamarzocco(
    request: pytest.FixtureRequest, device_fixture: LaMarzoccoModel
) -> Generator[MagicMock, None, None]:
    """Return a mocked LM client."""
    model_name = device_fixture

    if model_name == LaMarzoccoModel.GS3_AV:
        serial_number = "GS01234"
        true_model_name = "GS3 AV"
    elif model_name == LaMarzoccoModel.GS3_MP:
        serial_number = "GS01234"
        true_model_name = "GS3 MP"
    elif model_name == LaMarzoccoModel.LINEA_MICRA:
        serial_number = "MR01234"
        true_model_name = "Linea Micra"
    elif model_name == LaMarzoccoModel.LINEA_MINI:
        serial_number = "LM01234"
        true_model_name = "Linea Mini"

    with patch(
        "homeassistant.components.lamarzocco.coordinator.LaMarzoccoClient",
        autospec=True,
    ) as lamarzocco_mock, patch(
        "homeassistant.components.lamarzocco.config_flow.LaMarzoccoClient",
        new=lamarzocco_mock,
    ):
        lamarzocco = lamarzocco_mock.return_value

        lamarzocco.machine_info = {
            "machine_name": serial_number,
            "serial_number": serial_number,
        }

        lamarzocco.model_name = model_name
        lamarzocco.true_model_name = true_model_name
        lamarzocco.machine_name = serial_number
        lamarzocco.serial_number = serial_number

        lamarzocco.firmware_version = "1.1"
        lamarzocco.latest_firmware_version = "1.1"
        lamarzocco.gateway_version = "v2.2-rc0"
        lamarzocco.latest_gateway_version = "v3.1-rc4"

        lamarzocco.current_status = json.loads(
            load_fixture("current_status.json", DOMAIN)
        )
        lamarzocco.current_status = load_json_object_fixture(
            "current_status.json", DOMAIN
        )
        lamarzocco.config = load_json_object_fixture("config.json", DOMAIN)
        lamarzocco.statistics = load_json_array_fixture("statistics.json", DOMAIN)
        lamarzocco.schedule = load_json_array_fixture("schedule.json", DOMAIN)

        lamarzocco.get_all_machines.return_value = [
            (serial_number, model_name),
        ]
        lamarzocco.check_local_connection.return_value = True
        lamarzocco.initialized = False

        yield lamarzocco
