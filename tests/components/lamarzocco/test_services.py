"""Test the LaMarzocco services."""
from unittest.mock import MagicMock

from lmcloud.const import LaMarzoccoModel
from lmcloud.exceptions import RequestNotSuccessful
import pytest

from homeassistant.components.lamarzocco.const import DOMAIN
from homeassistant.components.lamarzocco.services import (
    CONF_CONFIG_ENTRY,
    CONF_DAY_OF_WEEK,
    CONF_ENABLE,
    CONF_HOUR_OFF,
    CONF_HOUR_ON,
    CONF_KEY,
    CONF_MINUTE_OFF,
    CONF_MINUTE_ON,
    CONF_PULSES,
    CONF_SECONDS,
    CONF_SECONDS_OFF,
    CONF_SECONDS_ON,
    SERVICE_AUTO_ON_OFF_ENABLE,
    SERVICE_AUTO_ON_OFF_TIMES,
    SERVICE_DOSE,
    SERVICE_DOSE_HOT_WATER,
    SERVICE_PREBREW_TIMES,
    SERVICE_PREINFUSION_TIME,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from tests.common import MockConfigEntry

pytestmark = pytest.mark.usefixtures("init_integration")


async def test_service_auto_on_off_enable(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco auto on/off enable service."""

    await hass.services.async_call(
        DOMAIN,
        SERVICE_AUTO_ON_OFF_ENABLE,
        {
            CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
            CONF_DAY_OF_WEEK: "mon",
            CONF_ENABLE: True,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_auto_on_off_enable.mock_calls) == 1
    mock_lamarzocco.set_auto_on_off_enable.assert_called_once_with(
        day_of_week="mon", enable=True
    )


async def test_service_call_error(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test an exception during the service call."""
    mock_lamarzocco.set_auto_on_off_enable.side_effect = RequestNotSuccessful(
        "BadRequest"
    )
    with pytest.raises(
        HomeAssistantError, match="Service call encountered error: BadRequest"
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_AUTO_ON_OFF_ENABLE,
            {
                CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
                CONF_DAY_OF_WEEK: "mon",
                CONF_ENABLE: True,
            },
            blocking=True,
        )


async def test_invalid_config_entry(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test validation error for invalid config entry."""
    entry_id = "invalid"
    with pytest.raises(
        ServiceValidationError,
        match=f"Invalid config entry: {entry_id}",
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_DOSE,
            {
                CONF_CONFIG_ENTRY: entry_id,
                CONF_KEY: 2,
                CONF_PULSES: 300,
            },
            blocking=True,
        )


async def test_unloaded_config_entry(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test validation error for unloaded config entry."""

    await mock_config_entry.async_unload(hass)

    with pytest.raises(
        ServiceValidationError,
        match=f"Config entry {mock_config_entry.title} is not loaded",
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_DOSE,
            {
                CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
                CONF_KEY: 2,
                CONF_PULSES: 300,
            },
            blocking=True,
        )


async def test_service_set_auto_on_off_times(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco auto on/off times service."""

    await hass.services.async_call(
        DOMAIN,
        SERVICE_AUTO_ON_OFF_TIMES,
        {
            CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
            CONF_DAY_OF_WEEK: "tue",
            CONF_HOUR_ON: 8,
            CONF_MINUTE_ON: 30,
            CONF_HOUR_OFF: 17,
            CONF_MINUTE_OFF: 0,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_auto_on_off.mock_calls) == 1
    mock_lamarzocco.set_auto_on_off.assert_called_once_with(
        day_of_week="tue", hour_on=8, minute_on=30, hour_off=17, minute_off=0
    )


async def test_service_set_dose(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco set dose service."""

    await hass.services.async_call(
        DOMAIN,
        SERVICE_DOSE,
        {
            CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
            CONF_KEY: 2,
            CONF_PULSES: 300,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_dose.mock_calls) == 1
    mock_lamarzocco.set_dose.assert_called_once_with(key=2, value=300)


@pytest.mark.parametrize(
    "device_fixture",
    [LaMarzoccoModel.GS3_MP, LaMarzoccoModel.LINEA_MICRA, LaMarzoccoModel.LINEA_MINI],
)
async def test_service_set_dose_validation_error(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Ensure the set dose service is only callable by GS3AV."""

    with pytest.raises(
        ServiceValidationError,
        match=f"Model {mock_lamarzocco.model_name} does not support this service",
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_DOSE,
            {
                CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
                CONF_KEY: 2,
                CONF_PULSES: 300,
            },
            blocking=True,
        )


async def test_service_set_dose_hot_water(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco set dose hot water service."""

    await hass.services.async_call(
        DOMAIN,
        SERVICE_DOSE_HOT_WATER,
        {
            CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
            CONF_SECONDS: 16,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_dose_hot_water.mock_calls) == 1
    mock_lamarzocco.set_dose_hot_water.assert_called_once_with(value=16)


@pytest.mark.parametrize(
    "device_fixture", [LaMarzoccoModel.LINEA_MICRA, LaMarzoccoModel.LINEA_MINI]
)
async def test_service_set_dose_hot_water_validation_error(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco set dose hot water service."""

    with pytest.raises(
        ServiceValidationError,
        match=f"Model {mock_lamarzocco.model_name} does not support this service",
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_DOSE_HOT_WATER,
            {
                CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
                CONF_SECONDS: 16,
            },
            blocking=True,
        )


async def test_service_set_prebrew_times(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco set prebrew times service."""

    await hass.services.async_call(
        DOMAIN,
        SERVICE_PREBREW_TIMES,
        {
            CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
            CONF_KEY: 3,
            CONF_SECONDS_ON: 4,
            CONF_SECONDS_OFF: 5,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_prebrew_times.mock_calls) == 1
    mock_lamarzocco.set_prebrew_times.assert_called_once_with(
        key=3, seconds_on=4, seconds_off=5
    )


@pytest.mark.parametrize(
    "device_fixture",
    [LaMarzoccoModel.GS3_MP],
)
async def test_service_set_prebrew_times_unsupported_model(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Ensure GS3MP can not call."""

    with pytest.raises(
        ServiceValidationError,
        match=f"Model {mock_lamarzocco.model_name} does not support this service",
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_PREBREW_TIMES,
            {
                CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
                CONF_KEY: 3,
                CONF_SECONDS_ON: 4,
                CONF_SECONDS_OFF: 5,
            },
            blocking=True,
        )


@pytest.mark.parametrize(
    "device_fixture",
    [LaMarzoccoModel.LINEA_MICRA, LaMarzoccoModel.LINEA_MINI],
)
@pytest.mark.parametrize("key", ["2", "3", "4"])
async def test_service_set_prebrew_times_invalid_key(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
    key: str,
) -> None:
    """Ensure keys greater than 1 fail for Mini and Micra."""

    with pytest.raises(
        ServiceValidationError,
        match=f"Key {key} is not supported for model {mock_lamarzocco.model_name}",
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_PREBREW_TIMES,
            {
                CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
                CONF_KEY: int(key),
                CONF_SECONDS_ON: 4,
                CONF_SECONDS_OFF: 5,
            },
            blocking=True,
        )


async def test_service_set_preinfusion_time(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Test the La Marzocco set preinfusion time service."""

    await hass.services.async_call(
        DOMAIN,
        SERVICE_PREINFUSION_TIME,
        {
            CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
            CONF_KEY: 3,
            CONF_SECONDS: 6,
        },
        blocking=True,
    )

    assert len(mock_lamarzocco.set_preinfusion_time.mock_calls) == 1
    mock_lamarzocco.set_preinfusion_time.assert_called_once_with(key=3, seconds=6)


@pytest.mark.parametrize(
    "device_fixture",
    [LaMarzoccoModel.GS3_MP],
)
async def test_service_set_preinfusion_times_unsupported_model(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
) -> None:
    """Ensure GS3MP can not call."""

    with pytest.raises(
        ServiceValidationError,
        match=f"Model {mock_lamarzocco.model_name} does not support this service",
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_PREINFUSION_TIME,
            {
                CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
                CONF_KEY: 3,
                CONF_SECONDS: 6,
            },
            blocking=True,
        )


@pytest.mark.parametrize(
    "device_fixture",
    [LaMarzoccoModel.LINEA_MICRA, LaMarzoccoModel.LINEA_MINI],
)
@pytest.mark.parametrize("key", ["2", "3", "4"])
async def test_service_set_preinfusion_times_invalid_key(
    hass: HomeAssistant,
    mock_lamarzocco: MagicMock,
    mock_config_entry: MockConfigEntry,
    key: str,
) -> None:
    """Ensure keys greater than 1 fail for Mini and Micra."""

    with pytest.raises(
        ServiceValidationError,
        match=f"Key {key} is not supported for model {mock_lamarzocco.model_name}",
    ):
        await hass.services.async_call(
            DOMAIN,
            SERVICE_PREINFUSION_TIME,
            {
                CONF_CONFIG_ENTRY: mock_config_entry.entry_id,
                CONF_KEY: int(key),
                CONF_SECONDS: 6,
            },
            blocking=True,
        )
