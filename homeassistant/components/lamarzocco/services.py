"""Global services for the La Marzocco integration."""

from collections.abc import Callable, Coroutine
import logging
from typing import Any, Final

from lmcloud.const import LaMarzoccoModel
from lmcloud.exceptions import AuthFail, RequestNotSuccessful
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv, selector

from .const import DOMAIN
from .coordinator import LaMarzoccoUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


SERVICE_DOSE = "set_dose"
SERVICE_DOSE_HOT_WATER = "set_dose_hot_water"
SERVICE_AUTO_ON_OFF_ENABLE = "set_auto_on_off_enable"
SERVICE_AUTO_ON_OFF_TIMES = "set_auto_on_off_times"
SERVICE_PREBREW_TIMES = "set_prebrew_times"
SERVICE_PREINFUSION_TIME = "set_preinfusion_time"

CONF_CONFIG_ENTRY: Final = "config_entry"
CONF_DAY_OF_WEEK = "day_of_week"
CONF_ENABLE = "enable"
CONF_HOUR_ON = "hour_on"
CONF_HOUR_OFF = "hour_off"
CONF_MINUTE_ON = "minute_on"
CONF_MINUTE_OFF = "minute_off"
CONF_SECONDS_ON = "seconds_on"
CONF_SECONDS_OFF = "seconds_off"
CONF_SECONDS = "seconds"
CONF_KEY = "key"
CONF_PULSES = "pulses"

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

CONFIG_ENTRY_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_CONFIG_ENTRY): selector.ConfigEntrySelector(
            {
                "integration": DOMAIN,
            }
        )
    }
)

SET_DOSE_SCHEMA = CONFIG_ENTRY_SCHEMA.extend(
    {
        vol.Required(CONF_KEY): vol.All(vol.Coerce(int), vol.Range(min=1, max=5)),
        vol.Required(CONF_PULSES): vol.All(vol.Coerce(int), vol.Range(min=0, max=1000)),
    }
)

SET_DOSE_HOT_WATER_SCHEMA = CONFIG_ENTRY_SCHEMA.extend(
    {
        vol.Required("seconds"): vol.All(vol.Coerce(int), vol.Range(min=0, max=30)),
    }
)

SET_AUTO_ON_OFF_ENABLE_SCHEMA = CONFIG_ENTRY_SCHEMA.extend(
    {
        vol.Required(CONF_DAY_OF_WEEK): vol.In(DAYS),
        vol.Required(CONF_ENABLE): cv.boolean,
    }
)

SET_AUTO_ON_OFF_TIMES_SCHEMA = CONFIG_ENTRY_SCHEMA.extend(
    {
        vol.Required(CONF_DAY_OF_WEEK): vol.In(DAYS),
        vol.Required(CONF_HOUR_ON): vol.All(vol.Coerce(int), vol.Range(min=0, max=23)),
        vol.Optional(CONF_MINUTE_ON, default=0): vol.All(
            vol.Coerce(int), vol.Range(min=0, max=59)
        ),
        vol.Required(CONF_HOUR_OFF): vol.All(vol.Coerce(int), vol.Range(min=0, max=23)),
        vol.Optional(CONF_MINUTE_OFF, default=0): vol.All(
            vol.Coerce(int), vol.Range(min=0, max=59)
        ),
    }
)

SET_PREBREW_TIMES_SCHEMA = CONFIG_ENTRY_SCHEMA.extend(
    {
        vol.Required(CONF_SECONDS_ON): vol.All(
            vol.Coerce(float), vol.Range(min=0, max=5.9)
        ),
        vol.Required(CONF_SECONDS_OFF): vol.All(
            vol.Coerce(float), vol.Range(min=0, max=5.9)
        ),
        vol.Required(CONF_KEY): vol.All(vol.Coerce(int), vol.Range(min=1, max=4)),
    }
)

SET_PREINFUSION_TIME_SCHEMA = CONFIG_ENTRY_SCHEMA.extend(
    {
        vol.Required(CONF_SECONDS): vol.All(
            vol.Coerce(float), vol.Range(min=0, max=24.9)
        ),
        vol.Required(CONF_KEY): vol.All(vol.Coerce(int), vol.Range(min=1, max=4)),
    }
)


async def __call_service(
    func: Callable[..., Coroutine[Any, Any, Any]], *args: Any, **kwargs: Any
) -> None:
    """Call a service and handle exceptions."""
    try:
        await func(*args, **kwargs)
    except (AuthFail, RequestNotSuccessful, TimeoutError) as ex:
        raise HomeAssistantError("Service call encountered error: %s" % str(ex)) from ex


def __get_coordinator(
    hass: HomeAssistant, call: ServiceCall
) -> LaMarzoccoUpdateCoordinator:
    """Get the coordinator from the entry."""
    entry_id: str = call.data[CONF_CONFIG_ENTRY]
    entry: ConfigEntry | None = hass.config_entries.async_get_entry(entry_id)

    if not entry:
        raise ServiceValidationError(
            f"Invalid config entry: {entry_id}",
            translation_domain=DOMAIN,
            translation_key="invalid_config_entry",
            translation_placeholders={
                "config_entry": entry_id,
            },
        )
    if entry.state != ConfigEntryState.LOADED:
        raise ServiceValidationError(
            f"Config entry {entry.title} is not loaded",
            translation_domain=DOMAIN,
            translation_key="unloaded_config_entry",
            translation_placeholders={
                "config_entry": entry.title,
            },
        )
    coordinator: LaMarzoccoUpdateCoordinator = hass.data[DOMAIN][entry_id]
    return coordinator


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Create and register services for the La Marzocco integration."""

    async def _set_auto_on_off_enable(service: ServiceCall) -> None:
        """Service call to enable auto on/off."""

        day_of_week = service.data[CONF_DAY_OF_WEEK]
        enable = service.data[CONF_ENABLE]

        coordinator = __get_coordinator(hass, service)

        _LOGGER.debug("Setting auto on/off for %s to %s", day_of_week, enable)
        await __call_service(
            coordinator.lm.set_auto_on_off_enable,
            day_of_week=day_of_week,
            enable=enable,
        )

    async def _set_auto_on_off_times(service: ServiceCall) -> None:
        """Service call to configure auto on/off hours for a day."""
        day_of_week = service.data[CONF_DAY_OF_WEEK]
        hour_on = service.data[CONF_HOUR_ON]
        minute_on = service.data[CONF_MINUTE_ON]
        hour_off = service.data[CONF_HOUR_OFF]
        minute_off = service.data[CONF_MINUTE_OFF]

        coordinator = __get_coordinator(hass, service)

        _LOGGER.debug(
            "Setting auto on/off hours for %s from %s:%s to %s:%s",
            day_of_week,
            hour_on,
            minute_on,
            hour_off,
            minute_off,
        )
        await __call_service(
            coordinator.lm.set_auto_on_off,
            day_of_week=day_of_week,
            hour_on=hour_on,
            minute_on=minute_on,
            hour_off=hour_off,
            minute_off=minute_off,
        )

    async def _set_dose(service: ServiceCall) -> None:
        """Service call to set the dose for a key."""

        key = service.data[CONF_KEY]
        pulses = service.data[CONF_PULSES]

        coordinator = __get_coordinator(hass, service)
        if coordinator.lm.model_name != LaMarzoccoModel.GS3_AV:
            raise ServiceValidationError(
                f"Model {coordinator.lm.model_name} does not support this service",
                translation_domain=DOMAIN,
                translation_key="invalid_model",
                translation_placeholders={
                    "model": coordinator.lm.model_name,
                },
            )

        _LOGGER.debug("Setting dose for key: %s to pulses: %s", key, pulses)
        await __call_service(coordinator.lm.set_dose, key=key, value=pulses)

    async def _set_dose_hot_water(service: ServiceCall) -> None:
        """Service call to set the hot water dose."""

        seconds = service.data[CONF_SECONDS]
        coordinator = __get_coordinator(hass, service)

        if coordinator.lm.model_name not in (
            LaMarzoccoModel.GS3_AV,
            LaMarzoccoModel.GS3_MP,
        ):
            raise ServiceValidationError(
                f"Model {coordinator.lm.model_name} does not support this service",
                translation_domain=DOMAIN,
                translation_key="invalid_model",
                translation_placeholders={
                    "model": coordinator.lm.model_name,
                },
            )

        _LOGGER.debug("Setting hot water dose to seconds: %s", seconds)
        await __call_service(coordinator.lm.set_dose_hot_water, value=seconds)

    async def _set_prebrew_times(service: ServiceCall) -> None:
        """Service call to set prebrew on time."""

        key = int(service.data[CONF_KEY])
        seconds_on = float(service.data[CONF_SECONDS_ON])
        seconds_off = float(service.data[CONF_SECONDS_OFF])

        coordinator = __get_coordinator(hass, service)

        if coordinator.lm.model_name == LaMarzoccoModel.GS3_MP:
            raise ServiceValidationError(
                f"Model {coordinator.lm.model_name} does not support this service",
                translation_domain=DOMAIN,
                translation_key="invalid_model",
                translation_placeholders={
                    "model": coordinator.lm.model_name,
                },
            )
        if (
            coordinator.lm.model_name
            in (
                LaMarzoccoModel.LINEA_MINI,
                LaMarzoccoModel.LINEA_MICRA,
            )
            and key > 1
        ):
            raise ServiceValidationError(
                f"Key {key} is not supported for model {coordinator.lm.model_name}",
                translation_domain=DOMAIN,
                translation_key="invalid_key",
                translation_placeholders={
                    "model": coordinator.lm.model_name,
                    "key": "1",
                },
            )

        _LOGGER.debug(
            "Setting prebrew on time for %s to %s and %s", key, seconds_on, seconds_off
        )
        await __call_service(
            coordinator.lm.set_prebrew_times,
            key=key,
            seconds_on=seconds_on,
            seconds_off=seconds_off,
        )

    async def _set_preinfusion_time(service: ServiceCall) -> None:
        """Service call to set preinfusion time."""

        key = int(service.data[CONF_KEY])
        seconds = float(service.data[CONF_SECONDS])

        coordinator = __get_coordinator(hass, service)

        if coordinator.lm.model_name == LaMarzoccoModel.GS3_MP:
            raise ServiceValidationError(
                f"Model {coordinator.lm.model_name} does not support this service",
                translation_domain=DOMAIN,
                translation_key="invalid_model",
                translation_placeholders={
                    "model": coordinator.lm.model_name,
                },
            )

        if (
            coordinator.lm.model_name
            in (
                LaMarzoccoModel.LINEA_MINI,
                LaMarzoccoModel.LINEA_MICRA,
            )
            and key > 1
        ):
            raise ServiceValidationError(
                f"Key {key} is not supported for model {coordinator.lm.model_name}",
                translation_domain=DOMAIN,
                translation_key="invalid_key",
                translation_placeholders={
                    "model": coordinator.lm.model_name,
                    "key": "1",
                },
            )

        _LOGGER.debug("Setting prebrew on time for %s to %s", key, seconds)
        await __call_service(
            coordinator.lm.set_preinfusion_time,
            key=key,
            seconds=seconds,
        )

    hass.services.async_register(
        DOMAIN,
        SERVICE_DOSE,
        _set_dose,
        schema=SET_DOSE_SCHEMA,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_DOSE_HOT_WATER,
        _set_dose_hot_water,
        schema=SET_DOSE_HOT_WATER_SCHEMA,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_AUTO_ON_OFF_ENABLE,
        _set_auto_on_off_enable,
        schema=SET_AUTO_ON_OFF_ENABLE_SCHEMA,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_AUTO_ON_OFF_TIMES,
        _set_auto_on_off_times,
        schema=SET_AUTO_ON_OFF_TIMES_SCHEMA,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_PREBREW_TIMES,
        _set_prebrew_times,
        schema=SET_PREBREW_TIMES_SCHEMA,
    )

    hass.services.async_register(
        DOMAIN,
        SERVICE_PREINFUSION_TIME,
        _set_preinfusion_time,
        schema=SET_PREINFUSION_TIME_SCHEMA,
    )
