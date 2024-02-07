"""Config flow for La Marzocco integration."""

from collections.abc import Mapping
import logging
from typing import Any

from lmcloud.client_cloud import LaMarzoccoCloudClient
from lmcloud.client_local import LaMarzoccoLocalClient
from lmcloud.exceptions import AuthFail, RequestNotSuccessful
from lmcloud.models import LaMarzoccoDeviceInfo
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow
from homeassistant.const import (
    CONF_HOST,
    CONF_MODEL,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_TOKEN,
    CONF_USERNAME,
)
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.httpx_client import get_async_client
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .const import CONF_MACHINE, DOMAIN

_LOGGER = logging.getLogger(__name__)


class LmConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for La Marzocco."""

    VERSION = 2

    def __init__(self) -> None:
        """Initialize the config flow."""

        self.reauth_entry: ConfigEntry | None = None
        self._config: dict[str, Any] = {}
        self._fleet: dict[str, LaMarzoccoDeviceInfo] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""

        errors = {}

        if user_input:
            data: dict[str, Any] = {}
            if self.reauth_entry:
                data = dict(self.reauth_entry.data)
            data = {
                **data,
                **user_input,
            }

            cloud_client = LaMarzoccoCloudClient(
                username=data[CONF_USERNAME],
                password=data[CONF_PASSWORD],
            )
            try:
                self._fleet = await cloud_client.get_customer_fleet()
            except AuthFail:
                _LOGGER.debug("Server rejected login credentials")
                errors["base"] = "invalid_auth"
            except RequestNotSuccessful as exc:
                _LOGGER.error("Error connecting to server: %s", exc)
                errors["base"] = "cannot_connect"
            else:
                if not self._fleet:
                    errors["base"] = "no_machines"

            if not errors:
                if self.reauth_entry:
                    self.hass.config_entries.async_update_entry(
                        self.reauth_entry, data=data
                    )
                    await self.hass.config_entries.async_reload(
                        self.reauth_entry.entry_id
                    )
                    return self.async_abort(reason="reauth_successful")

            if not errors:
                self._config = data
                return await self.async_step_machine_selection()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_USERNAME): str,
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
        )

    async def async_step_machine_selection(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Let user select machine to connect to."""
        errors: dict[str, str] = {}
        if user_input:
            serial_number = user_input[CONF_MACHINE]
            await self.async_set_unique_id(serial_number)
            self._abort_if_unique_id_configured()

            selected_device = self._fleet[CONF_MACHINE]

            # validate local connection if host is provided
            if user_input.get(CONF_HOST):
                if not await LaMarzoccoLocalClient.validate_connection(
                    client=get_async_client(self.hass),
                    host=user_input[CONF_HOST],
                    token=selected_device.communication_key,
                ):
                    errors[CONF_HOST] = "cannot_connect"

            if not errors:
                return self.async_create_entry(
                    title=serial_number,
                    data={
                        **self._config,
                        **user_input,
                        CONF_NAME: selected_device.name,
                        CONF_MODEL: selected_device.model,
                        CONF_TOKEN: selected_device.communication_key,
                    },
                )

        machine_options = [
            SelectOptionDict(
                value=serial_number,
                label=f"{device.model} ({device.serial_number})",
            )
            for device in self._fleet.values()
        ]

        machine_selection_schema = vol.Schema(
            {
                vol.Required(
                    CONF_MACHINE, default=machine_options[0]["value"]
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=machine_options,
                        mode=SelectSelectorMode.DROPDOWN,
                    )
                ),
                vol.Optional(CONF_HOST): cv.string,
            }
        )

        return self.async_show_form(
            step_id="machine_selection",
            data_schema=machine_selection_schema,
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> FlowResult:
        """Perform reauth upon an API authentication error."""
        self.reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Dialog that informs the user that reauth is required."""
        if not user_input:
            return self.async_show_form(
                step_id="reauth_confirm",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_PASSWORD): str,
                    }
                ),
            )

        return await self.async_step_user(user_input)
