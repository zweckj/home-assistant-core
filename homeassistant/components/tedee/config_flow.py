"""Config flow for Tedee integration."""
from collections.abc import Mapping
from typing import Any

from pytedee_async import (
    TedeeAuthException,
    TedeeClient,
    TedeeClientException,
    TedeeLocalAuthException,
)
from pytedee_async.bridge import TedeeBridge
import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow
from homeassistant.const import CONF_ACCESS_TOKEN, CONF_HOST
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .const import (
    CONF_CLOUD_BRIDGE_ID,
    CONF_LOCAL_ACCESS_TOKEN,
    CONF_USE_CLOUD_API,
    CONF_USE_LOCAL_API,
    DOMAIN,
    NAME,
)


class TedeeConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Tedee."""

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._errors: dict[str, str] = {}
        self._previous_step_data: dict[str, Any] = {}
        self._bridges: list[TedeeBridge] = []
        self._local_bridge: TedeeBridge | None = None
        self.reauth_entry: ConfigEntry | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            if user_input.get(CONF_USE_LOCAL_API):
                return await self.async_step_configure_local(user_input)
            if user_input.get(CONF_USE_CLOUD_API):
                return await self.async_step_configure_cloud(user_input)
            errors["base"] = "no_option_selected"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_USE_LOCAL_API): bool,
                    vol.Optional(CONF_USE_CLOUD_API): bool,
                }
            ),
            errors=errors,
        )

    async def async_step_configure_local(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            if self.reauth_entry:
                host = self.reauth_entry.data[CONF_HOST]
            else:
                host = user_input[CONF_HOST]
            local_access_token = user_input[CONF_LOCAL_ACCESS_TOKEN]
            tedee_client = TedeeClient(local_token=local_access_token, local_ip=host)
            try:
                self._local_bridge = await tedee_client.get_local_bridge()
            except (TedeeAuthException, TedeeLocalAuthException):
                errors[CONF_LOCAL_ACCESS_TOKEN] = "invalid_api_key"
            except TedeeClientException:
                errors[CONF_HOST] = "invalid_host"
            else:
                if self.reauth_entry:
                    self.hass.config_entries.async_update_entry(
                        self.reauth_entry,
                        data={**self.reauth_entry.data, **user_input},
                    )
                    await self.hass.config_entries.async_reload(
                        self.context["entry_id"]
                    )
                    return self.async_abort(reason="reauth_successful")
                await self.async_set_unique_id(self._local_bridge.serial)
                self._abort_if_unique_id_configured()
                if user_input.get(CONF_USE_CLOUD_API):
                    self._previous_step_data = user_input
                    return await self.async_step_configure_cloud()
                return self.async_create_entry(title=NAME, data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_HOST,
                    ): str,
                    vol.Required(
                        CONF_LOCAL_ACCESS_TOKEN,
                    ): str,
                }
            ),
            errors=errors,
        )

    async def async_step_configure_cloud(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Extra step for cloud configuration."""
        errors: dict[str, str] = {}
        if user_input is not None:
            bridges: list[TedeeBridge] = []
            tedee_client = TedeeClient(personal_token=user_input[CONF_ACCESS_TOKEN])
            try:
                await tedee_client.get_bridges()
            except TedeeAuthException:
                errors[CONF_ACCESS_TOKEN] = "invalid_api_key"
            except TedeeClientException:
                errors["base"] = "cannot_connect"

            if not errors:
                # if user has configured local API, make sure the bridge is the same
                if self._local_bridge:
                    cloud_bridge = [
                        bridge
                        for bridge in self._bridges
                        if bridge.bridge_id == self._local_bridge.bridge_id
                    ][0]
                    if not cloud_bridge:
                        errors["base"] = "bridge_not_found"
                    elif not self._local_bridge:
                        await self.async_set_unique_id(cloud_bridge.serial)
                        self._abort_if_unique_id_configured()

                    if not errors:
                        return self.async_create_entry(
                            title=NAME,
                            data=user_input
                            | self._previous_step_data
                            | {CONF_CLOUD_BRIDGE_ID: cloud_bridge.bridge_id},
                        )

                    self._bridges = bridges
                    self._previous_step_data |= user_input
                    return await self.async_step_select_bridge()

        return self.async_show_form(
            step_id="configure_cloud",
            data_schema=vol.Schema({vol.Required(CONF_ACCESS_TOKEN): str}),
            errors=errors,
        )

    async def async_step_select_bridge(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Select a bridge from the cloud."""
        errors: dict[str, str] = {}
        if user_input is not None:
            # find the bridge with the selected bridge_id
            selected_bridge = [
                bridge
                for bridge in self._bridges
                if str(bridge.bridge_id) == user_input[CONF_CLOUD_BRIDGE_ID]
            ][0]
            await self.async_set_unique_id(selected_bridge.serial)
            self._abort_if_unique_id_configured()

            if not errors:
                return self.async_create_entry(
                    title=NAME, data=self._previous_step_data | user_input
                )

        bridge_selection_schema = vol.Schema(
            {
                vol.Required(CONF_CLOUD_BRIDGE_ID): SelectSelector(
                    SelectSelectorConfig(
                        options=[
                            SelectOptionDict(
                                value=str(bridge.bridge_id),
                                label=f"{bridge.name} ({bridge.serial})",
                            )
                            for bridge in self._bridges
                        ],
                        mode=SelectSelectorMode.DROPDOWN,
                    )
                )
            }
        )
        return self.async_show_form(
            step_id="select_bridge",
            data_schema=bridge_selection_schema,
            errors=errors,
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> FlowResult:
        """Perform reauth upon an API authentication error."""
        self.reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_LOCAL_ACCESS_TOKEN,
                        default=entry_data[CONF_LOCAL_ACCESS_TOKEN],
                    ): str,
                }
            ),
        )
