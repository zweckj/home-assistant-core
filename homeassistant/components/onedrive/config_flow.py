"""Config flow for OneDrive."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any, cast

from onedrive_personal_sdk.clients.client import OneDriveClient
from onedrive_personal_sdk.exceptions import OneDriveException
from onedrive_personal_sdk.models.items import AppRoot, Drive, Folder, ItemUpdate
import voluptuous as vol

from homeassistant.config_entries import (
    SOURCE_REAUTH,
    SOURCE_RECONFIGURE,
    SOURCE_USER,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_ACCESS_TOKEN, CONF_TOKEN
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.config_entry_oauth2_flow import AbstractOAuth2FlowHandler
from homeassistant.helpers.instance_id import async_get as async_get_instance_id

from .const import (
    CONF_ACCOUNT_TYPE,
    CONF_DELETE_PERMANENTLY,
    CONF_FOLDER_ID,
    CONF_FOLDER_NAME,
    DOMAIN,
    OAUTH_SCOPES_BUSINESS,
    OAUTH_SCOPES_PERSONAL,
    AccountType,
)
from .coordinator import OneDriveConfigEntry

FOLDER_NAME_SCHEMA = vol.Schema({vol.Required(CONF_FOLDER_NAME): str})


class OneDriveConfigFlow(AbstractOAuth2FlowHandler, domain=DOMAIN):
    """Config flow to handle OneDrive OAuth2 authentication."""

    DOMAIN = DOMAIN
    MINOR_VERSION = 3

    client: OneDriveClient
    approot: AppRoot | None = None
    drive: Drive | None = None

    def __init__(self) -> None:
        """Initialize the OneDrive config flow."""
        super().__init__()
        self.step_data: dict[str, Any] = {}
        self._account_type: AccountType = AccountType.PERSONAL

    @property
    def logger(self) -> logging.Logger:
        """Return logger."""
        return logging.getLogger(__name__)

    @property
    def extra_authorize_data(self) -> dict[str, Any]:
        """Extra data that needs to be appended to the authorize url."""
        scopes = (
            OAUTH_SCOPES_BUSINESS
            if self._account_type == AccountType.BUSINESS
            else OAUTH_SCOPES_PERSONAL
        )
        return {"scope": " ".join(scopes)}

    @property
    def is_business_account(self) -> bool:
        """Return if the current flow is for a business account."""
        return self._account_type == AccountType.BUSINESS

    @property
    def apps_folder(self) -> str:
        """Return the name of the Apps folder (translated)."""
        if self.approot is None:
            return "Apps"
        return (
            path.split("/")[-1]
            if (path := self.approot.parent_reference.path)
            else "Apps"
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a flow initialized by the user."""
        return await self.async_step_account_type(user_input)

    async def async_step_account_type(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for account type (personal or business)."""
        if user_input is not None:
            self._account_type = AccountType(user_input[CONF_ACCOUNT_TYPE])
            return await super().async_step_user()

        return self.async_show_form(
            step_id="account_type",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_ACCOUNT_TYPE, default=AccountType.PERSONAL
                    ): vol.In(
                        {
                            AccountType.PERSONAL: "Personal",
                            AccountType.BUSINESS: "OneDrive for Business",
                        }
                    ),
                }
            ),
        )

    async def async_oauth_create_entry(
        self,
        data: dict[str, Any],
    ) -> ConfigFlowResult:
        """Handle the initial step."""

        async def get_access_token() -> str:
            return cast(str, data[CONF_TOKEN][CONF_ACCESS_TOKEN])

        self.client = OneDriveClient(
            get_access_token, async_get_clientsession(self.hass)
        )

        try:
            if self.is_business_account:
                self.drive = await self.client.get_drive()
            else:
                self.approot = await self.client.get_approot()
        except OneDriveException:
            self.logger.exception("Failed to connect to OneDrive")
            return self.async_abort(reason="connection_error")
        except Exception:
            self.logger.exception("Unknown error")
            return self.async_abort(reason="unknown")

        drive_id = (
            self.drive.id if self.is_business_account else self.approot.parent_reference.drive_id  # type: ignore[union-attr]
        )
        await self.async_set_unique_id(drive_id)

        if self.source not in (SOURCE_USER, SOURCE_REAUTH, SOURCE_RECONFIGURE):
            self._abort_if_unique_id_mismatch(
                reason="wrong_drive",
            )

        if self.source == SOURCE_REAUTH:
            reauth_entry = self._get_reauth_entry()
            self._abort_if_unique_id_mismatch(reason="wrong_drive")
            return self.async_update_reload_and_abort(
                entry=reauth_entry,
                data=data,
            )

        if self.source != SOURCE_RECONFIGURE:
            self._abort_if_unique_id_configured()

        self.step_data = data
        self.step_data[CONF_ACCOUNT_TYPE] = self._account_type

        if self.source == SOURCE_RECONFIGURE:
            return await self.async_step_reconfigure_folder()

        return await self.async_step_folder_name()

    async def async_step_folder_name(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step to ask for the folder name."""
        errors: dict[str, str] = {}
        instance_id = await async_get_instance_id(self.hass)
        folder: Folder | None = None
        if user_input is not None:
            try:
                if self.is_business_account:
                    folder = await self.client.create_folder(
                        "root", user_input[CONF_FOLDER_NAME]
                    )
                else:
                    folder = await self.client.create_folder(
                        self.approot.id, user_input[CONF_FOLDER_NAME]  # type: ignore[union-attr]
                    )
            except OneDriveException:
                self.logger.debug("Failed to create folder", exc_info=True)
                errors["base"] = "folder_creation_error"
            if not errors and folder:
                title = self._get_entry_title()
                return self.async_create_entry(
                    title=title,
                    data={
                        **self.step_data,
                        CONF_FOLDER_ID: folder.id,
                        CONF_FOLDER_NAME: user_input[CONF_FOLDER_NAME],
                    },
                )

        default_folder_name = (
            f"backups_{instance_id[:8]}"
            if user_input is None
            else user_input[CONF_FOLDER_NAME]
        )

        if self.is_business_account:
            return self.async_show_form(
                step_id="folder_name",
                data_schema=self.add_suggested_values_to_schema(
                    FOLDER_NAME_SCHEMA, {CONF_FOLDER_NAME: default_folder_name}
                ),
                description_placeholders={
                    "location": "root of your OneDrive",
                },
                errors=errors,
            )

        return self.async_show_form(
            step_id="folder_name",
            data_schema=self.add_suggested_values_to_schema(
                FOLDER_NAME_SCHEMA, {CONF_FOLDER_NAME: default_folder_name}
            ),
            description_placeholders={
                "location": f"`{self.apps_folder}/{self.approot.name}`",  # type: ignore[union-attr]
            },
            errors=errors,
        )

    def _get_entry_title(self) -> str:
        """Get the entry title based on account type."""
        if self.is_business_account:
            if (
                self.drive
                and self.drive.owner
                and self.drive.owner.user
                and self.drive.owner.user.display_name
            ):
                return f"{self.drive.owner.user.display_name}'s OneDrive"
            return "OneDrive for Business"

        if (
            self.approot
            and self.approot.created_by.user
            and self.approot.created_by.user.display_name
        ):
            return f"{self.approot.created_by.user.display_name}'s OneDrive"
        return "OneDrive"

    async def async_step_reconfigure_folder(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Reconfigure the folder name."""
        errors: dict[str, str] = {}
        reconfigure_entry = self._get_reconfigure_entry()

        if user_input is not None:
            if (
                new_folder_name := user_input[CONF_FOLDER_NAME]
            ) != reconfigure_entry.data[CONF_FOLDER_NAME]:
                try:
                    await self.client.update_drive_item(
                        reconfigure_entry.data[CONF_FOLDER_ID],
                        ItemUpdate(name=new_folder_name),
                    )
                except OneDriveException:
                    self.logger.debug("Failed to update folder", exc_info=True)
                    errors["base"] = "folder_rename_error"
            if not errors:
                return self.async_update_reload_and_abort(
                    reconfigure_entry,
                    data={**reconfigure_entry.data, CONF_FOLDER_NAME: new_folder_name},
                )

        # Determine location description based on account type
        if reconfigure_entry.data.get(CONF_ACCOUNT_TYPE) == AccountType.BUSINESS:
            location = "root of your OneDrive"
        elif self.approot:
            location = f"`{self.apps_folder}/{self.approot.name}`"
        else:
            location = "your OneDrive app folder"

        return self.async_show_form(
            step_id="reconfigure_folder",
            data_schema=self.add_suggested_values_to_schema(
                FOLDER_NAME_SCHEMA,
                {CONF_FOLDER_NAME: reconfigure_entry.data[CONF_FOLDER_NAME]},
            ),
            description_placeholders={"location": location},
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Perform reauth upon an API authentication error."""
        # Preserve account type from existing entry
        self._account_type = AccountType(
            entry_data.get(CONF_ACCOUNT_TYPE, AccountType.PERSONAL)
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm reauth dialog."""
        if user_input is None:
            return self.async_show_form(step_id="reauth_confirm")
        return await super().async_step_user()

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Reconfigure the entry."""
        reconfigure_entry = self._get_reconfigure_entry()
        # Preserve account type from existing entry
        self._account_type = AccountType(
            reconfigure_entry.data.get(CONF_ACCOUNT_TYPE, AccountType.PERSONAL)
        )
        return await super().async_step_user()

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: OneDriveConfigEntry,
    ) -> OneDriveOptionsFlowHandler:
        """Create the options flow."""
        return OneDriveOptionsFlowHandler()


class OneDriveOptionsFlowHandler(OptionsFlow):
    """Handles options flow for the component."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options for OneDrive."""
        if user_input:
            return self.async_create_entry(title="", data=user_input)

        options_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_DELETE_PERMANENTLY,
                    default=self.config_entry.options.get(
                        CONF_DELETE_PERMANENTLY, False
                    ),
                ): bool,
            }
        )

        return self.async_show_form(
            step_id="init",
            data_schema=options_schema,
        )
