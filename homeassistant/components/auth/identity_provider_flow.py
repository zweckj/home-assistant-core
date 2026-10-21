"""Config flow base for identity provider integrations.

An integration subclasses IdentityProviderConfigFlow, declares its form
schemas and points `identity_provider` at the spec builder of its
`identity_provider.py` platform. The base owns every step: it aborts when
the engine is off or no URL is available, shows the redirect URIs to
register, validates the spec through the engine, maps validation reasons to
form errors, never shows a stored client secret again and runs the options
flow. Brand specific behaviour is limited to resolving the user step input.
"""

from abc import ABCMeta, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from logging import getLogger
from typing import Any, override

import probatio

from homeassistant import data_entry_flow
from homeassistant.auth.providers.oidc import (
    IdentityProvider,
    IdentityProviderError,
    async_validate_identity_provider,
)
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_CLIENT_SECRET
from homeassistant.core import HomeAssistant, callback

from .identity_providers import (
    async_get_redirect_uris,
    async_identity_providers_enabled,
)

_LOGGER = getLogger(__name__)

# Validation reasons every flow translates; any other reason is invalid_config.
_COMMON_ERRORS = frozenset({"cannot_connect", "invalid_discovery"})


@dataclass(frozen=True, kw_only=True, slots=True)
class IdentityProviderSetup:
    """Config entry details resolved from the user step input."""

    title: str
    data: Mapping[str, Any]
    unique_id: str | None = None


class IdentityProviderFlowError(Exception):
    """Reject the user step input with a form error."""

    def __init__(
        self,
        error: str,
        *,
        field: str = "base",
        placeholders: Mapping[str, str] | None = None,
    ) -> None:
        """Initialize the error."""
        super().__init__(error)
        self.error = error
        self.field = field
        self.placeholders = dict(placeholders or {})


def _entry_data(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return config entry data; an empty client secret means a public client."""
    entry_data = dict(data)
    if not entry_data.get(CONF_CLIENT_SECRET):
        entry_data.pop(CONF_CLIENT_SECRET, None)
    return entry_data


def _format_redirect_uris(redirect_uris: list[str]) -> str:
    """Return the redirect URIs as a markdown list."""
    return "\n".join(f"- `{uri}`" for uri in redirect_uris)


def _errors_from_reason(
    err: IdentityProviderError, translated: frozenset[str]
) -> dict[str, str]:
    """Return the form errors for a validation reason."""
    if err.reason in _COMMON_ERRORS or err.reason in translated:
        return {"base": err.reason}
    _LOGGER.debug("Invalid identity provider configuration: %s", err.reason)
    return {"base": "invalid_config"}


class IdentityProviderConfigFlow(ConfigFlow, metaclass=ABCMeta):
    """Config flow for an identity provider integration.

    Set TITLE and DATA_SCHEMA and assign `identity_provider`. The user and
    reconfigure steps store the form input as entry data. Override
    `async_resolve_setup` when the entry title, unique ID or data have to be
    derived from the input, for example through discovery.
    """

    # Title of entries created by the default `async_resolve_setup`.
    TITLE: str
    # Form of the user step, also used by the reconfigure step by default.
    DATA_SCHEMA: probatio.Schema
    # The reconfigure form always asks for the client secret again.
    RECONFIGURE_SCHEMA: probatio.Schema | None = None
    # Options form; without one the entry has no options flow.
    OPTIONS_SCHEMA: probatio.Schema | None = None
    # Description placeholders of the user step besides `redirect_uris`.
    USER_PLACEHOLDERS: Mapping[str, str] = {}
    # Entry data keys shown as description placeholders of the reconfigure step.
    RECONFIGURE_PLACEHOLDERS: tuple[str, ...] = ()
    # Validation reasons with their own error translation besides the common ones.
    TRANSLATED_ERRORS: frozenset[str] = frozenset()

    @staticmethod
    @abstractmethod
    def identity_provider(
        data: Mapping[str, Any], options: Mapping[str, Any]
    ) -> IdentityProvider:
        """Return the spec for config entry data and options."""

    @callback
    def user_schema(self) -> probatio.Schema:
        """Return the user step form."""
        return self.DATA_SCHEMA

    @callback
    def reconfigure_schema(self) -> probatio.Schema:
        """Return the reconfigure step form."""
        return self.RECONFIGURE_SCHEMA or self.DATA_SCHEMA

    async def async_resolve_setup(
        self, user_input: Mapping[str, Any]
    ) -> IdentityProviderSetup:
        """Resolve the user step input to the entry to create.

        Raise IdentityProviderFlowError to show a form error, or let an
        IdentityProviderError from discovery through to show its reason.
        """
        return IdentityProviderSetup(title=self.TITLE, data=user_input)

    @classmethod
    @callback
    @override
    def async_supports_options_flow(cls, config_entry: ConfigEntry) -> bool:
        """Return whether the entry has an options flow."""
        return cls.OPTIONS_SCHEMA is not None

    @classmethod
    @callback
    @override
    def async_get_options_flow(cls, config_entry: ConfigEntry) -> OptionsFlow:
        """Return the options flow."""
        if cls.OPTIONS_SCHEMA is None:
            raise data_entry_flow.UnknownHandler
        return IdentityProviderOptionsFlow(cls.OPTIONS_SCHEMA, cls)

    @classmethod
    async def async_validate(
        cls,
        hass: HomeAssistant,
        data: Mapping[str, Any],
        options: Mapping[str, Any],
    ) -> dict[str, str]:
        """Build and validate the spec and return the form errors."""
        try:
            await async_validate_identity_provider(
                hass, cls.identity_provider(data, options)
            )
        except IdentityProviderError as err:
            return _errors_from_reason(err, cls.TRANSLATED_ERRORS)
        except Exception:
            _LOGGER.exception("Unexpected exception validating identity provider")
            return {"base": "unknown"}
        return {}

    @override
    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the user step."""
        if not async_identity_providers_enabled(self.hass):
            return self.async_abort(reason="identity_providers_disabled")
        if not (redirect_uris := async_get_redirect_uris(self.hass)):
            return self.async_abort(reason="no_url_available")

        errors: dict[str, str] = {}
        placeholders = {
            **self.USER_PLACEHOLDERS,
            "redirect_uris": _format_redirect_uris(redirect_uris),
        }
        if user_input is not None:
            try:
                setup = await self.async_resolve_setup(user_input)
            except IdentityProviderFlowError as err:
                errors[err.field] = err.error
                placeholders |= err.placeholders
            except IdentityProviderError as err:
                errors = _errors_from_reason(err, self.TRANSLATED_ERRORS)
            except Exception:
                _LOGGER.exception("Unexpected exception resolving identity provider")
                errors["base"] = "unknown"
            else:
                if setup.unique_id is not None:
                    await self.async_set_unique_id(setup.unique_id)
                    self._abort_if_unique_id_configured()
                data = _entry_data(setup.data)
                errors = await self.async_validate(self.hass, data, {})
                if not errors:
                    return self.async_create_entry(title=setup.title, data=data)

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                self.user_schema(), user_input
            ),
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the reconfigure step."""
        entry = self._get_reconfigure_entry()
        kept = {
            key: value for key, value in entry.data.items() if key != CONF_CLIENT_SECRET
        }
        errors: dict[str, str] = {}
        if user_input is not None:
            data = _entry_data({**kept, **user_input})
            errors = await self.async_validate(self.hass, data, entry.options)
            if not errors:
                return self.async_update_reload_and_abort(entry, data=data)

        suggested_values = {**kept, **(user_input or {})}
        suggested_values.pop(CONF_CLIENT_SECRET, None)
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self.add_suggested_values_to_schema(
                self.reconfigure_schema(), suggested_values
            ),
            errors=errors,
            description_placeholders={
                key: str(entry.data[key]) for key in self.RECONFIGURE_PLACEHOLDERS
            },
        )


class IdentityProviderOptionsFlow(OptionsFlow):
    """Options flow validating the spec built from the new options."""

    def __init__(
        self, schema: probatio.Schema, flow: type[IdentityProviderConfigFlow]
    ) -> None:
        """Initialize the options flow."""
        self._schema = schema
        self._flow = flow

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the options step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            errors = await self._flow.async_validate(
                self.hass, self.config_entry.data, user_input
            )
            if not errors:
                return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(
                self._schema, user_input or self.config_entry.options
            ),
            errors=errors,
        )
