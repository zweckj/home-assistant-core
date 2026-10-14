"""Connect identity provider integrations to the OpenID Connect auth engine."""

import asyncio
from collections.abc import Mapping
import logging
from typing import Any, Protocol

from homeassistant.auth.const import LOGIN_CALLBACK_PATH
from homeassistant.auth.models import User
from homeassistant.auth.providers.oidc import (
    IdentityProvider,
    IdentityProviderError,
    OidcAuthProvider,
    OidcIdentityProvider,
    OpenIDConnect,
    async_get_provider,
)
from homeassistant.config_entries import (
    SIGNAL_CONFIG_ENTRY_CHANGED,
    ConfigEntry,
    ConfigEntryChange,
    ConfigEntryState,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.integration_platform import (
    async_process_integration_platforms,
)
from homeassistant.helpers.network import NoURLAvailableError, get_url
from homeassistant.helpers.start import async_at_started
from homeassistant.loader import async_get_loaded_integration

DOMAIN = "auth"

_LOGGER = logging.getLogger(__name__)


class IdentityProviderPlatform(Protocol):
    """Protocol for identity provider platforms."""

    def get_identity_provider(
        self, data: Mapping[str, Any], options: Mapping[str, Any]
    ) -> IdentityProvider:
        """Return the identity provider spec for config entry data and options."""


@callback
def async_identity_providers_enabled(hass: HomeAssistant) -> bool:
    """Return if the identity provider engine is enabled in auth_providers."""
    return async_get_provider(hass) is not None


@callback
def async_get_redirect_uris(hass: HomeAssistant) -> list[str]:
    """Return the redirect URIs to register at an identity provider."""
    uris: list[str] = []
    for allow_internal, allow_external, allow_cloud in (
        (False, True, False),
        (False, True, True),
        (True, False, False),
    ):
        try:
            url = get_url(
                hass,
                allow_internal=allow_internal,
                allow_external=allow_external,
                allow_cloud=allow_cloud,
                prefer_cloud=allow_cloud,
            )
        except NoURLAvailableError:
            continue
        if (uri := f"{url}{LOGIN_CALLBACK_PATH}") not in uris:
            uris.append(uri)
    return uris


async def async_setup_identity_providers(hass: HomeAssistant) -> None:
    """Set up integration identity provider platforms."""
    bridge = _IdentityProviderBridge(hass)
    await bridge.async_setup()


class _IdentityProviderBridge:
    """Bridge config entry integration platforms to the OIDC engine."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the bridge."""
        self.hass = hass
        self._lock = asyncio.Lock()
        self._platforms: dict[str, IdentityProviderPlatform] = {}
        self._registered: dict[str, tuple[IdentityProvider, str]] = {}
        self._disabled_sessions_ended: set[str] = set()

    async def async_setup(self) -> None:
        """Set up integration platform processing and config entry change hooks."""
        async_dispatcher_connect(
            self.hass,
            SIGNAL_CONFIG_ENTRY_CHANGED,
            self._entry_changed,
        )
        async_at_started(self.hass, self._async_at_started)
        await async_process_integration_platforms(
            self.hass,
            "identity_provider",
            self._async_process_platform,
            wait_for_platforms=True,
        )

    async def _async_process_platform(
        self,
        hass: HomeAssistant,
        domain: str,
        platform: IdentityProviderPlatform,
    ) -> None:
        """Process an identity provider platform."""
        self._platforms[domain] = platform
        self._warn_custom_integration_once(domain)
        for entry in hass.config_entries.async_entries(domain, include_ignore=False):
            await self._async_reconcile(entry.entry_id)

    @callback
    def _warn_custom_integration_once(self, domain: str) -> None:
        """Warn once when a custom integration contributes sign-in configuration."""
        integration = async_get_loaded_integration(self.hass, domain)
        if integration.is_built_in:
            return
        _LOGGER.warning(
            "The custom integration %s provides sign-in configuration that has not "
            "been reviewed by Home Assistant",
            domain,
        )

    @callback
    def _entry_changed(
        self, change_type: ConfigEntryChange, entry: ConfigEntry
    ) -> None:
        """Handle a config entry change."""
        if entry.domain not in self._platforms and (
            (provider := async_get_provider(self.hass)) is None
            or entry.entry_id not in provider.identity_provider_ids
        ):
            return
        self.hass.async_create_task(
            self._async_reconcile(
                entry.entry_id,
                removed_entry=entry
                if change_type is ConfigEntryChange.REMOVED
                else None,
            ),
            "Reconcile identity provider config entry",
        )

    async def _async_at_started(self, hass: HomeAssistant) -> None:
        """Remove stored identity providers with no config entry after startup."""
        if (provider := async_get_provider(hass)) is None:
            return
        for idp_id in provider.identity_provider_ids:
            if hass.config_entries.async_get_entry(idp_id) is None:
                await self._async_reconcile(idp_id)

    async def _async_reconcile(
        self, entry_id: str, *, removed_entry: ConfigEntry | None = None
    ) -> None:
        """Reconcile one config entry to the auth engine."""
        async with self._lock:
            await self._async_reconcile_locked(entry_id, removed_entry=removed_entry)

    async def _async_reconcile_locked(
        self, entry_id: str, *, removed_entry: ConfigEntry | None
    ) -> None:
        """Reconcile one config entry to the auth engine with the lock held."""
        entry = self.hass.config_entries.async_get_entry(entry_id)
        provider = async_get_provider(self.hass)

        if provider is None:
            if entry is not None and entry.domain in self._platforms:
                self._async_create_disabled_issue()
            return

        if entry is None:
            if entry_id in provider.identity_provider_ids:
                title = removed_entry.title if removed_entry else entry_id
                await self._async_remove_identity_provider(provider, entry_id, title)
            return

        platform = self._platforms.get(entry.domain)
        has_record = entry_id in provider.identity_provider_ids

        if entry.disabled_by:
            if has_record:
                self._async_suspend(provider, entry_id)
                if entry_id not in self._disabled_sessions_ended:
                    await provider.async_end_identity_provider_sessions(entry_id)
                    self._disabled_sessions_ended.add(entry_id)
            return

        self._disabled_sessions_ended.discard(entry_id)

        if entry.state is not ConfigEntryState.LOADED or platform is None:
            self._async_suspend(provider, entry_id)
            return

        try:
            spec = platform.get_identity_provider(entry.data, entry.options)
        except Exception:
            _LOGGER.exception("Error getting identity provider from %s", entry.domain)
            self._async_suspend(provider, entry_id)
            self._async_create_invalid_issue(entry.title, entry.domain, entry_id)
            return

        # A protocol of its own runs integration code while signing in.
        if (
            type(getattr(spec, "protocol", None)) is not OpenIDConnect
            and not async_get_loaded_integration(self.hass, entry.domain).is_built_in
        ):
            _LOGGER.warning(
                "The custom integration %s may only use the OpenIDConnect protocol",
                entry.domain,
            )
            self._async_suspend(provider, entry_id)
            self._async_create_invalid_issue(entry.title, entry.domain, entry_id)
            return

        child = provider.async_get_child_provider(entry_id)
        if (
            self._registered.get(entry_id) == (spec, entry.title)
            and isinstance(child, OidcIdentityProvider)
            and child.active
        ):
            return

        try:
            await provider.async_register_identity_provider(
                entry_id, domain=entry.domain, title=entry.title, spec=spec
            )
        except IdentityProviderError as err:
            _LOGGER.warning(
                "Invalid identity provider %s from %s: %s",
                entry_id,
                entry.domain,
                err.reason,
            )
            self._async_suspend(provider, entry_id)
            self._async_create_invalid_issue(entry.title, entry.domain, entry_id)
            return

        self._registered[entry_id] = (spec, entry.title)
        ir.async_delete_issue(
            self.hass, DOMAIN, f"invalid_identity_provider_{entry_id}"
        )

    @callback
    def _async_suspend(self, provider: OidcAuthProvider, entry_id: str) -> None:
        """Suspend an identity provider and forget its registered spec."""
        provider.async_suspend_identity_provider(entry_id)
        self._registered.pop(entry_id, None)

    async def _async_remove_identity_provider(
        self, provider: OidcAuthProvider, entry_id: str, title: str
    ) -> None:
        """Remove an identity provider from the engine."""
        users = await provider.async_remove_identity_provider(entry_id)
        self._registered.pop(entry_id, None)
        self._disabled_sessions_ended.discard(entry_id)
        ir.async_delete_issue(
            self.hass, DOMAIN, f"invalid_identity_provider_{entry_id}"
        )
        if users:
            self._async_create_removed_issue(entry_id, title, users)

    @callback
    def _async_create_disabled_issue(self) -> None:
        """Create the disabled engine repair issue."""
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            "identity_providers_disabled",
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="identity_providers_disabled",
        )

    @callback
    def _async_create_invalid_issue(
        self, title: str, entry_domain: str, entry_id: str
    ) -> None:
        """Create an invalid identity provider repair issue."""
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            f"invalid_identity_provider_{entry_id}",
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="invalid_identity_provider",
            translation_placeholders={"title": title, "domain": entry_domain},
        )

    @callback
    def _async_create_removed_issue(
        self, entry_id: str, title: str, users: list[User]
    ) -> None:
        """Create a persistent repair issue for users left without login."""
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            f"identity_provider_removed_{entry_id}",
            is_fixable=False,
            is_persistent=True,
            severity=ir.IssueSeverity.WARNING,
            translation_key="identity_provider_removed",
            translation_placeholders={
                "title": title,
                "users": ", ".join(user.name or user.id for user in users),
            },
        )
