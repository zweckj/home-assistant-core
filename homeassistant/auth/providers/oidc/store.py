"""Storage for the OpenID Connect auth provider."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
import logging
import math
import time
from typing import Any

import probatio

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store

from .const import (
    DEFAULT_ADMIN_GROUP,
    DEFAULT_DISPLAY_NAME_CLAIM,
    DEFAULT_REVALIDATE_INTERVAL,
    DEFAULT_SCOPES,
    DEFAULT_USERNAME_CLAIM,
    GROUPS_CLAIM,
    MAX_REVALIDATE_INTERVAL,
    MIN_REVALIDATE_INTERVAL,
    REVALIDATE_REFRESH_RATIO,
    STORAGE_KEY,
    STORAGE_VERSION,
)

_LOGGER = logging.getLogger(__name__)

SAVE_DELAY = 1


def _claim_as_str(value: Any) -> str | None:
    """Return a claim that has to be a string."""
    return value if isinstance(value, str) else None


def _claim_as_list(value: Any) -> list[str]:
    """Return a claim that may be a list or a space separated string."""
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


@dataclass(kw_only=True, slots=True)
class OidcConfig:
    """The administrator provided configuration of the provider."""

    issuer: str
    client_id: str
    client_secret: str | None = None
    name: str | None = None
    icon_url: str | None = None
    scopes: list[str] = field(default_factory=lambda: list(DEFAULT_SCOPES))
    username_claim: str = DEFAULT_USERNAME_CLAIM
    display_name_claim: str = DEFAULT_DISPLAY_NAME_CLAIM
    admin_group: str | None = DEFAULT_ADMIN_GROUP
    allow_auto_create: bool = False
    revalidate_interval: int = DEFAULT_REVALIDATE_INTERVAL
    allow_insecure_transport: bool = False

    @property
    def trust_key(
        self,
    ) -> tuple[str, str, str | None, tuple[str, ...], str | None, bool]:
        """Return the settings whose change ends every existing session."""
        return (
            self.issuer,
            self.client_id,
            self.client_secret,
            tuple(self.scopes),
            self.admin_group,
            self.allow_insecure_transport,
        )

    def username_from(self, claims: Mapping[str, Any]) -> str | None:
        """Return the username a set of claims maps to."""
        return _claim_as_str(claims.get(self.username_claim))

    def display_name_from(self, claims: Mapping[str, Any]) -> str | None:
        """Return the display name a set of claims maps to."""
        return _claim_as_str(claims.get(self.display_name_claim))

    def grants_admin(self, claims: Mapping[str, Any]) -> bool:
        """Return if the group memberships grant administrator access."""
        if not self.admin_group:
            return False
        return self.admin_group in _claim_as_list(claims.get(GROUPS_CLAIM))

    def needs_userinfo(self, claims: Mapping[str, Any]) -> bool:
        """Return if a claim needed to create an account is missing."""
        return any(
            claim not in claims
            for claim in (self.username_claim, self.display_name_claim)
        )


@dataclass(kw_only=True, slots=True)
class OidcSession:
    """The identity provider session backing a Home Assistant credential."""

    credential_id: str
    subject: str
    # Expired until the identity provider has confirmed the session once.
    revalidate_after: float = 0.0
    refresh_after: float = 0.0
    refresh_token: str | None = None
    username: str | None = None
    display_name: str | None = None
    is_admin: bool = False

    def mark_validated(self, revalidate_interval: int) -> None:
        """Push the deadlines out after the identity provider confirmed us."""
        now = time.time()
        self.revalidate_after = now + revalidate_interval
        self.refresh_after = now + revalidate_interval * REVALIDATE_REFRESH_RATIO


def _finite(value: float) -> float:
    """Reject a timestamp that could never be reached or compared."""
    if not math.isfinite(value):
        raise probatio.Invalid("must be a finite number")
    return value


_OPTIONAL_STR = probatio.Any(str, None)
_TIMESTAMP = probatio.All(probatio.Any(int, float), _finite)

# Keys written by a newer version are dropped rather than rejected.
_STORAGE_SCHEMA = probatio.Schema(
    {
        probatio.Optional("config"): probatio.Any(dict, None),
        probatio.Optional("sessions"): probatio.Any(dict, None),
    },
    extra=probatio.REMOVE_EXTRA,
)

_CONFIG_SCHEMA = probatio.Schema(
    {
        probatio.Required("issuer"): str,
        probatio.Required("client_id"): str,
        probatio.Optional("client_secret"): _OPTIONAL_STR,
        probatio.Optional("name"): _OPTIONAL_STR,
        probatio.Optional("icon_url"): _OPTIONAL_STR,
        probatio.Optional("scopes"): [str],
        probatio.Optional("username_claim"): str,
        probatio.Optional("display_name_claim"): str,
        probatio.Optional("admin_group"): _OPTIONAL_STR,
        probatio.Optional("allow_auto_create"): bool,
        probatio.Optional("allow_insecure_transport"): bool,
        probatio.Optional("revalidate_interval"): probatio.All(
            int,
            probatio.Range(min=MIN_REVALIDATE_INTERVAL, max=MAX_REVALIDATE_INTERVAL),
        ),
    },
    extra=probatio.REMOVE_EXTRA,
)

_SESSION_SCHEMA = probatio.Schema(
    {
        probatio.Required("credential_id"): str,
        probatio.Required("subject"): str,
        probatio.Optional("revalidate_after"): _TIMESTAMP,
        probatio.Optional("refresh_after"): _TIMESTAMP,
        probatio.Optional("refresh_token"): _OPTIONAL_STR,
        probatio.Optional("username"): _OPTIONAL_STR,
        probatio.Optional("display_name"): _OPTIONAL_STR,
        probatio.Optional("is_admin"): bool,
    },
    extra=probatio.REMOVE_EXTRA,
)


class OidcStore:
    """Persist the provider configuration and the identity provider sessions."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the store."""
        self.hass = hass
        # Holds identity provider refresh tokens, so keep the file owner only.
        self._store = Store[dict[str, Any]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self.config: OidcConfig | None = None
        self.sessions: dict[str, OidcSession] = {}
        # A discarded configuration looks exactly like never having had one, so
        # the difference is kept for the UI to report.
        self.config_discarded = False

    async def async_load(self) -> None:
        """Load the stored data."""
        data: Any = await self._store.async_load()
        if data is None:
            return

        try:
            data = _STORAGE_SCHEMA(data)
            if (raw_config := data.get("config")) is not None:
                self.config = OidcConfig(**_CONFIG_SCHEMA(raw_config))
        except probatio.Invalid:
            _LOGGER.exception("Discarding unreadable OIDC configuration")
            self.config_discarded = True
            return

        if self.config is None:
            return

        for credential_id, raw_session in (data.get("sessions") or {}).items():
            try:
                session = OidcSession(**_SESSION_SCHEMA(raw_session))
            except probatio.Invalid:
                _LOGGER.exception("Discarding unreadable OIDC session")
                continue
            if session.credential_id != credential_id:
                _LOGGER.error("Discarding an OIDC session stored under another key")
                continue
            self.sessions[credential_id] = session

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        """Return the data to store."""
        return {
            "config": asdict(self.config) if self.config else None,
            "sessions": {
                credential_id: asdict(session)
                for credential_id, session in self.sessions.items()
            },
        }

    @callback
    def async_schedule_save(self) -> None:
        """Schedule saving the data."""
        self._store.async_delay_save(self._data_to_save, SAVE_DELAY)

    @callback
    def async_set_config(self, config: OidcConfig | None) -> None:
        """Replace the provider configuration."""
        self.config = config
        self.config_discarded = False
        if config is None:
            self.sessions.clear()
        self.async_schedule_save()

    @callback
    def async_set_session(self, session: OidcSession) -> None:
        """Store an identity provider session."""
        self.sessions[session.credential_id] = session
        self.async_schedule_save()

    @callback
    def async_remove_session(self, credential_id: str) -> OidcSession | None:
        """Drop an identity provider session."""
        if (session := self.sessions.pop(credential_id, None)) is not None:
            self.async_schedule_save()
        return session
