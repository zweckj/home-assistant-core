"""Storage for the OpenID Connect auth provider."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, fields
import logging
import math
import time
from typing import Any

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
    scopes: list[str] = field(default_factory=lambda: list(DEFAULT_SCOPES))
    username_claim: str = DEFAULT_USERNAME_CLAIM
    display_name_claim: str = DEFAULT_DISPLAY_NAME_CLAIM
    admin_group: str | None = DEFAULT_ADMIN_GROUP
    allow_auto_create: bool = False
    revalidate_interval: int = DEFAULT_REVALIDATE_INTERVAL

    @property
    def trust_key(self) -> tuple[str, str, str | None, tuple[str, ...]]:
        """Return the fields that decide who issued the existing sessions.

        A change to any of them makes what was issued before it meaningless;
        everything else is applied without signing anybody out.
        """
        return (self.issuer, self.client_id, self.client_secret, tuple(self.scopes))

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


def _from_dict[_T](cls: type[_T], data: Mapping[str, Any]) -> _T:
    """Build a dataclass, ignoring keys written by a newer version."""
    known = {item.name for item in fields(cls)}  # type: ignore[arg-type]
    return cls(**{key: value for key, value in data.items() if key in known})


def _config_from_dict(data: Any) -> OidcConfig:
    """Deserialize and validate stored provider configuration."""
    if not isinstance(data, Mapping):
        raise TypeError("configuration is not an object")
    config = _from_dict(OidcConfig, data)
    if (
        not isinstance(config.issuer, str)
        or not isinstance(config.client_id, str)
        or not (config.client_secret is None or isinstance(config.client_secret, str))
        or not isinstance(config.scopes, list)
        or any(not isinstance(scope, str) for scope in config.scopes)
        or not isinstance(config.username_claim, str)
        or not isinstance(config.display_name_claim, str)
        or not (config.admin_group is None or isinstance(config.admin_group, str))
        or type(config.allow_auto_create) is not bool
        or type(config.revalidate_interval) is not int
        or not MIN_REVALIDATE_INTERVAL
        <= config.revalidate_interval
        <= MAX_REVALIDATE_INTERVAL
    ):
        raise TypeError("configuration has invalid fields")
    return config


def _session_from_dict(data: Any) -> OidcSession:
    """Deserialize and validate a stored identity provider session."""
    if not isinstance(data, Mapping):
        raise TypeError("session is not an object")
    session = _from_dict(OidcSession, data)
    if (
        not isinstance(session.credential_id, str)
        or not isinstance(session.subject, str)
        or not isinstance(session.revalidate_after, int | float)
        or isinstance(session.revalidate_after, bool)
        or not math.isfinite(session.revalidate_after)
        or not isinstance(session.refresh_after, int | float)
        or isinstance(session.refresh_after, bool)
        or not math.isfinite(session.refresh_after)
        or not (session.refresh_token is None or isinstance(session.refresh_token, str))
        or not (session.username is None or isinstance(session.username, str))
        or not (session.display_name is None or isinstance(session.display_name, str))
        or type(session.is_admin) is not bool
    ):
        raise TypeError("session has invalid fields")
    return session


def _session_entry_from_dict(credential_id: Any, data: Any) -> OidcSession:
    """Deserialize a session entry and validate its storage key."""
    if not isinstance(credential_id, str):
        raise TypeError("session key is not a string")
    session = _session_from_dict(data)
    if session.credential_id != credential_id:
        raise TypeError("session credential ID does not match its key")
    return session


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
        if not isinstance(data, Mapping):
            _LOGGER.error("Discarding unreadable OIDC storage")
            self.config_discarded = True
            return

        if (raw_config := data.get("config")) is not None:
            try:
                self.config = _config_from_dict(raw_config)
            except TypeError:
                _LOGGER.exception("Discarding unreadable OIDC configuration")
                self.config_discarded = True

        if self.config is None:
            return

        raw_sessions = data.get("sessions")
        if raw_sessions is None:
            return
        if not isinstance(raw_sessions, Mapping):
            _LOGGER.error("Discarding unreadable OIDC sessions")
            return

        for credential_id, raw_session in raw_sessions.items():
            try:
                session = _session_entry_from_dict(credential_id, raw_session)
                self.sessions[credential_id] = session
            except TypeError:
                _LOGGER.exception("Discarding unreadable OIDC session")

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
