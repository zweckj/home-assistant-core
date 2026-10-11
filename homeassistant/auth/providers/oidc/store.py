"""Storage for the OpenID Connect auth provider engine."""

from dataclasses import asdict, dataclass
import logging
import math
import time
from typing import Any

import probatio

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store

from .const import REVALIDATE_REFRESH_RATIO, STORAGE_KEY, STORAGE_VERSION
from .spec import AccountPolicy

_LOGGER = logging.getLogger(__name__)

SAVE_DELAY = 1


@dataclass(kw_only=True, slots=True)
class IdentityProviderRecord:
    """Persisted identity provider registry record."""

    idp_id: str
    domain: str
    accounts: AccountPolicy
    trust_key: str


@dataclass(kw_only=True, slots=True)
class OidcSession:
    """The identity provider session backing a Home Assistant credential."""

    credential_id: str
    idp_id: str
    subject: str
    revalidate_after: float = 0.0
    refresh_after: float = 0.0
    refresh_token: str | None = None
    username: str | None = None
    display_name: str | None = None
    is_admin: bool = False

    def mark_validated(self, revalidate_interval: float) -> None:
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
        probatio.Optional("records"): probatio.Any(dict, None),
        probatio.Optional("sessions"): probatio.Any(dict, None),
    },
    extra=probatio.REMOVE_EXTRA,
)

_RECORD_SCHEMA = probatio.Schema(
    {
        probatio.Required("idp_id"): str,
        probatio.Required("domain"): str,
        probatio.Required("accounts"): probatio.Coerce(AccountPolicy),
        probatio.Required("trust_key"): str,
    },
    extra=probatio.REMOVE_EXTRA,
)

_SESSION_SCHEMA = probatio.Schema(
    {
        probatio.Required("credential_id"): str,
        probatio.Required("idp_id"): str,
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
    """Persist identity provider registry records and sessions."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the store."""
        self.hass = hass
        self._store = Store[dict[str, Any]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self.records: dict[str, IdentityProviderRecord] = {}
        self.sessions: dict[str, OidcSession] = {}

    async def async_load(self) -> None:
        """Load the stored data."""
        data: Any = await self._store.async_load()
        if data is None:
            return

        try:
            data = _STORAGE_SCHEMA(data)
        except probatio.Invalid:
            _LOGGER.exception("Discarding unreadable OIDC storage")
            return

        for idp_id, raw_record in (data.get("records") or {}).items():
            try:
                record = IdentityProviderRecord(**_RECORD_SCHEMA(raw_record))
            except probatio.Invalid:
                _LOGGER.exception("Discarding unreadable OIDC identity provider record")
                continue
            if record.idp_id != idp_id:
                _LOGGER.error(
                    "Discarding an OIDC identity provider record stored under"
                    " another key"
                )
                continue
            self.records[idp_id] = record

        for credential_id, raw_session in (data.get("sessions") or {}).items():
            try:
                session = OidcSession(**_SESSION_SCHEMA(raw_session))
            except probatio.Invalid:
                _LOGGER.exception("Discarding unreadable OIDC session")
                continue
            if session.credential_id != credential_id:
                _LOGGER.error("Discarding an OIDC session stored under another key")
                continue
            if session.idp_id not in self.records:
                _LOGGER.error(
                    "Discarding an OIDC session of an unregistered identity provider"
                )
                continue
            self.sessions[credential_id] = session

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        """Return the data to store."""
        return {
            "records": {
                idp_id: {**asdict(record), "accounts": record.accounts.value}
                for idp_id, record in self.records.items()
            },
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
    def async_set_record(self, record: IdentityProviderRecord) -> None:
        """Store an identity provider registry record."""
        self.records[record.idp_id] = record
        self.async_schedule_save()

    @callback
    def async_remove_record(self, idp_id: str) -> None:
        """Drop an identity provider registry record and its sessions."""
        if self.records.pop(idp_id, None) is None:
            return
        for credential_id, session in list(self.sessions.items()):
            if session.idp_id == idp_id:
                self.sessions.pop(credential_id)
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
