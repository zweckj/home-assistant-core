"""Storage for the OpenID Connect auth provider engine."""

from dataclasses import asdict, dataclass
import logging
from typing import Any

import probatio

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store

from .const import STORAGE_KEY, STORAGE_VERSION

_LOGGER = logging.getLogger(__name__)

SAVE_DELAY = 1


@dataclass(kw_only=True, slots=True)
class IdentityProviderRecord:
    """Persisted identity provider registry record."""

    idp_id: str
    domain: str
    trust_key: str


# Keys written by a newer version are dropped rather than rejected.
_STORAGE_SCHEMA = probatio.Schema(
    {probatio.Optional("records"): probatio.Any(dict, None)},
    extra=probatio.REMOVE_EXTRA,
)

_RECORD_SCHEMA = probatio.Schema(
    {
        probatio.Required("idp_id"): str,
        probatio.Required("domain"): str,
        probatio.Required("trust_key"): str,
    },
    extra=probatio.REMOVE_EXTRA,
)


class OidcStore:
    """Persist identity provider registry records."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the store."""
        self._store = Store[dict[str, Any]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self.records: dict[str, IdentityProviderRecord] = {}

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

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        """Return the data to store."""
        return {
            "records": {
                idp_id: asdict(record) for idp_id, record in self.records.items()
            }
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
        """Drop an identity provider registry record."""
        if self.records.pop(idp_id, None) is not None:
            self.async_schedule_save()
