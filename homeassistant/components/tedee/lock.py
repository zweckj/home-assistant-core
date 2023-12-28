"""Tedee lock entities."""
from typing import Any

from pytedee_async import TedeeClientException, TedeeLock, TedeeLockState

from homeassistant.components.lock import (
    LockEntity,
    LockEntityDescription,
    LockEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import TedeeApiCoordinator
from .entity import TedeeEntity

ENTITIES: tuple[LockEntityDescription, ...] = (
    LockEntityDescription(
        key="lock",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the Tedee lock entity."""
    coordinator = hass.data[DOMAIN][entry.entry_id]

    entities: list[TedeeLockEntity] = []
    for lock in coordinator.data.values():
        for entity_description in ENTITIES:
            if lock.is_enabled_pullspring:
                entities.append(
                    TedeeLockWithLatchEntity(
                        lock, coordinator, entity_description, entry
                    )
                )
            else:
                entities.append(
                    TedeeLockEntity(lock, coordinator, entity_description, entry)
                )

    async_add_entities(entities)


class TedeeLockEntity(TedeeEntity, LockEntity):
    """A tedee lock that doesn't have pullspring enabled."""

    entity_description: LockEntityDescription
    _attr_name = None

    def __init__(
        self,
        lock: TedeeLock,
        coordinator: TedeeApiCoordinator,
        entity_description: LockEntityDescription,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the lock."""
        super().__init__(lock, coordinator, entity_description)

    @property
    def is_locked(self) -> bool:
        """Return true if lock is locked."""
        return self._lock.state == TedeeLockState.LOCKED

    @property
    def is_unlocking(self) -> bool:
        """Return true if lock is unlocking."""
        return self._lock.state == TedeeLockState.UNLOCKING

    @property
    def is_locking(self) -> bool:
        """Return true if lock is locking."""
        return self._lock.state == TedeeLockState.LOCKING

    @property
    def is_jammed(self) -> bool:
        """Return true if lock is jammed."""
        return self._lock.is_state_jammed

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return self._lock.is_connected

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the door."""
        try:
            self._lock.state = TedeeLockState.UNLOCKING
            self.async_write_ha_state()

            await self.coordinator.tedee_client.unlock(self._lock.lock_id)
            await self.coordinator.async_request_refresh()
        except (TedeeClientException, Exception) as ex:
            raise HomeAssistantError(
                "Failed to unlock the door. Lock %s" % self._lock.lock_id
            ) from ex

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the door."""
        try:
            self._lock.state = TedeeLockState.LOCKING
            self.async_write_ha_state()

            await self.coordinator.tedee_client.lock(self._lock.lock_id)
            await self.coordinator.async_request_refresh()
        except (TedeeClientException, Exception) as ex:
            raise HomeAssistantError(
                "Failed to lock the door. Lock %s" % self._lock.lock_id
            ) from ex


class TedeeLockWithLatchEntity(TedeeLockEntity):
    """A tedee lock but has pullspring enabled, so it additional features."""

    @property
    def supported_features(self) -> LockEntityFeature:
        """Flag supported features."""
        return LockEntityFeature.OPEN

    async def async_open(self, **kwargs: Any) -> None:
        """Open the door with pullspring."""
        try:
            self._lock.state = TedeeLockState.UNLOCKING
            self.async_write_ha_state()

            await self.coordinator.tedee_client.open(self._lock.lock_id)
            await self.coordinator.async_request_refresh()
        except (TedeeClientException, Exception) as ex:
            raise HomeAssistantError(
                "Failed to unlatch the door. Lock %s" % self._lock.lock_id
            ) from ex
