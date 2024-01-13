"""Calendar platform for La Marzocco espresso machines."""
from collections.abc import Iterator
from datetime import datetime, timedelta

from homeassistant.components.calendar import CalendarEntity, CalendarEvent
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import LaMarzoccoBaseEntity

CALENDAR_KEY = "auto_on_off_schedule"


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up switch entities and services."""

    coordinator = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([LaMarzoccoCalendarEntity(coordinator, CALENDAR_KEY)])


class LaMarzoccoCalendarEntity(LaMarzoccoBaseEntity, CalendarEntity):
    """Class representing a La Marzocco Calendar."""

    _attr_translation_key = CALENDAR_KEY

    @property
    def event(self) -> CalendarEvent | None:
        """Return the next upcoming event."""
        # only need to check the next 6 days, because if we don't find anything there
        # then there is no event scheduled
        for date in self._asnyc_date_range(
            datetime.today(), datetime.today() + timedelta(days=6)
        ):
            scheduled = self._async_get_calendar_event(date)
            if scheduled:
                if scheduled.end > datetime.now():
                    continue
                return scheduled
        return None

    async def async_get_events(
        self,
        hass: HomeAssistant,
        start_date: datetime,
        end_date: datetime,
    ) -> list[CalendarEvent]:
        """Return calendar events within a datetime range."""

        events: list[CalendarEvent] = []

        for date in self._asnyc_date_range(start_date, end_date):
            scheduled = self._async_get_calendar_event(date)
            if scheduled:
                events.append(scheduled)
        return events

    def _asnyc_date_range(
        self, start_date: datetime, end_date: datetime
    ) -> Iterator[datetime]:
        current_date = start_date
        while current_date <= end_date:
            yield current_date
            current_date += timedelta(days=1)

    def _async_get_calendar_event(self, date: datetime) -> CalendarEvent | None:
        """Return calendar event for a given weekday."""

        # check first if auto/on off is turned on in general
        # because could still be on for that day but disabled
        if self.coordinator.lm.current_status.get("global_auto") != "Enabled":
            return None

        # parse the schedule for the day
        schedule_day = self.coordinator.lm.schedule[date.weekday()]
        if schedule_day["enable"] == "Disabled":
            return None
        hour_on, minute_on = schedule_day["on"].split(":")
        hour_off, minute_off = schedule_day["off"].split(":")
        return CalendarEvent(
            start=date.replace(
                hour=int(hour_on),
                minute=int(minute_on),
            ),
            end=date.replace(
                hour=int(hour_off),
                minute=int(minute_off),
            ),
            summary=f"Machine {self.coordinator.lm.true_model_name} ({self.coordinator.lm.serial_number}) on",
            description="Machine is scheduled to turn on at the start time and off at the end time",
        )
