"""Init the tedee component."""

from collections.abc import Awaitable, Callable
from http import HTTPStatus
import logging
import secrets
import string
from typing import Any

from aiohttp.hdrs import METH_POST
from aiohttp.web import Request, Response
from pytedee_async.exception import TedeeWebhookException

from homeassistant.components.http import HomeAssistantView
from homeassistant.components.webhook import (
    async_generate_path as webhook_generate_path,
    async_register as webhook_register,
    async_unregister as webhook_unregister,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_WEBHOOK_ID, EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.network import get_url

from .const import DOMAIN, NAME
from .coordinator import TedeeApiCoordinator

PLATFORMS = [
    Platform.BINARY_SENSOR,
    Platform.LOCK,
    Platform.SENSOR,
]

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Integration setup."""

    coordinator = TedeeApiCoordinator(hass)

    await coordinator.async_config_entry_first_refresh()

    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, coordinator.bridge.serial)},
        manufacturer="Tedee",
        name=coordinator.bridge.name,
        model="Bridge",
        serial_number=coordinator.bridge.serial,
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    def generate_api_key(length: int = 16) -> str:
        characters = string.ascii_letters + string.digits
        password = "".join(secrets.choice(characters) for _ in range(length))
        return password

    async def unregister_webhook(_: Any) -> None:
        await coordinator.async_unregister_webhook()
        webhook_unregister(hass, entry.data[CONF_WEBHOOK_ID])

    async def register_webhook() -> None:
        # webhook_url = webhook_generate_url(hass, entry.data[CONF_WEBHOOK_ID])
        webhook_url = (
            f"http://192.168.1.114:8123/api/webhook/{entry.data[CONF_WEBHOOK_ID]}"
        )
        webhook_url = f"{get_url(hass, allow_external=False)}{webhook_generate_path(entry.data[CONF_WEBHOOK_ID])}"
        webhook_name = "Tedee"
        if entry.title != NAME:
            webhook_name = f"{NAME} {entry.title}"

        api_key = generate_api_key()

        webhook_register(
            hass,
            DOMAIN,
            webhook_name,
            entry.data[CONF_WEBHOOK_ID],
            get_webhook_handler(coordinator, api_key),
            allowed_methods=[METH_POST],
        )
        _LOGGER.warning("Registered Tedee webhook at hass: %s", webhook_url)

        try:
            await coordinator.async_register_webhook(
                webhook_url, headers=[{"Authorization": api_key}]
            )
        except TedeeWebhookException as ex:
            _LOGGER.warning("Failed to register Tedee webhook from bridge: %s", ex)
        else:
            entry.async_on_unload(
                hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, unregister_webhook)
            )

    entry.async_create_background_task(
        hass, register_webhook(), "tedee_register_webhook"
    )
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""

    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


def get_webhook_handler(
    coordinator: TedeeApiCoordinator,
    api_key: str,
) -> Callable[[HomeAssistant, str, Request], Awaitable[Response | None]]:
    """Return webhook handler."""

    async def async_webhook_handler(
        hass: HomeAssistant, webhook_id: str, request: Request
    ) -> Response | None:
        # Handle http post calls to the path.
        if not request.body_exists:
            return HomeAssistantView.json(
                result="No Body", status_code=HTTPStatus.BAD_REQUEST
            )

        if request.headers.get("Authorization") != api_key:
            return HomeAssistantView.json(
                result="Unauthorized", status_code=HTTPStatus.UNAUTHORIZED
            )

        body = await request.json()
        try:
            coordinator.webhook_received(body)
        except TedeeWebhookException as ex:
            return HomeAssistantView.json(
                result=str(ex), status_code=HTTPStatus.BAD_REQUEST
            )

        return HomeAssistantView.json(result="OK", status_code=HTTPStatus.OK)

    return async_webhook_handler
